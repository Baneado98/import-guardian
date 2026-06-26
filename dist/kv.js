// Cloudflare KV via REST API.
//
// This MCP runs on Vercel (not Cloudflare Workers), so we cannot use a native
// KV binding. Instead we talk to Cloudflare's KV REST API directly. This is the
// shared store for:
//   1) prepaid API keys minted after a Stripe payment   (key:<apiKey> -> metadata)
//   2) the conversion funnel counters (pro_hit / 402_served / 200_paid)
//
// Three env vars wire it up (set in the Vercel project env):
//   CLOUDFLARE_ACCOUNT_ID
//   CLOUDFLARE_API_TOKEN       (token with "Workers KV Storage:Edit")
//   CLOUDFLARE_KV_NAMESPACE_ID (id of the KV namespace for this service)
//
// If any are missing the helpers degrade gracefully (kvEnabled() === false) so
// the server still boots — the env-var key list (PRO_API_KEYS) keeps working as
// a fallback and funnel counting silently no-ops.
const ACCOUNT_ID = (process.env.CLOUDFLARE_ACCOUNT_ID ?? "").trim();
const API_TOKEN = (process.env.CLOUDFLARE_API_TOKEN ?? "").trim();
const NS_ID = (process.env.CLOUDFLARE_KV_NAMESPACE_ID ?? "").trim();
export function kvEnabled() {
    return !!(ACCOUNT_ID && API_TOKEN && NS_ID);
}
function base() {
    return `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/storage/kv/namespaces/${NS_ID}`;
}
function authHeaders() {
    return { Authorization: `Bearer ${API_TOKEN}` };
}
async function withTimeout(p, ms = 8000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
        return await p(ctrl.signal);
    }
    finally {
        clearTimeout(t);
    }
}
/** GET a value. Returns the raw string, or null if the key does not exist. */
export async function kvGet(key) {
    if (!kvEnabled())
        return null;
    return withTimeout(async (signal) => {
        const res = await fetch(`${base()}/values/${encodeURIComponent(key)}`, {
            headers: authHeaders(),
            signal,
        });
        if (res.status === 404)
            return null;
        if (!res.ok)
            throw new Error(`kvGet ${key} -> ${res.status}`);
        return await res.text();
    });
}
/** PUT a value (optionally with a TTL in seconds, min 60). */
export async function kvPut(key, value, ttlSeconds) {
    if (!kvEnabled())
        return;
    await withTimeout(async (signal) => {
        let url = `${base()}/values/${encodeURIComponent(key)}`;
        if (ttlSeconds && ttlSeconds >= 60)
            url += `?expiration_ttl=${ttlSeconds}`;
        const res = await fetch(url, {
            method: "PUT",
            headers: { ...authHeaders(), "Content-Type": "text/plain" },
            body: value,
            signal,
        });
        if (!res.ok)
            throw new Error(`kvPut ${key} -> ${res.status} ${await res.text().catch(() => "")}`);
    });
}
/**
 * Atomic-ish counter increment. KV has no native INCR, so we read-modify-write.
 * Funnel counters tolerate the rare lost update under concurrency — they are a
 * signal, not billing. Never throws (instrumentation must not break a request).
 */
export async function kvIncr(counter, by = 1) {
    if (!kvEnabled())
        return;
    try {
        const cur = await kvGet(`counter:${counter}`);
        const n = (cur ? parseInt(cur, 10) || 0 : 0) + by;
        await kvPut(`counter:${counter}`, String(n));
    }
    catch {
        /* swallow */
    }
}
/** Read all funnel counters at once (best-effort). */
export async function kvCounters(names) {
    const out = {};
    await Promise.all(names.map(async (n) => {
        try {
            const v = await kvGet(`counter:${n}`);
            out[n] = v ? parseInt(v, 10) || 0 : 0;
        }
        catch {
            out[n] = -1;
        }
    }));
    return out;
}
// Per-service tag so a prepaid key minted for one service can NEVER unlock
// another, even if two deploys accidentally share a Cloudflare KV namespace.
const SVC = "ig";
const KEY_PREFIX = `key:${SVC}:`;
export async function putProKey(apiKey, rec) {
    await kvPut(KEY_PREFIX + apiKey, JSON.stringify(rec));
}
/** Look up a prepaid key. Returns the record if it exists AND is active. */
export async function getProKey(apiKey) {
    if (!apiKey)
        return null;
    const raw = await kvGet(KEY_PREFIX + apiKey);
    if (!raw)
        return null;
    try {
        const rec = JSON.parse(raw);
        return rec.status === "active" ? rec : null;
    }
    catch {
        return null;
    }
}
