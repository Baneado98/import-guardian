// Stripe payment lane — the HUMAN door to the /pro batch / unlimited scan.
//
// Two ways to pay for /pro coexist (Kiran's dual-pay directive):
//   • x402   — agents pay USDC per call automatically (handled in server.ts).
//   • Stripe — humans buy a prepaid API key via Checkout (handled here).
//
// Flow:
//   1) GET  /pro/checkout       -> create a Checkout Session, redirect/return its URL
//   2) Stripe hosts the card form (4242… in TEST). On success it fires a webhook.
//   3) POST /pro/webhook        -> verify signature, mint an API key, store in KV.
//   4) The buyer sets IMPORT_GUARDIAN_KEY=<key>; /pro/scan validates it vs KV.
//
// Keys/secrets come from env (set in Vercel, sourced from config/stripe.env):
//   STRIPE_SECRET_KEY        (sk_test_… in TEST, sk_live_/rk_live_… in LIVE)
//   STRIPE_WEBHOOK_SECRET    (whsec_…)
//   STRIPE_PRICE_EUR_CENTS   (optional, default 900 = €9.00)
//   PUBLIC_BASE_URL          (e.g. https://import-guardian.vercel.app)
import Stripe from "stripe";
import { randomBytes } from "node:crypto";
import { putProKey } from "./kv.js";
const SECRET = (process.env.STRIPE_SECRET_KEY ?? "").trim();
const WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET ?? "").trim();
const PRICE_CENTS = Number(process.env.STRIPE_PRICE_EUR_CENTS ?? 900); // €9.00 default
const PLAN_NAME = process.env.STRIPE_PLAN_NAME ?? "import-guardian Pro";
const KEY_PREFIX = process.env.STRIPE_KEY_PREFIX ?? "ig_";
export function stripeEnabled() {
    return !!SECRET;
}
let _stripe = null;
function stripe() {
    if (!_stripe) {
        if (!SECRET)
            throw new Error("STRIPE_SECRET_KEY not configured");
        _stripe = new Stripe(SECRET, { apiVersion: "2025-02-24.acacia" });
    }
    return _stripe;
}
/** A fresh, URL-safe prepaid key: <prefix><40 hex>. */
export function mintApiKey() {
    return KEY_PREFIX + randomBytes(20).toString("hex");
}
/**
 * Create a Checkout Session (mode=payment, EUR, one-off). Returns the hosted URL
 * the human opens to pay. We embed plan metadata so the webhook knows what was
 * bought without a second lookup.
 */
export async function createCheckoutSession(baseUrl) {
    const session = await stripe().checkout.sessions.create({
        mode: "payment",
        line_items: [
            {
                quantity: 1,
                price_data: {
                    currency: "eur",
                    unit_amount: PRICE_CENTS,
                    product_data: {
                        name: PLAN_NAME,
                        description: "Prepaid API key unlocking unlimited / batch slopsquat scanning (/pro). Set it as IMPORT_GUARDIAN_KEY in your MCP config.",
                    },
                },
            },
        ],
        metadata: { plan: "pro", product: "import-guardian" },
        success_url: `${baseUrl}/pro/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${baseUrl}/#pro`,
    });
    if (!session.url)
        throw new Error("Stripe did not return a Checkout URL");
    return { id: session.id, url: session.url };
}
/**
 * Verify a webhook payload signature and return the parsed event. Throws if the
 * signature is invalid — the route MUST treat a throw as 400 and NOT mint a key.
 * `rawBody` must be the EXACT bytes Stripe sent (no JSON re-serialisation).
 */
export function constructWebhookEvent(rawBody, signature) {
    if (!WEBHOOK_SECRET)
        throw new Error("STRIPE_WEBHOOK_SECRET not configured");
    return stripe().webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
}
/**
 * Handle a verified `checkout.session.completed` event: mint a prepaid API key
 * and store it (active) in KV with billing metadata. Returns the minted key (so
 * tests can assert it), or null if the event was not a completed/paid checkout.
 */
export async function handleCheckoutCompleted(event) {
    if (event.type !== "checkout.session.completed")
        return null;
    const session = event.data.object;
    if (session.payment_status !== "paid")
        return null;
    const apiKey = mintApiKey();
    const rec = {
        plan: session.metadata?.plan ?? "pro",
        createdAt: new Date().toISOString(),
        sessionId: session.id,
        email: session.customer_details?.email ?? session.customer_email ?? undefined,
        amountTotal: session.amount_total ?? undefined,
        currency: session.currency ?? undefined,
        status: "active",
    };
    await putProKey(apiKey, rec);
    await putProKey(`session_${session.id}`, { ...rec, plan: `lookup:${apiKey}` });
    return apiKey;
}
/** Retrieve the key minted for a given session (for the /pro/success page). */
export async function keyForSession(sessionId) {
    const { getProKey } = await import("./kv.js");
    const rec = await getProKey(`session_${sessionId}`);
    if (!rec)
        return null;
    const m = /^lookup:(.+)$/.exec(rec.plan);
    return m ? m[1] : null;
}
export const stripeConfig = { PRICE_CENTS, PLAN_NAME };
