// import-guardian — resolve each referenced package against the live npm
// registry and classify it for slopsquatting / hallucination risk.
import { closestPopular } from "./popular.js";
async function fetchJson(url, timeoutMs = 8000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            signal: ctrl.signal,
            headers: { accept: "application/json", "user-agent": "import-guardian" },
        });
        const status = res.status;
        let body = null;
        try {
            body = await res.json();
        }
        catch {
            body = null;
        }
        return { status, body };
    }
    catch {
        return { status: 0, body: null };
    }
    finally {
        clearTimeout(t);
    }
}
function daysSince(iso) {
    if (!iso)
        return null;
    const t = Date.parse(iso);
    if (Number.isNaN(t))
        return null;
    return Math.floor((Date.now() - t) / 86_400_000);
}
async function weeklyDownloads(pkg) {
    // npm download stats endpoint. Scoped packages are supported.
    const url = `https://api.npmjs.org/downloads/point/last-week/${pkg}`;
    const { status, body } = await fetchJson(url, 6000);
    if (status === 200 && body && typeof body.downloads === "number")
        return body.downloads;
    return null;
}
/**
 * Classify one referenced package. `raw`/`kind` are passed through from the
 * parser so the caller can point at the exact import.
 */
export async function classifyPackage(pkg, raw = pkg, kind = "import") {
    const reasons = [];
    // Look the package up in the registry. We hit the per-package doc, which is
    // cheap and gives us time (created/modified) + versions + repo + deprecation.
    const enc = pkg.startsWith("@")
        ? pkg.replace("/", "%2f")
        : encodeURIComponent(pkg);
    const { status, body } = await fetchJson(`https://registry.npmjs.org/${enc}`);
    // ---- Case 1: the package DOES NOT EXIST -> hallucination / slopsquat target.
    if (status === 404 || (status === 200 && body && body.error)) {
        const near = closestPopular(pkg, 3);
        reasons.push("This package does not exist on the npm registry. An AI model very likely hallucinated this name — do not install it. Attackers register such names to ship malware (slopsquatting).");
        const f = {
            pkg, raw, kind, status: "hallucinated", risk: 95, reasons,
        };
        if (near) {
            f.didYouMean = near.match;
            reasons.push(`Closest real package is "${near.match}" (edit distance ${near.distance}). Use that if it is what you meant.`);
        }
        return f;
    }
    // ---- Registry / network problem -> be honest, don't fake a verdict.
    if (status !== 200 || !body || !body.name) {
        reasons.push("Could not reach the npm registry to verify this package (network/registry error). Treat as unverified.");
        return { pkg, raw, kind, status: "suspicious", risk: 40, reasons };
    }
    // ---- Case 2: it exists — gather facts and weight slop signals.
    const time = body.time || {};
    const ageDays = daysSince(time.created);
    const lastPublishDays = daysSince(time.modified);
    const versions = body.versions ? Object.keys(body.versions).length : 0;
    const hasRepo = Boolean(body.repository && (body.repository.url || typeof body.repository === "string"));
    const deprecated = Boolean(body.versions &&
        body["dist-tags"] &&
        body.versions[body["dist-tags"].latest] &&
        body.versions[body["dist-tags"].latest].deprecated);
    const dl = await weeklyDownloads(pkg);
    let risk = 0;
    // Brand-new packages are the prime slopsquat vehicle (registered AFTER the
    // hallucination was observed). Recency is the strongest live signal.
    if (ageDays !== null) {
        if (ageDays <= 14) {
            risk += 55;
            reasons.push(`Published only ${ageDays} day(s) ago — brand-new packages matching a plausible name are a classic slopsquat vehicle.`);
        }
        else if (ageDays <= 60) {
            risk += 30;
            reasons.push(`Published ${ageDays} days ago — still very new; verify it is the package you intend.`);
        }
        else if (ageDays <= 180) {
            risk += 12;
            reasons.push(`Published ${ageDays} days ago — relatively new.`);
        }
    }
    if (!hasRepo) {
        risk += 18;
        reasons.push("No source repository linked — legitimate libraries almost always link their repo.");
    }
    if (versions <= 1) {
        risk += 12;
        reasons.push(`Only ${versions} published version — typical of a placeholder or freshly-squatted name.`);
    }
    if (dl !== null && dl < 50 && (ageDays === null || ageDays > 30)) {
        risk += 15;
        reasons.push(`Only ${dl} downloads in the last week despite being ${ageDays ?? "?"} days old — almost no real usage.`);
    }
    if (deprecated) {
        risk += 15;
        reasons.push("Latest version is marked deprecated.");
    }
    // A near-collision with a very popular package while itself being obscure is
    // the typosquat/slop overlap signal. The closer the edit distance and the
    // lower the usage, the stronger — a 1-edit lookalike with near-zero downloads
    // is a textbook typosquat and must clear the REVIEW threshold on its own.
    const near = closestPopular(pkg, 2);
    if (near && (dl === null || dl < 5000)) {
        const obscure = dl === null || dl < 1000;
        risk += near.distance <= 1 ? 45 : obscure ? 38 : 22;
        reasons.push(`Name is ${near.distance} edit(s) from the popular package "${near.match}" but is far less used — likely typosquat/slopsquat. Did you mean "${near.match}"?`);
    }
    risk = Math.min(risk, 90);
    let stt = "ok";
    if (risk >= 45)
        stt = "suspicious";
    if (risk === 0)
        reasons.push("Established package: exists, has history and real usage. No slop signals.");
    const f = {
        pkg, raw, kind, status: stt, risk,
        reasons,
        facts: { ageDays, lastPublishDays, versions, hasRepo, deprecated, weeklyDownloads: dl },
    };
    if (near && stt !== "ok")
        f.didYouMean = near.match;
    return f;
}
/** Classify a list of package names (already deduped). Bounded concurrency. */
export async function classifyAll(refs) {
    const findings = [];
    const queue = [...refs];
    const CONC = 5;
    async function worker() {
        for (;;) {
            const item = queue.shift();
            if (!item)
                return;
            findings.push(await classifyPackage(item.pkg, item.raw, item.kind));
        }
    }
    await Promise.all(Array.from({ length: Math.min(CONC, refs.length) }, worker));
    // Stable order: highest risk first.
    findings.sort((a, b) => b.risk - a.risk);
    const hallucinated = findings.filter((f) => f.status === "hallucinated").map((f) => f.pkg);
    const suspicious = findings.filter((f) => f.status === "suspicious").map((f) => f.pkg);
    let verdict = "CLEAN";
    if (suspicious.length)
        verdict = "REVIEW";
    if (hallucinated.length)
        verdict = "BLOCK";
    let summary;
    if (verdict === "BLOCK")
        summary = `${hallucinated.length} referenced package(s) do not exist on npm (${hallucinated.join(", ")}) — almost certainly AI-hallucinated. Do NOT install.`;
    else if (verdict === "REVIEW")
        summary = `${suspicious.length} referenced package(s) look risky (brand-new / near-typo / no usage). Review before installing.`;
    else
        summary = `All ${findings.length} referenced package(s) exist and look established. No slopsquat signals.`;
    return { verdict, summary, packagesChecked: findings.length, hallucinated, suspicious, findings };
}
