// Shared factory that builds the import-guardian MCP Server and its tool
// handlers. Used by the stdio entrypoint (mcp.ts) and the HTTP transport
// (server.ts).
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { scanCodeCapped, scanPackages, checkPackage } from "./engine.js";
export const VERSION = "0.3.0";
// ---- Pro (unlimited / batch) tier wiring -------------------------------
// The FREE tier runs locally and fast — a single fragment scan, one-package
// verify, and a SMALL batch check. That is what the vast majority of installs
// use and it stays unchanged.
//
// The PREMIUM tier is UNLIMITED / BATCH scanning (a large code blob, or many
// packages at once) and NO LONGER runs locally: when the caller asks for pro=true
// OR the input crosses the free CAP (large code / many packages) the MCP forwards
// the request to the hosted /pro endpoint, authenticating with the user's prepaid
// API key. No key → a clear, attractive upsell pointing at the checkout link.
//
// The MARQUEE premium product — the deep lockfile audit (dependency-confusion,
// transitive typosquat, install-script risk) — lives in src/premium/ and is
// NEVER bundled into the npm tarball (see package.json `files`): there is no
// `import` of it here, so the local package literally cannot run it. The
// audit_lockfile tool always forwards to the hosted /pro/audit endpoint behind
// payment. The cheap free checks (single-fragment scan, ≤5-name verify) run
// locally because they are public, reproducible facts — not the moat.
const PRO_BASE = (process.env.IMPORT_GUARDIAN_PRO_URL ?? "https://import-guardian.vercel.app").replace(/\/+$/, "");
const PRO_KEY = (process.env.IMPORT_GUARDIAN_KEY ?? "").trim();
const CHECKOUT_URL = (process.env.CHECKOUT_URL ?? "https://import-guardian.vercel.app/#pro").trim();
// Free-tier caps. Above these the scan is the PREMIUM batch/unlimited tier and is
// routed server-side behind payment (so the local install can't give it away).
const FREE_CODE_CHARS = 2000; // a fragment, not a whole repo dump
const FREE_PACKAGES = 5; // a handful of names, not a full dependency manifest
function badge(v) {
    return v === "BLOCK" ? "🔴 BLOCK" : v === "REVIEW" ? "🟠 REVIEW" : "🟢 CLEAN";
}
function pkgBadge(f) {
    return f.status === "hallucinated" ? "🔴" : f.status === "suspicious" ? "🟠" : "🟢";
}
export function renderScan(r) {
    const lines = [];
    lines.push(`${badge(r.verdict)}  —  ${r.summary}`);
    if (r.findings.length) {
        lines.push("");
        for (const f of r.findings) {
            const tag = f.status === "hallucinated" ? "DOES NOT EXIST" : f.status === "suspicious" ? `risk ${f.risk}/100` : "ok";
            lines.push(`${pkgBadge(f)} ${f.pkg}  (${tag})${f.didYouMean ? `  → did you mean "${f.didYouMean}"?` : ""}`);
            for (const reason of f.reasons)
                lines.push(`    • ${reason}`);
        }
    }
    return lines.join("\n");
}
export function renderOne(f) {
    const tag = f.status === "hallucinated" ? "DOES NOT EXIST on npm" : f.status === "suspicious" ? `SUSPICIOUS (risk ${f.risk}/100)` : "OK";
    const lines = [`${pkgBadge(f)} ${f.pkg} — ${tag}${f.didYouMean ? `  → did you mean "${f.didYouMean}"?` : ""}`];
    for (const reason of f.reasons)
        lines.push(`  • ${reason}`);
    if (f.facts) {
        lines.push(`  facts: age=${f.facts.ageDays ?? "?"}d versions=${f.facts.versions} repo=${f.facts.hasRepo} weeklyDownloads=${f.facts.weeklyDownloads ?? "?"}`);
    }
    return lines.join("\n");
}
// What the premium tier adds beyond the free quick checks — used in the upsell so
// the value is concrete, not a generic "upgrade" nag.
const PRO_PITCH = [
    "DEEP lockfile audit (audit_lockfile): resolve the WHOLE transitive tree and catch dependency-confusion, transitive typosquats and install-script risk your agent can't see",
    "scan a WHOLE generated file / repo dump in one call (no 2,000-char free cap)",
    "verify a FULL dependency manifest at once (no 5-package free cap)",
    "no rate limit — wire it into CI / a coding agent that scans on every generation",
];
function upsellText(what) {
    return [
        `🔒 ${what} is a premium (unlimited / batch) scan.`,
        "",
        "The free tier scans a code fragment, verifies one package, or checks a small",
        "handful of names — locally and instantly. The PREMIUM tier opens it up — it lets you:",
        ...PRO_PITCH.map((p) => `  • ${p}`),
        "",
        "Two ways to unlock it — pick whichever fits you:",
        "",
        "  💳  Pay with a card (Stripe)  — for humans/teams:",
        `      Buy a prepaid API key at  ${CHECKOUT_URL.replace(/#pro$/, "")}/pro/checkout`,
        "      then set it in your MCP config:",
        '          "env": { "IMPORT_GUARDIAN_KEY": "<your-key>" }',
        "",
        "  🪙  Pay per call with x402 (USDC) — for AI agents with a wallet:",
        "      Call the hosted endpoint directly; an x402-aware client pays per call",
        "      automatically, no key, no signup:",
        `          POST ${PRO_BASE}/pro/scan   { "code": "…" }`,
        "",
        "Tip: keep the input under the free cap (≤2,000 chars / ≤5 packages) for an",
        "instant free result right now.",
    ].join("\n");
}
// Call the hosted /pro endpoint with the user's prepaid key. Returns the parsed
// ScanResult on success, or a structured error (incl. 401/402 for bad/missing
// payment) so the tool can render a helpful message instead of a raw throw.
async function fetchPro(path, body) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 25_000);
    try {
        const res = await fetch(`${PRO_BASE}${path}`, {
            method: "POST",
            signal: ctrl.signal,
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
                "User-Agent": "import-guardian-mcp/pro",
                ...(PRO_KEY ? { Authorization: `Bearer ${PRO_KEY}` } : {}),
            },
            body: JSON.stringify(body),
        });
        if (res.status === 401 || res.status === 402 || res.status === 403) {
            return { ok: false, status: res.status, error: "payment-required" };
        }
        if (!res.ok) {
            return { ok: false, status: res.status, error: `server responded ${res.status}` };
        }
        return { ok: true, status: 200, result: (await res.json()) };
    }
    catch (err) {
        return { ok: false, status: 0, error: String(err?.message ?? err) };
    }
    finally {
        clearTimeout(t);
    }
}
async function fetchProAudit(body) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 30_000);
    try {
        const res = await fetch(`${PRO_BASE}/pro/audit`, {
            method: "POST",
            signal: ctrl.signal,
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
                "User-Agent": "import-guardian-mcp/pro-audit",
                ...(PRO_KEY ? { Authorization: `Bearer ${PRO_KEY}` } : {}),
            },
            body: JSON.stringify(body),
        });
        if (res.status === 401 || res.status === 402 || res.status === 403) {
            return { ok: false, status: res.status, error: "payment-required" };
        }
        if (!res.ok)
            return { ok: false, status: res.status, error: `server responded ${res.status}` };
        return { ok: true, status: 200, result: await res.json() };
    }
    catch (err) {
        return { ok: false, status: 0, error: String(err?.message ?? err) };
    }
    finally {
        clearTimeout(t);
    }
}
function badgeV(v) {
    return v === "BLOCK" ? "🔴 BLOCK" : v === "REVIEW" ? "🟠 REVIEW" : "🟢 CLEAN";
}
const SEV_ICON = { critical: "⛔", high: "🔴", medium: "🟠", low: "🟡", info: "ℹ️" };
export function renderAudit(a) {
    const lines = [];
    lines.push(`${badgeV(a.verdict)}  —  ${a.summary}`);
    lines.push(`   ecosystem=${a.ecosystem} lockfile=v${a.lockfileVersion ?? "?"} · ${a.totalPackages} resolved (${a.directPackages} direct, ${a.transitivePackages} transitive)`);
    const c = a.counts || {};
    lines.push(`   issues: ⛔${c.critical ?? 0} 🔴${c.high ?? 0} 🟠${c.medium ?? 0} 🟡${c.low ?? 0}`);
    if (Array.isArray(a.issues) && a.issues.length) {
        lines.push("");
        for (const i of a.issues.slice(0, 50)) {
            lines.push(`${SEV_ICON[i.severity] ?? "•"} [${i.type}] ${i.pkg}${i.version ? `@${i.version}` : ""}${i.didYouMean ? `  → did you mean "${i.didYouMean}"?` : ""}`);
            for (const r of i.reasons)
                lines.push(`    • ${r}`);
        }
        if (a.issues.length > 50)
            lines.push(`   …and ${a.issues.length - 50} more issue(s).`);
    }
    if (Array.isArray(a.warnings) && a.warnings.length) {
        lines.push("");
        for (const w of a.warnings)
            lines.push(`⚠️ ${w}`);
    }
    return lines.join("\n");
}
function auditUpsell() {
    return [
        "🔒 Deep lockfile supply-chain audit is the premium product.",
        "",
        "It parses your FULL resolved dependency graph across NINE ecosystems — npm, PyPI,",
        "Go, Rust/Cargo, Java/Maven, PHP/Composer, Ruby/RubyGems and .NET/NuGet (package-lock /",
        "yarn / pnpm / requirements / poetry / Pipfile / go.mod / go.sum / Cargo.lock / pom.xml /",
        "composer.lock / Gemfile.lock / packages.lock.json — every transitive package you never",
        "see) and reports:",
        "  • DEPENDENCY CONFUSION — private/internal names unclaimed on the public index",
        "    that an attacker can shadow (the highest-impact supply-chain bug), including",
        "    npm SCOPE-SHADOWING (an unclaimed @org scope = full scope takeover).",
        "  • TRANSITIVE typosquats & homoglyph clones across the whole tree (Damerau-",
        "    Levenshtein + Unicode confusable folding + crates.io -/_ equivalence).",
        "  • MAINTAINER-TAKEOVER fingerprints (dormant republish, new install script, burst).",
        "  • INSTALL-SCRIPT & provenance risk graded by REAL download counts.",
        "",
        "The free tier (POST /audit) shows the verdict + issue counts by severity, but",
        "WITHHOLDS which packages are affected and why.",
        "",
        "Two ways to unlock the full report:",
        `  💳  Buy a prepaid key:  ${CHECKOUT_URL.replace(/#pro$/, "")}/pro/checkout`,
        '      then set  "env": { "IMPORT_GUARDIAN_KEY": "<your-key>" }',
        `  🪙  Pay per call (x402):  POST ${PRO_BASE}/pro/audit  { "lockfile": "…" }`,
    ].join("\n");
}
export function buildMcpServer() {
    const server = new Server({ name: "import-guardian", version: VERSION }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: "scan_code_imports",
                description: "Scan a block of JS/TS source code for HALLUCINATED / slopsquatted npm imports BEFORE you install anything or commit. Extracts every npm package the code imports/requires and checks each against the live npm registry: flags packages that DO NOT EXIST (AI hallucinations — the #1 slopsquatting attack vector in 2026, where attackers register the plausible fake name to ship malware) and packages that exist but look freshly-squatted (brand-new, no repo, near-typo of a popular lib, near-zero usage). Returns a CLEAN / REVIEW / BLOCK verdict with a 'did you mean' suggestion for each bad import. ALWAYS run this on code you (an AI) just generated before running its install command. The free tier handles a code fragment (≤2,000 chars AND ≤5 distinct imported packages); a whole file / repo dump, more than 5 packages, or pro=true routes to the premium unlimited scan (requires IMPORT_GUARDIAN_KEY).",
                inputSchema: {
                    type: "object",
                    properties: {
                        code: { type: "string", description: "The JS/TS source code to scan (the code an AI agent just generated)." },
                        pro: { type: "boolean", description: "Force the PREMIUM unlimited/batch scan (runs server-side behind payment). Auto-enabled when the code exceeds the free fragment cap. Requires IMPORT_GUARDIAN_KEY; without one you'll get instructions to unlock it." },
                    },
                    required: ["code"],
                },
            },
            {
                name: "check_packages",
                description: "Check an explicit list of npm package names for hallucination / slopsquatting (e.g. a dependency list you are about to install). Returns CLEAN / REVIEW / BLOCK per package with a 'did you mean' for fakes. The free tier verifies a small handful (≤5 names); a full dependency manifest or pro=true routes to the premium unlimited batch verify (requires IMPORT_GUARDIAN_KEY).",
                inputSchema: {
                    type: "object",
                    properties: {
                        names: { type: "array", items: { type: "string" }, description: "npm package names to verify." },
                        pro: { type: "boolean", description: "Force the PREMIUM unlimited batch verify (runs server-side behind payment). Auto-enabled when the list exceeds the free cap. Requires IMPORT_GUARDIAN_KEY; without one you'll get instructions to unlock it." },
                    },
                    required: ["names"],
                },
            },
            {
                name: "verify_package",
                description: "Verify a single npm package name exists and is not a slopsquat: registry existence, age, version history, repo, weekly downloads, and edit-distance to popular packages. Use right before adding a dependency you are not 100% sure is real. Always free.",
                inputSchema: {
                    type: "object",
                    properties: {
                        name: { type: "string", description: "The npm package name, e.g. 'lodash' or '@scope/pkg'." },
                    },
                    required: ["name"],
                },
            },
            {
                name: "audit_lockfile",
                description: "DEEP supply-chain audit of a RESOLVED lockfile — the premium product. Works across NINE ecosystems: npm (package-lock.json v1/v2/v3, yarn.lock classic/berry, pnpm-lock.yaml), Python/PyPI (requirements.txt, poetry.lock, Pipfile.lock), Go (go.mod, go.sum), Rust/Cargo (Cargo.lock, Cargo.toml), Java (Maven pom.xml, Gradle build.gradle/.kts + gradle.lockfile), PHP/Composer (composer.json, composer.lock), Ruby/RubyGems (Gemfile.lock, Gemfile), and .NET/NuGet (packages.lock.json, .csproj/Directory.Packages.props). It resolves the dependency graph and cross-checks each name against that ecosystem's LIVE public index (npm registry, PyPI, the Go module proxy, crates.io, Maven Central, Packagist, rubygems.org, nuget.org), auditing for: (1) DEPENDENCY CONFUSION — internal/private package names unclaimed on the public registry that an attacker can shadow (the highest-impact supply-chain attack), INCLUDING npm SCOPE-SHADOWING (a private @org/pkg whose whole @org scope is unclaimed), Maven groupId confusion, Composer vendor/package confusion, RubyGems private-source gem confusion, and NuGet feed confusion (the ORIGINAL Birsan 2021 vector — an internal package ID not reserved on nuget.org while a private feed is restored alongside it); (2) transitive TYPOSQUATS and homoglyph/Unicode-confusable clones (Damerau-Levenshtein + confusable folding, per-registry canonicalization incl. crates.io -/_ equivalence, Maven/Composer coordinate typos, RubyGems gem typos incl. the rest-client/rest_client class, and NuGet dotted-ID typos); (3) nonexistent pinned packages; (4) MAINTAINER-TAKEOVER fingerprints (dormant package republished, version burst, Packagist-ABANDONED packages, the RubyGems rest-client-hijack pattern); (5) INSTALL-SCRIPT VERSION-DIFFING — a package whose newest release ADDED a preinstall/postinstall/install/prepare hook the previous release did NOT have (the exact injection shape of event-stream / ua-parser-js); (6) INSTALL-SCRIPT PAYLOAD ANALYSIS — downloads the package tarball and statically analyzes the actual hook code (network egress, credential/env exfil, child-process exec, download-and-run, obfuscation) using an obfuscation-RESISTANT AST/token analyzer that decodes escapes and folds split strings, so a payload hidden as require(\"child_pro\"+\"cess\") or global[\"ev\"+\"al\"](…) is still caught; (7) Go `replace`→external-host HIJACK, live-verified against the module proxy; (8) KNOWN-MALWARE / known-vulnerability cross-reference of the EXACT resolved version against the live OSV.dev database (covers RubyGems and NuGet too); plus INSTALL-SCRIPT and provenance risk graded by REAL download counts. Returns CLEAN / REVIEW / BLOCK with per-package findings and 'did you mean'. Runs server-side behind payment (IMPORT_GUARDIAN_KEY or an x402 wallet); the free tier returns only the verdict and issue counts, withholding which packages are affected.",
                inputSchema: {
                    type: "object",
                    properties: {
                        lockfile: { type: "string", description: "The full contents of the lockfile to audit (package-lock.json / yarn.lock / pnpm-lock.yaml / requirements.txt / poetry.lock / Pipfile.lock / go.mod / go.sum / Cargo.lock / Cargo.toml / pom.xml / composer.lock / composer.json / Gemfile.lock / Gemfile / packages.lock.json / *.csproj)." },
                        filename: { type: "string", description: "Optional filename so the ecosystem is detected reliably (e.g. 'pnpm-lock.yaml', 'Cargo.lock', 'go.sum', 'Gemfile.lock', 'packages.lock.json', 'App.csproj'). Defaults to package-lock.json." },
                    },
                    required: ["lockfile"],
                },
            },
        ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
        const { name, arguments: args } = req.params;
        try {
            if (name === "scan_code_imports") {
                const code = String(args?.code ?? "");
                if (!code.trim())
                    return { content: [{ type: "text", text: "Error: 'code' is required." }], isError: true };
                // Decide free vs premium on the SAME two dimensions the HTTP /scan
                // handler uses: too many characters (repo dump) OR too many distinct
                // packages extracted (the premium "audit many in one call" value). A
                // char cap alone is bypassable with 30 compact imports in <1KB, so we
                // pre-extract and count packages here too. This closes the leak on all
                // surfaces — POST /mcp and the local npm package both run this handler.
                const charCapped = code.length > FREE_CODE_CHARS;
                const slice = charCapped ? code.slice(0, FREE_CODE_CHARS) : code;
                // Probe the package count on the free slice (cheap: regex extract only,
                // no registry calls happen until classifyAll runs inside scanCodeCapped).
                const probe = await scanCodeCapped(slice, FREE_PACKAGES);
                const wantsPro = Boolean(args?.pro) || charCapped || probe.capped;
                // PREMIUM = unlimited/batch. Route to the hosted /pro endpoint behind payment.
                if (wantsPro) {
                    if (!PRO_KEY) {
                        const what = charCapped
                            ? "Scanning a large code blob"
                            : `Auditing ${probe.packagesExtracted} imported packages at once`;
                        // Free preview: still give the capped audit + the explicit upsell,
                        // so the user sees value AND the withheld list, never the full set.
                        const preview = renderScan(probe.result);
                        const withheldNote = probe.capped
                            ? `\n\n🔒 Audited only the first ${probe.packagesAudited} of ${probe.packagesExtracted} imported packages (free cap ${FREE_PACKAGES}). Withheld: ${probe.withheld.join(", ")}.`
                            : "";
                        return { content: [{ type: "text", text: `${preview}${withheldNote}\n\n${upsellText(what)}` }] };
                    }
                    const pro = await fetchPro("/pro/scan", { code });
                    if (pro.ok && pro.result) {
                        return { content: [{ type: "text", text: renderScan(pro.result) }] };
                    }
                    if (pro.error === "payment-required") {
                        return {
                            content: [{ type: "text", text: `🔒 Your IMPORT_GUARDIAN_KEY was rejected (HTTP ${pro.status}) for the premium scan. The key may be invalid or expired.\n\nGet or renew a key → ${CHECKOUT_URL.replace(/#pro$/, "")}/pro/checkout\n\nMeanwhile, scan ≤${FREE_CODE_CHARS} chars / ≤${FREE_PACKAGES} packages for a free result.` }],
                        };
                    }
                    // Network/server hiccup: do NOT silently run the premium scan locally.
                    return {
                        content: [{ type: "text", text: `⚠️ The premium scan was unavailable right now (${pro.error}). Try again, or scan ≤${FREE_CODE_CHARS} chars / ≤${FREE_PACKAGES} packages for a free local result.` }],
                    };
                }
                // FREE tier — fragment scan within BOTH caps, runs locally and fast.
                return { content: [{ type: "text", text: renderScan(probe.result) }] };
            }
            if (name === "check_packages") {
                const names = Array.isArray(args?.names) ? args.names.map(String) : [];
                if (!names.length)
                    return { content: [{ type: "text", text: "Error: 'names' must be a non-empty array." }], isError: true };
                const wantsPro = Boolean(args?.pro) || names.length > FREE_PACKAGES;
                // PREMIUM = unlimited batch. Route to the hosted /pro endpoint behind payment.
                if (wantsPro) {
                    if (!PRO_KEY) {
                        return { content: [{ type: "text", text: upsellText(`Checking ${names.length} packages at once`) }] };
                    }
                    const pro = await fetchPro("/pro/check", { names });
                    if (pro.ok && pro.result) {
                        return { content: [{ type: "text", text: renderScan(pro.result) }] };
                    }
                    if (pro.error === "payment-required") {
                        return {
                            content: [{ type: "text", text: `🔒 Your IMPORT_GUARDIAN_KEY was rejected (HTTP ${pro.status}) for the premium batch verify. The key may be invalid or expired.\n\nGet or renew a key → ${CHECKOUT_URL.replace(/#pro$/, "")}/pro/checkout\n\nMeanwhile, check ≤${FREE_PACKAGES} names for a free result.` }],
                        };
                    }
                    return {
                        content: [{ type: "text", text: `⚠️ The premium batch verify was unavailable right now (${pro.error}). Try again, or check ≤${FREE_PACKAGES} names for a free local result.` }],
                    };
                }
                // FREE tier — small batch, runs locally.
                const r = await scanPackages(names.slice(0, FREE_PACKAGES));
                return { content: [{ type: "text", text: renderScan(r) }] };
            }
            if (name === "verify_package") {
                const pkg = String(args?.name ?? "").trim();
                if (!pkg)
                    return { content: [{ type: "text", text: "Error: 'name' is required." }], isError: true };
                const f = await checkPackage(pkg);
                return { content: [{ type: "text", text: renderOne(f) }] };
            }
            if (name === "audit_lockfile") {
                const lockfile = String(args?.lockfile ?? "");
                const filename = String(args?.filename ?? "package-lock.json");
                if (!lockfile.trim())
                    return { content: [{ type: "text", text: "Error: 'lockfile' is required (paste the lockfile contents)." }], isError: true };
                // ALWAYS premium: the deep engine runs server-side only. No local fallback.
                if (!PRO_KEY) {
                    return { content: [{ type: "text", text: auditUpsell() }] };
                }
                const pro = await fetchProAudit({ lockfile, filename });
                if (pro.ok && pro.result) {
                    return { content: [{ type: "text", text: renderAudit(pro.result) }] };
                }
                if (pro.error === "payment-required") {
                    return {
                        content: [{ type: "text", text: `🔒 Your IMPORT_GUARDIAN_KEY was rejected (HTTP ${pro.status}) for the deep lockfile audit. The key may be invalid or expired.\n\nGet or renew a key → ${CHECKOUT_URL.replace(/#pro$/, "")}/pro/checkout` }],
                    };
                }
                // Never run the premium audit locally on a server hiccup.
                return {
                    content: [{ type: "text", text: `⚠️ The deep lockfile audit was unavailable right now (${pro.error}). Please try again.` }],
                };
            }
            return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
        }
        catch (err) {
            return { content: [{ type: "text", text: `import-guardian error: ${err?.message ?? err}` }], isError: true };
        }
    });
    return server;
}
