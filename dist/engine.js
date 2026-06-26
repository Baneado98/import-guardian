// import-guardian — public engine: from a block of code (or an explicit list
// of package names) to a slopsquat / hallucination verdict.
import { extractImports } from "./parse.js";
import { classifyAll, classifyPackage } from "./resolve.js";
/**
 * FREE-tier scan: extract the code's npm imports but audit at most `maxPackages`
 * of them. This is the shared gate enforced identically by the HTTP /scan
 * handler and the MCP scan_code_imports tool (and therefore the local npm
 * package, which runs the same MCP server). A character cap alone does NOT
 * paywall the premium "audit many packages in one call" value — 30 compact
 * imports fit in <1KB — so we ALSO cap by the number of distinct packages
 * extracted, mirroring the FREE_PACKAGES cap that /check already enforces.
 */
export async function scanCodeCapped(code, maxPackages) {
    const refs = extractImports(code);
    const packagesExtracted = refs.length;
    if (packagesExtracted === 0) {
        return {
            result: {
                verdict: "CLEAN",
                summary: "No npm package imports found in the provided code (only built-ins / local paths).",
                packagesChecked: 0,
                hallucinated: [],
                suspicious: [],
                findings: [],
            },
            packagesExtracted: 0,
            packagesAudited: 0,
            capped: false,
            withheld: [],
        };
    }
    const audited = refs.slice(0, maxPackages);
    const withheld = refs.slice(maxPackages).map((r) => r.pkg);
    const result = await classifyAll(audited);
    return {
        result,
        packagesExtracted,
        packagesAudited: audited.length,
        capped: packagesExtracted > maxPackages,
        withheld,
    };
}
/**
 * Scan a block of JS/TS source code: extract its npm imports and check each
 * one for hallucination / slopsquatting. This is the headline tool — meant to
 * be run on code an AI agent just generated, before any install.
 */
export async function scanCode(code) {
    const refs = extractImports(code);
    if (refs.length === 0) {
        return {
            verdict: "CLEAN",
            summary: "No npm package imports found in the provided code (only built-ins / local paths).",
            packagesChecked: 0,
            hallucinated: [],
            suspicious: [],
            findings: [],
        };
    }
    return classifyAll(refs);
}
/** Scan an explicit list of package names (no parsing). */
export async function scanPackages(names) {
    const refs = names
        .map((n) => n.trim())
        .filter(Boolean)
        .map((n) => ({ pkg: n, raw: n, kind: "name" }));
    if (refs.length === 0) {
        return { verdict: "CLEAN", summary: "No package names provided.", packagesChecked: 0, hallucinated: [], suspicious: [], findings: [] };
    }
    return classifyAll(refs);
}
/** Check a single package name. */
export async function checkPackage(name) {
    return classifyPackage(name.trim());
}
