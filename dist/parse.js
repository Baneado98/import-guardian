// import-guardian — extract the npm package specifiers a block of code depends on.
//
// The whole point: an AI coding agent has just GENERATED some code. Before that
// code is trusted, we want to know which npm packages it pulls in — so we can
// flag the ones that DON'T EXIST (hallucinated / slopsquatted) or that look
// like opportunistic registrations. This file turns raw source text into the
// list of real npm package names referenced, with zero AST dependency.
const BUILTINS = new Set([
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
]);
/**
 * Resolve a raw module specifier to the npm package name you would install,
 * or null if it is not an installable npm package (relative path, builtin,
 * node: protocol, URL, bare path alias).
 */
export function specifierToPackage(spec) {
    if (!spec)
        return null;
    spec = spec.trim();
    // Relative / absolute paths — local files, not packages.
    if (spec.startsWith(".") || spec.startsWith("/"))
        return null;
    // node: / bun: / data: / http(s): protocols.
    if (/^[a-z][a-z0-9+.-]*:/i.test(spec)) {
        // node:fs -> builtin; anything else with a protocol is not an npm package.
        if (spec.startsWith("node:"))
            return null;
        return null;
    }
    // Bare builtin (fs, path, ...).
    if (BUILTINS.has(spec))
        return null;
    if (spec.startsWith("@")) {
        // Scoped: @scope/name[/subpath...] -> @scope/name
        const parts = spec.split("/");
        if (parts.length < 2)
            return null; // "@foo" alone is invalid
        return parts[0] + "/" + parts[1];
    }
    // Unscoped: name[/subpath...] -> name
    return spec.split("/")[0];
}
const STRING = `["'\`]([^"'\`]+)["'\`]`;
// Matches: import ... from "x";  import "x";  export ... from "x";
const RE_IMPORT_FROM = new RegExp(`\\b(?:import|export)\\b[^;\\n]*?\\bfrom\\s*${STRING}`, "g");
const RE_IMPORT_BARE = new RegExp(`\\bimport\\s*${STRING}`, "g");
// require("x") and require ( "x" )
const RE_REQUIRE = new RegExp(`\\brequire\\s*\\(\\s*${STRING}\\s*\\)`, "g");
// import("x") dynamic import
const RE_DYN = new RegExp(`\\bimport\\s*\\(\\s*${STRING}\\s*\\)`, "g");
/**
 * Extract the unique installable npm packages referenced by a block of
 * JS/TS source. Deduped by package name, preserving the first raw specifier.
 */
export function extractImports(code) {
    const out = new Map();
    const add = (raw, kind) => {
        const pkg = specifierToPackage(raw);
        if (!pkg)
            return;
        if (!out.has(pkg))
            out.set(pkg, { pkg, raw, kind });
    };
    for (const m of code.matchAll(RE_IMPORT_FROM))
        add(m[1], "import");
    for (const m of code.matchAll(RE_REQUIRE))
        add(m[1], "require");
    for (const m of code.matchAll(RE_DYN))
        add(m[1], "dynamic-import");
    // Bare `import "x"` (side-effect import). Run last so `from` form wins kind.
    for (const m of code.matchAll(RE_IMPORT_BARE))
        add(m[1], "import");
    return [...out.values()];
}
