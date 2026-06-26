// Curated set of high-download npm packages used as the typosquatting reference.
// A candidate package whose name is a tiny edit-distance away from one of these,
// but is NOT one of these, is a classic typosquat red flag.
// Kept intentionally focused on the packages attackers most often impersonate
// (top utility / framework / crypto / devops libs). Source: npm download rankings
// + documented 2026 typosquat campaigns (dayjs->easy-day-js, opensearch, etc.).
export const POPULAR_PACKAGES = [
    // core utilities
    "lodash", "chalk", "express", "react", "react-dom", "axios", "moment", "dayjs",
    "commander", "debug", "request", "async", "underscore", "bluebird", "rxjs",
    "uuid", "dotenv", "yargs", "glob", "minimist", "semver", "node-fetch", "cross-env",
    "rimraf", "fs-extra", "mkdirp", "colors", "inquirer", "ora", "winston", "morgan",
    // frameworks / tooling
    "next", "vue", "angular", "svelte", "webpack", "vite", "rollup", "esbuild",
    "babel", "@babel/core", "typescript", "ts-node", "tsx", "eslint", "prettier",
    "jest", "mocha", "chai", "vitest", "nodemon", "concurrently", "pm2",
    // http / net / db
    "cors", "body-parser", "helmet", "socket.io", "ws", "got", "undici", "superagent",
    "mongoose", "mongodb", "pg", "mysql", "mysql2", "redis", "ioredis", "sequelize",
    "prisma", "knex", "sqlite3", "typeorm",
    // auth / crypto / security
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "crypto-js", "node-forge",
    "ethers", "web3", "viem", "@solana/web3.js", "bitcoinjs-lib", "elliptic",
    // build / ci common
    "@types/node", "tslib", "core-js", "regenerator-runtime", "zod", "joi", "yup",
    "graphql", "apollo-server", "@apollo/client", "openai", "@anthropic-ai/sdk",
    "@modelcontextprotocol/sdk", "playwright", "puppeteer", "cheerio", "jsdom",
    // packages targeted in real 2026 campaigns
    "opensearch", "@opensearch-project/opensearch", "elasticsearch", "@elastic/elasticsearch",
];
// Levenshtein edit distance.
export function editDistance(a, b) {
    const m = a.length;
    const n = b.length;
    if (m === 0)
        return n;
    if (n === 0)
        return m;
    const dp = new Array(n + 1);
    for (let j = 0; j <= n; j++)
        dp[j] = j;
    for (let i = 1; i <= m; i++) {
        let prev = dp[0];
        dp[0] = i;
        for (let j = 1; j <= n; j++) {
            const tmp = dp[j];
            dp[j] = Math.min(dp[j] + 1, // deletion
            dp[j - 1] + 1, // insertion
            prev + (a[i - 1] === b[j - 1] ? 0 : 1) // substitution
            );
            prev = tmp;
        }
    }
    return dp[n];
}
// Returns the closest popular package within `maxDist` edits, or null.
// Ignores the case where the candidate IS a popular package (distance 0).
export function closestPopular(name, maxDist = 2) {
    const lower = name.toLowerCase();
    let best = null;
    for (const pkg of POPULAR_PACKAGES) {
        const d = editDistance(lower, pkg.toLowerCase());
        if (d === 0)
            return null; // it's a known-good popular package
        if (d <= maxDist && (best === null || d < best.distance)) {
            best = { match: pkg, distance: d };
        }
    }
    return best;
}
