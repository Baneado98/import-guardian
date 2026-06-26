# Minimal, deterministic image for MCP introspection (Glama et al.).
# Installs the already-published, pre-built npm package (ships dist/),
# so there is NO in-container TypeScript build that can fail.
FROM node:20-alpine
WORKDIR /app
RUN npm install --omit=dev --no-audit --no-fund import-guardian-mcp@latest
ENV NODE_ENV=production
# Stdio MCP server. Glama runs this and sends initialize + tools/list.
CMD ["npx", "--no-install", "import-guardian-mcp"]
