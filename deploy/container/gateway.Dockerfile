# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# aithos/gateway — the single enforcement point (SPEC-container-runtime §13.6).
# The only multi-homed component: attached to BOTH the internal cage network
# and the egress network. Verifies the mandate on every call, filters tools by
# scope, proxies inference, records gamma.
#
# It holds the secrets (mandate pack, sphere keys, downstream credentials); the
# cage holds none. Build from the monorepo ROOT (the Dockerfile COPYs the whole
# workspace so `npm ci` sees every workspace package.json the lockfile expects):
#   docker build -f deploy/container/gateway.Dockerfile -t ghcr.io/aithos-protocol/gateway .

FROM node:20-bookworm-slim AS build
WORKDIR /src
# Whole workspace in one shot: npm ci validates root + every packages/*
# against the lockfile, so all nine workspace package.json files must be
# present (a partial copy fails with "Missing … from lock file"). A root
# .dockerignore keeps node_modules/dist/.git out of the context.
COPY . .
RUN npm ci --include-workspace-root
# Only the three packages the gateway actually runs on need building.
RUN npm run build --workspace=@aithos/agent-tools \
 && npm run build --workspace=@aithos/protocol-core \
 && npm run build --workspace=@aithos/mcp

FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
# Copy the built workspace (dist + installed node_modules) verbatim.
COPY --from=build /src /app
EXPOSE 8787
# Non-root: the gateway needs no privilege.
USER node
# Mandate pack + registry are provided at run time (mounted / env), never baked.
#   AITHOS_MCP_TOKEN         shared bearer for the cage↔gateway MCP channel
#   AITHOS_HOME              read-only ethos + mandate store (cas 1: local mount)
#   AITHOS_LLM_UPSTREAM      e.g. https://api.anthropic.com
ENTRYPOINT ["node", "packages/mcp/dist/bin.js"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8787", \
     "--mandate-pack", "/run/aithos/pack.json", \
     "--mcp-registry", "/run/aithos/registry.json", \
     "--llm-proxy"]
