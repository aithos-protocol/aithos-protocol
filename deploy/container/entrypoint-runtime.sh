#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# Runtime entrypoint (PLAN-CONTAINER P0.2): generate a fresh Claude Code
# configuration pointing every capability at the gateway, then run the mission.
#
# The cage has no egress: the ONLY reachable host is $AITHOS_GATEWAY_URL. This
# script neither holds nor writes any Aithos authority secret — it configures
# an agent to speak to the gateway and nothing else.
set -euo pipefail

: "${AITHOS_GATEWAY_URL:?AITHOS_GATEWAY_URL is required (the gateway base URL)}"
: "${AITHOS_MCP_TOKEN:?AITHOS_MCP_TOKEN is required (session bearer)}"

WORK="$(mktemp -d)"            # tmpfs; nothing survives the container
export CLAUDE_CONFIG_DIR="$WORK/.claude"
mkdir -p "$CLAUDE_CONFIG_DIR"

# 1. MCP config: the single Aithos gateway, over HTTP with the session bearer.
cat > "$WORK/.mcp.json" <<JSON
{
  "mcpServers": {
    "aithos": {
      "type": "http",
      "url": "${AITHOS_GATEWAY_URL%/}/mcp",
      "headers": { "Authorization": "Bearer ${AITHOS_MCP_TOKEN}" }
    }
  }
}
JSON

# 2. Settings: no direct web (that egress does not exist anyway), and redirect
#    inference through the gateway's LLM proxy — the cage's only path out.
cat > "$CLAUDE_CONFIG_DIR/settings.json" <<JSON
{
  "permissions": { "deny": ["WebSearch", "WebFetch"] },
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "ANTHROPIC_BASE_URL": "${AITHOS_GATEWAY_URL%/}/llm"
  }
}
JSON

export ANTHROPIC_BASE_URL="${AITHOS_GATEWAY_URL%/}/llm"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Inference auth preflight: Claude Code needs a credential to send to the /llm
# proxy — a subscription OAuth token (claude setup-token) or an API key, or a
# mounted ~/.claude. Warn early with an actionable message rather than let the
# first model call fail cryptically inside the cage.
if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ] \
   && [ ! -e "$HOME/.claude" ]; then
  echo "entrypoint-runtime: no inference credential — set CLAUDE_CODE_OAUTH_TOKEN" \
       "(claude setup-token) or ANTHROPIC_API_KEY, or mount ~/.claude. See" \
       "docker-compose.yml." >&2
fi

# 3a. Harness mode (P1): a supervisor loop owns mission state. When present,
#     hand over to it — it polls the mailbox and spawns a fresh agent run per
#     mission. AITHOS_MCP_CONFIG points it at the generated .mcp.json.
if [ "${AITHOS_HARNESS:-0}" = "1" ]; then
  export AITHOS_MCP_CONFIG="$WORK/.mcp.json"
  exec node /app/harness/dist/bin/harness.js
fi

# 3b. Job mode (P0): one mission in, run it, exit. One container, one mission.
: "${AITHOS_MISSION:?AITHOS_MISSION is required in job mode (or set AITHOS_HARNESS=1)}"
cd "$WORK"
exec claude -p "$AITHOS_MISSION" \
  --output-format stream-json \
  --mcp-config "$WORK/.mcp.json" \
  --dangerously-skip-permissions
