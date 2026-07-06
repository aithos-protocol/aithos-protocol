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

# Inference mode:
#   gateway (default) — route inference through the gateway /llm proxy (sealed
#                       cage; the only path out). Custody/API-key auth.
#   direct            — DEV subscription mode (ÉTUDE-CAGE-ABONNEMENT "B-egress"):
#                       do NOT redirect the base URL. Claude Code talks to
#                       api.anthropic.com natively (its own subscription auth),
#                       reaching it only through the allowlist egress proxy set
#                       via HTTPS_PROXY. Actions still go through the gateway MCP.
INFER_MODE="${AITHOS_INFERENCE_MODE:-gateway}"

# 2. Settings: never let the agent browse the web directly.
if [ "$INFER_MODE" = "direct" ]; then
  cat > "$CLAUDE_CONFIG_DIR/settings.json" <<JSON
{
  "permissions": { "deny": ["WebSearch", "WebFetch"] },
  "env": { "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1" }
}
JSON
else
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
fi
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

# A credential must be a SINGLE token with no whitespace. The classic mistake is
# `export CLAUDE_CODE_OAUTH_TOKEN=$(claude setup-token)` — setup-token is
# interactive, so $(...) captures its whole UI (banner, spinner, the OAuth URL,
# the token). Claude Code would then put that blob in the Authorization header
# and fail with a cryptic "invalid header value". Fail fast, clearly, instead.
for _var in CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY; do
  eval "_val=\${$_var:-}"
  case "$_val" in
    *[[:space:]]*)
      echo "entrypoint-runtime: $_var contains whitespace/newlines — it looks" \
           "like the full 'claude setup-token' output was captured. Set it to" \
           "JUST the token value (e.g. sk-ant-oat01-…), single-quoted." >&2
      exit 1 ;;
  esac
done

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
# --output-format stream-json requires --verbose (Claude Code CLI contract).
exec claude -p "$AITHOS_MISSION" \
  --output-format stream-json \
  --verbose \
  --mcp-config "$WORK/.mcp.json" \
  --dangerously-skip-permissions
