#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# make demo — the 90-second story (PLAN-CONTAINER P0.5, P3.3):
#   grant → boot the cage → run a mission → show it act in-scope, refuse
#   out-of-scope → `make revoke` → everything stops → show the gamma trail.
#
# Uses the built CLI + gateway; requires Docker for the full cage. For a
# Docker-free proof of the same five assertions, run:  npm test  (in this dir).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/deploy/container"
RUN="$HERE/run"
export AITHOS_HOME="${AITHOS_HOME:-$RUN/home}"
mkdir -p "$RUN" "$AITHOS_HOME"

AITHOS="node $ROOT/packages/cli/dist/index.js"

echo "==> 1. identity (once)"
$AITHOS init --handle demo --name "Demo Owner" 2>/dev/null || echo "   (identity exists)"

echo "==> 2. delegate key (throwaway, dedicated to this mandate)"
$AITHOS delegate-key --out "$RUN/agent.key.json" --force
PUBKEY=$(node -e "console.log(require('$RUN/agent.key.json').pubkey_multibase)")

echo "==> 3. grant a READ-ONLY mandate over the demo connector"
$AITHOS grant urn:aithos:agent:demo \
  --handle demo \
  --sphere public \
  --scope mcp.demo.read \
  --ttl 1h \
  --pubkey "$PUBKEY" \
  --json > "$RUN/grant.json"
MANDATE_ID=$(node -e "console.log(require('$RUN/grant.json').mandate.id)")
echo "   mandate: $MANDATE_ID  (scope: mcp.demo.read — NOT mcp.demo.write)"

echo "==> 4. assemble the pack (mounted to the GATEWAY, never the cage)"
node "$HERE/scripts/make-pack.mjs" "$RUN/grant.json" "$RUN/agent.key.json" > "$RUN/pack.json"
cp "$HERE/registry.example.json" "$RUN/registry.json"

echo "==> 5. boot the cage + run the mission"
export AITHOS_MCP_TOKEN="${AITHOS_MCP_TOKEN:-$(openssl rand -hex 24)}"
export AITHOS_MISSION="${AITHOS_MISSION:-List my dormant contacts and tell me who to re-engage. Do NOT add anyone.}"
echo "   mission: $AITHOS_MISSION"
echo "   \$AITHOS_MCP_TOKEN and \$AITHOS_HOME exported for compose."
echo
echo "   docker compose -f $HERE/docker-compose.yml up --abort-on-container-exit"
echo
echo "   Watch: the agent calls demo__list_contacts (in scope, traced), and"
echo "   demo__add_contact is not even in its tool list (out of scope)."
echo
echo "==> To revoke live and watch everything stop:"
echo "   AITHOS_HOME=$AITHOS_HOME $AITHOS revoke $MANDATE_ID --handle demo"
echo "   (the next gateway call — tool or inference — is refused, fail closed)"
echo
echo "Demo prepared under $RUN. Docker-free equivalent proof: (cd $HERE && npm test)"
