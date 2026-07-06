#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# make demo — prepare the 90-second story (grant → boot the cage → run a
# mission → in-scope acts, out-of-scope refused → revoke → everything stops).
#
# Prep is done by prepare-demo.mjs (workspace protocol-core) rather than the
# `aithos` CLI: the CLI package pins an old protocol-core that rejects sphere-
# neutral mcp.* scopes. Fix the CLI's dependency range to restore that path.
#
# For a Docker-free proof of the same five assertions, run:  npm test  (root)
# or:  bash scripts/check.sh  (boots the real gateway, no Docker).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/deploy/container"

echo "==> Building workspace (protocol-core, mcp, cli)…"
( cd "$ROOT" && npm run build >/dev/null 2>&1 ) || {
  echo "   build failed — run 'npm ci && npm run build' at the repo root first." >&2
  exit 1
}

echo "==> Preparing identity + mandate + pack + registry…"
node "$HERE/scripts/prepare-demo.mjs"

echo
echo "==> Boot the cage (needs Docker):"
echo "   export AITHOS_MCP_TOKEN=\$(openssl rand -hex 24)"
echo "   export ANTHROPIC_API_KEY=sk-ant-...        # (a) API key — simplest"
echo "   docker compose -f $HERE/docker-compose.yml up --abort-on-container-exit"
echo
echo "==> The kill-switch (in another terminal, while it runs):"
echo "   node $HERE/scripts/revoke-demo.mjs"
echo "   → the cage's next call (tool OR inference) is refused; the watcher stops it."
