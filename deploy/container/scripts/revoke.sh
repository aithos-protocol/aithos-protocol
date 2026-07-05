#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mathieu Colla
#
# make revoke — the punchline: revoke the demo mandate. The next gateway call
# (tool OR inference) is refused, fail closed (§13.9 L1). The watcher (P1) then
# stops the container (§13.9 L2) — "revoke = unplug".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN="$ROOT/deploy/container/run"
export AITHOS_HOME="${AITHOS_HOME:-$RUN/home}"

MANDATE_ID="${1:-$(node -e "console.log(require('$RUN/grant.json').mandate.id)" 2>/dev/null || true)}"
if [ -z "${MANDATE_ID:-}" ]; then
  echo "usage: revoke.sh <mandate-id>   (or run make demo first)" >&2
  exit 2
fi

echo "==> revoking $MANDATE_ID"
node "$ROOT/packages/cli/dist/index.js" revoke "$MANDATE_ID" --handle demo --reason "demo revoke"
echo "==> done. The cage's next call fails closed; the watcher will stop it."
