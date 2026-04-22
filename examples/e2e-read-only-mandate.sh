#!/usr/bin/env bash
# End-to-end test: `ethos.read.X` ONLY mandate.
#
# A mandate holding only `ethos.read.circle`:
#   - CAN decrypt + read the circle zone (grant rewraps the zone DEK to the
#     delegate's X25519 pubkey).
#   - CANNOT write to the zone (no ethos.write.X → add/modify/delete refused
#     at resolveAuthor() before any state change).
#   - CANNOT read the gamma log payloads (no gamma.read → not on
#     `manifest.gamma.readers`, entries come back _access_denied).
#
# This asymmetry is the whole point of v0.3: "read a zone" and "read the
# audit log" are now two separate capabilities. A coworker you've granted
# ethos.read.circle can see what's there today but cannot reconstruct the
# edit history or see mutations they weren't party to.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-read-only-mandate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
ZONE="${ZONE:-circle}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-read-only-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-read-only-dst}"
WORK="${WORK:-/tmp/aithos-e2e-read-only-work}"

say()  { printf "\n### %s\n" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }
expect_fail() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$label unexpectedly SUCCEEDED"; fi
  pass "$label correctly refused"
}
jqf() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$1"; }

src() { AITHOS_HOME="$SRC_HOME" $CLI "$@"; }
dst() { AITHOS_HOME="$DST_HOME" $CLI "$@"; }

# --------------------------------------------------------------------------- #
say "0. reset scratch"
rm -rf "$SRC_HOME" "$DST_HOME" "$WORK"
mkdir -p "$WORK"

say "1. SRC: init + seed a section in $ZONE"
src init --handle "$HANDLE" --display-name "ReadOnly Alice" >/dev/null
SEED=$(src ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "shared-note" --body "Content the reader is allowed to see." --json)
SEED_SEC=$(jqf "section.id" <<<"$SEED")
pass "seed section: $SEED_SEC"

say "2. SRC: delegate keypair"
KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:reader-only" --json)
PUB=$(jqf "pubkey" <<<"$DK")
pass "delegate pubkey: $PUB"

say "3. SRC: grant READ-ONLY mandate on $ZONE (scope=ethos.read.$ZONE)"
GRANT=$(src grant "urn:aithos:agent:reader-only" \
  --sphere "$ZONE" --scope "ethos.read.$ZONE" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
REWRAPPED=$(jqf "rewrapped" <<<"$GRANT")
[[ "$REWRAPPED" == "true" ]] \
  || fail "expected rewrapped=true (zone DEK rewrap lets the reader decrypt)"

# v0.3 assertion — read-only delegate NOT on gamma readers list.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:reader-only#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "no" ]] \
  || fail "read-only delegate must NOT be on manifest.gamma.readers"
pass "delegate on zone DEK wrap list, NOT on manifest.gamma.readers"

say "4. SRC: pack + install tracked on DST"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
dst ethos install "$BUNDLE" --set-default >/dev/null
dst mandate add "$MANDATE_PATH" >/dev/null
cp "$KEY" "$WORK/agent-dst.key.json"
chmod 600 "$WORK/agent-dst.key.json"
AGENT="$WORK/agent-dst.key.json"
pass "DST installed"

# --------------------------------------------------------------------------- #
say "5. DST: READ the seed section via mandate — MUST succeed"
SHOW_OUT=$(dst ethos show --handle "$HANDLE" --zone "$ZONE" --section "$SEED_SEC" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT")
echo "$SHOW_OUT" | grep -q "Content the reader is allowed to see" \
  || fail "delegate could not read the seed section"
pass "delegate read the seed section successfully"

say "6. DST: WRITE must be refused (no ethos.write.$ZONE scope)"
expect_fail "ethos add-section via read-only mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone "$ZONE" --title "should-not-land" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "ethos modify-section via read-only mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos modify-section --handle "$HANDLE" \
    --zone "$ZONE" --section "$SEED_SEC" --body "overwrite" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "ethos delete-section via read-only mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos delete-section --handle "$HANDLE" \
    --zone "$ZONE" --section "$SEED_SEC" --reason "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "7. DST: GAMMA payloads must be opaque (no gamma.read scope)"
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
ALL_DENIED=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.length > 0 && a.every(e => e._access_denied === true) ? 'yes' : 'no');
" "$GAMMA_JSON")
[[ "$ALL_DENIED" == "yes" ]] \
  || fail "expected every gamma entry to be _access_denied for read-only mandate"
pass "all gamma entries are _access_denied (zone-read ≠ gamma-read)"

say "8. DST: integrity-tier gamma verify still passes"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS (integrity tier, no payload decryption)"

printf "\n### e2e-read-only-mandate: OK\n"
