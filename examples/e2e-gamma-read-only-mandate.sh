#!/usr/bin/env bash
# End-to-end test: `gamma.read` ONLY mandate — the auditor role.
#
# New in v0.3: the dedicated `gamma.read` capability. This test grants ONLY
# `gamma.read` (no ethos.read / ethos.write on any zone) and asserts that:
#
#   - The delegate IS on `manifest.gamma.readers` (can decrypt entries
#     appended after the grant).
#   - The delegate is NOT on any zone's DEK wrap list, so `ethos show` on
#     encrypted zones is refused at scope-check time (no ethos.read.X).
#   - Writes to any zone are refused at scope-check time (no ethos.write.X).
#   - `gamma show` returns decrypted entries (at least for those appended
#     after the grant — v0.3 envelopes are forward-only; pre-grant entries
#     stay `_access_denied` because nobody retro-seals).
#   - `gamma verify` passes (integrity tier works for anyone; with gamma.read
#     it can also verify chain + signatures over decrypted content).
#
# The auditor role is the cleanest expression of the v0.3 decoupling: you
# can give someone the audit trail without giving them current zone content,
# and vice versa.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-gamma-read-only-mandate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
# actor_sphere must be one of public|circle|self. Use circle (encrypted).
ACTOR_SPHERE="${ACTOR_SPHERE:-circle}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-gamma-ro-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-gamma-ro-dst}"
WORK="${WORK:-/tmp/aithos-e2e-gamma-ro-work}"

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

say "1. SRC: init + seed sections in all three zones"
src init --handle "$HANDLE" --display-name "Auditor Alice" >/dev/null
src ethos add-section --handle "$HANDLE" --zone public \
  --title "pub-seed" --body "public content" >/dev/null
src ethos add-section --handle "$HANDLE" --zone circle \
  --title "circle-seed" --body "circle content" >/dev/null
src ethos add-section --handle "$HANDLE" --zone self \
  --title "self-seed" --body "self content" >/dev/null
pass "3 seed sections (one per zone, 3 gamma entries)"

say "2. SRC: delegate keypair"
KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:auditor" --json)
PUB=$(jqf "pubkey" <<<"$DK")
pass "delegate pubkey: $PUB"

say "3. SRC: grant GAMMA-READ-ONLY mandate (scope=gamma.read, actor_sphere=$ACTOR_SPHERE)"
GRANT=$(src grant "urn:aithos:agent:auditor" \
  --sphere "$ACTOR_SPHERE" --scope "gamma.read" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
REWRAPPED=$(jqf "rewrapped" <<<"$GRANT")
[[ "$REWRAPPED" == "true" ]] \
  || fail "expected rewrapped=true (gamma.read triggers rewrap to seed new gamma DEK + add to readers)"
pass "mandate: $MANDATE_ID (rewrapped=true)"

# v0.3 key assertion — auditor IS on gamma readers.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:auditor#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "yes" ]] \
  || fail "gamma-read-only delegate MUST be on manifest.gamma.readers"
pass "delegate IS on manifest.gamma.readers (gamma.read scope held)"

say "4. SRC: seed one more entry AFTER grant (so we have a forward-sealed entry)"
src ethos add-section --handle "$HANDLE" --zone circle \
  --title "post-grant" --body "written after the auditor was granted" >/dev/null
pass "post-grant entry appended"

say "5. SRC: pack + install tracked on DST"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
dst ethos install "$BUNDLE" --set-default >/dev/null
dst mandate add "$MANDATE_PATH" >/dev/null
cp "$KEY" "$WORK/agent-dst.key.json"
chmod 600 "$WORK/agent-dst.key.json"
AGENT="$WORK/agent-dst.key.json"
pass "DST installed + mandate imported"

# --------------------------------------------------------------------------- #
say "6. DST: ethos show (encrypted zones) must be REFUSED (no ethos.read.X)"
expect_fail "ethos show --zone circle via gamma-read-only" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone circle --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "ethos show --zone self via gamma-read-only" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone self --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "7. DST: writes must be REFUSED (no ethos.write.X on any zone)"
expect_fail "ethos add-section circle via gamma-read-only" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone circle --title "nope" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "ethos add-section public via gamma-read-only" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone public --title "nope" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "8. DST: gamma show — post-grant entries MUST decrypt"
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
TOTAL=$(node -e "console.log(JSON.parse(process.argv[1]).length)" "$GAMMA_JSON")
POST_GRANT_READABLE=$(node -e "
  const a = JSON.parse(process.argv[1]);
  // Entries [0..2] were pre-grant (seed x3). Entry 3 is post-grant.
  const last = a[a.length - 1];
  if (last._access_denied) { console.log('no'); process.exit(0); }
  console.log(last.payload && Object.keys(last.payload).length > 0 ? 'yes' : 'no');
" "$GAMMA_JSON")
[[ "$TOTAL" -ge 4 ]] || fail "expected at least 4 gamma entries, got $TOTAL"
[[ "$POST_GRANT_READABLE" == "yes" ]] \
  || fail "the post-grant entry must be readable by the auditor"
pass "post-grant entry decrypts for auditor (payload visible)"

# Pre-grant entries may or may not decrypt depending on whether the grant
# triggered a DEK rotation. In v0.3 the grant performs a rewrap that creates
# a new gamma edition; prior entries' envelopes are NOT re-created — so they
# remain access-denied for the auditor (forward-only).
PRE_GRANT_DENIED=$(node -e "
  const a = JSON.parse(process.argv[1]).slice(0, 3);
  console.log(a.every(e => e._access_denied === true) ? 'yes' : 'no');
" "$GAMMA_JSON")
[[ "$PRE_GRANT_DENIED" == "yes" ]] \
  || fail "pre-grant entries should be _access_denied for a later-added auditor"
pass "pre-grant entries are _access_denied (forward-only envelope seal)"

say "9. DST: gamma verify PASSES for the auditor"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS"

printf "\n### e2e-gamma-read-only-mandate: OK (auditor role works)\n"
