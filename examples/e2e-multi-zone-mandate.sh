#!/usr/bin/env bash
# End-to-end test: cross-zone gamma visibility with a single-zone read mandate.
#
# A mandate has ONE `actor_sphere` (set at grant time) but can carry multiple
# scopes. Its zone-read / zone-write scopes are enforced against the zone
# AND the actor_sphere: a mandate with actor_sphere=circle cannot be used to
# act on the self zone even if its scopes include `ethos.read.self`.
#
# BUT `gamma.read` is zone-agnostic — the gamma log commits to ALL zones, so
# a delegate with `gamma.read` sees entries from every zone, not just the
# one their mandate is bound to.
#
# This test verifies exactly that asymmetry:
#
#   mandate: actor_sphere=circle, scopes=[ethos.read.circle, gamma.read]
#
#   - ethos show --zone circle    → OK (zone scope matches actor_sphere)
#   - ethos show --zone self      → REFUSED (actor_sphere mismatch)
#   - ethos show --zone public    → OK (public is plaintext, no mandate needed)
#   - gamma show                  → decrypts entries from circle + self + public
#                                   (forward-only: post-grant entries only).
#   - All writes                  → REFUSED (no ethos.write.X).
#
# This is the "read-only auditor with one zone view" pattern — a teammate
# who can see your circle content AND follow the full audit trail across
# all zones, but cannot touch self content directly.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-multi-zone-mandate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-multi-zone-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-multi-zone-dst}"
WORK="${WORK:-/tmp/aithos-e2e-multi-zone-work}"

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

say "1. SRC: init + grant FIRST (so all subsequent entries seal to auditor)"
src init --handle "$HANDLE" --display-name "CrossZone Alice" >/dev/null

KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:cross-zone" --json)
PUB=$(jqf "pubkey" <<<"$DK")

# actor_sphere=circle, scopes include ethos.read.circle + gamma.read.
# We INTENTIONALLY omit ethos.read.self — even if we added it, the
# actor_sphere mismatch check would still refuse self reads.
GRANT=$(src grant "urn:aithos:agent:cross-zone" \
  --sphere circle \
  --scope "ethos.read.circle,gamma.read" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
[[ "$(jqf 'rewrapped' <<<"$GRANT")" == "true" ]] || fail "expected rewrapped=true"
pass "mandate: $MANDATE_ID (actor=circle, gamma.read in scope)"

# v0.3 assertion — auditor IS on gamma readers.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:cross-zone#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "yes" ]] || fail "expected delegate on gamma.readers"
pass "delegate IS on manifest.gamma.readers"

say "2. SRC: add sections across all three zones (post-grant — forward-sealed to auditor)"
src ethos add-section --handle "$HANDLE" --zone public \
  --title "pub-after" --body "public after grant" >/dev/null
src ethos add-section --handle "$HANDLE" --zone circle \
  --title "circle-after" --body "circle after grant" >/dev/null
CIRCLE_SEC=$(src ethos list --handle "$HANDLE" --zone circle --json 2>/dev/null \
  | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); const secs=(d.zones?.circle?.sections ?? d.sections ?? d); console.log(Array.isArray(secs) ? secs[secs.length-1].id : '')")
src ethos add-section --handle "$HANDLE" --zone self \
  --title "self-after" --body "self after grant" >/dev/null
pass "added 1 section per zone (3 more gamma entries, all sealed to auditor)"

say "3. SRC: pack + install tracked on DST"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
dst ethos install "$BUNDLE" --set-default >/dev/null
dst mandate add "$MANDATE_PATH" >/dev/null
cp "$KEY" "$WORK/agent-dst.key.json"
chmod 600 "$WORK/agent-dst.key.json"
AGENT="$WORK/agent-dst.key.json"
pass "DST ready"

# --------------------------------------------------------------------------- #
say "4. DST: ethos show circle — MUST succeed (scope match + actor_sphere match)"
dst ethos show --handle "$HANDLE" --zone circle \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" | grep -q "circle after grant" \
  || fail "delegate could not read circle zone"
pass "circle zone readable"

say "5. DST: ethos show self — MUST be REFUSED (actor_sphere=circle ≠ self)"
expect_fail "ethos show --zone self via circle-actor mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone self --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "6. DST: ethos show public — OK without a mandate (public is plaintext)"
dst ethos show --handle "$HANDLE" --zone public | grep -q "public after grant" \
  || fail "public zone should be readable without mandate"
pass "public zone readable without mandate"

say "7. DST: writes anywhere must be REFUSED"
expect_fail "write to circle (no ethos.write.circle)" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone circle --title "nope" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "write to self (actor_sphere mismatch AND no write scope)" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone self --title "nope" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "8. DST: gamma show — decrypts entries from ALL THREE zones (cross-zone view)"
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)

# All post-grant entries (the 3 we just added) must decrypt + span 3 zones.
ZONES_DECRYPTED=$(node -e "
  const a = JSON.parse(process.argv[1]);
  const ok = a.filter(e => !e._access_denied);
  const zones = new Set(ok.map(e => e.zone));
  console.log(JSON.stringify([...zones].sort()));
" "$GAMMA_JSON")
echo "  decrypted zones: $ZONES_DECRYPTED"
[[ "$ZONES_DECRYPTED" == '["circle","public","self"]' ]] \
  || fail "expected decrypted entries to span circle+public+self, got $ZONES_DECRYPTED"
pass "gamma visibility spans circle + public + self (cross-zone audit)"

say "9. DST: gamma verify PASSES"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS"

printf "\n### e2e-multi-zone-mandate: OK (zone scope zone-bound, gamma.read zone-agnostic)\n"
