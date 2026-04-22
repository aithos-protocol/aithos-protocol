#!/usr/bin/env bash
# End-to-end test: full zone CRUD WITHOUT gamma.read — the common case.
#
# Scope granted: `ethos.read.X,ethos.write.X` (NO `gamma.read`).
#
# This is the shape most delegates will have in practice: they can add,
# modify, delete sections in their zone, and they can see the current state
# of the zone — but they CANNOT read the mutation log. Every gamma entry
# (including their own) comes back as `_access_denied`.
#
# Key assertions:
#   - All three CRUD ops succeed (add / modify / delete).
#   - Every CRUD op produces a signed gamma entry (authored by the delegate).
#   - Zone reads succeed (zone DEK rewrap at grant time).
#   - gamma show: all entries _access_denied (not on gamma.readers list).
#   - gamma verify: still passes (integrity tier walks hashes + signatures
#     without needing envelopes).
#
# This is the scope shape covered implicitly by e2e-delegate-crud-encrypted
# in the gamma.read-stripped variant — here we make it explicit and add the
# invariants.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-crud-no-gamma-read.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
ZONE="${ZONE:-circle}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-crud-nogamma-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-crud-nogamma-dst}"
WORK="${WORK:-/tmp/aithos-e2e-crud-nogamma-work}"

say()  { printf "\n### %s\n" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }
jqf() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$1"; }

src() { AITHOS_HOME="$SRC_HOME" $CLI "$@"; }
dst() { AITHOS_HOME="$DST_HOME" $CLI "$@"; }

# --------------------------------------------------------------------------- #
say "0. reset scratch"
rm -rf "$SRC_HOME" "$DST_HOME" "$WORK"
mkdir -p "$WORK"

say "1. SRC: init + seed a section in $ZONE"
src init --handle "$HANDLE" --display-name "CrudNoGamma Alice" >/dev/null
SEED=$(src ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "seed" --body "Owner seed." --json)
SEED_SEC=$(jqf "section.id" <<<"$SEED")
pass "seed section: $SEED_SEC"

say "2. SRC: delegate key + grant ethos.read+write on $ZONE (NO gamma.read)"
KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:crud-nogamma" --json)
PUB=$(jqf "pubkey" <<<"$DK")
GRANT=$(src grant "urn:aithos:agent:crud-nogamma" \
  --sphere "$ZONE" \
  --scope "ethos.read.$ZONE,ethos.write.$ZONE" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
[[ "$(jqf 'rewrapped' <<<"$GRANT")" == "true" ]] || fail "expected rewrapped=true"

# v0.3 assertion — delegate NOT on gamma readers.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:crud-nogamma#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "no" ]] \
  || fail "CRUD-without-gamma-read delegate must NOT be on manifest.gamma.readers"
pass "delegate on zone DEK wrap, NOT on gamma readers (v0.3 decoupling)"

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
say "4. DST: READ the seed section (proves zone DEK rewrap worked)"
dst ethos show --handle "$HANDLE" --zone "$ZONE" --section "$SEED_SEC" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" | grep -q "Owner seed." \
  || fail "delegate could not read the seed section"
pass "delegate read OK"

say "5. DST: CREATE a new section via mandate"
ADD=$(dst ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "delegate-add" --body "Added by delegate." \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
NEW_SEC=$(jqf "section.id" <<<"$ADD")
pass "section created: $NEW_SEC"

say "6. DST: UPDATE that section via mandate"
sleep 1
dst ethos modify-section --handle "$HANDLE" --zone "$ZONE" \
  --section "$NEW_SEC" --body "Modified by delegate." \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "section modified"

say "7. DST: DELETE that section via mandate"
sleep 1
dst ethos delete-section --handle "$HANDLE" --zone "$ZONE" \
  --section "$NEW_SEC" --reason "end of CRUD cycle" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "section deleted"

say "8. DST: gamma show — all entries MUST be _access_denied"
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
TOTAL=$(node -e "console.log(JSON.parse(process.argv[1]).length)" "$GAMMA_JSON")
DENIED=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.filter(e => e._access_denied === true).length);
" "$GAMMA_JSON")
# We expect 4 entries: seed + add + modify + delete.
[[ "$TOTAL" == "4" ]] || fail "expected 4 gamma entries (seed + 3 CRUD), got $TOTAL"
[[ "$DENIED" == "4" ]] || fail "expected all 4 gamma entries _access_denied, got $DENIED"
pass "all 4 gamma entries are _access_denied (no gamma.read → no payloads)"

# Sanity: the delegate can STILL see unencrypted metadata (op, zone,
# timestamp, authored_by, hashes) — those are in public_header, which is
# visible to anyone who can read the file. The payload is what's sealed.
DELEGATE_ENTRY_COUNT=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.filter(e => e.authorized_by === process.argv[2]).length);
" "$GAMMA_JSON" "$MANDATE_ID")
[[ "$DELEGATE_ENTRY_COUNT" == "3" ]] \
  || fail "expected 3 entries signed under $MANDATE_ID, got $DELEGATE_ENTRY_COUNT"
pass "3 entries carry authorized_by=$MANDATE_ID (public header visible)"

say "9. DST: gamma verify still PASSES (integrity tier)"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS"

printf "\n### e2e-crud-no-gamma-read: OK\n"
