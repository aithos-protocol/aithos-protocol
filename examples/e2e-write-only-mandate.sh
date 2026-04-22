#!/usr/bin/env bash
# End-to-end test: `ethos.write.X` ONLY mandate.
#
# This is THE v0.3 security property — the whole point of the format break:
#
#   "Par défaut un mandat sur une zone autre que le gamma ne donne JAMAIS
#    accès a la lecture du gamma. En revanche, il doit permettre d'ajouter
#    une section dans le gamma, donc d'écrire, mais en aucun cas de
#    modifier/supprimer l'existant. Juste ajouter."
#
# A mandate holding `ethos.write.circle` (and nothing else):
#   - CAN append a new section to the circle zone (the whole point).
#     Appending a section triggers the usual `section.add` gamma entry,
#     signed by the delegate under `authorized_by: <mandate_id>`.
#   - Because section.add is APPEND-ONLY (no state changes to prior entries),
#     a write-only mandate de facto can only append to gamma. It cannot
#     overwrite or truncate — gamma is an append-only log by construction.
#   - CANNOT read circle (no `ethos.read.circle`) — so cannot see what's
#     already there.
#   - CANNOT read gamma (no `gamma.read`) — every entry comes back as
#     `_access_denied`. This is verified below.
#
# The "append-without-read" property relies on the v0.3 per-entry envelope
# format: writing a new entry only needs (a) the delegate's Ed25519 signing
# seed and (b) the subject's public metadata (readers list + sphere pubkeys).
# No zone DEK, no gamma DEK.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-write-only-mandate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
ZONE="${ZONE:-circle}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-write-only-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-write-only-dst}"
WORK="${WORK:-/tmp/aithos-e2e-write-only-work}"

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

say "1. SRC: init + seed a section in $ZONE (owner-signed entry #1 in gamma)"
src init --handle "$HANDLE" --display-name "WriteOnly Alice" >/dev/null
SEED_OUT=$(src ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "seed" --body "Owner's private $ZONE seed." --json)
SEED_SEC=$(jqf "section.id" <<<"$SEED_OUT")
pass "seed section: $SEED_SEC"

say "2. SRC: generate delegate keypair"
KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:writer-only" --json)
PUB=$(jqf "pubkey" <<<"$DK")
pass "delegate pubkey: $PUB"

say "3. SRC: grant WRITE-ONLY mandate on $ZONE (scope=ethos.write.$ZONE — nothing else)"
GRANT=$(src grant "urn:aithos:agent:writer-only" \
  --sphere "$ZONE" \
  --scope "ethos.write.$ZONE" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
REWRAPPED=$(jqf "rewrapped" <<<"$GRANT")
[[ "$REWRAPPED" == "true" ]] \
  || fail "expected rewrapped=true (zone DEK rewrap happens even for write-only — delegate needs to re-encrypt the zone blob when appending)"
pass "mandate: $MANDATE_ID (rewrapped=true)"

# v0.3 key assertion #1 — delegate NOT on manifest.gamma.readers.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:writer-only#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "no" ]] \
  || fail "write-only delegate must NOT be on manifest.gamma.readers (got yes)"
pass "delegate is NOT on manifest.gamma.readers (v0.3 decoupling holds)"

say "4. SRC: pack + install tracked on DST"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
dst ethos install "$BUNDLE" --set-default >/dev/null
dst mandate add "$MANDATE_PATH" >/dev/null
cp "$KEY" "$WORK/agent-dst.key.json"
chmod 600 "$WORK/agent-dst.key.json"
AGENT="$WORK/agent-dst.key.json"
pass "DST installed + mandate imported"

# --------------------------------------------------------------------------- #
say "5. DST: APPEND via write-only mandate — MUST succeed (the whole point)"
ADD_OUT=$(dst ethos add-section --handle "$HANDLE" \
  --zone "$ZONE" \
  --title "delegate-append" \
  --body "Blind write: the delegate doesn't read, just appends." \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
NEW_SEC=$(jqf "section.id" <<<"$ADD_OUT")
NEW_GAMMA=$(jqf "gammaEntry.id" <<<"$ADD_OUT")
pass "delegate appended section: $NEW_SEC"
pass "signed gamma entry: $NEW_GAMMA (authorized_by=$MANDATE_ID)"

say "6. DST: write-only mandate can NOT read the $ZONE zone (no ethos.read.$ZONE)"
expect_fail "ethos show --zone $ZONE via write-only mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone "$ZONE" --mandate "$MANDATE_ID" --agent-key "$AGENT"
expect_fail "ethos show --section via write-only mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone "$ZONE" --section "$SEED_SEC" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "7. DST: write-only mandate can NOT read the gamma log payloads (no gamma.read)"
# gamma show itself succeeds (header walk works without key material), but every
# entry comes back with _access_denied=true.
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
ACCESS_DENIED_COUNT=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.filter(e => e._access_denied === true).length);
" "$GAMMA_JSON")
TOTAL_COUNT=$(node -e "console.log(JSON.parse(process.argv[1]).length)" "$GAMMA_JSON")
[[ "$TOTAL_COUNT" -ge 2 ]] \
  || fail "expected at least 2 gamma entries (seed + delegate-append), got $TOTAL_COUNT"
[[ "$ACCESS_DENIED_COUNT" == "$TOTAL_COUNT" ]] \
  || fail "expected ALL $TOTAL_COUNT entries _access_denied, got $ACCESS_DENIED_COUNT"
pass "all $TOTAL_COUNT gamma entries come back _access_denied=true (no payload leaked)"

# The delegate's OWN entry is also _access_denied — even though it signed it,
# it didn't get an envelope (not on the readers list). This is v0.3 by design.
OWN_DENIED=$(node -e "
  const a = JSON.parse(process.argv[1]);
  const mine = a.filter(e => e.authorized_by === process.argv[2]);
  if (mine.length === 0) { console.log('missing'); process.exit(0); }
  console.log(mine.every(e => e._access_denied === true) ? 'yes' : 'no');
" "$GAMMA_JSON" "$MANDATE_ID")
[[ "$OWN_DENIED" == "yes" ]] \
  || fail "delegate's own entries should also be _access_denied (write-only has no read path)"
pass "even the delegate's own signed entries are _access_denied (sign ≠ read)"

say "8. DST: gamma verify (integrity-only tier) still PASSES for the delegate"
# §10.14.2′: integrity tier walks per-entry hashes + Ed25519 signatures + the
# manifest anchor, without any key material. Runs over --mandate too.
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS (integrity tier, no envelopes decrypted)"

say "9. DST: ethos verify (tracked mode) PASSES"
dst ethos verify --handle "$HANDLE" >/dev/null
pass "ethos verify PASS"

printf "\n### e2e-write-only-mandate: OK (append-without-read is live)\n"
