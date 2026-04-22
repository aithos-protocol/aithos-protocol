#!/usr/bin/env bash
# End-to-end test: delegate-path CRUD on the encrypted zones (circle, self),
# with delegate gamma reads + verify via the new --mandate flags.
#
# v0.3 semantics (post gamma-v0.3 clean-cut — see spec/drafts/gamma-v0.3-*):
#   Gamma access is gated by an explicit `gamma.read` scope. A mandate with
#   only `ethos.read.*`/`ethos.write.*` rewraps the zone DEK (so the delegate
#   can read + write that zone) but does NOT add the delegate to
#   `manifest.gamma.readers`. Therefore gamma entries appended AFTER the grant
#   carry no envelope for the delegate — they appear with _access_denied=true.
#
#   To preserve the test's original intent (delegate sees full CRUD history
#   decrypted), we include `gamma.read` in the mandate scope below. The
#   owner's pre-grant seed entry still stays encrypted-to-owner-only because
#   envelopes are forward-only: being added to the readers list never
#   retro-seals prior entries.
#
# For each zone in {circle, self}:
#   SRC side (owner):
#     1. init identity + owner adds a seed section (owner-signed entry #1).
#     2. generate delegate keypair.
#     3. grant a read+write+gamma.read mandate bound to the delegate pubkey
#        → triggers issueMandateWithRewrap, which:
#          * bumps a new edition,
#          * rewraps the zone DEK to include the delegate X25519 pubkey,
#          * adds the delegate to `manifest.gamma.readers` (v0.3) so FUTURE
#            gamma entries will seal an envelope for them.
#     4. delete all sealed seeds (safety: no owner-path fallback).
#     5. pack the bundle.
#
#   DST side (delegate):
#     6. install the bundle (tracked identity, no sealed seeds).
#     7. add the mandate.
#     8. ship the delegate keyfile over.
#     9. read the owner-seeded section via --mandate --agent-key.
#    10. CREATE: add-section via delegate path.
#    11. UPDATE: modify-section via delegate path.
#    12. DELETE: delete-section via delegate path.
#   After each write: assert gamma count grew by 1, head moved, latest op matches.
#    13. gamma show --mandate    — delegate reads the full log.
#    14. gamma verify --mandate  — delegate walks signatures + chain + anchor.
#    15. ethos verify            — tracked-mode verify still passes.
#
# Usage (from repo root, after `npm run build`):
#
#   bash examples/e2e-delegate-crud-encrypted.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
SAY_PREFIX="${SAY_PREFIX:-}"

say()  { printf "\n### %s%s\n" "$SAY_PREFIX" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

jqf() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$1"; }

# --------------------------------------------------------------------------- #
# Per-zone runner. Takes one arg: the zone name (circle|self).
# Uses TWO AITHOS_HOME values so we never confuse owner and delegate sides.
run_zone() {
  local ZONE="$1"
  [[ "$ZONE" == "circle" || "$ZONE" == "self" ]] || fail "run_zone: zone must be circle|self"

  local SRC_HOME="/tmp/aithos-e2e-delegate-${ZONE}-src"
  local DST_HOME="/tmp/aithos-e2e-delegate-${ZONE}-dst"
  local WORK="/tmp/aithos-e2e-delegate-${ZONE}-work"

  local src=(env AITHOS_HOME="$SRC_HOME" $CLI)
  local dst=(env AITHOS_HOME="$DST_HOME" $CLI)

  SAY_PREFIX="[$ZONE] "

  # --- Counters for gamma assertions on DST side ---
  local expected_count=0

  # Helpers that read DST gamma state via the delegate mandate.
  dst_gamma_count() { "${dst[@]}" gamma show --head --handle "$HANDLE" --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | awk -F'count=' '{print $2}'; }
  dst_gamma_latest_op()   { "${dst[@]}" gamma show --json --handle "$HANDLE" --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].op);"; }
  dst_gamma_latest_zone() { "${dst[@]}" gamma show --json --handle "$HANDLE" --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].zone);"; }
  dst_gamma_latest_auth() { "${dst[@]}" gamma show --json --handle "$HANDLE" --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].authorized_by||'');"; }

  assert_dst_gamma() {
    local expected_op="$1"
    local got_count got_op got_zone got_auth
    got_count=$(dst_gamma_count)
    got_op=$(dst_gamma_latest_op)
    got_zone=$(dst_gamma_latest_zone)
    got_auth=$(dst_gamma_latest_auth)
    [[ "$got_count" == "$expected_count" ]] || fail "expected gamma.count=$expected_count, got $got_count"
    [[ "$got_op" == "$expected_op" ]] || fail "expected op=$expected_op, got $got_op"
    [[ "$got_zone" == "$ZONE" ]] || fail "expected zone=$ZONE, got $got_zone"
    [[ "$got_auth" == "$MANDATE_ID" ]] || fail "expected authorized_by=$MANDATE_ID, got '$got_auth'"
    pass "gamma via mandate: count=$got_count op=$got_op zone=$got_zone auth=$got_auth"
  }

  # --------------------------------------------------------------------- #
  say "reset scratch dirs"
  rm -rf "$SRC_HOME" "$DST_HOME" "$WORK"
  mkdir -p "$WORK"

  say "SRC: init identity + ethos"
  "${src[@]}" init --handle "$HANDLE" --display-name "Alice ($ZONE)" >/dev/null
  pass "identity created"

  say "SRC: owner seeds a section in $ZONE (entry #1 in gamma)"
  OWNER_ADD=$("${src[@]}" ethos add-section --handle "$HANDLE" \
    --zone "$ZONE" \
    --title "seed-$ZONE" \
    --body "Owner-seeded content in the $ZONE zone." \
    --tags "seed,owner" \
    --json)
  OWNER_SEC=$(jqf "section.id" <<<"$OWNER_ADD")
  pass "seed section: $OWNER_SEC (owner-signed)"

  say "SRC: generate delegate keypair"
  AGENT_KEY_SRC="$WORK/agent.key.json"
  DK_OUT=$("${src[@]}" delegate-key --out "$AGENT_KEY_SRC" \
    --id "urn:aithos:agent:alice-${ZONE}-delegate" --json)
  DELEGATE_PUBKEY=$(jqf "pubkey" <<<"$DK_OUT")
  pass "delegate pubkey: $DELEGATE_PUBKEY"

  say "SRC: grant read+write+gamma.read mandate on $ZONE (v0.3: rewraps zone DEK AND adds delegate to manifest.gamma.readers)"
  GRANT_OUT=$("${src[@]}" grant "urn:aithos:agent:alice-${ZONE}-delegate" \
    --sphere "$ZONE" \
    --scope "ethos.read.$ZONE,ethos.write.$ZONE,gamma.read" \
    --pubkey "$DELEGATE_PUBKEY" \
    --ttl 30d \
    --json)
  MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT_OUT")
  MANDATE_PATH=$(jqf "path" <<<"$GRANT_OUT")
  REWRAPPED=$(jqf "rewrapped" <<<"$GRANT_OUT")
  [[ "$REWRAPPED" == "true" ]] || fail "expected rewrapped=true (DEKs must be rewrapped to the delegate for encrypted zones)"
  cp "$MANDATE_PATH" "$WORK/mandate.json"
  pass "mandate: $MANDATE_ID (rewrapped=true)"

  say "SRC: delete ALL sealed seeds"
  for f in "$SRC_HOME/identities/$HANDLE"/{root,public,circle,self}.sealed.json; do
    [[ -f "$f" ]] || fail "expected sealed seed missing: $f"
    rm -f "$f"
  done
  pass "owner sphere seeds gone"

  say "SRC: pack the bundle"
  BUNDLE="$WORK/alice.ethos"
  "${src[@]}" ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
  pass "bundle: $BUNDLE"

  # --------------------------------------------------------------------- #
  say "DST: install bundle (tracked)"
  "${dst[@]}" ethos install "$BUNDLE" --set-default >/dev/null
  pass "installed under $DST_HOME"

  say "DST: import the mandate"
  "${dst[@]}" mandate add "$WORK/mandate.json" >/dev/null
  pass "mandate registered"

  say "DST: ship the delegate keyfile"
  AGENT_KEY_DST="$WORK/agent-dst.key.json"
  cp "$AGENT_KEY_SRC" "$AGENT_KEY_DST"
  chmod 600 "$AGENT_KEY_DST"
  pass "keyfile present on DST (mode 0600)"

  # Starting gamma count on DST = owner's 1 seed entry + 0 (grant rewrap does
  # NOT emit a gamma entry — it only bumps the manifest edition).
  expected_count=1
  pass "starting gamma count on DST: $expected_count (owner's seed)"

  # --------------------------------------------------------------------- #
  say "DST.R) read the owner-seeded section via --mandate (proves DEK rewrap worked)"
  if ! "${dst[@]}" ethos show --handle "$HANDLE" \
      --zone "$ZONE" --section "$OWNER_SEC" \
      --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | grep -q "Owner-seeded content"; then
    fail "delegate could not read the owner-seeded section in $ZONE"
  fi
  pass "delegate read: owner-seeded content visible"

  # --------------------------------------------------------------------- #
  say "DST.C) add-section via mandate"
  ADD_OUT=$("${dst[@]}" ethos add-section --handle "$HANDLE" \
    --zone "$ZONE" \
    --title "delegate-added-$ZONE" \
    --body "Delegate wrote this under mandate $MANDATE_ID." \
    --tags "delegate,test" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" --json)
  DEL_SEC=$(jqf "section.id" <<<"$ADD_OUT")
  expected_count=$((expected_count + 1))
  assert_dst_gamma "section.add"
  pass "delegate-added section: $DEL_SEC"

  # --------------------------------------------------------------------- #
  say "DST.U) modify-section via mandate"
  sleep 1
  "${dst[@]}" ethos modify-section --handle "$HANDLE" \
    --zone "$ZONE" --section "$DEL_SEC" \
    --body "Updated by delegate at $(date -u +%FT%TZ)." \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" >/dev/null
  expected_count=$((expected_count + 1))
  assert_dst_gamma "section.modify"

  # --------------------------------------------------------------------- #
  say "DST.D) delete-section via mandate"
  sleep 1
  "${dst[@]}" ethos delete-section --handle "$HANDLE" \
    --zone "$ZONE" --section "$DEL_SEC" \
    --reason "e2e-delegate-crud-encrypted: end of cycle on $ZONE" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" >/dev/null
  expected_count=$((expected_count + 1))
  assert_dst_gamma "section.delete"

  # The original owner-seeded section should STILL be readable via mandate
  # (delete-section only removed the delegate-added one).
  if ! "${dst[@]}" ethos show --handle "$HANDLE" --zone "$ZONE" --section "$OWNER_SEC" \
      --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" >/dev/null 2>&1; then
    fail "delegate can no longer read owner-seeded section — unexpected side effect"
  fi
  pass "owner-seeded section still readable (delete did not nuke the wrong section)"

  # --------------------------------------------------------------------- #
  say "DST: delegate gamma show (via mandate) sees the full log"
  "${dst[@]}" gamma show --handle "$HANDLE" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" | head -10
  [[ "$(dst_gamma_count)" == "$expected_count" ]] || fail "gamma count mismatch at end"

  # v0.3 invariant — `gamma.read` in scope means the delegate's own writes
  # are decryptable (envelopes seal to them on append). The owner's seed
  # entry (#1) pre-dates the grant and stays _access_denied (forward-only
  # readers list). Assert: entries 2..N decrypt; entry 1 is access-denied.
  FULL_JSON=$("${dst[@]}" gamma show --handle "$HANDLE" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST" --json)
  FIRST_DENIED=$(node -e "const a=JSON.parse(process.argv[1]); console.log(a[0]._access_denied===true?'yes':'no')" "$FULL_JSON")
  # Post-grant entries: not access-denied + payload has at least one field
  # (body/title/tags for add/modify, reason for delete).
  POST_GRANT_READABLE=$(node -e "
    const a = JSON.parse(process.argv[1]).slice(1);
    console.log(a.every(e => !e._access_denied && e.payload && Object.keys(e.payload).length > 0) ? 'yes' : 'no');
  " "$FULL_JSON")
  [[ "$FIRST_DENIED" == "yes" ]] \
    || fail "expected owner's pre-grant seed entry to be _access_denied for the delegate (v0.3 forward-only)"
  [[ "$POST_GRANT_READABLE" == "yes" ]] \
    || fail "expected all post-grant entries to decrypt for the delegate (gamma.read scope held)"
  pass "v0.3 envelope scope: seed entry access_denied, post-grant entries readable"

  say "DST: delegate gamma verify (via mandate)"
  "${dst[@]}" gamma verify --handle "$HANDLE" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT_KEY_DST"
  pass "gamma chain + anchor verify via delegate"

  say "DST: ethos verify (tracked mode)"
  "${dst[@]}" ethos verify --handle "$HANDLE"
  pass "ethos verify PASS"
}

# --------------------------------------------------------------------------- #
# Run both encrypted zones in sequence.
run_zone circle
run_zone self

printf "\n### e2e-delegate-crud-encrypted: OK (circle + self)\n"
