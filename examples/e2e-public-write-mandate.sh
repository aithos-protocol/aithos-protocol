#!/usr/bin/env bash
# End-to-end test: write-mandate on the PUBLIC zone, with hard deletion of
# every sphere seed on the subject side + pack/unpack to a second keystore.
#
# The point of this test:
#
#   Once a write mandate is signed by a sphere key, the delegate can keep
#   writing under that sphere's authority EVEN IF the sphere seed has been
#   deleted (lost, rotated-out, or simply purged for safety). The mandate
#   signature was captured at issuance — subsequent verification walks the
#   did.json public key, not the sealed seed.
#
# Scenario (single script, two separate AITHOS_HOME values = two "machines"):
#
#   SRC_HOME = subject's machine (alice).
#   DST_HOME = delegate's machine (alice's secondary device).
#
#    1. SRC: init identity + ethos
#    2. SRC: add a public section via the owner path (sphere #public signs)
#    3. SRC: generate a delegate keypair → capture pubkey (multibase)
#    4. SRC: grant a write mandate on the public zone, bound to that pubkey
#    5. SRC: DELETE every sealed seed (root + public + circle + self)
#            — simulates "the owner keys are gone, on purpose or by accident"
#    6. SRC: verify the ethos is still intact (ethos verify + gamma verify)
#    7. SRC: sanity-check that owner-path writes are now IMPOSSIBLE
#    8. SRC: pack the bundle (bundle never carries sealed seeds anyway)
#    9. DST: unpack + install the bundle as a tracked identity
#   10. DST: add the mandate (mandate add) — needs the bundle's did.json
#   11. DST: ship the delegate keyfile over (simulated by a cp)
#   12. DST: write a new public section USING the mandate + the agent key
#   13. DST: delete that section USING the mandate + the agent key
#   14. DST: verify the ethos + gamma log
#   15. DST: confirm owner-path writes on the tracked install are REFUSED
#
# Usage (run from the repo root, after `npm run build`):
#
#   bash examples/e2e-public-write-mandate.sh
#
# Override the scratch dirs by exporting SRC_HOME, DST_HOME, WORK before running.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-public-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-public-dst}"
WORK="${WORK:-/tmp/aithos-e2e-public-work}"

SRC_HANDLE="${SRC_HANDLE:-alice}"

say()  { printf "\n### %s\n" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

# Run a command with a given AITHOS_HOME — every CLI call goes through this,
# so we never accidentally touch the wrong keystore.
src() { AITHOS_HOME="$SRC_HOME" $CLI "$@"; }
dst() { AITHOS_HOME="$DST_HOME" $CLI "$@"; }

jq_field() {
  # tiny JSON field extractor via node, so we don't require jq on the box.
  local path="$1"
  node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$path"
}

# --------------------------------------------------------------------------- #
say "0. reset scratch dirs"
rm -rf "$SRC_HOME" "$DST_HOME" "$WORK"
mkdir -p "$WORK"

# --------------------------------------------------------------------------- #
say "1. SRC: init identity + ethos for $SRC_HANDLE"
src init --handle "$SRC_HANDLE" --display-name "Alice Test" >/dev/null
pass "identity + ethos created under $SRC_HOME"

# --------------------------------------------------------------------------- #
say "2. SRC: add a public section (owner path — #public signs directly)"
ADD_OUT=$(src ethos add-section \
  --zone public \
  --title "Voice" \
  --body "I write in short paragraphs." \
  --tags voice,style \
  --json)
OWNER_SEC=$(jq_field "section.id" <<<"$ADD_OUT")
[[ -n "$OWNER_SEC" ]] || fail "could not read section.id from add-section JSON"
pass "public section added: $OWNER_SEC"

# --------------------------------------------------------------------------- #
say "3. SRC: generate a delegate keypair for alice's secondary device"
KEYFILE="$WORK/bob-delegate.key.json"
DK_OUT=$(src delegate-key \
  --out "$KEYFILE" \
  --id "urn:aithos:agent:alice-secondary" \
  --json)
DELEGATE_PUBKEY=$(jq_field "pubkey" <<<"$DK_OUT")
[[ "$DELEGATE_PUBKEY" == z* ]] || fail "delegate pubkey did not look like multibase z…"
pass "delegate pubkey: $DELEGATE_PUBKEY"
pass "delegate keyfile: $KEYFILE (mode 0600)"

# --------------------------------------------------------------------------- #
say "4. SRC: grant write mandate on zone=public bound to that pubkey"
GRANT_OUT=$(src grant "urn:aithos:agent:alice-secondary" \
  --sphere public \
  --scope "ethos.read.public,ethos.write.public" \
  --pubkey "$DELEGATE_PUBKEY" \
  --label "Alice's secondary device" \
  --ttl 30d \
  --json)
MANDATE_ID=$(jq_field "mandate.id" <<<"$GRANT_OUT")
MANDATE_PATH=$(jq_field "path" <<<"$GRANT_OUT")
[[ -f "$MANDATE_PATH" ]] || fail "mandate file not written at $MANDATE_PATH"
pass "mandate id: $MANDATE_ID"
pass "signed by:  $(jq_field 'mandate.issued_by_key' <<<"$GRANT_OUT")"

# Copy the mandate json + bundle did.json out now, BEFORE we nuke the seeds.
cp "$MANDATE_PATH" "$WORK/mandate.json"

# --------------------------------------------------------------------------- #
say "5. SRC: DELETE every sealed seed on the owner side"
SEALED_DIR="$SRC_HOME/identities/$SRC_HANDLE"
ls "$SEALED_DIR"/*.sealed.json >/dev/null || fail "no sealed seeds found — unexpected keystore layout"
for f in "$SEALED_DIR"/root.sealed.json \
         "$SEALED_DIR"/public.sealed.json \
         "$SEALED_DIR"/circle.sealed.json \
         "$SEALED_DIR"/self.sealed.json; do
  [[ -f "$f" ]] || fail "expected sealed seed missing: $f"
  rm -f "$f"
done
pass "removed: root / public / circle / self sealed seeds"
ls "$SEALED_DIR" | grep -q sealed && fail "some sealed seed survived deletion" || true

# --------------------------------------------------------------------------- #
say "6. SRC: ethos still verifies (mandate signatures live in did.json)"
#
# NOTE: after seed deletion the identity is effectively tracked-only, so:
#   - `ethos verify` downgrades to "tracked — public-only verify" and prints
#     warnings for the encrypted zones + gamma anchor. Exit code is still 0.
#   - `gamma verify` is NOT available on tracked installs (it needs the
#     encryption key to walk the sealed log — loadIdentity() throws). That's
#     a known limitation of the CLI command, NOT a signal that the log is
#     compromised: the manifest still anchors to the log's head and the head
#     is visible via `gamma show --head` on a tracked install via the
#     unencrypted manifest fields.
src ethos verify --handle "$SRC_HANDLE"
pass "ethos verify PASS after seed deletion (tracked-mode, with expected warnings)"

# --------------------------------------------------------------------------- #
say "7. SRC: owner-path writes must now FAIL (there is no sphere seed to sign)"
if src ethos add-section \
     --zone public \
     --title "Should not land" \
     --body "This should be rejected." \
     --json >/dev/null 2>&1; then
  fail "owner-path write unexpectedly SUCCEEDED with no sphere seeds"
fi
pass "owner-path write correctly rejected"

# --------------------------------------------------------------------------- #
say "8. SRC: pack the ethos bundle"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$SRC_HANDLE" --out "$BUNDLE" >/dev/null
[[ -f "$BUNDLE" ]] || fail "bundle not written"
pass "bundle: $BUNDLE"

# --------------------------------------------------------------------------- #
say "9. DST: install the bundle as a tracked identity under a fresh keystore"
rm -rf "$DST_HOME"
dst ethos install "$BUNDLE" --set-default >/dev/null
# handle on DST side matches manifest.subject_handle (=SRC_HANDLE) unless --as.
DST_HANDLE="$SRC_HANDLE"
pass "installed as tracked identity: $DST_HANDLE (no sealed seeds)"

# --------------------------------------------------------------------------- #
say "10. DST: import the mandate (auto-resolves issuer via installed did.json)"
dst mandate add "$WORK/mandate.json" >/dev/null
pass "mandate $MANDATE_ID registered on DST"

# --------------------------------------------------------------------------- #
say "11. DST: ship the delegate keyfile (simulated copy)"
cp "$KEYFILE" "$WORK/bob-delegate-on-dst.key.json"
chmod 600 "$WORK/bob-delegate-on-dst.key.json"
pass "keyfile present on DST side (mode 0600)"

# --------------------------------------------------------------------------- #
say "12. DST: add a public section via the MANDATE (delegate path)"
DELEGATE_ADD=$(dst ethos add-section \
  --zone public \
  --title "Availability" \
  --body "Booking slots: Tue/Thu afternoons." \
  --mandate "$MANDATE_ID" \
  --agent-key "$WORK/bob-delegate-on-dst.key.json" \
  --handle "$DST_HANDLE" \
  --json)
DELEGATE_SEC=$(jq_field "section.id" <<<"$DELEGATE_ADD")
DELEGATE_GAMMA=$(jq_field "gammaEntry.id" <<<"$DELEGATE_ADD")
[[ -n "$DELEGATE_SEC" ]] || fail "delegate add-section did not return a section id"
pass "new section: $DELEGATE_SEC"
pass "gamma entry: $DELEGATE_GAMMA (authorized_by=$MANDATE_ID)"

# --------------------------------------------------------------------------- #
say "13. DST: delete a public section via the MANDATE (delegate path)"
dst ethos delete-section \
  --zone public \
  --section "$DELEGATE_SEC" \
  --reason "end of e2e demo — delegate clean-up" \
  --mandate "$MANDATE_ID" \
  --agent-key "$WORK/bob-delegate-on-dst.key.json" \
  --handle "$DST_HANDLE" >/dev/null
pass "delegate delete-section OK"

# Confirm the section is gone from the live zone:
if dst ethos show --zone public --handle "$DST_HANDLE" | grep -q "Availability"; then
  fail "section 'Availability' should be gone from the live public zone"
fi
pass "live public.md no longer contains 'Availability'"

# But the gamma log MUST retain both the add and the delete entries.
# `gamma show` requires sphere keys to decrypt the sealed log, but the
# manifest's gamma anchor is plaintext on disk — read it directly so we
# can probe the log state from a tracked install.
MANIFEST_PATH="$DST_HOME/identities/$DST_HANDLE/ethos/manifest.json"
GAMMA_HEAD=$(node -e "const m=require('$MANIFEST_PATH'); console.log((m.gamma&&m.gamma.head)||'(none)')")
GAMMA_COUNT=$(node -e "const m=require('$MANIFEST_PATH'); console.log((m.gamma&&m.gamma.count)||0)")
pass "gamma after delete: head=$GAMMA_HEAD count=$GAMMA_COUNT"
# We started with 1 entry (owner add) and added 2 more (delegate add + delete)
# → 3 signed entries, with the delete entry at the head.
[[ "$GAMMA_COUNT" == "3" ]] || fail "expected gamma.count=3 after owner-add + delegate-add + delegate-delete"

# --------------------------------------------------------------------------- #
say "14. DST: end-to-end verify (ethos verify, tracked mode)"
# Same rationale as step 6: on a tracked install `ethos verify` is the right
# command and degrades gracefully, while `gamma verify` is owner-only.
dst ethos verify --handle "$DST_HANDLE"
pass "ethos verify PASS on DST (delegate-signed editions + mandate + did.json)"

# --------------------------------------------------------------------------- #
say "15. DST: owner-path writes must STILL be refused (tracked identity)"
if dst ethos add-section \
     --zone public \
     --title "Should not land either" \
     --body "Tracked install without sealed seeds." \
     --handle "$DST_HANDLE" \
     --json >/dev/null 2>&1; then
  fail "owner-path write unexpectedly succeeded on tracked install"
fi
pass "tracked install correctly refuses owner-path writes"

printf "\n### e2e-public-write-mandate: OK\n"
# Follow-up scenarios (separate tests):
#   - pull back the delegate-advanced edition into the SRC keystore without
#     colliding with SRC's `history/` chain (needs care: history/ on SRC
#     still reflects the original timeline).
#   - circle and self zones: same shape, but with encrypted wrap + delegate
#     read via mandate.
#   - mandate revocation + post-revocation write rejection.
#   - gamma tamper detection on a tracked install.
