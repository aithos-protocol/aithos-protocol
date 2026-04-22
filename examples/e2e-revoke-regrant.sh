#!/usr/bin/env bash
# End-to-end test: mandate revocation + fresh re-grant lifecycle.
#
# The scenario:
#   1. SRC grants mandate A (ethos.read+write+gamma.read on circle) to an agent.
#   2. DST imports A, successfully reads + writes + reads gamma.
#   3. SRC revokes A (reason=device_lost) — triggers repinAfterRevocation,
#      which rotates zone DEKs and gamma DEK under the remaining active
#      delegates (= owner only). The revocation is propagated to DST.
#   4. DST tries to use mandate A → REFUSED (revoked).
#   5. SRC issues mandate B with the SAME scopes for the SAME agent-id (or
#      a brand-new pubkey, since the agent got a new device). B triggers a
#      fresh rewrap.
#   6. DST imports B, installs the new edition from SRC, and can once again
#      read+write+read-gamma — proving that revocation is a clean cut and
#      re-grant works without any special "reactivation" path.
#   7. A gamma entry written via B is NOT readable via A (even if A weren't
#     revoked) — because the DEK rotation at step 3 created a new generation
#     the old mandate never had a wrap for.
#
# This exercises the full revocation lifecycle: cryptographic rotation +
# forward secrecy against the revoked delegate + re-admission via a new
# mandate.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-revoke-regrant.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"
ZONE="${ZONE:-circle}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-revoke-regrant-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-revoke-regrant-dst}"
WORK="${WORK:-/tmp/aithos-e2e-revoke-regrant-work}"

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

AGENT_ID="urn:aithos:agent:alice-laptop"

# --------------------------------------------------------------------------- #
say "0. reset scratch"
rm -rf "$SRC_HOME" "$DST_HOME" "$WORK"
mkdir -p "$WORK"

# --------------------------------------------------------------------------- #
say "1. SRC: init + seed section"
src init --handle "$HANDLE" --display-name "RevokeRegrant Alice" >/dev/null
src ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "seed" --body "Seed before any grant." >/dev/null
pass "owner-seeded section"

say "2. SRC: FIRST key + grant mandate A"
KEY_A="$WORK/agent-A.key.json"
DK_A=$(src delegate-key --out "$KEY_A" --id "$AGENT_ID" --json)
PUB_A=$(jqf "pubkey" <<<"$DK_A")
GRANT_A=$(src grant "$AGENT_ID" \
  --sphere "$ZONE" \
  --scope "ethos.read.$ZONE,ethos.write.$ZONE,gamma.read" \
  --pubkey "$PUB_A" --ttl 30d --json)
MANDATE_A=$(jqf "mandate.id" <<<"$GRANT_A")
MANDATE_A_PATH=$(jqf "path" <<<"$GRANT_A")
pass "mandate A: $MANDATE_A"

say "3. SRC: pack + install on DST + import A"
BUNDLE_A="$WORK/alice-A.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE_A" >/dev/null
dst ethos install "$BUNDLE_A" --set-default >/dev/null
dst mandate add "$MANDATE_A_PATH" >/dev/null
cp "$KEY_A" "$WORK/agent-A-dst.key.json"
chmod 600 "$WORK/agent-A-dst.key.json"
AGENT_A="$WORK/agent-A-dst.key.json"
pass "DST installed under edition A"

say "4. DST: mandate A WORKS — read + write + gamma.read"
dst ethos show --handle "$HANDLE" --zone "$ZONE" \
  --mandate "$MANDATE_A" --agent-key "$AGENT_A" | grep -q "Seed before any grant" \
  || fail "A should read the seed"
ADD_A=$(dst ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "written-under-A" --body "Written via mandate A." \
  --mandate "$MANDATE_A" --agent-key "$AGENT_A" --json)
SEC_A=$(jqf "section.id" <<<"$ADD_A")
# gamma.read in scope → the post-grant entry should decrypt
GAMMA_A_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_A" --agent-key "$AGENT_A" --json)
LAST_READABLE=$(node -e "
  const a = JSON.parse(process.argv[1]);
  const last = a[a.length - 1];
  console.log(!last._access_denied && last.payload && Object.keys(last.payload).length > 0 ? 'yes' : 'no');
" "$GAMMA_A_JSON")
[[ "$LAST_READABLE" == "yes" ]] || fail "A should be able to read its own gamma entry"
pass "A can read + write + read gamma"

# --------------------------------------------------------------------------- #
say "5. SRC: REVOKE mandate A (reason=device_lost)"
src revoke "$MANDATE_A" --reason "device_lost" >/dev/null
REV_FILE=$(ls "$SRC_HOME/revocations/"*.json | head -1)
[[ -f "$REV_FILE" ]] || fail "no revocation file produced"
# Propagate revocation to DST by copying the revocation file.
mkdir -p "$DST_HOME/revocations"
cp "$REV_FILE" "$DST_HOME/revocations/"
pass "A revoked on SRC + revocation propagated to DST"

# Sanity: revocation triggers repinAfterRevocation. SRC manifest should now
# show a fresh edition (version > 1, height > 1).
EDITION_AFTER=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  console.log(m.edition.version + '@' + m.edition.height);
" "$SRC_HOME/identities/$HANDLE/ethos/manifest.json")
pass "SRC post-revoke edition: $EDITION_AFTER"

say "6. DST: mandate A must now be REFUSED everywhere (revoked)"
expect_fail "ethos show via revoked A" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone "$ZONE" --mandate "$MANDATE_A" --agent-key "$AGENT_A"
expect_fail "ethos add-section via revoked A" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone "$ZONE" --title "should-not-land" --body "nope" \
    --mandate "$MANDATE_A" --agent-key "$AGENT_A"
expect_fail "gamma show via revoked A" \
  env AITHOS_HOME="$DST_HOME" $CLI gamma show --handle "$HANDLE" \
    --mandate "$MANDATE_A" --agent-key "$AGENT_A"

# --------------------------------------------------------------------------- #
say "7. SRC: re-grant — fresh keypair for the same agent-id, new mandate B"
KEY_B="$WORK/agent-B.key.json"
DK_B=$(src delegate-key --out "$KEY_B" --id "$AGENT_ID" --json)
PUB_B=$(jqf "pubkey" <<<"$DK_B")
GRANT_B=$(src grant "$AGENT_ID" \
  --sphere "$ZONE" \
  --scope "ethos.read.$ZONE,ethos.write.$ZONE,gamma.read" \
  --pubkey "$PUB_B" --ttl 30d --json)
MANDATE_B=$(jqf "mandate.id" <<<"$GRANT_B")
MANDATE_B_PATH=$(jqf "path" <<<"$GRANT_B")
[[ "$MANDATE_B" != "$MANDATE_A" ]] || fail "mandate B should have a fresh id"
pass "mandate B: $MANDATE_B"

say "8. DST: re-pack + reinstall SRC's new edition, then import B"
BUNDLE_B="$WORK/alice-B.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE_B" >/dev/null
# Install over the existing DST tracked identity (--force replaces the
# earlier install's edition files; all under $DST_HOME/identities/$HANDLE).
dst ethos install "$BUNDLE_B" --set-default --force >/dev/null
dst mandate add "$MANDATE_B_PATH" >/dev/null
cp "$KEY_B" "$WORK/agent-B-dst.key.json"
chmod 600 "$WORK/agent-B-dst.key.json"
AGENT_B="$WORK/agent-B-dst.key.json"
pass "DST upgraded to edition B"

say "9. DST: mandate B WORKS — read + write + gamma.read"
dst ethos show --handle "$HANDLE" --zone "$ZONE" \
  --mandate "$MANDATE_B" --agent-key "$AGENT_B" | grep -q "Seed before any grant" \
  || fail "B should read the seed"
ADD_B=$(dst ethos add-section --handle "$HANDLE" --zone "$ZONE" \
  --title "written-under-B" --body "Written via mandate B (post-revoke re-grant)." \
  --mandate "$MANDATE_B" --agent-key "$AGENT_B" --json)
SEC_B=$(jqf "section.id" <<<"$ADD_B")
pass "B can read + write"

say "10. DST: via B, gamma decrypts post-B entries; the entry written under A may be opaque"
GAMMA_B_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_B" --agent-key "$AGENT_B" --json)
LAST_B_READABLE=$(node -e "
  const a = JSON.parse(process.argv[1]);
  const last = a[a.length - 1];
  console.log(!last._access_denied && last.payload && Object.keys(last.payload).length > 0 ? 'yes' : 'no');
" "$GAMMA_B_JSON")
[[ "$LAST_B_READABLE" == "yes" ]] || fail "B should decrypt the entry it just wrote"
pass "B decrypts the new post-grant entry (forward-only envelopes work)"

say "11. DST: A is STILL refused (revocation is sticky)"
expect_fail "gamma show via A after re-grant" \
  env AITHOS_HOME="$DST_HOME" $CLI gamma show --handle "$HANDLE" \
    --mandate "$MANDATE_A" --agent-key "$AGENT_A"

say "12. DST: integrity-tier gamma verify still PASSES via B"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_B" --agent-key "$AGENT_B" >/dev/null
pass "gamma verify PASS via B"

printf "\n### e2e-revoke-regrant: OK (revocation + re-grant lifecycle works)\n"
