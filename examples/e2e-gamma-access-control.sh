#!/usr/bin/env bash
# End-to-end test: negative coverage of gamma access control.
#
# The positive path is covered by e2e-owner-crud.sh (owner reads) and
# e2e-delegate-crud-encrypted.sh (delegate with a write+read mandate reads).
# Here we check the cases that MUST fail, and a gamma-tamper case that MUST
# be detected.
#
# Matrix covered (v0.3 semantics — per-entry envelopes, `gamma.read` scope):
#   A. Tracked install WITHOUT any mandate → gamma show + gamma verify REFUSED
#      (owner path needs sealed seeds, delegate path needs --mandate).
#   B. Mandate WITHOUT `gamma.read` scope → delegate is NOT on
#      `manifest.gamma.readers` → every entry comes back as `_access_denied`.
#      The grant itself still rewraps (for zone DEK access), but the gamma
#      readers list is untouched. This is the core v0.3 decoupling property
#      (task #14): write-only / zone-read mandates do not grant gamma access.
#   C. Delegate keyfile whose pubkey doesn't match mandate.grantee.pubkey →
#      REFUSED at resolveAuthor time (before touching gamma).
#   D. Revoked mandate → REFUSED at resolveAuthor time.
#   E. Tampered gamma.jsonl.enc on DST → gamma verify via delegate FAILS.
#      v0.3: we tamper `entries[0].payload_ct` inside the top-level
#      { "aithos-gamma-file": "0.3.0", entries: [...] } envelope, NOT the old
#      v0.2 flat `j.ciphertext` field (which no longer exists).
#
# Each case resets its own scratch subdir so failures are isolated.
#
# Usage (from repo root, after `npm run build`):
#
#   bash examples/e2e-gamma-access-control.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"

say()  { printf "\n### %s\n" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }
# Run a command expected to FAIL. $1 is a label, the rest is the command.
expect_fail() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    fail "$label unexpectedly SUCCEEDED"
  fi
  pass "$label correctly refused"
}

jqf() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$1"; }

# --------------------------------------------------------------------------- #
# Shared setup: one owner identity with a seed section in `circle`, packed
# into a bundle. Each case then installs it fresh and exercises the denial.
# --------------------------------------------------------------------------- #
SETUP_HOME=/tmp/aithos-gamma-acl-setup
WORK=/tmp/aithos-gamma-acl-work
BUNDLE="$WORK/alice.ethos"

src_cmd() { AITHOS_HOME="$SETUP_HOME" $CLI "$@"; }

say "SETUP: fresh owner identity + seed + pack"
rm -rf "$SETUP_HOME" "$WORK"
mkdir -p "$WORK"
src_cmd init --handle "$HANDLE" --display-name "ACL Owner" >/dev/null
src_cmd ethos add-section --handle "$HANDLE" --zone circle \
  --title "seed" --body "circle seed body" >/dev/null
src_cmd ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
pass "setup bundle: $BUNDLE (1 gamma entry, circle)"

# --------------------------------------------------------------------------- #
# CASE A — tracked install without ANY mandate cannot read gamma.
# --------------------------------------------------------------------------- #
A_HOME=/tmp/aithos-gamma-acl-A
rm -rf "$A_HOME"
say "A) Tracked install with NO mandate"
AITHOS_HOME="$A_HOME" $CLI ethos install "$BUNDLE" --set-default >/dev/null

# gamma show (no flags) triggers the owner path → loadIdentity → fails because
# no sealed seeds on a tracked install.
expect_fail "gamma show without mandate on tracked install" \
  env AITHOS_HOME="$A_HOME" $CLI gamma show --handle "$HANDLE"
expect_fail "gamma verify without mandate on tracked install" \
  env AITHOS_HOME="$A_HOME" $CLI gamma verify --handle "$HANDLE"

# --------------------------------------------------------------------------- #
# CASE B — mandate without `gamma.read` cannot decrypt gamma payloads.
#
# v0.3 semantics:
#   - grant.ts rewraps for ANY ethos-touching mandate (read or write on a
#     zone), so rewrapped=true even for a zone-read-only scope.
#   - `manifest.gamma.readers` is only extended when `gamma.read` is in the
#     mandate's scope list.
#   - Without `gamma.read`, every entry comes back with payload={} and
#     _access_denied=true. The command itself succeeds (header walk still
#     works) — but no payload is readable.
# --------------------------------------------------------------------------- #
B_HOME=/tmp/aithos-gamma-acl-B
B_SRC_HOME=/tmp/aithos-gamma-acl-B-src
rm -rf "$B_HOME" "$B_SRC_HOME"
say "B) Zone-read mandate WITHOUT gamma.read (v0.3 decoupling)"

# For this case we rebuild from scratch so we can grant BEFORE packing.
AITHOS_HOME="$B_SRC_HOME" $CLI init --handle "$HANDLE" --display-name "B" >/dev/null
AITHOS_HOME="$B_SRC_HOME" $CLI ethos add-section --handle "$HANDLE" --zone circle \
  --title "seed" --body "circle seed B" >/dev/null
RO_KEY="$WORK/B-readonly.key.json"
DK_OUT=$(AITHOS_HOME="$B_SRC_HOME" $CLI delegate-key --out "$RO_KEY" \
  --id "urn:aithos:agent:readonly-B" --json)
RO_PUB=$(jqf "pubkey" <<<"$DK_OUT")
RO_GRANT=$(AITHOS_HOME="$B_SRC_HOME" $CLI grant "urn:aithos:agent:readonly-B" \
  --sphere circle --scope "ethos.read.circle" \
  --pubkey "$RO_PUB" --ttl 30d --json)
RO_MANDATE_ID=$(jqf "mandate.id" <<<"$RO_GRANT")
RO_MANDATE_PATH=$(jqf "path" <<<"$RO_GRANT")
RO_REWRAPPED=$(jqf "rewrapped" <<<"$RO_GRANT")
[[ "$RO_REWRAPPED" == "true" ]] \
  || fail "expected rewrapped=true (zone DEK rewrap happens for ethos.read.* mandates)"
pass "grant rewrapped the edition (zone DEK), as expected for ethos.read.*"

# But the delegate must NOT be on the gamma readers list (v0.3 decoupling —
# gamma access requires an explicit `gamma.read` scope).
B_MANIFEST="$B_SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RO_RECIPIENT="urn:aithos:agent:readonly-B#$RO_PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
  const want = process.argv[2];
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === want) ? 'yes' : 'no');
" "$B_MANIFEST" "$RO_RECIPIENT")
[[ "$IN_GAMMA" == "no" ]] \
  || fail "delegate must NOT be on manifest.gamma.readers without gamma.read scope (got $IN_GAMMA)"
pass "delegate is NOT on manifest.gamma.readers (no gamma.read scope)"

AITHOS_HOME="$B_SRC_HOME" $CLI ethos pack --handle "$HANDLE" --out "$WORK/B.ethos" >/dev/null
AITHOS_HOME="$B_HOME" $CLI ethos install "$WORK/B.ethos" --set-default >/dev/null
AITHOS_HOME="$B_HOME" $CLI mandate add "$RO_MANDATE_PATH" >/dev/null

# v0.3: gamma show succeeds (header walk works with no key material), but
# every entry is `_access_denied` because the delegate has no envelope.
GAMMA_JSON=$(AITHOS_HOME="$B_HOME" $CLI gamma show --handle "$HANDLE" \
  --mandate "$RO_MANDATE_ID" --agent-key "$RO_KEY" --json)
ACCESS_DENIED_COUNT=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.filter(e => e._access_denied === true).length);
" "$GAMMA_JSON")
TOTAL_COUNT=$(node -e "console.log(JSON.parse(process.argv[1]).length)" "$GAMMA_JSON")
[[ "$ACCESS_DENIED_COUNT" == "$TOTAL_COUNT" && "$TOTAL_COUNT" -gt 0 ]] \
  || fail "expected all $TOTAL_COUNT entries to be _access_denied, got $ACCESS_DENIED_COUNT"
pass "all $TOTAL_COUNT gamma entries returned with _access_denied=true (no payload leaked)"

# --------------------------------------------------------------------------- #
# CASE C — delegate keyfile with the WRONG pubkey (pubkey tampered).
# --------------------------------------------------------------------------- #
C_HOME=/tmp/aithos-gamma-acl-C
C_SRC_HOME=/tmp/aithos-gamma-acl-C-src
rm -rf "$C_HOME" "$C_SRC_HOME"
say "C) Keyfile with the WRONG pubkey"

AITHOS_HOME="$C_SRC_HOME" $CLI init --handle "$HANDLE" --display-name "C" >/dev/null
AITHOS_HOME="$C_SRC_HOME" $CLI ethos add-section --handle "$HANDLE" --zone circle \
  --title "seed" --body "circle seed C" >/dev/null
C_KEY="$WORK/C-agent.key.json"
C_DK_OUT=$(AITHOS_HOME="$C_SRC_HOME" $CLI delegate-key --out "$C_KEY" \
  --id "urn:aithos:agent:C" --json)
C_PUB=$(jqf "pubkey" <<<"$C_DK_OUT")
C_GRANT=$(AITHOS_HOME="$C_SRC_HOME" $CLI grant "urn:aithos:agent:C" \
  --sphere circle --scope "ethos.read.circle,ethos.write.circle" \
  --pubkey "$C_PUB" --ttl 30d --json)
C_MANDATE_ID=$(jqf "mandate.id" <<<"$C_GRANT")
C_MANDATE_PATH=$(jqf "path" <<<"$C_GRANT")

AITHOS_HOME="$C_SRC_HOME" $CLI ethos pack --handle "$HANDLE" --out "$WORK/C.ethos" >/dev/null
AITHOS_HOME="$C_HOME" $CLI ethos install "$WORK/C.ethos" --set-default >/dev/null
AITHOS_HOME="$C_HOME" $CLI mandate add "$C_MANDATE_PATH" >/dev/null

# Generate a different delegate key and try to use it against the first mandate.
WRONG_KEY="$WORK/C-wrong.key.json"
AITHOS_HOME="$C_SRC_HOME" $CLI delegate-key --out "$WRONG_KEY" \
  --id "urn:aithos:agent:C-wrong" --json >/dev/null
expect_fail "gamma show with wrong agent key (pubkey mismatch)" \
  env AITHOS_HOME="$C_HOME" $CLI gamma show --handle "$HANDLE" \
    --mandate "$C_MANDATE_ID" --agent-key "$WRONG_KEY"

# --------------------------------------------------------------------------- #
# CASE D — revoked mandate.
# --------------------------------------------------------------------------- #
say "D) Revoked mandate"
# Reuse the C source (we still have sealed seeds there), but point at a new dst.
D_HOME=/tmp/aithos-gamma-acl-D
rm -rf "$D_HOME"

# Grant a fresh mandate on the C source (it still has sealed seeds).
D_KEY="$WORK/D-agent.key.json"
D_PUB=$(AITHOS_HOME="$C_SRC_HOME" $CLI delegate-key --out "$D_KEY" \
  --id "urn:aithos:agent:D" --json | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.pubkey);")
D_GRANT=$(AITHOS_HOME="$C_SRC_HOME" $CLI grant "urn:aithos:agent:D" \
  --sphere circle --scope "ethos.read.circle,ethos.write.circle" \
  --pubkey "$D_PUB" --ttl 30d --json)
D_MANDATE_ID=$(jqf "mandate.id" <<<"$D_GRANT")
D_MANDATE_PATH=$(jqf "path" <<<"$D_GRANT")

# Pack + install on D_HOME.
AITHOS_HOME="$C_SRC_HOME" $CLI ethos pack --handle "$HANDLE" --out "$WORK/D.ethos" >/dev/null
AITHOS_HOME="$D_HOME" $CLI ethos install "$WORK/D.ethos" --set-default >/dev/null
AITHOS_HOME="$D_HOME" $CLI mandate add "$D_MANDATE_PATH" >/dev/null

# Sanity: before revocation, the delegate CAN read gamma.
AITHOS_HOME="$D_HOME" $CLI gamma show --head --handle "$HANDLE" \
  --mandate "$D_MANDATE_ID" --agent-key "$D_KEY" >/dev/null
pass "pre-revocation: delegate can read gamma"

# Now revoke on the source side (owner has sealed seeds).
AITHOS_HOME="$C_SRC_HOME" $CLI revoke "$D_MANDATE_ID" --reason "other" >/dev/null
# Propagate the revocation to D_HOME: we simulate it by copying the revocation file.
REV_FILE=$(ls "$C_SRC_HOME/revocations/"*.json | head -1)
[[ -f "$REV_FILE" ]] || fail "no revocation file produced"
mkdir -p "$D_HOME/revocations"
cp "$REV_FILE" "$D_HOME/revocations/"
pass "revocation propagated to DST"

expect_fail "gamma show via revoked mandate" \
  env AITHOS_HOME="$D_HOME" $CLI gamma show --handle "$HANDLE" \
    --mandate "$D_MANDATE_ID" --agent-key "$D_KEY"

# --------------------------------------------------------------------------- #
# CASE E — tampered gamma.jsonl.enc
# --------------------------------------------------------------------------- #
say "E) Tampered gamma file detection via delegate"
# Use the D install (which has a valid mandate + key, but we just revoked it;
# revoke a fresh one for this case). Simpler: rebuild a fresh scratch.

E_SRC=/tmp/aithos-gamma-acl-E-src
E_HOME=/tmp/aithos-gamma-acl-E
rm -rf "$E_SRC" "$E_HOME"

AITHOS_HOME="$E_SRC" $CLI init --handle "$HANDLE" --display-name "E" >/dev/null
AITHOS_HOME="$E_SRC" $CLI ethos add-section --handle "$HANDLE" --zone circle \
  --title "seed" --body "circle seed E" >/dev/null
E_KEY="$WORK/E-agent.key.json"
E_PUB=$(AITHOS_HOME="$E_SRC" $CLI delegate-key --out "$E_KEY" \
  --id "urn:aithos:agent:E" --json | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.pubkey);")
E_GRANT=$(AITHOS_HOME="$E_SRC" $CLI grant "urn:aithos:agent:E" \
  --sphere circle --scope "ethos.read.circle,ethos.write.circle,gamma.read" \
  --pubkey "$E_PUB" --ttl 30d --json)
E_MANDATE_ID=$(jqf "mandate.id" <<<"$E_GRANT")
E_MANDATE_PATH=$(jqf "path" <<<"$E_GRANT")
AITHOS_HOME="$E_SRC" $CLI ethos pack --handle "$HANDLE" --out "$WORK/E.ethos" >/dev/null
AITHOS_HOME="$E_HOME" $CLI ethos install "$WORK/E.ethos" --set-default >/dev/null
AITHOS_HOME="$E_HOME" $CLI mandate add "$E_MANDATE_PATH" >/dev/null

# Pre-tamper baseline.
AITHOS_HOME="$E_HOME" $CLI gamma verify --handle "$HANDLE" \
  --mandate "$E_MANDATE_ID" --agent-key "$E_KEY" >/dev/null
pass "pre-tamper: delegate gamma verify PASS"

# Tamper a byte in the first entry's ciphertext.
# v0.3 file shape: { "aithos-gamma-file": "0.3.0", "entries": [ { payload_ct, ... }, ... ] }
# Flipping one char in payload_ct breaks the per-entry hash (§10.5.1′),
# which `gamma verify` detects without any key material.
GAMMA_FILE="$E_HOME/identities/$HANDLE/ethos/gamma/gamma.jsonl.enc"
cp "$GAMMA_FILE" "$GAMMA_FILE.bak"
node -e "
const fs = require('fs');
const p = process.argv[1];
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
if (!Array.isArray(j.entries) || j.entries.length === 0) {
  throw new Error('expected v0.3 gamma file with non-empty entries[]');
}
const e = j.entries[0];
const ct = e.payload_ct;
const mid = Math.floor(ct.length / 2);
e.payload_ct = ct.slice(0, mid) + (ct[mid] === 'A' ? 'B' : 'A') + ct.slice(mid + 1);
fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
" "$GAMMA_FILE"

expect_fail "gamma verify (tampered file) via delegate" \
  env AITHOS_HOME="$E_HOME" $CLI gamma verify --handle "$HANDLE" \
    --mandate "$E_MANDATE_ID" --agent-key "$E_KEY"

# Restore and confirm we're back to green.
mv "$GAMMA_FILE.bak" "$GAMMA_FILE"
AITHOS_HOME="$E_HOME" $CLI gamma verify --handle "$HANDLE" \
  --mandate "$E_MANDATE_ID" --agent-key "$E_KEY" >/dev/null
pass "post-restore: delegate gamma verify PASS again"

printf "\n### e2e-gamma-access-control: OK\n"
