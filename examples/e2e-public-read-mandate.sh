#!/usr/bin/env bash
# End-to-end test: `ethos.read.public` ONLY mandate — degenerate but valid.
#
# The public zone is plaintext on disk. Reading it never needs a mandate:
# anyone with the installed bundle can read it.
#
# So what does `ethos.read.public` actually grant? In v0.3:
#   - The grant goes through issueMandateWithRewrap (touchesEthos is true).
#   - There's no public zone DEK to rewrap (public is clear), so the only
#     practical effect is bumping a new edition + recording the mandate.
#   - CRITICALLY, the delegate is NOT added to `manifest.gamma.readers`
#     (no gamma.read in scope) — the v0.3 decoupling holds even for
#     clear-text zones.
#
# Expected behavior:
#   - The CLI REJECTS `ethos show --zone public --mandate X` with a clear
#     message ("--mandate is only meaningful for encrypted zones") — because
#     public is plaintext, the mandate adds nothing and the CLI refuses the
#     ambiguous form. The delegate can just read public directly without
#     the mandate flags.
#   - Writes anywhere: REFUSED (no ethos.write.*).
#   - Gamma: every entry `_access_denied` (no gamma.read).
#
# Bottom line: `ethos.read.public` is a no-op mandate in terms of effective
# capabilities. The test pins that this edge case does not accidentally
# grant gamma access or leak writes.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/e2e-public-read-mandate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

HANDLE="${HANDLE:-alice}"

SRC_HOME="${SRC_HOME:-/tmp/aithos-e2e-pub-read-src}"
DST_HOME="${DST_HOME:-/tmp/aithos-e2e-pub-read-dst}"
WORK="${WORK:-/tmp/aithos-e2e-pub-read-work}"

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

say "1. SRC: init + add a public section"
src init --handle "$HANDLE" --display-name "PubRead Alice" >/dev/null
src ethos add-section --handle "$HANDLE" --zone public \
  --title "bio" --body "I work in short paragraphs." --tags voice,style >/dev/null
pass "public section added"

say "2. SRC: delegate keypair"
KEY="$WORK/agent.key.json"
DK=$(src delegate-key --out "$KEY" --id "urn:aithos:agent:pub-reader" --json)
PUB=$(jqf "pubkey" <<<"$DK")

say "3. SRC: grant PUBLIC-READ mandate (scope=ethos.read.public)"
GRANT=$(src grant "urn:aithos:agent:pub-reader" \
  --sphere public --scope "ethos.read.public" \
  --pubkey "$PUB" --ttl 30d --json)
MANDATE_ID=$(jqf "mandate.id" <<<"$GRANT")
MANDATE_PATH=$(jqf "path" <<<"$GRANT")
# rewrapped=true is fine — issueMandateWithRewrap always runs for touchesEthos;
# there's just no DEK to rewrap on the public zone.
pass "mandate: $MANDATE_ID (rewrapped=$(jqf 'rewrapped' <<<"$GRANT"))"

# v0.3 assertion — even a public-read mandate does NOT join gamma.readers.
MANIFEST="$SRC_HOME/identities/$HANDLE/ethos/manifest.json"
RECIPIENT="urn:aithos:agent:pub-reader#$PUB"
IN_GAMMA=$(node -e "
  const m = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  const readers = (m.gamma && m.gamma.readers) || [];
  console.log(readers.some(r => r.recipient === process.argv[2]) ? 'yes' : 'no');
" "$MANIFEST" "$RECIPIENT")
[[ "$IN_GAMMA" == "no" ]] \
  || fail "public-read delegate must NOT be on manifest.gamma.readers"
pass "delegate is NOT on manifest.gamma.readers (no gamma.read scope)"

say "4. SRC: pack + install tracked on DST"
BUNDLE="$WORK/alice.ethos"
src ethos pack --handle "$HANDLE" --out "$BUNDLE" >/dev/null
dst ethos install "$BUNDLE" --set-default >/dev/null
dst mandate add "$MANDATE_PATH" >/dev/null
cp "$KEY" "$WORK/agent-dst.key.json"
chmod 600 "$WORK/agent-dst.key.json"
AGENT="$WORK/agent-dst.key.json"
pass "DST ready"

# --------------------------------------------------------------------------- #
say "5. DST: ethos show --zone public WITHOUT --mandate → OK (plaintext, no auth)"
dst ethos show --handle "$HANDLE" --zone public | grep -q "I work in short paragraphs" \
  || fail "public zone should be readable without mandate"
pass "public zone readable without mandate (as it should be)"

say "6. DST: ethos show --zone public WITH --mandate → REJECTED (ambiguous)"
# The CLI explicitly refuses --mandate for public zones.
expect_fail "ethos show --zone public --mandate X (ambiguous form)" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos show --handle "$HANDLE" \
    --zone public --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "7. DST: writes must be REFUSED (no ethos.write.*)"
expect_fail "ethos add-section via public-read mandate" \
  env AITHOS_HOME="$DST_HOME" $CLI ethos add-section --handle "$HANDLE" \
    --zone public --title "nope" --body "nope" \
    --mandate "$MANDATE_ID" --agent-key "$AGENT"

say "8. DST: gamma entries must all come back _access_denied"
GAMMA_JSON=$(dst gamma show --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" --json)
TOTAL=$(node -e "console.log(JSON.parse(process.argv[1]).length)" "$GAMMA_JSON")
DENIED=$(node -e "
  const a = JSON.parse(process.argv[1]);
  console.log(a.filter(e => e._access_denied === true).length);
" "$GAMMA_JSON")
[[ "$TOTAL" -ge 1 ]] || fail "expected at least 1 gamma entry"
[[ "$DENIED" == "$TOTAL" ]] \
  || fail "expected all $TOTAL gamma entries _access_denied, got $DENIED"
pass "all $TOTAL gamma entries are _access_denied (public-read ≠ gamma-read)"

say "9. DST: gamma verify PASSES (integrity tier)"
dst gamma verify --handle "$HANDLE" \
  --mandate "$MANDATE_ID" --agent-key "$AGENT" >/dev/null
pass "gamma verify PASS"

printf "\n### e2e-public-read-mandate: OK (degenerate case pinned)\n"
