#!/usr/bin/env bash
# End-to-end gamma walkthrough — reproduces the worked example from
# `spec/drafts/gamma-deep-memory.md §D.7` via the real CLI.
#
# The scenario:
#   1. init a fresh identity,
#   2. add a section to the `self` zone,
#   3. observe that the live ethos AND the gamma log both show it,
#   4. delete the section with a free-text reason,
#   5. observe that the live ethos forgot it but the gamma log retains BOTH
#      the original `section.add` entry AND a new signed `section.delete`,
#   6. tamper with the encrypted gamma log and watch `gamma verify` fail,
#   7. restore and re-verify.
#
# Run from the repo root after `npm run build`:
#
#   bash examples/gamma-smoke-test.sh
#
# Uses a scratch AITHOS_HOME under /tmp by default so it never touches
# your real keystore.

set -euo pipefail

AITHOS_HOME="${AITHOS_HOME:-/tmp/aithos-gamma-smoke}"
CLI="${CLI:-node $(pwd)/packages/cli/dist/index.js}"
HANDLE="${HANDLE:-mathieu}"

export AITHOS_HOME

say() { printf "\n### %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

say "Reset $AITHOS_HOME"
rm -rf "$AITHOS_HOME"

say "1. init identity (creates the ethos layout too)"
$CLI init --handle "$HANDLE" --display-name "Mathieu Colla" >/dev/null

say "2. gamma show --head on an empty identity"
# Nothing has been written yet — expect a '(none)' head and count=0.
HEAD_OUT=$($CLI gamma show --handle "$HANDLE" --head)
echo "  $HEAD_OUT"
[[ "$HEAD_OUT" == *"(none)"* ]] || fail "expected '(none)' head on fresh identity"
[[ "$HEAD_OUT" == *"count=0"* ]] || fail "expected count=0 on fresh identity"

say "3. add a section to the self zone"
ADD_OUT=$($CLI ethos add-section --handle "$HANDLE" \
  --zone self \
  --title "Testnet wallet" \
  --body "seed: apple pie refrigerator …" \
  --json)
SEC=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.section.id)" <<< "$ADD_OUT")
ADD_GAMMA_ID=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.gammaEntry.id)" <<< "$ADD_OUT")
ADD_HEAD=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.manifest.gamma.head)" <<< "$ADD_OUT")
echo "  section:    $SEC"
echo "  gamma:      $ADD_GAMMA_ID"
echo "  head:       $ADD_HEAD"

say "4. section is present in the live self zone"
$CLI ethos list --handle "$HANDLE" --zone self
$CLI ethos show --handle "$HANDLE" --zone self --section "$SEC"

say "5. gamma log shows the add (count=1, head matches manifest)"
$CLI gamma show --handle "$HANDLE"

say "6. gamma verify — should PASS"
$CLI gamma verify --handle "$HANDLE"

say "7. ethos verify — should PASS (manifest now commits to gamma head)"
$CLI ethos verify --handle "$HANDLE"

say "8. delete the section with reason 'moved offline'"
DEL_OUT=$($CLI ethos delete-section --handle "$HANDLE" \
  --zone self \
  --section "$SEC" \
  --reason "moved offline" \
  --json)
DEL_GAMMA_ID=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.gammaEntry.id)" <<< "$DEL_OUT")
DEL_HEAD=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.manifest.gamma.head)" <<< "$DEL_OUT")
DEL_PREV=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.gammaEntry.prev_gamma_hash)" <<< "$DEL_OUT")
DEL_PREV_SEC=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.gammaEntry.prev_section_gamma)" <<< "$DEL_OUT")
echo "  gamma:             $DEL_GAMMA_ID"
echo "  head:              $DEL_HEAD"
echo "  prev_gamma_hash:   $DEL_PREV"
echo "  prev_section_gamma: $DEL_PREV_SEC"
[[ "$DEL_PREV" == "$ADD_HEAD" ]] || fail "delete.prev_gamma_hash should equal add head"
[[ "$DEL_PREV_SEC" == "$ADD_GAMMA_ID" ]] || fail "delete.prev_section_gamma should equal add entry id"

say "9. self zone is now empty in the live ethos"
LIST_OUT=$($CLI ethos list --handle "$HANDLE" --zone self --json)
SELF_COUNT=$(node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log((d.zones?.self ?? d.self ?? d).length ?? 0)" <<< "$LIST_OUT" 2>/dev/null || echo "?")
echo "  self.sections.length = $SELF_COUNT (expected 0)"
# Also confirm textually — show the zone and check for the section title.
if $CLI ethos show --handle "$HANDLE" --zone self | grep -q "Testnet wallet"; then
  fail "self zone should no longer contain 'Testnet wallet'"
fi

say "10. gamma log now holds BOTH entries (count=2)"
$CLI gamma show --handle "$HANDLE"
GLOB_HEAD=$($CLI gamma show --handle "$HANDLE" --head)
echo "  $GLOB_HEAD"
[[ "$GLOB_HEAD" == *"count=2"* ]] || fail "expected count=2 after delete"

say "11. per-section filter surfaces both entries"
$CLI gamma show --handle "$HANDLE" --section "$SEC"

say "12. gamma show --id on the delete entry"
$CLI gamma show --handle "$HANDLE" --id "$DEL_GAMMA_ID"

say "13. gamma verify — should still PASS"
$CLI gamma verify --handle "$HANDLE"

say "14. ethos verify — should still PASS"
$CLI ethos verify --handle "$HANDLE"

say "15. tamper with the encrypted gamma log"
GAMMA_FILE="$AITHOS_HOME/identities/$HANDLE/ethos/gamma/gamma.jsonl.enc"
[[ -f "$GAMMA_FILE" ]] || fail "expected $GAMMA_FILE to exist"
cp "$GAMMA_FILE" "$GAMMA_FILE.bak"
# v0.3: the file is a JSON envelope { 'aithos-gamma-file': '0.3.0', entries: [...] }
# where each entry carries its own payload_ct. Corrupt the first entry's
# ciphertext — any entry works; we just need one byte flip to break the
# XChaCha20-Poly1305 tag AND the per-entry hash commitment.
node -e "
const fs = require('fs');
const p = process.argv[1];
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
if (!Array.isArray(j.entries) || j.entries.length === 0) {
  throw new Error('expected v0.3 gamma file with non-empty entries[]');
}
const e = j.entries[0];
const ct = e.payload_ct;
// Flip one char near the middle of the ciphertext (still a valid base64url
// char, just wrong — will fail the entry hash check BEFORE we even get to
// the AEAD tag).
const mid = Math.floor(ct.length / 2);
const flipped = ct.slice(0, mid) + (ct[mid] === 'A' ? 'B' : 'A') + ct.slice(mid + 1);
e.payload_ct = flipped;
fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
" "$GAMMA_FILE"

say "16. gamma verify on the tampered log — should FAIL"
if $CLI gamma verify --handle "$HANDLE" 2>&1; then
  mv "$GAMMA_FILE.bak" "$GAMMA_FILE"
  fail "gamma verify should have failed on a tampered log!"
fi

say "17. restore and re-verify — should PASS again"
mv "$GAMMA_FILE.bak" "$GAMMA_FILE"
$CLI gamma verify --handle "$HANDLE"
$CLI ethos verify --handle "$HANDLE"

printf "\n### gamma-smoke-test: OK\n"
