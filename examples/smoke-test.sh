#!/usr/bin/env bash
# End-to-end smoke test for the aithos CLI (v0.2.0).
#
# Covers the happy path (init → ethos init → add-section × 3 →
# modify-section → verify → pack/unpack) and the unhappy path (tamper with
# the live public.md → verify fails).
#
# In v0.2.0 there is no per-section revisions[] anymore: every mutation is a
# signed entry in the gamma log, and the manifest's gamma anchor commits to
# the log's current tail. Tampering with either the live doc or the log tail
# must make `ethos verify` fail.
#
# Run from the repo root after building the CLI.
#
# Usage:
#   AITHOS_HOME=/tmp/aithos-smoke bash examples/smoke-test.sh

set -euo pipefail

AITHOS_HOME="${AITHOS_HOME:-/tmp/aithos-smoke}"
CLI="${CLI:-node $(pwd)/packages/cli/dist/index.js}"
HANDLE="${HANDLE:-alice}"

export AITHOS_HOME

echo "### Reset $AITHOS_HOME"
rm -rf "$AITHOS_HOME"

echo
echo "### 1. init identity (also initializes the ethos layout)"
$CLI init --handle "$HANDLE" --display-name "Alice Test"

echo
echo "### 2. verify empty ethos (gamma anchor absent, count=0)"
$CLI ethos verify

echo
echo "### 4. add sections across all zones (each emits a signed gamma entry)"
$CLI ethos add-section --zone public --title "Voice" --body "I write in short paragraphs." --tags voice,style
$CLI ethos add-section --zone circle --title "Day rate" --body "EUR 900/day for strategy, EUR 1200 for hands-on build."
$CLI ethos add-section --zone self --title "Morning routine" --body "No email before 10am. Coffee first, always."

echo
echo "### 5. verify after additions (gamma.count should be 3, head pinned)"
$CLI ethos verify

echo
echo "### 6. list sections (each row shows gamma_ref + updated_at)"
$CLI ethos list

echo
echo "### 7. modify the public 'Voice' section (full new body recorded in one signed gamma entry)"
PUBLIC_SEC=$($CLI ethos list --zone public --json | grep -o '"id": "sec_[^"]*' | head -1 | sed 's/.*"sec_/sec_/')
echo "  section: $PUBLIC_SEC"
sleep 1  # ensure strictly greater 'at'
$CLI ethos modify-section --zone public --section "$PUBLIC_SEC" \
  --body "I prefer short paragraphs for casual writing. For long-form subjects I'll write prose."

echo
echo "### 8. verify after modification"
$CLI ethos verify

echo
echo "### 9. show the live Voice section (current body only; history lives in gamma log)"
$CLI ethos show --zone public --section "$PUBLIC_SEC"

echo
echo "### 10. gamma show — walk the signed mutation history"
$CLI gamma show

echo
echo "### 11. gamma verify — full chain + signature walk"
$CLI gamma verify

echo
echo "### 12. tamper with the live public.md (should make verify fail)"
PUBLIC_MD="$AITHOS_HOME/identities/$HANDLE/ethos/public/public.md"
cp "$PUBLIC_MD" "$PUBLIC_MD.bak"
sed -i 's/I prefer short paragraphs/I prefer LONG paragraphs/' "$PUBLIC_MD"

echo
echo "### 13. verify tampered (expected: FAILED — zone hash or signature mismatch)"
if $CLI ethos verify; then
  echo "ERROR: verify should have failed on a tampered live zone!"
  exit 1
fi

echo
echo "### 14. restore and re-verify"
mv "$PUBLIC_MD.bak" "$PUBLIC_MD"
$CLI ethos verify

echo
echo "### 15. pack the bundle"
$CLI ethos pack --out /tmp/alice.ethos

echo
echo "### 16. unpack and inspect (should include gamma.jsonl.enc)"
rm -rf /tmp/alice-unpacked
$CLI ethos unpack /tmp/alice.ethos --out /tmp/alice-unpacked
ls -la /tmp/alice-unpacked/

echo
echo "### smoke-test: OK"
