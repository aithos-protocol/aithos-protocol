#!/usr/bin/env bash
# End-to-end smoke test for the aithos CLI.
#
# Covers the happy path (init → ethos init → add-section × 3 → add-revision →
# verify) and the unhappy path (tamper with a past revision → verify fails).
#
# Run from the repo root after `cd cli && npm run build`.
#
# Usage:
#   AITHOS_HOME=/tmp/aithos-smoke bash examples/smoke-test.sh

set -euo pipefail

AITHOS_HOME="${AITHOS_HOME:-/tmp/aithos-smoke}"
CLI="${CLI:-node $(pwd)/cli/dist/index.js}"
HANDLE="${HANDLE:-alice}"

export AITHOS_HOME

echo "### Reset $AITHOS_HOME"
rm -rf "$AITHOS_HOME"

echo
echo "### 1. init identity"
$CLI init --handle "$HANDLE" --display-name "Alice Test"

echo
echo "### 2. ethos init"
$CLI ethos init

echo
echo "### 3. verify empty ethos"
$CLI ethos verify

echo
echo "### 4. add sections across all zones"
$CLI ethos add-section --zone public --title "Voice" --body "I write in short paragraphs." --tags voice,style
$CLI ethos add-section --zone circle --title "Day rate" --body "EUR 900/day for strategy, EUR 1200 for hands-on build."
$CLI ethos add-section --zone self --title "Morning routine" --body "No email before 10am. Coffee first, always."

echo
echo "### 5. verify after additions"
$CLI ethos verify

echo
echo "### 6. list sections"
$CLI ethos list

echo
echo "### 7. add a revision to the public 'Voice' section"
PUBLIC_SEC=$($CLI ethos list --zone public --json | grep -o '"id": "sec_[^"]*' | head -1 | sed 's/.*"sec_/sec_/')
echo "  section: $PUBLIC_SEC"
sleep 1  # ensure strictly greater 'at'
$CLI ethos add-revision --zone public --section "$PUBLIC_SEC" \
  --body "I prefer short paragraphs for casual writing. For long-form subjects I'll write prose."

echo
echo "### 8. verify after revision"
$CLI ethos verify

echo
echo "### 9. show the full revision history of the Voice section"
$CLI ethos show --zone public --section "$PUBLIC_SEC" --revisions

echo
echo "### 10. tamper with the first revision body (should make verify fail)"
PUBLIC_MD="$AITHOS_HOME/identities/$HANDLE/ethos/public/public.md"
cp "$PUBLIC_MD" "$PUBLIC_MD.bak"
sed -i 's/I write in short paragraphs\./I write in LONG paragraphs./' "$PUBLIC_MD"

echo
echo "### 11. verify tampered (expected: FAILED)"
if $CLI ethos verify; then
  echo "ERROR: verify should have failed on a tampered past revision!"
  exit 1
fi

echo
echo "### 12. restore and re-verify"
mv "$PUBLIC_MD.bak" "$PUBLIC_MD"
$CLI ethos verify

echo
echo "### 13. pack the bundle"
$CLI ethos pack --out /tmp/alice.ethos

echo
echo "### 14. unpack and inspect"
rm -rf /tmp/alice-unpacked
$CLI ethos unpack /tmp/alice.ethos --out /tmp/alice-unpacked
ls -la /tmp/alice-unpacked/

echo
echo "### smoke-test: OK"
