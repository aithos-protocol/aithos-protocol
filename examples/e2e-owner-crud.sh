#!/usr/bin/env bash
# End-to-end test: owner-path CRUD over all three zones (public, circle, self),
# with gamma verification after each mutation.
#
# Scope:
#   - A single owner identity, no delegates.
#   - For each zone: Create → Read → Update (modify-section) → Delete.
#   - After every mutation, assert:
#       * gamma.count increased by exactly 1
#       * gamma.head matches manifest.gamma.head
#       * latest gamma entry has the expected op (section.add/modify/delete)
#   - At the end: ethos verify + gamma verify must both PASS.
#
# The zone MATTERS for gamma: public is signed by #public, circle by #circle,
# self by #self — we check `signature.key` on each entry to confirm the right
# sphere was used.
#
# Usage (from repo root, after `npm run build`):
#
#   bash examples/e2e-owner-crud.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-node $REPO_ROOT/packages/cli/dist/index.js}"

export AITHOS_HOME="${AITHOS_HOME:-/tmp/aithos-e2e-owner-crud}"
HANDLE="${HANDLE:-alice}"

say()  { printf "\n### %s\n" "$1"; }
pass() { printf "    ✓ %s\n" "$1"; }
fail() { printf "ERROR: %s\n" "$1" >&2; exit 1; }

jqf() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(eval('d.'+process.argv[1]));" "$1"; }

# Extract ops for the LATEST gamma entry.
latest_gamma_op()  { $CLI gamma show --json --handle "$HANDLE" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].op);"; }
latest_gamma_zone() { $CLI gamma show --json --handle "$HANDLE" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].zone);"; }
latest_gamma_sigkey() { $CLI gamma show --json --handle "$HANDLE" | node -e "const e=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(e[e.length-1].signature.key);"; }
gamma_count() { $CLI gamma show --head --handle "$HANDLE" | awk -F'count=' '{print $2}'; }
gamma_head()  { $CLI gamma show --head --handle "$HANDLE" | awk '{print $1}'; }
manifest_head() { node -e "const m=require('$AITHOS_HOME/identities/$HANDLE/ethos/manifest.json'); console.log((m.gamma&&m.gamma.head)||'(none)')"; }

# Assert gamma count is exactly N, head matches manifest, last op matches.
assert_gamma() {
  local expected_count="$1"
  local expected_op="$2"
  local expected_zone="$3"

  local got_count got_head mhead got_op got_zone got_sigkey
  got_count=$(gamma_count)
  got_head=$(gamma_head)
  mhead=$(manifest_head)
  got_op=$(latest_gamma_op)
  got_zone=$(latest_gamma_zone)
  got_sigkey=$(latest_gamma_sigkey)

  [[ "$got_count" == "$expected_count" ]] || fail "expected gamma.count=$expected_count, got $got_count"
  [[ "$got_head"  == "$mhead" ]]          || fail "gamma head $got_head != manifest head $mhead"
  [[ "$got_op"    == "$expected_op" ]]    || fail "expected op=$expected_op, got $got_op"
  [[ "$got_zone"  == "$expected_zone" ]]  || fail "expected zone=$expected_zone, got $got_zone"
  # Owner signs with the zone's sphere key — check the signature key fragment.
  if [[ "$got_sigkey" != *"#$expected_zone" ]]; then
    fail "expected signature key ending in #$expected_zone, got $got_sigkey"
  fi
  pass "gamma count=$got_count  head=ok  op=$got_op  zone=$got_zone  sig=#$expected_zone"
}

# --------------------------------------------------------------------------- #
say "0. reset $AITHOS_HOME"
rm -rf "$AITHOS_HOME"

say "1. init identity + ethos"
$CLI init --handle "$HANDLE" --display-name "Alice CRUD Test" >/dev/null
pass "identity + ethos created"

# Fresh identity: gamma should be empty (count=0, head=(none)).
[[ "$(gamma_count)" == "0" ]] || fail "fresh identity gamma.count should be 0"
[[ "$(gamma_head)"  == "(none)" ]] || fail "fresh identity gamma.head should be (none)"
pass "gamma is empty on init"

# --------------------------------------------------------------------------- #
# Per-zone CRUD loop. Keep a running counter so we assert the log really just
# grows by one per mutation — no silent duplicate entries, no accidental adds
# during reads.
count=0

for zone in public circle self; do
  say "── ZONE: $zone ──"

  # CREATE
  say "C) add-section to $zone"
  add_out=$($CLI ethos add-section --handle "$HANDLE" \
              --zone "$zone" \
              --title "voice-$zone" \
              --body "Initial body in $zone zone." \
              --tags "tag1,tag2" \
              --json)
  SEC=$(jqf "section.id" <<<"$add_out")
  pass "section: $SEC"
  count=$((count + 1))
  assert_gamma "$count" "section.add" "$zone"

  # READ
  say "R) ethos show --zone $zone --section $SEC"
  # Reading must NOT produce a gamma entry.
  $CLI ethos show --handle "$HANDLE" --zone "$zone" --section "$SEC" >/dev/null
  [[ "$(gamma_count)" == "$count" ]] || fail "read should not have changed gamma count"
  pass "read did not emit a gamma entry (count still $count)"

  # UPDATE
  say "U) modify-section on $SEC"
  sleep 1  # guarantee strictly increasing `at`
  $CLI ethos modify-section --handle "$HANDLE" \
    --zone "$zone" \
    --section "$SEC" \
    --body "Updated body in $zone zone." \
    --tags "tag1,tag3" >/dev/null
  count=$((count + 1))
  assert_gamma "$count" "section.modify" "$zone"

  # DELETE
  say "D) delete-section on $SEC"
  sleep 1
  $CLI ethos delete-section --handle "$HANDLE" \
    --zone "$zone" \
    --section "$SEC" \
    --reason "e2e-owner-crud: end of cycle on $zone" >/dev/null
  count=$((count + 1))
  assert_gamma "$count" "section.delete" "$zone"

  # Confirm the live zone no longer shows the section.
  if $CLI ethos show --handle "$HANDLE" --zone "$zone" | grep -q "$SEC"; then
    fail "$zone still shows section $SEC after delete"
  fi
  pass "live $zone no longer mentions $SEC (gamma retains full history)"
done

# --------------------------------------------------------------------------- #
say "── Final end-to-end verification ──"
$CLI ethos verify --handle "$HANDLE"
$CLI gamma verify --handle "$HANDLE"
pass "ethos verify + gamma verify both PASS on the full CRUD history"

# Sanity: gamma should now hold 3 zones × 3 mutations (add, modify, delete) = 9 entries.
[[ "$count" == "9" ]] || fail "expected 9 total gamma entries, got $count"
pass "total gamma entries: $count (3 zones × {add, modify, delete})"

# Per-zone section-filter sanity: for each zone's section we should see 3
# entries (add, modify, delete).
say "── per-section gamma filter sanity ──"
for zone in public circle self; do
  # Each zone's section id isn't easily recovered here, so we do a coarser
  # check: count gamma entries by zone via the JSON output.
  PER_ZONE=$($CLI gamma show --json --handle "$HANDLE" | \
    node -e "const a=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(a.filter(e=>e.zone==='$zone').length)")
  [[ "$PER_ZONE" == "3" ]] || fail "expected 3 gamma entries for $zone, got $PER_ZONE"
  pass "$zone: 3 gamma entries (add + modify + delete)"
done

printf "\n### e2e-owner-crud: OK\n"
