// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Lint the DEV subscription overlay (docker-compose.subscription-dev.yml). The
 * "B-egress" compromise must stay NARROW: the cage gains exactly one reachable
 * domain and no more. These are configuration invariants, pinned as tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OVERLAY = readFileSync(
  join(HERE, "..", "docker-compose.subscription-dev.yml"),
  "utf8",
);

function serviceBlock(text, name) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l.match(new RegExp(`^  ${name}:\\s*$`)));
  if (start < 0) return "";
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  \S/.test(lines[i]) || /^\S/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join("\n");
}

const egress = serviceBlock(OVERLAY, "egress-proxy");
const runtime = serviceBlock(OVERLAY, "runtime");

test("egress-proxy allowlists ONLY api.anthropic.com", () => {
  assert.match(egress, /EGRESS_ALLOWLIST:\s*"api\.anthropic\.com"/);
  // No wildcard / additional domains snuck in.
  assert.doesNotMatch(egress, /EGRESS_ALLOWLIST:\s*"[^"]*[, ]/, "single domain only");
});

test("egress-proxy is the only two-legged component (cage + egress)", () => {
  const nets = egress.match(/networks:\s*\[([^\]]*)\]/);
  assert.ok(nets, "egress-proxy declares networks");
  assert.deepEqual(nets[1].split(",").map((s) => s.trim()).sort(), ["cage", "egress"]);
});

test("egress-proxy is hardened (non-root, read-only, caps dropped)", () => {
  assert.match(egress, /read_only:\s*true/);
  assert.match(egress, /cap_drop:\s*\[ALL\]/);
  assert.match(egress, /no-new-privileges:true/);
  assert.match(egress, /user:\s*"1000/);
});

test("the runtime is NOT given a direct egress leg (stays cage-only)", () => {
  // The overlay must not add the runtime to the `egress` network — its only
  // path out is the allowlist proxy.
  assert.doesNotMatch(runtime, /networks:/, "overlay must not re-net the runtime onto egress");
  assert.doesNotMatch(OVERLAY, /runtime:[\s\S]*networks:\s*\[[^\]]*egress/);
});

test("the runtime reaches the world only through the egress proxy", () => {
  assert.match(runtime, /HTTPS_PROXY:\s*"http:\/\/egress-proxy:8888"/);
  assert.match(runtime, /AITHOS_INFERENCE_MODE:\s*"direct"/);
});

test("the gateway (actions) bypasses the egress proxy (NO_PROXY)", () => {
  assert.match(runtime, /NO_PROXY:\s*"[^"]*gateway/);
});

test("no active ~/.claude mount (macOS uses the token; file mount is commented)", () => {
  for (const l of runtime.split("\n")) {
    if (l.includes(".claude")) {
      assert.ok(l.trim().startsWith("#"), "~/.claude mount must ship commented");
    }
  }
});
