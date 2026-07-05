// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Compose topology lint (SPEC-container-runtime §13.3 conformance): the cage
 * invariants are configuration, so they are pinned as configuration tests.
 * These do NOT need Docker — they parse docker-compose.yml and assert the
 * boundary the reference deployment claims:
 *
 *   N1  the runtime is on the `cage` network and NOTHING else;
 *   N1  `cage` is `internal: true` (no egress — the kernel boundary);
 *   N2  the runtime exposes no ports (zero ingress);
 *   N3  non-root, read-only rootfs, cap_drop ALL, no-new-privileges;
 *   §13.7.1  the runtime mounts NO pack / key / credential (nothing but the
 *            optional, commented ~/.claude subscription exception);
 *   the gateway is the ONLY component on both `cage` and `egress`.
 *
 * A YAML parser is not guaranteed in the toolchain, so we lint structurally on
 * the text with targeted assertions — enough to catch a regression that would
 * silently punch a hole in the cage.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const COMPOSE = readFileSync(join(HERE, "..", "docker-compose.yml"), "utf8");

/** Extract the indented block of a top-level `services:` child. */
function serviceBlock(name) {
  const lines = COMPOSE.split("\n");
  const start = lines.findIndex((l) => l.match(new RegExp(`^  ${name}:\\s*$`)));
  assert.ok(start >= 0, `service ${name} present`);
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  \S/.test(lines[i]) || /^\S/.test(lines[i])) break; // next service / top key
    out.push(lines[i]);
  }
  return out.join("\n");
}

const runtime = serviceBlock("runtime");
const gateway = serviceBlock("gateway");

test("cage network is internal (N1 — the kernel egress boundary)", () => {
  assert.match(
    COMPOSE,
    /cage:\s*\n\s*internal:\s*true/,
    "networks.cage.internal must be true",
  );
});

test("runtime is attached to the cage network only (N1)", () => {
  const nets = runtime.match(/networks:\s*\[([^\]]*)\]/);
  assert.ok(nets, "runtime declares networks");
  const list = nets[1].split(",").map((s) => s.trim());
  assert.deepEqual(list, ["cage"], "runtime must be on `cage` and nothing else");
});

test("gateway is the only two-legged component (cage + egress)", () => {
  const nets = gateway.match(/networks:\s*\[([^\]]*)\]/);
  assert.ok(nets);
  const list = nets[1].split(",").map((s) => s.trim()).sort();
  assert.deepEqual(list, ["cage", "egress"]);
});

test("runtime exposes no ports (N2 — zero ingress)", () => {
  assert.doesNotMatch(runtime, /^\s*ports:/m, "runtime must not publish ports");
});

test("runtime hardening: non-root, read-only, caps dropped, no-new-privileges (N3)", () => {
  assert.match(runtime, /read_only:\s*true/, "read-only rootfs");
  assert.match(runtime, /cap_drop:\s*\[ALL\]/, "all caps dropped");
  assert.match(runtime, /no-new-privileges:true/, "no-new-privileges");
  assert.match(runtime, /user:\s*"?10001/, "non-root user");
});

test("no authority secret is mounted into the cage (§13.7.1)", () => {
  // The runtime block must not ACTIVELY mount a pack / registry / sphere key.
  // The only tolerated secret is the commented ~/.claude subscription (§13.7.2),
  // which must remain commented (a leading # on the mount line).
  const activeMountLines = runtime
    .split("\n")
    .filter((l) => /:\s*ro\b/.test(l) || /\/run\/aithos/.test(l))
    .filter((l) => !l.trim().startsWith("#"));
  assert.deepEqual(
    activeMountLines,
    [],
    `no active secret mount in the cage (found: ${activeMountLines.join(" | ")})`,
  );
  // And if ~/.claude appears at all, it is commented out.
  for (const l of runtime.split("\n")) {
    if (l.includes(".claude")) {
      assert.ok(l.trim().startsWith("#"), "~/.claude exception must ship commented");
    }
  }
});

test("the pack + registry are mounted to the GATEWAY, read-only", () => {
  assert.match(gateway, /pack\.json:\/run\/aithos\/pack\.json:ro/);
  assert.match(gateway, /registry\.json:\/run\/aithos\/registry\.json:ro/);
});

test("gateway boots with mandate pack, registry and the LLM proxy", () => {
  assert.match(GATEWAY_DOCKERFILE, /--mandate-pack/);
  assert.match(GATEWAY_DOCKERFILE, /--mcp-registry/);
  assert.match(GATEWAY_DOCKERFILE, /--llm-proxy/);
});

const GATEWAY_DOCKERFILE = readFileSync(
  join(HERE, "..", "gateway.Dockerfile"),
  "utf8",
);
