#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Revoke the demo mandate — the kill-switch (§13.9). The gateway checks
 * revocation on EVERY call (tools and inference), so the cage's next action
 * fails closed the instant this lands; the watcher then stops the container.
 *
 * Uses the workspace protocol-core (same reason as prepare-demo.mjs). Reads the
 * mandate id from run/mandate-id.txt unless one is passed as an argument.
 *
 *   AITHOS_HOME=deploy/container/run/home \
 *     node deploy/container/scripts/revoke-demo.mjs [mandate_id]
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const RUN = resolve(HERE, "..", "run");

if (!process.env.AITHOS_HOME) process.env.AITHOS_HOME = join(RUN, "home");

let mandateId = process.argv[2];
if (!mandateId) {
  try {
    mandateId = readFileSync(join(RUN, "mandate-id.txt"), "utf8").trim();
  } catch {
    console.error("no mandate id given and run/mandate-id.txt not found — run prepare-demo.mjs first");
    process.exit(2);
  }
}

const core = await import("@aithos/protocol-core");

// The revocation must be signed by the SAME identity that issued the mandate.
const mandate = core.loadMandate
  ? core.loadMandate(mandateId)
  : JSON.parse(readFileSync(join(process.env.AITHOS_HOME, "mandates", `${mandateId}.json`), "utf8"));
const identity = core.loadIdentity("demo");

const revocation = core.createRevocation({
  issuer: identity,
  mandate,
  reason: "user_request",
});
core.writeRevocation(revocation);

console.log(`✓ revoked ${mandateId} at ${revocation.revoked_at}`);
console.log("  The cage's next gateway call — tool OR inference — is now refused.");
console.log("  The revocation watcher will pause then stop the runtime.");
