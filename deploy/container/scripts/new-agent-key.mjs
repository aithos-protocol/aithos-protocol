#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// Generate the AGENT's keypair — the delegate the gateway signs with. You then
// grant your mandate (from app.aithos.be, the example app, or `aithos grant`)
// to the PRINTED pubkey, and feed the saved key to assemble-pack.mjs.
//
//   node deploy/container/scripts/new-agent-key.mjs
//
// Writes deploy/container/run/agent-key.json (seed + pubkey). The seed is the
// agent's secret; it lives with the GATEWAY, never in the cage.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const RUN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "run");
mkdirSync(RUN, { recursive: true });

const core = await import("@aithos/protocol-core");
const seed = new Uint8Array(randomBytes(32));
const pubkey_multibase = core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed));
const key = { seed_hex: Buffer.from(seed).toString("hex"), pubkey_multibase };
writeFileSync(join(RUN, "agent-key.json"), JSON.stringify(key, null, 2) + "\n");

console.log("✓ agent key written    " + join(RUN, "agent-key.json"));
console.log("");
console.log("Grant your mandate to THIS agent (sphere: self, scope: mcp.browser.<action>):");
console.log("  agent pubkey (multibase):  " + pubkey_multibase);
console.log("");
console.log("Then assemble the pack from the mandate you exported:");
console.log("  node deploy/container/scripts/assemble-pack.mjs --mandate <mandate.json>");
