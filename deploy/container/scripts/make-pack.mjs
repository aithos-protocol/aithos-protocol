#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Assemble a mandate pack (§6.2.1) from a mandate JSON + a delegate keyfile —
 * the one file the gateway boots under (`--mandate-pack`). Both inputs are
 * produced by the CLI:
 *
 *   aithos delegate-key --out agent.key.json          # → pubkey_multibase
 *   aithos grant urn:aithos:agent:demo \
 *     --sphere public --scope mcp.demo.read --ttl 1h \
 *     --pubkey <pubkey> --json > grant.json           # → { mandate, ... }
 *
 *   node make-pack.mjs grant.json agent.key.json > pack.json
 *
 * The pack carries the delegate SEED, so it is a secret: it is mounted to the
 * GATEWAY, never into the cage (§13.7.1).
 */
import { readFileSync } from "node:fs";

const [, , grantPath, keyPath] = process.argv;
if (!grantPath || !keyPath) {
  console.error("usage: make-pack.mjs <grant.json> <agent.key.json> > pack.json");
  process.exit(2);
}

const grant = JSON.parse(readFileSync(grantPath, "utf8"));
const mandate = grant.mandate ?? grant; // accept `grant --json` or a bare mandate
const key = JSON.parse(readFileSync(keyPath, "utf8"));

if (!mandate?.id || !Array.isArray(mandate.scopes)) {
  console.error("make-pack: first argument is not a mandate (missing id/scopes)");
  process.exit(1);
}
if (!key?.seed_hex || !key?.pubkey_multibase) {
  console.error("make-pack: keyfile missing seed_hex / pubkey_multibase");
  process.exit(1);
}
if (mandate.grantee?.pubkey && mandate.grantee.pubkey !== key.pubkey_multibase) {
  console.error("make-pack: keyfile pubkey does not match mandate.grantee.pubkey");
  process.exit(1);
}

const pack = {
  "aithos-mandate-pack": "1",
  mandate,
  agent_key: {
    seed_hex: key.seed_hex,
    pubkey_multibase: key.pubkey_multibase,
  },
  options: { auto_commit: true },
};
process.stdout.write(JSON.stringify(pack, null, 2) + "\n");
