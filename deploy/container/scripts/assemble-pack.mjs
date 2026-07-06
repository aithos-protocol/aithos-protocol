#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// Assemble a gateway pack from a mandate you minted YOURSELF (app.aithos.be, the
// example app, or `aithos grant`) + the agent key from new-agent-key.mjs. The
// mandate's SOURCE does not matter: everything is protocol-core, so a mandate
// from the web app is byte-identical to a CLI one, and the gateway verifies it
// the same way.
//
//   node deploy/container/scripts/new-agent-key.mjs         # -> run/agent-key.json + a pubkey
//   # grant your mandate to that pubkey (sphere self, scope mcp.browser.<action>), export JSON
//   node deploy/container/scripts/assemble-pack.mjs --mandate mandate.json \
//        [--action inscription-sandbox --param nom --service browser]
//
// Writes run/pack.json + run/actions.json + a minimal run/home (revocation
// store only — NO owner private key ever enters the cage).
import { mkdirSync, writeFileSync, readFileSync, copyFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const RUN = resolve(HERE, "..", "run");
if (!process.env.AITHOS_HOME) process.env.AITHOS_HOME = join(RUN, "home");
mkdirSync(process.env.AITHOS_HOME, { recursive: true });
mkdirSync(RUN, { recursive: true });

const arg = (f) => {
  const i = process.argv.indexOf(f);
  return i >= 0 ? process.argv[i + 1] : undefined;
};

const bundlePath = arg("--bundle");
const mandatePath = arg("--mandate");
if (!bundlePath && !mandatePath) {
  console.error("usage: assemble-pack.mjs --bundle <delegate-bundle.json>   (app.aithos.be / example app export)");
  console.error("   or: assemble-pack.mjs --mandate <mandate.json> [--agent-seed <hex>]");
  console.error("   [--action <id> --param <name> --service <svc>]");
  process.exit(2);
}
const service = arg("--service") ?? "browser";
const action = arg("--action") ?? "inscription-sandbox";
const param = arg("--param") ?? "nom";
const scope = `mcp.${service}.${action}`;

async function keyFromSeed(seedHex) {
  const core = await import("@aithos/protocol-core");
  const ed = await import("@noble/ed25519");
  const { sha512 } = await import("@noble/hashes/sha512");
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
  const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));
  return { seed_hex: seedHex, pubkey_multibase: core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed)) };
}

// 1. get the mandate + agent key. A DELEGATE BUNDLE carries both (the export
//    from app.aithos.be / the example app: { mandate, delegate_seed_hex }). A
//    bare mandate uses a separate agent key (--agent-seed or run/agent-key.json).
let mandate, agentKey;
if (bundlePath) {
  const b = JSON.parse(readFileSync(resolve(bundlePath), "utf8"));
  mandate = b.mandate;
  if (!mandate || typeof b.delegate_seed_hex !== "string") {
    console.error("bundle: expected a delegate bundle { mandate, delegate_seed_hex }.");
    process.exit(1);
  }
  agentKey = await keyFromSeed(b.delegate_seed_hex);
} else {
  const seedHex = arg("--agent-seed");
  agentKey = seedHex ? await keyFromSeed(seedHex) : JSON.parse(readFileSync(join(RUN, "agent-key.json"), "utf8"));
  const raw = JSON.parse(readFileSync(resolve(mandatePath), "utf8"));
  mandate = raw.mandate ?? raw;
}
if (!mandate || typeof mandate !== "object" || !Array.isArray(mandate.scopes)) {
  console.error("mandate: not a valid Mandate (no scopes[]).");
  process.exit(1);
}

// 3. cross-checks — fail loudly rather than boot a mandate that won't gate.
if (!mandate.scopes.includes(scope)) {
  console.error(`mandate does NOT carry the scope ${scope}. It has: ${JSON.stringify(mandate.scopes)}`);
  console.error("Mint the mandate with that scope (or pass --service/--action to match).");
  process.exit(1);
}
const grantee = mandate.grantee?.pubkey;
if (grantee && grantee !== agentKey.pubkey_multibase) {
  console.error("mandate.grantee.pubkey does not match the agent key.");
  console.error(`  mandate grantee: ${grantee}`);
  console.error(`  agent key      : ${agentKey.pubkey_multibase}`);
  console.error("Grant the mandate to the agent pubkey printed by new-agent-key.mjs.");
  process.exit(1);
}

// 4. write the pack + the action catalogue.
writeFileSync(
  join(RUN, "pack.json"),
  JSON.stringify({ "aithos-mandate-pack": "1", mandate, agent_key: agentKey, options: { auto_commit: true } }, null, 2) + "\n",
);
writeFileSync(
  join(RUN, "actions.json"),
  JSON.stringify(
    {
      aud: "urn:aithos:downstream:browser-agent",
      service,
      actions: [
        { id: action, goal: `Run the ${action} action`, params_schema: { type: "object", properties: { [param]: { type: "string", minLength: 1 } }, required: [param] } },
      ],
    },
    null,
    2,
  ) + "\n",
);

// 5. registry (what is connectable) — the demo gateway command mounts it too.
copyFileSync(resolve(HERE, "..", "registry.example.json"), join(RUN, "registry.json"));

console.log(`✓ pack       ${join(RUN, "pack.json")}   (mandate ${mandate.id} by ${mandate.issuer})`);
console.log(`✓ actions    ${join(RUN, "actions.json")}   (tool: ${service}_action__${action}, param: ${param})`);
console.log(`✓ home       ${process.env.AITHOS_HOME}   (revocation store only — no owner key)`);
console.log("");
console.log("Boot the cage (demo overlay) as usual — it runs under YOUR mandate.");
