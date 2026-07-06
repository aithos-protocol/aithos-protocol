#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Prepare a self-contained ACTIONS demo run: identity → delegate key → mandate
 * granting a browser action → pack → actions.json. The gateway container mounts
 * these and, on a tool call, signs a Mandated Intent Envelope and dispatches
 * run_action to browser-agent (the hand) over the WebSocket.
 *
 * Mirrors prepare-demo.mjs, with two differences that matter:
 *   - the scope is `mcp.browser.<action>`, which rides on the SELF sphere (the
 *     mcp.* family is not permitted on `public`);
 *   - it also writes run/actions.json (the action catalogue the gateway loads).
 *
 * Usage:
 *   node deploy/container/scripts/prepare-actions-demo.mjs \
 *     [--action inscription-sandbox] [--param nom] [--ttl-hours 1]
 */
import { mkdirSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTAINER_DIR = resolve(HERE, "..");
const RUN = join(CONTAINER_DIR, "run");

if (!process.env.AITHOS_HOME) process.env.AITHOS_HOME = join(RUN, "home");
const HOME = process.env.AITHOS_HOME;
mkdirSync(HOME, { recursive: true });
mkdirSync(RUN, { recursive: true });

const action = argValue("--action") ?? "inscription-sandbox";
const param = argValue("--param") ?? "nom";
const handle = argValue("--handle") ?? "demo";
const ttlHours = Number(argValue("--ttl-hours") ?? "1");
const scope = `mcp.browser.${action}`;

const core = await import("@aithos/protocol-core");

// 1. identity + keystore.
const identity = core.createIdentity(handle, "Demo Owner");
core.writeIdentityToDisk(identity);
core.initKeystoreV03({ handle, identity });

// 2. throwaway delegate key for this mandate.
const seed = new Uint8Array(randomBytes(32));
const agentKey = {
  seed_hex: Buffer.from(seed).toString("hex"),
  pubkey_multibase: core.ed25519PublicKeyToMultibase(ed.getPublicKey(seed)),
};

// 3. a mandate granting exactly this one browser action, on the SELF sphere
//    (mcp.* is not a public-sphere family).
const mandate = core.createMandate({
  issuer: identity,
  actorSphere: "self",
  grantee: { id: "urn:aithos:agent:demo", label: "demo agent", pubkey: agentKey.pubkey_multibase },
  scopes: [scope],
  ttlSeconds: Math.round(ttlHours * 3600),
});
core.writeMandate(mandate);

// 4. the pack (mounted to the GATEWAY, never the cage).
writeFileSync(
  join(RUN, "pack.json"),
  JSON.stringify({ "aithos-mandate-pack": "1", mandate, agent_key: agentKey, options: { auto_commit: true } }, null, 2) + "\n",
);

// 5. the action catalogue the gateway exposes (one tool per in-scope action).
writeFileSync(
  join(RUN, "actions.json"),
  JSON.stringify(
    {
      aud: "urn:aithos:downstream:browser-agent",
      actions: [
        {
          id: action,
          goal: `Run the ${action} action`,
          params_schema: {
            type: "object",
            properties: { [param]: { type: "string", minLength: 1 } },
            required: [param],
          },
        },
      ],
    },
    null,
    2,
  ) + "\n",
);

// 6. registry (unchanged) + mandate id for revoke-demo.
copyFileSync(join(CONTAINER_DIR, "registry.example.json"), join(RUN, "registry.json"));
writeFileSync(join(RUN, "mandate-id.txt"), mandate.id + "\n");

console.log(`✓ identity + keystore   $AITHOS_HOME = ${HOME}`);
console.log(`✓ mandate               ${mandate.id}  (scope: ${scope})`);
console.log(`✓ pack                  ${join(RUN, "pack.json")}`);
console.log(`✓ actions               ${join(RUN, "actions.json")}  (tool: browser_action__${action}, param: ${param})`);
console.log("");
console.log("Next (see deploy/container/CONTAINER-ACTIONS-GUIDE.md):");
console.log("  export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)");
console.log("  export AITHOS_ACTIONS_BEARER=<same token as browser-agent --ws-bearer>");
console.log("  docker compose -f deploy/container/docker-compose.yml \\");
console.log("    -f deploy/container/docker-compose.actions-dev.yml up --build gateway");

function argValue(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
