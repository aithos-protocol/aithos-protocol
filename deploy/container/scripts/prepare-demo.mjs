#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Prepare a self-contained demo run (identity → delegate key → mandate → pack
 * → registry) using the WORKSPACE protocol-core directly.
 *
 * Why not the `aithos` CLI? In this monorepo the CLI package pins an old
 * protocol-core range (^0.8.0) that predates sphere-neutral `mcp.*` scopes, so
 * `aithos grant --scope mcp.demo.read` fails against a stale nested copy. The
 * gateway itself uses a current protocol-core, so a mandate authored here (like
 * the one the P0 acceptance test builds) is exactly what it verifies. Bypassing
 * the CLI keeps the demo working without churning the lockfile before release.
 * (Fix the CLI's protocol-core range to restore the `aithos grant` path.)
 *
 * Usage:
 *   AITHOS_HOME=deploy/container/run/home \
 *     node deploy/container/scripts/prepare-demo.mjs [--scope mcp.demo.read]
 *
 * Writes: the keystore under $AITHOS_HOME, plus run/pack.json + run/registry.json
 * next to this script's ../run directory.
 */
import { mkdirSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTAINER_DIR = resolve(HERE, "..");
const RUN = join(CONTAINER_DIR, "run");

// AITHOS_HOME must be set BEFORE protocol-core is imported (it freezes the home
// at import time). Default to run/home so a bare invocation just works.
if (!process.env.AITHOS_HOME) process.env.AITHOS_HOME = join(RUN, "home");
const HOME = process.env.AITHOS_HOME;
mkdirSync(HOME, { recursive: true });
mkdirSync(RUN, { recursive: true });

const scope = argValue("--scope") ?? "mcp.demo.read";
const handle = argValue("--handle") ?? "demo";
const ttlHours = Number(argValue("--ttl-hours") ?? "1");

const core = await import("@aithos/protocol-core");

// 1. identity (idempotent-ish: recreate is fine for a demo run).
const identity = core.createIdentity(handle, "Demo Owner");
core.writeIdentityToDisk(identity);
core.initKeystoreV03({ handle, identity });

// 2. delegate key (throwaway, dedicated to this mandate).
const seed = new Uint8Array(randomBytes(32));
const pub = ed.getPublicKey(seed);
const agentKey = {
  seed_hex: Buffer.from(seed).toString("hex"),
  pubkey_multibase: core.ed25519PublicKeyToMultibase(pub),
};

// 3. a READ-ONLY connector mandate on the public sphere.
const mandate = core.createMandate({
  issuer: identity,
  actorSphere: "public",
  grantee: { id: "urn:aithos:agent:demo", label: "demo agent", pubkey: agentKey.pubkey_multibase },
  scopes: [scope],
  ttlSeconds: Math.round(ttlHours * 3600),
});
core.writeMandate(mandate);

// 4. the pack (mounted to the GATEWAY, never the cage).
const pack = {
  "aithos-mandate-pack": "1",
  mandate,
  agent_key: agentKey,
  options: { auto_commit: true },
};
writeFileSync(join(RUN, "pack.json"), JSON.stringify(pack, null, 2) + "\n");

// 5. the registry (what is connectable).
const registrySrc = join(CONTAINER_DIR, "registry.example.json");
copyFileSync(registrySrc, join(RUN, "registry.json"));

// 6. record the mandate id so revoke-demo can find it without re-parsing.
writeFileSync(join(RUN, "mandate-id.txt"), mandate.id + "\n");

console.log(`✓ identity + keystore   $AITHOS_HOME = ${HOME}`);
console.log(`✓ mandate               ${mandate.id}  (scope: ${scope})`);
console.log(`✓ pack                  ${join(RUN, "pack.json")}`);
console.log(`✓ registry              ${join(RUN, "registry.json")}`);
console.log("");
console.log("Next:");
console.log(`  export AITHOS_HOME=${HOME}`);
console.log(`  export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)`);
console.log(`  docker compose -f ${join(CONTAINER_DIR, "docker-compose.yml")} up --abort-on-container-exit`);
console.log(`  # then, to see the kill-switch:`);
console.log(`  node ${join(HERE, "revoke-demo.mjs")}`);

function argValue(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
