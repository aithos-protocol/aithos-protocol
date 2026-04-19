/**
 * `aithos init` — create a new Aithos identity.
 *
 * Usage:
 *   aithos init --handle <handle> [--display-name <name>] [--force]
 *
 * Writes:
 *   ~/.aithos/identities/<handle>/did.json
 *   ~/.aithos/identities/<handle>/{root,public,circle,self}.sealed.json
 *   ~/.aithos/config.json  (sets default_handle if unset)
 */

import { existsSync, rmSync } from "node:fs";
import { createIdentity, writeIdentityToDisk, rootDid } from "../identity.js";
import { identityDir, loadConfig, saveConfig } from "../storage.js";

export interface InitOpts {
  handle: string;
  displayName?: string;
  force?: boolean;
}

export function runInit(opts: InitOpts): void {
  if (!/^[a-z0-9][a-z0-9_-]{1,63}$/.test(opts.handle)) {
    throw new Error(
      `Invalid handle "${opts.handle}". Use 2-64 chars: a-z, 0-9, underscore, hyphen.`,
    );
  }

  const dir = identityDir(opts.handle);
  if (existsSync(dir)) {
    if (!opts.force) {
      throw new Error(
        `Identity "${opts.handle}" already exists at ${dir}. Use --force to overwrite.`,
      );
    }
    rmSync(dir, { recursive: true, force: true });
  }

  const id = createIdentity(opts.handle, opts.displayName ?? opts.handle);
  const { dir: writtenDir, did } = writeIdentityToDisk(id);

  const config = loadConfig();
  if (!config.default_handle) {
    config.default_handle = opts.handle;
    saveConfig(config);
  }

  console.log(`Created identity "${opts.handle}"`);
  console.log(`  DID:     ${did}`);
  console.log(`  Stored:  ${writtenDir}`);
  console.log(`  Default: ${config.default_handle === opts.handle ? "yes" : "no"}`);
  console.log();
  console.log("Sphere DID URLs:");
  for (const sphere of ["public", "circle", "self"] as const) {
    console.log(`  ${sphere.padEnd(7)} ${rootDid(id)}#${sphere}`);
  }
  console.log();
  console.log(
    "SECURITY NOTE: v0.1.0 stores seeds as plaintext JSON files (mode 0600). " +
      "Do not use this keystore for anything beyond a developer preview.",
  );
}
