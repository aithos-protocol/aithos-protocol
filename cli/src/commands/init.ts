/**
 * `aithos init` — create a new Aithos identity AND its ethos in one step.
 *
 * Usage:
 *   aithos init --handle <handle> [--display-name <name>] [--force] [--no-ethos]
 *
 * Writes:
 *   ~/.aithos/identities/<handle>/did.json
 *   ~/.aithos/identities/<handle>/{root,public,circle,self}.sealed.json
 *   ~/.aithos/identities/<handle>/ethos/…        (unless --no-ethos)
 *   ~/.aithos/config.json                        (sets default_handle if unset)
 *
 * Pass `--no-ethos` for headless/service identities that only exist to sign
 * mandates or action artifacts and will never author a live ethos document.
 */

import { existsSync, rmSync } from "node:fs";
import { createIdentity, writeIdentityToDisk, rootDid } from "../identity.js";
import { identityDir, loadConfig, saveConfig } from "../storage.js";
import { initializeEthos } from "./ethos-init.js";

export interface InitOpts {
  handle: string;
  displayName?: string;
  force?: boolean;
  noEthos?: boolean;
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

  console.log(`[handle=${opts.handle}] Created identity`);
  console.log(`  DID:     ${did}`);
  console.log(`  Stored:  ${writtenDir}`);
  console.log(`  Default: ${config.default_handle === opts.handle ? "yes" : "no"}`);
  console.log();
  console.log("Sphere DID URLs:");
  for (const sphere of ["public", "circle", "self"] as const) {
    console.log(`  ${sphere.padEnd(7)} ${rootDid(id)}#${sphere}`);
  }

  if (!opts.noEthos) {
    console.log();
    // --force above has already wiped the identity dir, including any pre-existing
    // ethos under it. So initializeEthos should find a clean slate.
    const { dir: ethosPath, manifest } = initializeEthos(opts.handle);
    console.log(`[handle=${opts.handle}] Ethos initialized`);
    console.log(`  Directory:    ${ethosPath}`);
    console.log(`  Edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
    console.log(`  Bundle id:    ${manifest.bundle_id}`);
    console.log(`  Zones:        public (clear), circle (encrypted), self (encrypted)`);
  }

  console.log();
  console.log(
    "SECURITY NOTE: v0.1.0 stores seeds as plaintext JSON files (mode 0600). " +
      "Do not use this keystore for anything beyond a developer preview.",
  );

  if (!opts.noEthos) {
    console.log();
    console.log(
      `Next: aithos ethos add-section --zone public --title "Voice" --body "I prefer short paragraphs."`,
    );
  }
}
