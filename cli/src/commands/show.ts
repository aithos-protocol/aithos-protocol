/**
 * `aithos show [handle]` — print identity info. If no handle is given, shows
 * the current default.
 */

import { join } from "node:path";
import { readFileSync } from "node:fs";
import { loadIdentity, rootDid } from "../identity.js";
import { identityDir, loadConfig, listIdentities } from "../storage.js";

export interface ShowOpts {
  handle?: string;
  json?: boolean;
}

export function runShow(opts: ShowOpts): void {
  const config = loadConfig();
  const handle = opts.handle ?? config.default_handle;
  if (!handle) {
    const identities = listIdentities();
    if (identities.length === 0) {
      console.error("No identity found. Run `aithos init --handle <name>` first.");
      process.exitCode = 1;
      return;
    }
    console.error(
      `No default handle set. Known identities: ${identities.join(", ")}. ` +
        `Pass --handle <name> to select one.`,
    );
    process.exitCode = 1;
    return;
  }

  const id = loadIdentity(handle);
  const didJson = readFileSync(join(identityDir(handle), "did.json"), "utf8");
  const didDoc = JSON.parse(didJson);

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          handle: id.handle,
          display_name: id.displayName,
          did: rootDid(id),
          did_document: didDoc,
          storage: identityDir(handle),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Handle:         ${id.handle}`);
  console.log(`Display name:   ${id.displayName}`);
  console.log(`DID:            ${rootDid(id)}`);
  console.log(`Storage:        ${identityDir(handle)}`);
  console.log();
  console.log("Verification methods:");
  for (const vm of didDoc.verificationMethod ?? []) {
    console.log(`  ${vm.id}`);
    console.log(`    type:  ${vm.type}`);
    console.log(`    key:   ${vm.publicKeyMultibase}`);
  }
  console.log();
  console.log("Key agreement:");
  for (const ka of didDoc.keyAgreement ?? []) {
    console.log(`  ${ka.id}`);
    console.log(`    type:  ${ka.type}`);
    console.log(`    key:   ${ka.publicKeyMultibase}`);
  }
}
