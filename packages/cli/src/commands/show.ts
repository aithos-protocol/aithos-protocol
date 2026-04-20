/**
 * `aithos show [handle]` — print identity info. If no handle is given, shows
 * the current default. Works for both owned and tracked identities — tracked
 * ones are flagged in the header.
 */

import {
  loadIdentityMetadata,
  identityDir,
  loadConfig,
  listIdentities,
} from "@aithos/protocol-core";

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

  const meta = loadIdentityMetadata(handle);
  const didDoc = meta.didDocument;

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          handle: meta.handle,
          display_name: meta.displayName,
          did: meta.did,
          tracked: meta.tracked,
          did_document: didDoc,
          storage: identityDir(handle),
        },
        null,
        2,
      ),
    );
    return;
  }

  const trackedSuffix = meta.tracked ? "  [tracked — public data only]" : "";
  console.log(`Handle:         ${meta.handle}${trackedSuffix}`);
  console.log(`Display name:   ${meta.displayName}`);
  console.log(`DID:            ${meta.did}`);
  console.log(`Storage:        ${identityDir(handle)}`);
  if (meta.tracked) {
    console.log();
    console.log(
      "This identity has no private sphere keys on disk. You can read its public",
    );
    console.log(
      "zone and verify signatures, but cannot decrypt circle/self or sign for it.",
    );
  }
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
