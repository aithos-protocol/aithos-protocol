/**
 * `aithos delegate-key` — generate an Ed25519 delegate keypair for a write
 * mandate. Prints the multibase-encoded public key (suitable for
 * `aithos grant --pubkey z…`) and writes the private seed to a keyfile the
 * subject can then hand to the delegate device.
 *
 * A delegate key is NOT added to the subject's DID document. Its authority is
 * conveyed entirely by the write mandate the subject issues against it, and
 * disappears the moment that mandate is revoked.
 */

import { writeFileSync, chmodSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import { ed25519PublicKeyToMultibase } from "@aithos/protocol-core";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface DelegateKeyOpts {
  out: string;
  id?: string; // optional agent identifier to embed in the keyfile
  force?: boolean;
  json?: boolean;
}

export function runDelegateKey(opts: DelegateKeyOpts): void {
  if (existsSync(opts.out) && !opts.force) {
    throw new Error(`Refusing to overwrite ${opts.out}. Pass --force to replace it.`);
  }

  const seed = new Uint8Array(randomBytes(32));
  const publicKey = ed.getPublicKey(seed);
  const multibase = ed25519PublicKeyToMultibase(publicKey);

  const keyfile = {
    aithos: "0.1.0",
    role: "delegate",
    ...(opts.id ? { id: opts.id } : {}),
    pubkey_multibase: multibase,
    seed_hex: Buffer.from(seed).toString("hex"),
    created_at: new Date().toISOString(),
  };

  writeFileSync(opts.out, JSON.stringify(keyfile, null, 2) + "\n", { mode: 0o600 });
  chmodSync(opts.out, 0o600);

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          out: opts.out,
          pubkey: multibase,
          ...(opts.id ? { id: opts.id } : {}),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Generated delegate keypair`);
  console.log(`  Public key:  ${multibase}`);
  console.log(`  Keyfile:     ${opts.out}`);
  if (opts.id) console.log(`  Agent id:    ${opts.id}`);
  console.log();
  console.log(`Next step — issue a write mandate against this public key:`);
  console.log();
  console.log(
    `  aithos grant ${opts.id ?? "<agent-id>"} \\`,
  );
  console.log(`    --sphere <public|circle|self> \\`);
  console.log(`    --scope ethos.write.<zone> \\`);
  console.log(`    --pubkey ${multibase} \\`);
  console.log(`    --ttl 7d`);
  console.log();
  console.log(`The seed file is mode 0600. Transfer it to the delegate device over a secure channel.`);
}
