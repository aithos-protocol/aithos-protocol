// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos rotate --sphere <s> [--reason <r>]` — rotate a sphere key.
 *
 * This is the "kill switch" of the protocol. Rotating the sphere key invalidates
 * every mandate signed by the old key, regardless of TTL, regardless of whether
 * a revocation is visible. It is the appropriate response when:
 *
 *   - The sphere key may have been exfiltrated (compromise).
 *   - Mandates issued from a now-unreachable device exist that you cannot
 *     enumerate and individually revoke.
 *   - You want a clean break (moving machines, ending a collaboration).
 *
 * Rotation costs the subject a new DID document edition: the old sphere public
 * key is recorded under `aithos.rotated[]` with a reason and a timestamp, and
 * the new key replaces it under `verificationMethod`. A root-key signature
 * attests the new DID document. See §1.6 of the spec.
 *
 * Rotation is a forward-only operation: everything signed by the old key
 * *before* the rotation timestamp remains verifiable by anyone who has the old
 * DID document. But any verifier resolving the current DID document will see
 * the old key as rotated and refuse it for any purpose except historical audit.
 */

import { writeFileSync, chmodSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import {
  canonicalize,
  loadIdentity,
  base64url,
  x25519PublicFromSecret,
  edSeedToX25519Secret,
  type DidDocument,
  ed25519PublicKeyToMultibase,
  x25519PublicKeyToMultibase,
  didUrlForSphere,
  didUrlForKex,
  type Sphere,
  identityDir,
  loadConfig,
  writeJson,
} from "@aithos/protocol-core";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface RotateOpts {
  sphere: string;
  reason?: string;
  handle?: string;
  yes?: boolean;
  json?: boolean;
}

export function runRotate(opts: RotateOpts): void {
  if (!["public", "circle", "self"].includes(opts.sphere)) {
    throw new Error(`--sphere must be public|circle|self`);
  }
  const sphere = opts.sphere as Sphere;

  const config = loadConfig();
  const handle = opts.handle ?? config.default_handle;
  if (!handle) throw new Error("No identity selected. Pass --handle or set a default.");
  const id = loadIdentity(handle);

  const dir = identityDir(handle);
  const didDocPath = join(dir, "did.json");
  const didDoc = JSON.parse(readFileSync(didDocPath, "utf8")) as DidDocument;

  const reason = opts.reason ?? "user_request";
  const oldPubMultibase = ed25519PublicKeyToMultibase(id[sphere].publicKey);

  if (!opts.yes) {
    console.log(`Rotating ${sphere} sphere key on ${id.handle} (${didDoc.id}).`);
    console.log(`  Old public key: ${oldPubMultibase}`);
    console.log(`  Reason:         ${reason}`);
    console.log();
    console.log(
      "Consequences:",
    );
    console.log(
      "  - Every mandate signed by the old key becomes INVALID to any verifier",
    );
    console.log(
      "    that resolves the updated DID document, regardless of TTL.",
    );
    console.log(
      "  - Future mandates, revisions, and action counter-signatures will be",
    );
    console.log(
      "    signed by the NEW key.",
    );
    console.log(
      "  - Past actions signed by the old key REMAIN historically attributable",
    );
    console.log(
      "    (the rotation is forward-only; the old key stays in aithos.rotated[]).",
    );
    console.log(
      "  - If this is the `circle` key, circle-zone bundles will need to be re-",
    );
    console.log(
      "    encrypted for new recipients on the next edition (§1.6).",
    );
    console.log();
    console.log(`Pass --yes to proceed.`);
    return;
  }

  // Generate new sphere key material.
  const newSeed = new Uint8Array(randomBytes(32));
  const newPk = ed.getPublicKey(newSeed);
  const newPkMultibase = ed25519PublicKeyToMultibase(newPk);
  const newXPriv = edSeedToX25519Secret(newSeed);
  const newXPub = x25519PublicFromSecret(newXPriv);

  // Write the new sealed seed (v0.1.0 cleartext; see SECURITY NOTE).
  const now = new Date().toISOString();
  writeJson(
    join(dir, `${sphere}.sealed.json`),
    {
      aithos: "0.1.0",
      role: sphere,
      seed_hex: Buffer.from(newSeed).toString("hex"),
      created_at: now,
    },
    0o600,
  );

  // Update DID document
  const sphereDidUrl = didUrlForSphere(didDoc.id, sphere);
  const kexDidUrl = didUrlForKex(didDoc.id, sphere);

  didDoc.verificationMethod = didDoc.verificationMethod.map((vm) =>
    vm.id === sphereDidUrl
      ? { ...vm, publicKeyMultibase: newPkMultibase }
      : vm,
  );
  didDoc.keyAgreement = didDoc.keyAgreement.map((ka) =>
    ka.id === kexDidUrl
      ? { ...ka, publicKeyMultibase: x25519PublicKeyToMultibase(newXPub) }
      : ka,
  );
  didDoc.aithos.rotated = [
    ...(didDoc.aithos.rotated ?? []),
    {
      sphere,
      previous_key: oldPubMultibase,
      rotated_at: now,
      reason,
    },
  ];

  // Resign DID document with the root key.
  const unsigned: DidDocument = {
    ...didDoc,
    proof: {
      type: "Ed25519Signature2020",
      created: now,
      verificationMethod: `${didDoc.id}#root`,
      proofPurpose: "assertionMethod",
      proofValue: "",
    },
  };
  const sig = ed.sign(new TextEncoder().encode(canonicalize(unsigned)), id.root.seed);
  unsigned.proof!.proofValue = base64url(sig);

  writeFileSync(didDocPath, JSON.stringify(unsigned, null, 2) + "\n");
  chmodSync(didDocPath, 0o644);

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          handle,
          sphere,
          old_public_key: oldPubMultibase,
          new_public_key: newPkMultibase,
          rotated_at: now,
          reason,
          did_document: didDocPath,
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Rotated ${sphere} sphere key.`);
  console.log(`  Old key: ${oldPubMultibase}`);
  console.log(`  New key: ${newPkMultibase}`);
  console.log(`  DID doc: ${didDocPath}`);
  console.log();
  console.log(
    `All mandates signed by the old ${sphere} key are now invalid to any verifier resolving the updated DID document.`,
  );
  console.log(
    `Re-issue the mandates you still want, under the new key. Publish the new DID document wherever the old one was referenced.`,
  );
}
