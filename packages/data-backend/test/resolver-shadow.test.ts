// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Forgeable-mandate fix — the PDS now verifies mandate signatures ONLY against
 * the subject's real published DID document. The caller-supplied
 * `_subject_sphere_pubkeys` override (and `withSphereOverride`) is gone, so a
 * caller can no longer substitute the key their forged mandate is checked
 * against.
 *
 * Invariant under test: a mandate that CLAIMS the owner as issuer but is signed
 * by an attacker key is rejected when verified against the owner's real DID
 * document — the exact substitution the deleted override used to let through.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  createIdentity,
  type Identity,
  type DidDocument,
} from "@aithos/protocol-core/identity";
import { createMandate, verifyMandate } from "@aithos/protocol-core/mandate";
import {
  rootDid,
  sphereDidUrl,
  ed25519PublicKeyToMultibase,
} from "@aithos/protocol-core/did";

/** Build the subject's real DID document straight from its sphere keypairs. */
function didDocFor(identity: Identity): DidDocument {
  const did = rootDid(identity);
  const vm = (frag: string, pk: Uint8Array) => ({
    id: `${did}#${frag}`,
    type: "Ed25519VerificationKey2020" as const,
    controller: did,
    publicKeyMultibase: ed25519PublicKeyToMultibase(pk),
  });
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      vm("root", identity.root.publicKey),
      vm("public", identity.public.publicKey),
      vm("circle", identity.circle.publicKey),
      vm("self", identity.self.publicKey),
    ],
    keyAgreement: [],
    aithos: { version: "0.1.0", created_at: "1970-01-01T00:00:00Z", rotated: [] },
  } as DidDocument;
}

describe("PDS mandate verification — forgery rejected against the real published DID doc", () => {
  it("a mandate signed by the owner verifies against the owner's DID document", () => {
    const owner = createIdentity("owner", "Owner");
    const ownerDoc = didDocFor(owner);

    const mandate = createMandate({
      issuer: owner,
      actorSphere: "self",
      grantee: { id: "did:aithos:zGranteeApp" },
      scopes: ["data.contacts.read"],
      ttlSeconds: 3600,
    });

    const v = verifyMandate(mandate, ownerDoc, new Date());
    assert.ok(v.ok, `legit mandate should verify, got: ${v.errors?.join("; ")}`);
  });

  it("a mandate CLAIMING the owner but signed by an attacker is REJECTED", () => {
    const owner = createIdentity("owner", "Owner");
    const ownerDoc = didDocFor(owner);
    const attacker = createIdentity("attacker", "Attacker");

    // The attacker mints a perfectly valid mandate under THEIR own identity…
    const forged = createMandate({
      issuer: attacker,
      actorSphere: "self",
      grantee: { id: "did:aithos:zGranteeApp" },
      scopes: ["data.contacts.read"],
      ttlSeconds: 3600,
    });

    // …then relabels it to claim the OWNER as issuer (the move the deleted
    // override used to make succeed by also substituting the verification key).
    // The signature is still the attacker's.
    forged.issuer = rootDid(owner);
    forged.issued_by_key = sphereDidUrl(owner, "self");
    forged.signature.key = sphereDidUrl(owner, "self");

    // Verified against the owner's REAL doc — no caller override — the
    // attacker's signature does not match the owner's self-sphere key.
    const v = verifyMandate(forged, ownerDoc, new Date());
    assert.equal(v.ok, false, "forged mandate must be rejected");
  });

  it("the resolver exposes no override hook (regression guard)", async () => {
    const resolver = await import("../lambda/auth/did-resolver.js");
    assert.equal(
      (resolver as Record<string, unknown>).withSphereOverride,
      undefined,
      "withSphereOverride must stay removed",
    );
  });
});
