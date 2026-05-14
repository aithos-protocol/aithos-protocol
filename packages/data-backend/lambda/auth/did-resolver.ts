// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * DID resolver for the data sub-protocol PDS.
 *
 * Sub-jalon 3.2a scope: supports `did:key:…` only. The pubkey is
 * encoded multibase-multicodec in the identifier itself, so resolution
 * is fully offline and deterministic — no network call needed.
 *
 * Sub-jalon 3.2b: extends with `did:aithos:…` via HTTP fetch to the
 * upstream platform endpoint, with in-memory cache + TTL.
 *
 * The protocol's existing helper `multibaseToEd25519PublicKey` (from
 * @aithos/protocol-core/did) handles the byte-level decoding. We build
 * a synthetic DID document from a `did:key:` so downstream code in
 * @aithos/protocol-core/envelope sees the standard shape.
 */

import { multibaseToEd25519PublicKey, ed25519PublicKeyToMultibase } from "@aithos/protocol-core/did";
import type { DidDocument } from "@aithos/protocol-core/identity";

import { RpcError } from "../jsonrpc.js";

/**
 * Resolve a DID to its current DID document.
 *
 * Returns `null` when the DID is well-formed but cannot be resolved
 * (per the verifyEnvelope contract — callers map null to a -32011 error).
 * Throws an RpcError when the DID itself is malformed.
 */
export async function resolveIssuerDoc(did: string): Promise<DidDocument | null> {
  if (typeof did !== "string" || did.length === 0) {
    throw new RpcError(-32010, "invalid envelope.iss: empty");
  }

  if (did.startsWith("did:key:")) {
    return resolveDidKey(did);
  }

  if (did.startsWith("did:aithos:")) {
    // Sub-jalon 3.2b: HTTP fetch + cache. For now, signal "unresolvable"
    // — the caller will surface this as -32011 "cannot resolve DID document".
    return null;
  }

  throw new RpcError(
    -32010,
    `unsupported DID method in iss: ${did}. v0.1 PDS resolves did:key only (did:aithos coming in Sub-jalon 3.2b).`,
  );
}

/**
 * Decode a `did:key:z6Mk…` into a synthetic DID document.
 *
 * Format: `did:key:<multibase(multicodec-prefix ‖ raw_pubkey)>`.
 * For Ed25519 the multicodec prefix is `0xed 0x01`, decoded inside
 * multibaseToEd25519PublicKey.
 *
 * The DID document is built so that downstream code in
 * verifyEnvelope (which expects DidDocument.verificationMethod[].id
 * equal to envelope.proof.verificationMethod) finds the key at the
 * expected URL forms.
 */
function resolveDidKey(did: string): DidDocument {
  const multibase = did.slice("did:key:".length);
  let pubkey: Uint8Array;
  try {
    pubkey = multibaseToEd25519PublicKey(multibase);
  } catch (e) {
    throw new RpcError(
      -32010,
      `invalid did:key encoding: ${(e as Error).message}`,
    );
  }
  // Round-trip to canonical multibase (defends against non-canonical
  // base58 encodings the caller may have used).
  const canonicalMultibase = ed25519PublicKeyToMultibase(pubkey);
  const canonicalDid = `did:key:${canonicalMultibase}`;

  if (canonicalDid !== did) {
    throw new RpcError(
      -32010,
      `non-canonical did:key encoding: got ${did}, expected ${canonicalDid}`,
    );
  }

  // Synthesize the Aithos DidDocument shape. did:key has no native
  // metadata; we fill the Aithos extension fields with stable defaults
  // so envelope verification (which reads only `id` and
  // `verificationMethod`) is unaffected.
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${canonicalMultibase}`,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: canonicalMultibase,
      },
    ],
    keyAgreement: [],
    aithos: {
      version: "0.1.0" as const,
      created_at: "1970-01-01T00:00:00Z",
      rotated: [],
    },
  };
}
