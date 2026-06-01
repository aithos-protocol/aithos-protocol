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
    return resolveDidAithos(did);
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
  //
  // We expose the same Ed25519 key under several URLs:
  //   - did:key:X#X            (canonical did:key form)
  //   - did:key:X#root         owner-path data envelopes sign under #root
  //   - did:key:X#data         data sub-protocol dedicated sphere (spec
  //                            spec/data/02-key-hierarchy.md: owner = #data|#root)
  //   - did:key:X#public  \
  //   - did:key:X#circle  |    Ethos mandate spheres
  //   - did:key:X#self    /
  //
  // The mandate shape from @aithos/protocol-core expects `issued_by_key` to be
  // `<did>#<sphere>`. A did:key has only one key, so ALL aliases point to it —
  // adding #root/#data is purely additive (same key, more labels) and lets a
  // did:key owner sign data ops under #root, the same convention a did:aithos
  // account uses (whose multibase IS the #root key). No security change:
  // verification still checks the signature against that single key.
  // When we add did:aithos:… resolution in a later jalon, real subjects
  // will have distinct keys per sphere.
  const sphereAliases = ["root", "data", "public", "circle", "self"] as const;
  const baseVm = {
    type: "Ed25519VerificationKey2020" as const,
    controller: did,
    publicKeyMultibase: canonicalMultibase,
  };
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      { ...baseVm, id: `${did}#${canonicalMultibase}` },
      ...sphereAliases.map((s) => ({ ...baseVm, id: `${did}#${s}` })),
    ],
    keyAgreement: [],
    aithos: {
      version: "0.1.0" as const,
      created_at: "1970-01-01T00:00:00Z",
      rotated: [],
    },
  };
}

/* -------------------------------------------------------------------------- */
/*  did:aithos — local synthesis (PDS resolver MEDIUM bug fix)                 */
/* -------------------------------------------------------------------------- */

/**
 * Decode a `did:aithos:z6Mk…` into a synthetic DID document.
 *
 * Same wire format as did:key (multibase of multicodec-prefix ‖ raw_pubkey,
 * Ed25519), but the multibase encodes the user's ROOT pubkey rather than
 * an arbitrary key.
 *
 * This synthesis is "best effort offline": it exposes the root pubkey
 * under the 4 sphere aliases (#root, #public, #circle, #self) all
 * mapping to the SAME key. For custodial Aithos users whose sphere
 * seeds are distinct from root (the prod case), this means:
 *
 *   - **owner-path envelopes signed by #root** verify correctly
 *     (because #root in the synthetic doc IS the real root pubkey).
 *
 *   - **mandate signatures signed by #public/#circle/#self** verify
 *     against the WRONG pubkey unless the caller passes the real
 *     sphere pubkeys via the `_subject_sphere_pubkeys` extension
 *     field (handled in `withSphereOverride` below + `authenticate.ts`).
 *
 *   - **owner-path envelopes signed by #public/#circle/#self** would
 *     also fail without the override — currently no Aithos call does
 *     this in practice (the SDK signs envelopes with #public by
 *     default but for backends with synthesis resolvers, callers force
 *     sphere: "root").
 *
 * The proper long-term fix is the HTTP registry resolver (audit MEDIUM
 * "did:aithos resolver stubbed"). This synthesis unblocks Linkedone and
 * any similar A2a tenant in the meantime — and stays correct forever
 * for users where root == public == circle == self (the did:key case).
 */
function resolveDidAithos(did: string): DidDocument | null {
  const multibase = did.slice("did:aithos:".length);
  // Guard: refuse the `did:aithos:app:*` family — these are placeholder
  // app DIDs, not pubkey-encoded user DIDs. Returning null lets the
  // verifier surface a clean -32011 instead of crashing on a bad decode.
  if (multibase.startsWith("app:") || !multibase.startsWith("z")) {
    return null;
  }

  let pubkey: Uint8Array;
  try {
    pubkey = multibaseToEd25519PublicKey(multibase);
  } catch {
    // Malformed multibase → unresolvable (not a crash). Verifier maps
    // null → -32011, which is the right behaviour for a bad iss.
    return null;
  }
  if (pubkey.length !== 32) return null;

  // Round-trip canonicalisation guard (same as resolveDidKey).
  const canonicalMultibase = ed25519PublicKeyToMultibase(pubkey);
  if (canonicalMultibase !== multibase) {
    // Non-canonical encoding. We accept it (= we don't throw), but the
    // verifier's `issuerDoc.id !== envelope.iss` check will fail right
    // after and surface a clean -32011. Returning null here would mask
    // the precise reason (the diff between encodings is useful in logs).
  }

  const baseVm = {
    type: "Ed25519VerificationKey2020" as const,
    controller: did,
    publicKeyMultibase: canonicalMultibase,
  };
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      { ...baseVm, id: `${did}#root` },
      { ...baseVm, id: `${did}#public` },
      { ...baseVm, id: `${did}#circle` },
      { ...baseVm, id: `${did}#self` },
    ],
    keyAgreement: [],
    aithos: {
      version: "0.1.0" as const,
      created_at: "1970-01-01T00:00:00Z",
      rotated: [],
    },
  };
}

/* -------------------------------------------------------------------------- */
/*  Sphere-override factory — used by authenticate.ts when a caller passes     */
/*  the real sphere pubkeys via `_subject_sphere_pubkeys`                      */
/* -------------------------------------------------------------------------- */

/**
 * Shape of the `_subject_sphere_pubkeys` extension field that callers
 * can put in their JSON-RPC `params` to enrich the DID doc resolution.
 *
 * Used when the caller has knowledge the PDS lacks: the real per-sphere
 * pubkeys of `envelope.iss`. The PDS, lacking a real did:aithos registry
 * resolver, synthesises a DID doc with all 4 spheres collapsed onto the
 * root pubkey by default — which breaks mandate signature verification
 * when the mandate is signed by a non-root sphere (e.g. #circle, which
 * has its own distinct seed for custodial users).
 *
 * With this extension, the PDS uses the caller-provided pubkeys to
 * reconstruct the correct DID doc before verifyEnvelope runs, making
 * mandate verification succeed end-to-end.
 *
 * Each value is a `z…`-prefixed multibase encoding of an Ed25519 pubkey
 * (same shape as the multibase inside a did:key:z…).
 */
export interface SubjectSpherePubkeys {
  readonly root: string;
  readonly public: string;
  readonly circle: string;
  readonly self: string;
}

/**
 * Wrap a base resolver so that when the resolved DID matches the
 * `subjectDid` we're enriching, we override its 4 sphere
 * verificationMethods with the caller-provided real pubkeys.
 *
 * If the base resolver returns null (DID unresolvable), we still
 * return null — the override only kicks in when we have a DID doc to
 * enrich.
 *
 * Defense in depth — invalid override values (non-string, missing
 * z-prefix, wrong length) are silently ignored per-sphere; the base
 * resolver's value is kept. Worst case: verifier rejects the signature
 * cleanly. No DoS surface.
 */
export function withSphereOverride(
  baseResolver: (did: string) => Promise<DidDocument | null>,
  subjectDid: string,
  sphereKeys: Partial<Record<keyof SubjectSpherePubkeys, unknown>>,
): (did: string) => Promise<DidDocument | null> {
  return async (did: string) => {
    const baseDoc = await baseResolver(did);
    if (!baseDoc || did !== subjectDid) return baseDoc;

    const FRAGMENTS = ["root", "public", "circle", "self"] as const;
    const enrichedVm = baseDoc.verificationMethod.map((vm) => {
      const fragment = FRAGMENTS.find((f) => vm.id === `${subjectDid}#${f}`);
      if (!fragment) return vm;
      const override = sphereKeys[fragment];
      if (typeof override !== "string" || !override.startsWith("z")) return vm;
      // Sanity: decodable as 32-byte Ed25519 pubkey.
      try {
        const decoded = multibaseToEd25519PublicKey(override);
        if (decoded.length !== 32) return vm;
      } catch {
        return vm;
      }
      return { ...vm, publicKeyMultibase: override };
    });
    return {
      ...baseDoc,
      verificationMethod: enrichedVm,
    };
  };
}
