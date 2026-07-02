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
import { verifyDidDocument } from "@aithos/protocol-core/identity";

import { RpcError } from "./errors.js";

/* -------------------------------------------------------------------------- */
/*  did:aithos real resolution — fetch the published DID document             */
/* -------------------------------------------------------------------------- */

/**
 * Base URL of the Ethos identity registry that serves `aithos.get_identity`
 * (returns the subject's signed did.json). Defaults to the public read API.
 * Override via the ETHOS_RESOLVER_URL env (CDK) for staging/preview.
 */
const ETHOS_RESOLVER_URL = (process.env.ETHOS_RESOLVER_URL ?? "https://api.aithos.be").replace(/\/$/, "");
const RESOLVE_TIMEOUT_MS = 3_000;
const RESOLVE_TTL_MS = 5 * 60_000; // positive cache: a published doc rarely changes
// Negative cache: covers a genuinely-unpublished subject OR a transient miss.
// Kept SHORT because the root-only synthesis has no #data sphere: caching it too
// long turns a sub-second propagation lag on a freshly-onboarded v0.4 identity
// (published did.json not yet readable) into a guaranteed outage window — every
// #data-signed write returns -32011 "#data not found" until the entry expires.
// 3s lets a propagation race self-heal on the next write instead of ~30s. A real
// published doc is served from the 5-min positive cache, so this only affects the
// unpublished/lagging path. (F2 — first-write -32011 after onboarding.)
const RESOLVE_NEG_TTL_MS = 3_000;

interface CacheEntry {
  doc: DidDocument | null;
  expiresAt: number;
}
const didDocCache = new Map<string, CacheEntry>();

/**
 * Drop the cached DID document for `did`, forcing the next resolution to
 * re-fetch the published did.json. The router calls this before verifying a
 * MANDATE-bearing envelope so the subject's revocation epoch
 * (`aithos.mandates_void_before`) is seen immediately — the positive cache
 * (5 min) would otherwise delay a `revokeAll()` kill-switch on the PDS by up to
 * the TTL (audit B5; mirrors the platform read path that never caches the
 * mandate-verification did.json, aithos-provider commit 5c7ef1e).
 */
export function invalidateDidCache(did: string): void {
  didDocCache.delete(did);
}

/**
 * Fetch the published, root-signed did.json for a did:aithos subject from the
 * Ethos registry. Returns the inner DidDocument, or null on not-found / any
 * transport error (caller falls back to the root-only synthesis). The caller
 * is responsible for verifying the doc's root proof — we do NOT trust the
 * endpoint, only the self-certifying root signature inside the doc.
 */
async function fetchPublishedDidDoc(did: string): Promise<DidDocument | null> {
  try {
    const res = await fetch(`${ETHOS_RESOLVER_URL}/mcp/primitives/read`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "pds-resolve",
        method: "aithos.get_identity",
        params: { did },
      }),
      signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as {
      result?: { object?: unknown };
      error?: unknown;
    };
    if (json.error || !json.result) return null; // -32020 NOT_FOUND etc.
    const doc = json.result.object;
    if (!doc || typeof doc !== "object") return null;
    return doc as DidDocument;
  } catch {
    // Network error, timeout, malformed JSON → unresolvable via registry.
    return null;
  }
}

/**
 * Root-only synthesis: expose the root pubkey (decoded from the DID's own
 * multibase) under #root + the three Ethos sphere aliases. Used when the
 * subject has no published did.json yet (or the registry is unreachable), so
 * `#root`-signed envelopes always verify (self-certifying). A subject whose
 * real sphere keys differ from root must publish their did.json — the resolver
 * then uses the real per-sphere keys. There is no caller-supplied override.
 */
function synthesizeDidAithosFromRoot(
  did: string,
  canonicalMultibase: string,
): DidDocument {
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

/**
 * Merge the implicit, self-certifying `#root` verification method (the DID's
 * own multibase) into a published DID document. The published doc lists the
 * real `#public`/`#circle`/`#self`/`#data` keys but NOT `#root` (root is
 * implicit per spec §1.5), so without this an envelope signed under `#root`
 * would not resolve.
 */
function withRootVm(
  did: string,
  canonicalMultibase: string,
  published: DidDocument,
): DidDocument {
  const hasRoot = published.verificationMethod.some(
    (vm) => vm.id === `${did}#root`,
  );
  if (hasRoot) return published;
  return {
    ...published,
    verificationMethod: [
      {
        id: `${did}#root`,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: canonicalMultibase,
      },
      ...published.verificationMethod,
    ],
  };
}

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
 * Resolution order:
 *
 *   1. Fetch the subject's PUBLISHED did.json from the Ethos registry and
 *      verify its root proof. If valid, use its REAL per-sphere keys
 *      (#public/#circle/#self/#data) + the implicit #root. This is the path
 *      that makes mandate signatures (signed by a non-root sphere) verify
 *      against the subject's true key — and the only trusted source of sphere
 *      keys (no caller-supplied override exists anymore).
 *
 *   2. If no valid published doc (unpublished subject / registry unreachable),
 *      fall back to a root-only synthesis: every sphere alias maps to the root
 *      pubkey decoded from the DID itself. `#root`-signed owner envelopes still
 *      verify; mandates signed by a distinct sphere will NOT verify until the
 *      subject publishes their did.json.
 */
async function resolveDidAithos(did: string): Promise<DidDocument | null> {
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

  // Round-trip canonicalisation: the #root pubkey the verifier will need, and
  // the fallback synthesis key.
  const canonicalMultibase = ed25519PublicKeyToMultibase(pubkey);

  const now = Date.now();
  const cached = didDocCache.get(did);
  if (cached && cached.expiresAt > now) return cached.doc;

  // Real resolution: fetch the published, root-signed did.json from the Ethos
  // registry. Trust is anchored in the doc's OWN root proof (self-certifying),
  // NOT in the endpoint — a compromised registry cannot forge sphere keys
  // because the forged doc would fail verifyDidDocument.
  const published = await fetchPublishedDidDoc(did);
  let resolved: DidDocument | null;
  let ttl: number;
  if (published && published.id === did && verifyDidDocument(published)) {
    // Real per-sphere keys (#public/#circle/#self/#data) + implicit #root.
    resolved = withRootVm(did, canonicalMultibase, published);
    ttl = RESOLVE_TTL_MS;
  } else {
    // No valid published doc (unpublished subject, registry unreachable, or a
    // doc that failed its root proof) → root-only synthesis. `#root`-signed
    // owner envelopes still verify; non-root spheres need the published doc.
    resolved = synthesizeDidAithosFromRoot(did, canonicalMultibase);
    ttl = RESOLVE_NEG_TTL_MS;
  }
  didDocCache.set(did, { doc: resolved, expiresAt: now + ttl });
  return resolved;
}
