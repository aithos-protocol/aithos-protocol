// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Author abstraction (§v0.2.1).
 *
 * Who is writing to an ethos? Two cases exist and they look very different
 * at the signing layer:
 *
 *   - OwnerAuthor   — the subject themselves, with all four sealed seeds
 *                     loaded into memory. Signs with the sphere key of the
 *                     target zone.
 *   - DelegateAuthor — an agent operating under a signed mandate, holding
 *                     ONLY their own Ed25519 delegate seed (never a sphere
 *                     seed). Signs with the delegate key; every signed
 *                     artefact carries `authorized_by = mandate.id`.
 *
 * Every mutation API that used to take an `Identity` now takes an `Author`.
 * This unifies the call site for owner and delegate code paths and forces
 * delegate-specific validation (scope match, sphere match, validity window)
 * to happen exactly once, at the construction of the DelegateAuthor.
 *
 * The rest of the library consumes the abstraction through three helpers:
 *
 *   - `authorSubjectDid(author)`   — who the write is on behalf of
 *   - `authorHandle(author)`        — the local handle used for paths
 *   - `authorGammaSigner(author, zone)` — `GammaSigner` bound to the right key
 *
 * See `delegate-e2e.test.ts` for the acceptance spec.
 */

import * as ed from "@noble/ed25519";

import type { Identity, IdentityMetadata } from "./identity.js";
import type { Sphere } from "./did.js";
import { ed25519PublicKeyToMultibase, rootDid } from "./did.js";
import type { Mandate } from "./mandate.js";
import {
  type GammaSigner,
  sphereGammaSigner,
  delegateGammaSigner,
} from "./gamma.js";

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * The subject themselves, fully decrypted. An OwnerAuthor can read and write
 * any zone and sign with any sphere key.
 */
export interface OwnerAuthor {
  kind: "owner";
  identity: Identity;
}

/**
 * An agent acting under a mandate. Holds only the delegate Ed25519 seed plus
 * the subject's public metadata — never a sphere seed.
 */
export interface DelegateAuthor {
  kind: "delegate";
  /** Public metadata of the subject (did.json-derived; works on tracked installs). */
  subject: IdentityMetadata;
  /** 32-byte Ed25519 seed the delegate uses to sign. Never leaves this process. */
  seed: Uint8Array;
  /** Multibase (z-prefixed, 0xed01 multicodec) pubkey matching `seed`. */
  pubkeyMultibase: string;
  /** The signed mandate authorising this agent's writes/reads. */
  mandate: Mandate;
}

export type Author = OwnerAuthor | DelegateAuthor;

/* -------------------------------------------------------------------------- */
/*  Constructors                                                              */
/* -------------------------------------------------------------------------- */

/** Wrap a fully-loaded Identity as an OwnerAuthor. Always succeeds. */
export function ownerAuthor(identity: Identity): OwnerAuthor {
  return { kind: "owner", identity };
}

export interface DelegateAuthorInput {
  subject: IdentityMetadata;
  seed: Uint8Array;
  pubkeyMultibase: string;
  mandate: Mandate;
}

/**
 * Construct a DelegateAuthor, validating that:
 *   - the seed produces the claimed pubkey
 *   - the pubkey matches `mandate.grantee.pubkey` (if set)
 *   - the mandate was issued by the subject we're going to act on behalf of
 *
 * Scope/sphere/window checks are deferred to the moment of use
 * (`authorGammaSigner`, `assertDelegateCanWrite`, `authorCanRead`) so that
 * one DelegateAuthor can be reused across multiple operations.
 */
export function delegateAuthor(input: DelegateAuthorInput): DelegateAuthor {
  if (input.seed.length !== 32) {
    throw new Error(
      `delegateAuthor: seed must be 32 bytes (got ${input.seed.length})`,
    );
  }
  const pub = ed.getPublicKey(input.seed);
  const recomputed = ed25519PublicKeyToMultibase(pub);
  if (recomputed !== input.pubkeyMultibase) {
    throw new Error(
      `delegateAuthor: seed does not match pubkeyMultibase ` +
        `(recomputed ${recomputed}, got ${input.pubkeyMultibase})`,
    );
  }
  if (
    input.mandate.grantee.pubkey !== undefined &&
    input.mandate.grantee.pubkey !== input.pubkeyMultibase
  ) {
    throw new Error(
      `delegateAuthor: pubkeyMultibase (${input.pubkeyMultibase}) does not ` +
        `match mandate.grantee.pubkey (${input.mandate.grantee.pubkey})`,
    );
  }
  if (input.mandate.issuer !== input.subject.did) {
    throw new Error(
      `delegateAuthor: mandate.issuer (${input.mandate.issuer}) does not ` +
        `match subject did (${input.subject.did})`,
    );
  }
  return {
    kind: "delegate",
    subject: input.subject,
    seed: input.seed,
    pubkeyMultibase: input.pubkeyMultibase,
    mandate: input.mandate,
  };
}

/* -------------------------------------------------------------------------- */
/*  Accessors                                                                 */
/* -------------------------------------------------------------------------- */

/** Subject DID the author is writing on behalf of. */
export function authorSubjectDid(author: Author): string {
  return author.kind === "owner" ? rootDid(author.identity) : author.subject.did;
}

/** Local handle under AITHOS_HOME the author is writing to. */
export function authorHandle(author: Author): string {
  return author.kind === "owner" ? author.identity.handle : author.subject.handle;
}

/** The mandate id to record in `authorized_by`, or undefined for owner signs. */
export function authorMandateId(author: Author): string | undefined {
  return author.kind === "delegate" ? author.mandate.id : undefined;
}

/* -------------------------------------------------------------------------- */
/*  Authorization checks                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Throw unless the delegate's mandate authorises a write to `zone` at `now`.
 * Owner writes always pass.
 */
export function assertCanWrite(
  author: Author,
  zone: Sphere,
  now: Date = new Date(),
): void {
  if (author.kind === "owner") return;
  const { mandate } = author;
  const scope = `ethos.write.${zone}` as const;
  if (!mandate.scopes.includes(scope)) {
    throw new Error(
      `Delegate mandate ${mandate.id} does not carry ${scope} ` +
        `(scopes: [${mandate.scopes.join(", ")}])`,
    );
  }
  if (mandate.actor_sphere !== zone) {
    throw new Error(
      `Delegate mandate ${mandate.id} actor_sphere=${mandate.actor_sphere} ` +
        `does not match target zone=${zone}`,
    );
  }
  const nb = new Date(mandate.not_before).getTime();
  const na = new Date(mandate.not_after).getTime();
  const t = now.getTime();
  if (t < nb) {
    throw new Error(
      `Delegate mandate ${mandate.id} is not yet valid (not_before=${mandate.not_before})`,
    );
  }
  if (t >= na) {
    throw new Error(
      `Delegate mandate ${mandate.id} has expired (not_after=${mandate.not_after})`,
    );
  }
}

/**
 * True if the author is authorised to read the given zone. Owner always yes;
 * delegate iff the mandate carries `ethos.read.<zone>`, `ethos.write.<zone>`,
 * or `ethos.read.all`. Does NOT enforce the validity window — reading stale
 * plaintext that's already on disk is a separate concern from new writes.
 */
export function authorCanRead(author: Author, zone: Sphere): boolean {
  if (author.kind === "owner") return true;
  const { scopes } = author.mandate;
  return (
    scopes.includes(`ethos.read.${zone}`) ||
    scopes.includes(`ethos.write.${zone}`) ||
    scopes.includes("ethos.read.all")
  );
}

/* -------------------------------------------------------------------------- */
/*  Signer factories                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Build a GammaSigner appropriate for the author and target zone.
 *
 * For owners: the sphere key of `zone` (mirrors legacy behaviour).
 * For delegates: the delegate key, with `mandateId` set — this is what
 * causes `buildGammaEntry` to emit the `authorized_by` field.
 *
 * Enforces `assertCanWrite` before returning, so callers can assume the
 * signer is legitimate for the zone.
 */
export function authorGammaSigner(author: Author, zone: Sphere): GammaSigner {
  assertCanWrite(author, zone);
  if (author.kind === "owner") {
    return sphereGammaSigner(author.identity, zone);
  }
  return delegateGammaSigner(author.mandate.id, author.seed, author.pubkeyMultibase);
}
