// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AithosStorage — backend abstraction for the protocol primitives.
 *
 * A single interface that both local (filesystem) and remote (platform API)
 * backends implement. The MCP server and any future protocol-speaking host
 * talks to one of these instead of importing filesystem helpers directly.
 *
 * Design choices
 * --------------
 *
 *   - **Resource-oriented, not path-oriented.** Methods take handles, zones,
 *     and ids. They never return, accept, or leak filesystem paths. A
 *     path-returning utility is fs-only (see `storage.ts` / `ethos.ts` for
 *     the direct helpers the filesystem impl uses).
 *
 *   - **Async throughout.** The filesystem impl wraps synchronous fs calls;
 *     a remote impl naturally performs network I/O. Callers must not assume
 *     synchronous semantics.
 *
 *   - **High-level semantic writes.** `addSection` / `modifySection` are
 *     exposed as operations rather than as blob writes. The filesystem impl
 *     orchestrates the standard flow (build signed gamma entry → append log
 *     → re-sign manifest). A remote impl signs a §11 envelope for the
 *     matching method and lets the platform do the actual persistence with
 *     the hosted subject key. Callers (MCP tools, CLI) see the same shape
 *     in both worlds.
 *
 *   - **Envelope verification hooks are kept pure.** Replay cache, revocation
 *     lookup, and issuer-DID resolution are passed to `verifyEnvelope`
 *     directly by the server transport — they are not reached through this
 *     interface. Storage does not implement the signed-envelope machinery;
 *     it is a _source_ of the data (mandates, DID documents) that machinery
 *     reads.
 *
 *   - **v0.1 surface is intentionally small.** Gamma log reads, tombstones,
 *     bundle pack/install, and mandate issuance are not yet part of the
 *     interface. They land as the platform needs them; the filesystem impl
 *     will always expose its direct module helpers as an escape hatch so
 *     protocol-core clients are never blocked waiting for an interface
 *     widening.
 */

import type { Sphere } from "./did.js";
import type {
  Identity,
  IdentityMetadata,
  DidDocument,
} from "./identity.js";
import type {
  Manifest,
  ZoneDoc,
  Section,
  AddSectionArgs,
  ModifySectionArgs,
  DelegateSigner,
  VerifyEthosResult,
} from "./ethos.js";
import type { Mandate, Revocation } from "./mandate.js";
import type { GammaEntry } from "./gamma.js";

/* -------------------------------------------------------------------------- */
/*  Write-auth context                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Authorization context for a write. Exactly one of `identity` / `delegate`
 * must be supplied by the caller; the storage backend may additionally enforce
 * policy (e.g. a remote backend rejects `identity`-signed writes when the
 * subject keys live server-side).
 */
export interface WriteAuth {
  /**
   * Owner-signed write. The subject's loaded Identity (with sphere secret
   * keys) is used to sign the new manifest and the gamma entry.
   */
  identity?: Identity;
  /**
   * Delegate-signed write. The gamma entry is signed with the delegate key;
   * the subject still signs the manifest either because the backend holds
   * the subject key (remote) or because the owner is online alongside the
   * delegate (local).
   */
  delegate?: DelegateSigner;
}

/* -------------------------------------------------------------------------- */
/*  Write-result shape                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Result returned by `addSection` / `modifySection`. The shape is stable
 * across backends: the MCP tool projects a subset of this to the caller.
 */
export interface SectionWriteResult {
  readonly section: {
    readonly id: string;
    readonly title: string;
    readonly gamma_ref: string;
    readonly tags: readonly string[];
  };
  readonly manifest: Manifest;
  /**
   * The signed gamma-log entry produced by the write. Present on v0.2 writes.
   * Absent on v0.3 (per-section) writes for now: the new edition stamps a fresh
   * `gamma_ref` on the section, but the signed gamma-log append for v0.3 lands
   * with the gamma-v0.3 work — until then the section's `gamma_ref` is the
   * provenance anchor.
   */
  readonly gammaEntry?: GammaEntry;
}

/**
 * Result of a section delete. The section is removed from the live edition;
 * `gammaEntry` follows the same v0.2-present / v0.3-pending rule as
 * {@link SectionWriteResult}.
 */
export interface SectionDeleteResult {
  readonly sectionId: string;
  readonly deletedTitle?: string;
  readonly manifest: Manifest;
  readonly gammaEntry?: GammaEntry;
}

/* -------------------------------------------------------------------------- */
/*  Per-section read shapes (v0.3)                                             */
/* -------------------------------------------------------------------------- */

/**
 * One row of a zone's section index — id + title + provenance, WITHOUT the
 * body. For the encrypted `self` index, `title` is present only when the reader
 * is entitled to that section (otherwise `title_hidden` is true and `title` is
 * omitted), exactly as a keyless host sees it. This is the cheap discovery
 * surface: fetch the index, then fetch the bodies you actually need by id.
 */
export interface SectionIndexEntry {
  readonly section_id: string;
  readonly title?: string;
  readonly tags?: readonly string[];
  readonly title_hidden: boolean;
  readonly gamma_ref: string;
}

/**
 * Result of a per-id section fetch. `accessible` is false (with a `reason`) when
 * the section is absent or the reader is not a recipient of its DEK.
 */
export interface SectionFetchResult {
  readonly zone: Sphere;
  readonly section_id: string;
  readonly accessible: boolean;
  readonly section?: Section;
  readonly reason?: string;
}

/** Options for the per-section reads: a subject identity enables decryption. */
export interface SectionReadOpts {
  identity?: Identity;
  manifest?: Manifest;
}

/* -------------------------------------------------------------------------- */
/*  AithosStorage                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The minimum surface every Aithos backend must provide.
 *
 * The filesystem backend (`FilesystemStorage`, landing in B-2b) satisfies
 * this interface by reading/writing under `$AITHOS_HOME`. A platform-side
 * remote backend satisfies it by signing §11 envelopes and calling
 * `api.aithos.*`. The MCP server in `packages/mcp` accepts any
 * implementation via dependency injection.
 */
export interface AithosStorage {
  /* -------- identity domain -------------------------------------------- */

  /** Enumerate every handle this backend can serve. */
  listHandles(): Promise<string[]>;

  /**
   * Public metadata (DID, display name, sphere pubkeys, tracked flag). Works
   * for both owned and tracked identities. Throws if the handle is unknown.
   */
  loadIdentityMetadata(handle: string): Promise<IdentityMetadata>;

  /**
   * Load the full Identity including sphere secret keys. Throws
   * `TrackedIdentityError` if the backend only holds tracked (public-key)
   * data for this handle — remote backends will always throw for handles
   * they don't have the secret material for.
   */
  loadIdentity(handle: string): Promise<Identity>;

  /** The signed DID document attached to this handle. */
  loadDidDocument(handle: string): Promise<DidDocument>;

  /**
   * `true` if the backend holds only public DID+manifest state for this
   * handle (no sphere secret keys). Cheap check; does not decrypt.
   */
  isTrackedIdentity(handle: string): Promise<boolean>;

  /* -------- ethos domain (reads) --------------------------------------- */

  /** Current signed ethos manifest. */
  readManifest(handle: string): Promise<Manifest>;

  /**
   * Decrypted ZoneDoc. For `public`, no identity is required. For
   * `circle` / `self`, the caller provides (or the backend loads) an
   * Identity capable of decrypting the sealed zone.
   *
   * Throws `TrackedIdentityError` when the backend cannot decrypt (e.g. a
   * remote backend asked for a zone it has no key for).
   */
  readZoneDoc(
    handle: string,
    zone: Sphere,
    opts?: { identity?: Identity; manifest?: Manifest },
  ): Promise<ZoneDoc>;

  /**
   * Raw on-the-wire bytes for a zone as stored by this backend. For the
   * public zone that is plaintext markdown; for circle / self it is the
   * sealed (ciphertext) envelope. Used by resource templates that surface
   * the raw artefact without interpreting it.
   */
  readZoneBytes(handle: string, zone: Sphere): Promise<Uint8Array>;

  /* -------- ethos domain (per-section reads, v0.3) --------------------- */

  /**
   * The section index of a zone: id + title + gamma_ref per section, WITHOUT
   * decrypting any body. For the encrypted `self` index, titles appear only for
   * sections the reader is entitled to (see {@link SectionIndexEntry}); pass an
   * `identity` in `opts` to decrypt the index. This is the discovery surface a
   * host fetches first, then it reads only the bodies it needs by id.
   *
   * On a v0.2 (monolithic) install the whole zone is decrypted internally to
   * synthesize the index — the cost win is a v0.3 property.
   */
  readSectionIndex(
    handle: string,
    zone: Sphere,
    opts?: SectionReadOpts,
  ): Promise<SectionIndexEntry[]>;

  /**
   * Fetch one or more sections by id, decrypting ONLY those blobs (the v0.3
   * payoff — no full-zone decryption). Ids are located across all zones (or the
   * single zone in `opts.zone`); each result reports whether it was accessible.
   * Order matches the input `ids`.
   */
  readSections(
    handle: string,
    ids: string[],
    opts?: SectionReadOpts & { zone?: Sphere },
  ): Promise<SectionFetchResult[]>;

  /* -------- ethos domain (writes) -------------------------------------- */

  /**
   * Append a new section to a zone. See {@link SectionWriteResult}.
   *
   * Filesystem backend: runs the full `core.addSection` orchestration
   * (sign gamma entry → append log → re-sign manifest) locally. Remote
   * backend: signs a `ethos.add_section` §11 envelope with `auth.delegate`
   * (or the configured principal key) and hands it to the platform, which
   * runs the same orchestration server-side.
   */
  addSection(
    args: Omit<AddSectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult>;

  /** Modify a section in place. Semantics mirror {@link addSection}. */
  modifySection(
    args: Omit<ModifySectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult>;

  /**
   * Delete a section from its zone. v0.2: emits a signed `section.delete` gamma
   * entry. v0.3: drops the section's blob and writes a new per-section edition.
   * Owner or delegate (auth semantics mirror {@link addSection}).
   */
  deleteSection(
    args: { handle: string; zone: Sphere; sectionId: string; reason?: string },
    auth: WriteAuth,
  ): Promise<SectionDeleteResult>;

  /* -------- ethos verification ----------------------------------------- */

  /**
   * Full ethos integrity check: zone signatures, manifest signature,
   * edition-history link, and gamma anchor. Pass `identity = null` to
   * skip decryption of circle / self and verify only the public artefacts.
   */
  verifyEthos(
    handle: string,
    identity: Identity | null,
    didDoc: DidDocument,
  ): Promise<VerifyEthosResult>;

  /* -------- mandate domain --------------------------------------------- */

  /** Load a mandate by id. */
  loadMandate(id: string): Promise<Mandate>;

  /**
   * Resolve the active revocation for a mandate, if any. Returns `null`
   * when the mandate is not revoked. Used by `verifyEnvelope` and by
   * `verifyMandate` callers that want to honor the local revocation store.
   */
  findRevocation(mandateId: string): Promise<Revocation | null>;

  /* -------- backend-instance state ------------------------------------- */

  /**
   * The handle this backend resolves by default when a tool call omits
   * `handle`. Returns `null` when no default is set (CLI never ran `init`,
   * remote backend without a pinned principal, etc.).
   */
  defaultHandle(): Promise<string | null>;
}
