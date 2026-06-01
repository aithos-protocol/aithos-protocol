// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Gamma log v0.3 — per-entry envelope format with decoupled append / read.
 *
 * See `spec/drafts/gamma-v0.3-per-entry-envelopes.md` for the normative
 * description. Summary of the v0.2 → v0.3 change:
 *
 *   - v0.2: the whole JSONL log was sealed under a single DEK, wrapped to
 *     the subject's three sphere keys (+ any delegate whom `issueMandateWith
 *     Rewrap` had added). Possession of the DEK implied read of the entire
 *     history, including pre-mandate entries. This coupled `ethos.write.*`
 *     with gamma read access.
 *   - v0.3: every entry carries its own 32-byte `entry_key`, sealed to each
 *     reader's X25519 pubkey via one wrap per reader. Appending requires
 *     only the subject's public metadata (`manifest.gamma.readers`) and the
 *     writer's Ed25519 signing key — no prior plaintext is decrypted.
 *     Reading requires being on the `envelopes` list of an entry.
 *
 *     Append-only-for-writers is the core cryptographic property: a
 *     delegate with `ethos.write.<zone>` but NO `gamma.read` can append
 *     correct signed entries without being able to decrypt any prior
 *     history.
 *
 * Storage layout (on-disk):
 *
 *   ~/.aithos/identities/<handle>/ethos/gamma/gamma.jsonl.enc
 *
 * File shape:
 *
 *   {
 *     "aithos-gamma-file": "0.3.0",
 *     "entries": [
 *       { "format": "v0.3",
 *         "payload_ct": "base64url(XChaCha20-Poly1305(plaintext, entry_key, nonce))",
 *         "nonce": "base64url(24 bytes)",
 *         "envelopes": [ { recipient, alg, ephemeral_public, wrap_nonce, wrapped_key }, ... ],
 *         "public_header": {
 *           "aithos-gamma": "0.3.0",
 *           "id": "gamma_...", "at": "...", "subject_did": "...", "zone": "...",
 *           "op": "section.add", "target": { ... },
 *           "prev_gamma_hash": "sha256:...",
 *           "prev_section_gamma"?: "gamma_...",
 *           "readers_hash": "sha256:...",
 *           "hash": "sha256:..."
 *         },
 *         "signature": { "alg": "ed25519", "key": "...", "authorized_by"?: "mandate_...", "value": "..." }
 *       },
 *       ...
 *     ]
 *   }
 *
 * Clean-cut: the v0.2 file format is not read. An existing v0.2 log cannot
 * be migrated by v0.3 code — the repo is pre-release, all E2E flows start
 * from `rm -rf`, and migration tooling would add cryptographic surface area
 * for no practical gain.
 */

import { join } from "node:path";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  renameSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { x25519 } from "@noble/curves/ed25519.js";
import { ulid } from "ulid";

import { canonicalize } from "./canonical.js";
import {
  type Identity,
  type DidDocument,
  base64url,
  base64urlDecode,
  edSeedToX25519Secret,
  ed25519PubToX25519Pub,
  x25519PublicFromSecret,
} from "./identity.js";
import {
  type Sphere,
  SPHERE_FRAGMENTS,
  didUrlForKex,
  multibaseToEd25519PublicKey,
  x25519PublicKeyToMultibase,
  signWithSphere,
  sphereDidUrl,
  rootDid,
} from "./did.js";
import { ensureDir, identityDir } from "./storage.js";
import type { Author } from "./author.js";

/* -------------------------------------------------------------------------- */
/*  Path helpers                                                              */
/* -------------------------------------------------------------------------- */

export function gammaDir(handle: string): string {
  return join(identityDir(handle), "ethos", "gamma");
}

export function gammaFilePath(handle: string): string {
  return join(gammaDir(handle), "gamma.jsonl.enc");
}

/* -------------------------------------------------------------------------- */
/*  Ops, ids, shared building blocks                                          */
/* -------------------------------------------------------------------------- */

/**
 * Gamma operations. Unchanged from v0.2 — only the storage format changed.
 * Unknown ops are permitted under an `x-` prefix for experimentation but MUST
 * cause a strict verifier to reject the log otherwise.
 */
export type GammaOp =
  | "section.add"
  | "section.modify"
  | "section.delete"
  | "section.reorder"
  | "zone.meta.set"
  | "section.redact"
  | "identity.rotate"
  | "mandate.issue"
  | "mandate.revoke";

export const GAMMA_VERSION = "0.3.0" as const;
export const GAMMA_FILE_VERSION = "0.3.0" as const;

export function newGammaId(): string {
  return `gamma_${ulid()}`;
}

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * The reader half of a v0.3 envelope: a stable recipient identifier and
 * their multibase X25519 public key. Writers build the per-entry envelopes
 * list from an array of these.
 *
 * This is a local mirror of the `GammaReader` shape that lives in the ethos
 * manifest (`manifest.gamma.readers`). The two types are structurally
 * compatible — ethos.ts re-exports its version for manifest typing.
 */
export interface GammaReaderKey {
  /** Stable identifier (e.g. `did:aithos:*#<sphere>` or `urn:aithos:agent:*`). */
  recipient: string;
  /** Multibase-encoded X25519 public key. */
  pubkey: string;
}

/**
 * One wrap of an entry's symmetric key, sealed to a single reader.
 */
export interface GammaEnvelope {
  recipient: string;
  alg: "x25519-hkdf-sha256-aead";
  ephemeral_public: string;
  wrap_nonce: string;
  wrapped_key: string;
}

/**
 * Cleartext header for a v0.3 entry. Carries everything needed to:
 *   - walk the chain (`prev_gamma_hash`, `hash`),
 *   - recognize the entry (`id`, `at`, `subject_did`, `zone`, `op`, `target`),
 *   - verify the reader set (`readers_hash` commits to `envelopes` — §10.3.4′).
 *
 * The header is committed by the entry hash (§10.5.1′). Tampering with any
 * header field breaks the hash, which in turn breaks the signature.
 */
export interface GammaPublicHeader {
  "aithos-gamma": typeof GAMMA_VERSION;
  id: string;
  at: string;
  subject_did: string;
  zone: Sphere;
  op: GammaOp;
  target: Record<string, unknown>;
  prev_gamma_hash: string | null;
  prev_section_gamma?: string;
  readers_hash: string; // "sha256:<hex>" — commits to the envelopes reader set
  hash: string; // "sha256:<hex>" — commits to ciphertext + nonce + this header
}

/**
 * Signature block for a v0.3 entry. Signature domain (§10.5.2′) is
 * intentionally narrow: `jcs({ hash, authorized_by: <str> | null, key })`.
 * The entry hash already commits to ciphertext + header; the signature only
 * binds "I, this signer, attest to this hash under this mandate (if any)."
 */
export interface GammaSignatureBlock {
  alg: "ed25519";
  key: string;
  authorized_by?: string;
  value: string; // base64url
}

/**
 * A full v0.3 entry as persisted on disk.
 */
export interface GammaEntryV03 {
  format: "v0.3";
  payload_ct: string; // base64url, XChaCha20-Poly1305(jcs(payload), entry_key, nonce)
  nonce: string; // base64url, 24 bytes
  envelopes: GammaEnvelope[];
  public_header: GammaPublicHeader;
  signature: GammaSignatureBlock;
}

/**
 * On-disk file envelope. Versioned so future changes can ship side-by-side.
 */
export interface GammaFileV03 {
  "aithos-gamma-file": typeof GAMMA_FILE_VERSION;
  entries: GammaEntryV03[];
}

/**
 * Logical entry returned to callers by the read APIs. Flattens header +
 * decrypted payload into a single object, matching the v0.2 `GammaEntry`
 * shape for minimum call-site churn. For entries the caller could not
 * decrypt (access-denied), `payload = {}` and `_access_denied = true`.
 *
 * IMPORTANT: Chain / hash verification MUST operate on the on-disk form
 * (`GammaEntryV03`), not on this logical view — the hash covers the
 * ciphertext, which is lost after decryption.
 */
export interface GammaEntry {
  "aithos-gamma": typeof GAMMA_VERSION;
  id: string;
  at: string;
  subject_did: string;
  zone: Sphere;
  op: GammaOp;
  target: Record<string, unknown>;
  payload: Record<string, unknown>;
  prev_gamma_hash: string | null;
  prev_section_gamma?: string;
  hash: string;
  signature: { alg: "ed25519"; key: string; value: string };
  authorized_by?: string;
  note?: string;
  /** Set on v0.3 entries the caller lacks an envelope for. Payload is {}. */
  _access_denied?: true;
}

/* -------------------------------------------------------------------------- */
/*  Readers (default set)                                                     */
/* -------------------------------------------------------------------------- */

/**
 * The three sphere X25519 pubkeys, packaged as `GammaReaderKey`s. Used when
 * bootstrapping a fresh identity's `manifest.gamma.readers` list so every
 * v0.3 entry is always sealed to the subject's own keys regardless of
 * delegate state.
 */
export function defaultGammaReaderKeys(identity: Identity): GammaReaderKey[] {
  return SPHERE_FRAGMENTS.map((s) => {
    const sk = edSeedToX25519Secret(identity[s].seed);
    const pk = x25519PublicFromSecret(sk);
    sk.fill(0);
    return {
      recipient: didUrlForKex(rootDid(identity), s),
      pubkey: x25519PublicKeyToMultibase(pk),
    };
  });
}

/**
 * Decryption handle for one reader. Used to open per-entry envelopes.
 */
export interface GammaReaderSecret {
  /** Must match an envelope's `recipient` on disk, exactly. */
  recipient: string;
  /** X25519 secret key (32 bytes). */
  x25519Secret: Uint8Array;
}

/**
 * Derive one of the subject's decryption identities (owner path). Any of the
 * three sphere-derived X25519 secrets can open an entry envelope sealed to
 * that sphere pubkey.
 */
export function subjectGammaReaderSecret(
  identity: Identity,
  zone: Sphere,
): GammaReaderSecret {
  return {
    recipient: didUrlForKex(rootDid(identity), zone),
    x25519Secret: edSeedToX25519Secret(identity[zone].seed),
  };
}

/**
 * Stable envelope-recipient label for a delegate reader. Keep in sync with
 * `ethos.ts#delegateWrapDid` for zone DEK wraps so a delegate's envelopes
 * are uniformly keyed regardless of which chunk of ciphertext they target.
 */
export function delegateGammaRecipient(
  granteeId: string,
  pubkeyMultibase: string,
): string {
  return `${granteeId}#${pubkeyMultibase}`;
}

/* -------------------------------------------------------------------------- */
/*  Wrap / unwrap (X25519-HKDF-SHA256-AEAD, shared with zone DEKs)            */
/* -------------------------------------------------------------------------- */

const WRAP_SALT = new TextEncoder().encode("aithos-wrap-v1");

function wrapEntryKey(
  entryKey: Uint8Array,
  recipient: string,
  recipientX25519Pub: Uint8Array,
): GammaEnvelope {
  const esk = new Uint8Array(randomBytes(32));
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientX25519Pub);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(recipient), 32);

  const wrapNonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrapped = aead.seal(wrapNonce, entryKey, new TextEncoder().encode(recipient));

  esk.fill(0);
  (shared as Uint8Array).fill?.(0);
  wrapKey.fill(0);

  return {
    recipient,
    alg: "x25519-hkdf-sha256-aead",
    ephemeral_public: x25519PublicKeyToMultibase(epk),
    wrap_nonce: base64url(wrapNonce),
    wrapped_key: base64url(wrapped),
  };
}

function unwrapEntryKey(env: GammaEnvelope, mySk: Uint8Array): Uint8Array {
  if (env.alg !== "x25519-hkdf-sha256-aead") {
    throw new Error(`Unsupported gamma envelope alg: ${env.alg}`);
  }
  const epk = multibaseToX25519PublicKey(env.ephemeral_public);
  const shared = x25519.getSharedSecret(mySk, epk);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(env.recipient), 32);
  const aead = new XChaCha20Poly1305(wrapKey);
  const nonce = base64urlDecode(env.wrap_nonce);
  const out = aead.open(
    nonce,
    base64urlDecode(env.wrapped_key),
    new TextEncoder().encode(env.recipient),
  );
  (shared as Uint8Array).fill?.(0);
  wrapKey.fill(0);
  if (!out) throw new Error("gamma entry-key unwrap failed");
  return out;
}

function multibaseToX25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) throw new Error("Expected multibase z-prefixed");
  const decoded = base58decode(mb.slice(1));
  if (decoded[0] !== 0xec || decoded[1] !== 0x01) {
    throw new Error("Not an X25519 multicodec-prefixed multibase key");
  }
  return decoded.slice(2);
}

/* -------------------------------------------------------------------------- */
/*  Hashing and signature                                                     */
/* -------------------------------------------------------------------------- */

/**
 * readers_hash (§10.3.4′) — commits to the reader set of an entry without
 * committing to the (necessarily non-canonical) wrapped key material.
 *
 *   sha256(jcs(sort_by_recipient([ {recipient, alg, ephemeral_public, wrap_nonce} ])))
 *
 * Note that `wrapped_key` is EXCLUDED: each wrap uses a fresh ephemeral
 * pubkey and therefore produces different ciphertext even for the same
 * entry_key, so including it would make every seal produce a different
 * readers_hash.
 */
export function computeReadersHash(envelopes: GammaEnvelope[]): string {
  const reduced = envelopes
    .map((e) => ({
      recipient: e.recipient,
      alg: e.alg,
      ephemeral_public: e.ephemeral_public,
      wrap_nonce: e.wrap_nonce,
    }))
    .sort((a, b) => (a.recipient < b.recipient ? -1 : a.recipient > b.recipient ? 1 : 0));
  const bytes = new TextEncoder().encode(canonicalize(reduced));
  return "sha256:" + Buffer.from(sha256fn(bytes)).toString("hex");
}

/**
 * Entry hash (§10.5.1′):
 *   sha256(jcs({ payload_ct, nonce, public_header: { ... hash: "" } }))
 *
 * The header is blanked on its own `hash` field (otherwise the computation
 * would be recursive). All other header fields, including `readers_hash`,
 * are in scope. Any change to the ciphertext, nonce, or public_header
 * invalidates the entry hash.
 */
export function computeEntryHashV03(
  payload_ct: string,
  nonce: string,
  header: GammaPublicHeader,
): string {
  const blanked: GammaPublicHeader = { ...header, hash: "" };
  const bytes = new TextEncoder().encode(
    canonicalize({ payload_ct, nonce, public_header: blanked }),
  );
  return "sha256:" + Buffer.from(sha256fn(bytes)).toString("hex");
}

/**
 * Bytes to sign (§10.5.2′):
 *
 *   jcs({ hash, authorized_by: <string | null>, key })
 *
 * Narrow by design. The entry hash already commits to every other aspect of
 * the entry (ciphertext + nonce + header). The signature's only job is to
 * bind the hash to the signer identity + optional mandate id.
 */
export function signableBytesV03(
  hash: string,
  key: string,
  authorizedBy: string | undefined,
): Uint8Array {
  const domain = { hash, authorized_by: authorizedBy ?? null, key };
  return new TextEncoder().encode(canonicalize(domain));
}

/* -------------------------------------------------------------------------- */
/*  Signers                                                                   */
/* -------------------------------------------------------------------------- */

export interface GammaSigner {
  /** Public identifier of the signing key — used as `signature.key`. */
  keyId: string;
  /** Sign raw bytes and return the 64-byte Ed25519 signature. */
  sign(payload: Uint8Array): Uint8Array;
  /** Mandate id if this is a delegate; undefined for direct sphere-key signers. */
  mandateId?: string;
}

export function sphereGammaSigner(identity: Identity, zone: Sphere): GammaSigner {
  return {
    keyId: sphereDidUrl(identity, zone),
    sign: (payload) => signWithSphere(identity, zone, payload),
  };
}

export function delegateGammaSigner(
  mandateId: string,
  keySeed: Uint8Array,
  keyMultibase: string,
): GammaSigner {
  return {
    keyId: keyMultibase,
    sign: (payload) => ed.sign(payload, keySeed),
    mandateId,
  };
}

/* -------------------------------------------------------------------------- */
/*  Build one entry (seal + hash + sign)                                      */
/* -------------------------------------------------------------------------- */

export interface BuildGammaEntryInput {
  subjectDid: string;
  zone: Sphere;
  op: GammaOp;
  target: Record<string, unknown>;
  payload: Record<string, unknown>;
  prevGammaHash: string | null;
  prevSectionGamma?: string;
  signer: GammaSigner;
  /** Readers to seal the entry_key to. MUST be non-empty. */
  readers: GammaReaderKey[];
  at?: Date;
  /** Override the generated id (tests / deterministic fixtures). */
  id?: string;
}

/**
 * Build a fully-formed v0.3 entry (ready to append). Steps §10.11′ 2–9:
 *
 *   1. Fresh 32-byte entry_key.
 *   2. Encrypt payload under entry_key + fresh nonce.
 *   3. Seal entry_key to every reader's X25519 pubkey.
 *   4. Build public_header with readers_hash.
 *   5. Compute entry hash.
 *   6. Sign the narrow signature domain.
 *
 * Does NOT touch disk. Append is the caller's responsibility.
 */
export function buildGammaEntryV03(input: BuildGammaEntryInput): GammaEntryV03 {
  if (input.readers.length === 0) {
    throw new Error("buildGammaEntryV03: readers list must not be empty");
  }

  const entryKey = new Uint8Array(randomBytes(32));
  try {
    const nonce = new Uint8Array(randomBytes(24));
    const plaintext = new TextEncoder().encode(canonicalize(input.payload));
    const aead = new XChaCha20Poly1305(entryKey);
    const ciphertext = aead.seal(nonce, plaintext);
    const payload_ct = base64url(ciphertext);
    const nonce_b64 = base64url(nonce);

    // Seal to each reader — decode pubkey once per reader.
    const envelopes: GammaEnvelope[] = input.readers.map((r) => {
      const pk = multibaseToX25519PublicKey(r.pubkey);
      return wrapEntryKey(entryKey, r.recipient, pk);
    });

    const readers_hash = computeReadersHash(envelopes);

    const header: GammaPublicHeader = {
      "aithos-gamma": GAMMA_VERSION,
      id: input.id ?? newGammaId(),
      at: (input.at ?? new Date()).toISOString(),
      subject_did: input.subjectDid,
      zone: input.zone,
      op: input.op,
      target: input.target,
      prev_gamma_hash: input.prevGammaHash,
      ...(input.prevSectionGamma ? { prev_section_gamma: input.prevSectionGamma } : {}),
      readers_hash,
      hash: "",
    };

    header.hash = computeEntryHashV03(payload_ct, nonce_b64, header);

    const sigBytes = signableBytesV03(
      header.hash,
      input.signer.keyId,
      input.signer.mandateId,
    );
    const sig = input.signer.sign(sigBytes);

    const signature: GammaSignatureBlock = {
      alg: "ed25519",
      key: input.signer.keyId,
      ...(input.signer.mandateId ? { authorized_by: input.signer.mandateId } : {}),
      value: base64url(sig),
    };

    return {
      format: "v0.3",
      payload_ct,
      nonce: nonce_b64,
      envelopes,
      public_header: header,
      signature,
    };
  } finally {
    entryKey.fill(0);
  }
}

/**
 * Backward-compatible alias for v0.3. Callers migrated from v0.2 that just
 * want a "signed gamma entry" get a v0.3 on-disk record.
 */
export const buildGammaEntry = buildGammaEntryV03;

/* -------------------------------------------------------------------------- */
/*  Verification                                                              */
/* -------------------------------------------------------------------------- */

export interface VerifyGammaEntryContext {
  didDoc: DidDocument;
  prev: GammaEntryV03 | null;
  /**
   * Resolver for delegate public keys when `signature.authorized_by` is set.
   * Returns raw 32-byte Ed25519 public key or throws.
   */
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

export interface VerifyGammaEntryResult {
  ok: boolean;
  error?: string;
}

/**
 * Verify a single v0.3 entry without decryption:
 *   - readers_hash matches envelopes
 *   - entry hash matches ciphertext + nonce + header
 *   - chain link (prev_gamma_hash + strictly increasing at)
 *   - signature over the narrow signature domain verifies
 *
 * This is the integrity tier (§10.14.2′). A caller with no envelope on the
 * entry can still check everything here.
 */
export function verifyGammaEntry(
  entry: GammaEntryV03,
  ctx: VerifyGammaEntryContext,
): VerifyGammaEntryResult {
  // readers_hash integrity — detects silent tampering of envelope set.
  const expectedReadersHash = computeReadersHash(entry.envelopes);
  if (expectedReadersHash !== entry.public_header.readers_hash) {
    return {
      ok: false,
      error: `readers_hash mismatch (expected ${expectedReadersHash}, got ${entry.public_header.readers_hash})`,
    };
  }

  // Entry hash integrity.
  const expectedHash = computeEntryHashV03(
    entry.payload_ct,
    entry.nonce,
    entry.public_header,
  );
  if (expectedHash !== entry.public_header.hash) {
    return {
      ok: false,
      error: `hash mismatch (expected ${expectedHash}, got ${entry.public_header.hash})`,
    };
  }

  // Chain link.
  const h = entry.public_header;
  if (ctx.prev === null) {
    if (h.prev_gamma_hash !== null) {
      return { ok: false, error: "first entry must have prev_gamma_hash = null" };
    }
  } else {
    const prevHash = ctx.prev.public_header.hash;
    if (h.prev_gamma_hash !== prevHash) {
      return {
        ok: false,
        error: `prev_gamma_hash mismatch (expected ${prevHash}, got ${h.prev_gamma_hash})`,
      };
    }
    if (new Date(h.at).getTime() <= new Date(ctx.prev.public_header.at).getTime()) {
      return {
        ok: false,
        error: `at (${h.at}) must be strictly after prev.at (${ctx.prev.public_header.at})`,
      };
    }
  }

  // Signature.
  let pubkey: Uint8Array;
  if (entry.signature.authorized_by !== undefined) {
    if (!ctx.resolveDelegatePubkey) {
      return {
        ok: false,
        error: `entry is delegated but no resolveDelegatePubkey provided`,
      };
    }
    try {
      pubkey = ctx.resolveDelegatePubkey(entry.signature.key, entry.signature.authorized_by);
    } catch (e) {
      return { ok: false, error: `failed to resolve delegate key: ${(e as Error).message}` };
    }
  } else {
    const vm = ctx.didDoc.verificationMethod.find((v) => v.id === entry.signature.key);
    if (!vm) {
      return { ok: false, error: `no verificationMethod for ${entry.signature.key}` };
    }
    pubkey = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  }

  const sigBytes = base64urlDecode(entry.signature.value);
  const toVerify = signableBytesV03(
    h.hash,
    entry.signature.key,
    entry.signature.authorized_by,
  );
  const verified = ed.verify(sigBytes, toVerify, pubkey);
  if (!verified) return { ok: false, error: "signature failed to verify" };

  return { ok: true };
}

export interface VerifyGammaLogResult {
  ok: boolean;
  count: number;
  errors: Array<{ index: number; entryId: string; error: string }>;
}

/**
 * Walk the on-disk log in order and verify each entry. Integrity-only;
 * does not decrypt any payload.
 */
export function verifyGammaLog(
  entries: GammaEntryV03[],
  didDoc: DidDocument,
  opts: { resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array } = {},
): VerifyGammaLogResult {
  const errors: VerifyGammaLogResult["errors"] = [];
  let prev: GammaEntryV03 | null = null;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const res = verifyGammaEntry(entry, {
      didDoc,
      prev,
      resolveDelegatePubkey: opts.resolveDelegatePubkey,
    });
    if (!res.ok) {
      errors.push({
        index: i,
        entryId: entry.public_header.id,
        error: res.error ?? "unknown error",
      });
    }
    prev = entry;
  }
  return { ok: errors.length === 0, count: entries.length, errors };
}

/* -------------------------------------------------------------------------- */
/*  File IO                                                                   */
/* -------------------------------------------------------------------------- */

export function ensureGammaDir(handle: string): void {
  ensureDir(gammaDir(handle));
}

/**
 * Read the gamma file from disk. Returns null if the file does not exist
 * yet (fresh identity with no history).
 *
 * Validates the top-level version marker. Unknown marker → throw.
 */
export function readGammaFile(handle: string): GammaFileV03 | null {
  const p = gammaFilePath(handle);
  if (!existsSync(p)) return null;
  const raw = readFileSync(p, "utf8");
  const parsed = JSON.parse(raw) as GammaFileV03;
  if (parsed["aithos-gamma-file"] !== GAMMA_FILE_VERSION) {
    throw new Error(
      `Unsupported gamma file version: ${(parsed as { "aithos-gamma-file"?: string })["aithos-gamma-file"]}. ` +
        `This build expects ${GAMMA_FILE_VERSION}. The v0.2 format is not read by v0.3 code (clean-cut release).`,
    );
  }
  if (!Array.isArray(parsed.entries)) {
    throw new Error("gamma file is missing 'entries' array");
  }
  return parsed;
}

/**
 * Write the gamma file to disk atomically (temp + rename).
 */
export function writeGammaFile(
  handle: string,
  file: GammaFileV03,
  mode: number = 0o600,
): void {
  ensureGammaDir(handle);
  const p = gammaFilePath(handle);
  const tmp = p + ".tmp";
  writeFileSync(tmp, JSON.stringify(file, null, 2) + "\n", { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, p);
}

/**
 * Convenience: return the on-disk entries array, or [] if the file doesn't
 * exist. Integrity-only callers (verifiers) use this; it does not touch
 * any key material.
 */
export function readGammaEntriesOnDisk(handle: string): GammaEntryV03[] {
  const file = readGammaFile(handle);
  return file ? file.entries : [];
}

/**
 * Return just the public headers — no envelope decoding, no decryption.
 * Used by callers that need chain navigation / section lookup without any
 * cryptographic material (`latestGammaForSection`, the head/count anchor).
 */
export function readGammaHeaders(handle: string): GammaPublicHeader[] {
  return readGammaEntriesOnDisk(handle).map((e) => e.public_header);
}

/* -------------------------------------------------------------------------- */
/*  Append                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Append an already-built v0.3 entry to the log.
 *
 * The caller is responsible for having built the entry with correct
 * `prev_gamma_hash` (typically from `gammaHead(handle)`) and a readers list
 * derived from `manifest.gamma.readers`.
 *
 * This function touches no plaintext and decrypts nothing. A delegate with
 * `ethos.write.<zone>` but no gamma-read envelope can execute this path end
 * to end.
 */
export function appendGammaEntryOnDisk(handle: string, entry: GammaEntryV03): void {
  const existing = readGammaFile(handle);
  const file: GammaFileV03 = existing ?? {
    "aithos-gamma-file": GAMMA_FILE_VERSION,
    entries: [],
  };
  file.entries.push(entry);
  writeGammaFile(handle, file);
}

/**
 * Back-compat wrapper for callers migrated from v0.2 who passed a single
 * GammaEntryV03 as `entry`. Same as `appendGammaEntryOnDisk` but accepts the
 * old positional identity arg (ignored — no plaintext is decrypted here).
 *
 * @deprecated Use `appendGammaEntryOnDisk(handle, entry)` directly.
 */
export function appendGammaEntry(
  handle: string,
  _identity: Identity,
  entry: GammaEntryV03,
): void {
  appendGammaEntryOnDisk(handle, entry);
}

/**
 * @deprecated Use `appendGammaEntryOnDisk(handle, entry)` directly.
 */
export function appendGammaEntryForAuthor(
  handle: string,
  _author: Author,
  entry: GammaEntryV03,
): void {
  appendGammaEntryOnDisk(handle, entry);
}

/* -------------------------------------------------------------------------- */
/*  Reading + decryption                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Decrypt one entry for a given reader secret. Returns the logical GammaEntry
 * shape. If the reader has no envelope on this entry, returns a flat entry
 * with `payload = {}` and `_access_denied = true`.
 */
export function openGammaEntry(
  entry: GammaEntryV03,
  me: GammaReaderSecret,
): GammaEntry {
  const env = entry.envelopes.find((e) => e.recipient === me.recipient);
  const h = entry.public_header;
  const flatSig = {
    alg: entry.signature.alg,
    key: entry.signature.key,
    value: entry.signature.value,
  };
  if (!env) {
    return {
      "aithos-gamma": GAMMA_VERSION,
      id: h.id,
      at: h.at,
      subject_did: h.subject_did,
      zone: h.zone,
      op: h.op,
      target: h.target,
      payload: {},
      prev_gamma_hash: h.prev_gamma_hash,
      ...(h.prev_section_gamma ? { prev_section_gamma: h.prev_section_gamma } : {}),
      hash: h.hash,
      signature: flatSig,
      ...(entry.signature.authorized_by ? { authorized_by: entry.signature.authorized_by } : {}),
      _access_denied: true,
    };
  }
  const entryKey = unwrapEntryKey(env, me.x25519Secret);
  try {
    const aead = new XChaCha20Poly1305(entryKey);
    const nonce = base64urlDecode(entry.nonce);
    const ct = base64urlDecode(entry.payload_ct);
    const plain = aead.open(nonce, ct);
    if (!plain) {
      throw new Error("gamma payload authentication failed");
    }
    const payload = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
    return {
      "aithos-gamma": GAMMA_VERSION,
      id: h.id,
      at: h.at,
      subject_did: h.subject_did,
      zone: h.zone,
      op: h.op,
      target: h.target,
      payload,
      prev_gamma_hash: h.prev_gamma_hash,
      ...(h.prev_section_gamma ? { prev_section_gamma: h.prev_section_gamma } : {}),
      hash: h.hash,
      signature: flatSig,
      ...(entry.signature.authorized_by ? { authorized_by: entry.signature.authorized_by } : {}),
    };
  } finally {
    entryKey.fill(0);
  }
}

/**
 * Decrypt the whole log for a reader secret. Entries the reader can't open
 * are still returned, with `payload = {}` and `_access_denied = true`.
 */
export function readGammaLogWith(
  handle: string,
  me: GammaReaderSecret,
): GammaEntry[] {
  const entries = readGammaEntriesOnDisk(handle);
  return entries.map((e) => openGammaEntry(e, me));
}

/**
 * Owner path: read with any of the three sphere X25519 secrets (they all
 * produce identical envelope lookups when the subject's sphere pubkey is
 * the recipient). We pick `self` by convention.
 */
export function readGammaLog(handle: string, identity: Identity): GammaEntry[] {
  const me = subjectGammaReaderSecret(identity, "self");
  try {
    return readGammaLogWith(handle, me);
  } finally {
    me.x25519Secret.fill(0);
  }
}

/**
 * Author-aware variant. Owner path uses the subject's `self` X25519 secret;
 * delegate path uses the delegate seed's X25519 secret with the delegate's
 * recipient label (`<granteeId>#<pubkeyMb>`).
 */
export function readGammaLogForAuthor(handle: string, author: Author): GammaEntry[] {
  if (author.kind === "owner") return readGammaLog(handle, author.identity);
  const me: GammaReaderSecret = {
    recipient: delegateGammaRecipient(author.mandate.grantee.id, author.pubkeyMultibase),
    x25519Secret: edSeedToX25519Secret(author.seed),
  };
  try {
    return readGammaLogWith(handle, me);
  } finally {
    me.x25519Secret.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Chain navigation                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Head hash of the chain (tail entry's `public_header.hash`), or `null` if
 * the log is empty. Reads headers only — no keys required.
 */
export function gammaHead(handle: string, _identity?: Identity): string | null {
  const hs = readGammaHeaders(handle);
  return hs.length === 0 ? null : hs[hs.length - 1].hash;
}

/** Author-aware variant — identical to `gammaHead`; no decryption required. */
export function gammaHeadForAuthor(handle: string, _author: Author): string | null {
  return gammaHead(handle);
}

/**
 * Latest gamma entry (logical view — but only the header is consulted) for
 * a given section id. Walks entries in reverse.
 *
 * Accepts either v0.3 on-disk entries or logical GammaEntry views — both
 * carry `target.section_id` in the same position (`target`).
 */
export function latestGammaForSection<T extends GammaEntry | GammaEntryV03>(
  entries: T[],
  sectionId: string,
): T | null {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    const target = isOnDisk(e) ? e.public_header.target : e.target;
    if (typeof target?.section_id === "string" && target.section_id === sectionId) {
      return e;
    }
  }
  return null;
}

function isOnDisk(e: GammaEntry | GammaEntryV03): e is GammaEntryV03 {
  return (e as GammaEntryV03).format === "v0.3";
}

/**
 * Helper: latest section-scoped gamma entry, return the id. Works against
 * the on-disk form without decrypting anything.
 */
export function latestGammaIdForSection(
  handle: string,
  sectionId: string,
): string | null {
  const entries = readGammaEntriesOnDisk(handle);
  const match = latestGammaForSection(entries, sectionId);
  return match ? match.public_header.id : null;
}

/* -------------------------------------------------------------------------- */
/*  Local helpers                                                             */
/* -------------------------------------------------------------------------- */

function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hkdf = new HKDF(SHA256, ikm, salt, info);
  return hkdf.expand(length);
}

function base58decode(s: string): Uint8Array {
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map = new Map<string, number>();
  for (let i = 0; i < ALPHA.length; i++) map.set(ALPHA[i], i);

  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;

  const b256: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const c = s[i];
    const v = map.get(c);
    if (v === undefined) throw new Error(`Invalid base58 char: ${c}`);
    let carry = v;
    for (let j = 0; j < b256.length; j++) {
      carry += b256[j] * 58;
      b256[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      b256.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + b256.length);
  for (let i = 0; i < b256.length; i++) out[zeros + b256.length - 1 - i] = b256[i];
  return out;
}
