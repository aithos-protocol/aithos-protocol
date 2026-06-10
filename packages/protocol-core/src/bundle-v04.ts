// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// Bundle v0.4 — incremental manifest + zone master keys.
// Spec: spec/drafts/bundle-v0.4-incremental-manifest-and-zone-keys.md (Partie II).
//
// v0.4 keeps the v0.3 manifest ENVELOPE byte-for-byte in spirit (bundle_id,
// edition chain, integrity.manifest_signature signed over the JCS-canonical
// blank-sig document) and changes only what `zones` carries: instead of inline
// section descriptors, each zone references content-addressed OBJECTS —
// sharded zone indexes (`zone_shard`), a per-zone `keyring` sealing the zone
// master key to each grantee, and an optional `extra_wraps` table for
// per-section grants. Section DEKs are unchanged (the blobs of a v0.3 ethos
// migrate by sha, zero re-encryption); each DEK is ALSO sealed symmetrically
// under the zone master key (`enc_dek`), so a zone grantee needs ONE wrap for
// the whole zone.
//
// Everything here is pure (no filesystem): object canonicalization + shas,
// deterministic sharding, zone-key generation / sealing / opening, enc_dek and
// title-v2 AEAD constructions, and the v0.4 manifest canonical/sign/verify
// quartet (mirrors v0.3's, zone-shape aside).

import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { canonicalize } from "./canonical.js";
import { base64url, base64urlDecode } from "./encoding.js";
import {
  type Sphere,
  multibaseToEd25519PublicKey,
  sphereDidUrl,
  signWithSphere,
} from "./did.js";
import { type Identity, type DidDocument } from "./identity.js";
import {
  type ZoneWrap,
  type ManifestSignature,
  type GammaManifestAnchor,
  wrapDek,
  unwrapDek,
} from "./ethos.js";
import { type Author, ownerAuthor } from "./author.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const AITHOS_VERSION_V04 = "0.4.0" as const;

/* -------------------------------------------------------------------------- */
/*  Types — manifest (N5)                                                     */
/* -------------------------------------------------------------------------- */

/** Per-zone reference block: counts + content-addressed object shas. */
export interface ZoneRefV04 {
  /** Total sections in the zone (drives shard_count determinism). */
  n: number;
  shard_count: number;
  /** sha256 (hex) of each zone_shard object, index-ordered (0..shard_count-1). */
  shard_shas: string[];
  /** keyring object sha — REQUIRED for encrypted zones (circle/self), absent for public. */
  keyring_sha?: string;
  /** extra_wraps object sha — absent ⇔ no per-section grants. */
  extrawraps_sha?: string;
}

/** v0.4 manifest — the v0.3 envelope with object-reference zones. */
export interface ManifestV04 {
  aithos: typeof AITHOS_VERSION_V04;
  bundle_id: string;
  subject_did: string;
  subject_handle: string;
  display_name: string;
  edition: {
    version: string;
    created_at: string;
    supersedes: string | null;
    prev_hash: string | null;
    height: number;
  };
  zones: Record<Sphere, ZoneRefV04>;
  gamma?: GammaManifestAnchor;
  integrity: {
    sha256_of_did_json: string;
    manifest_signature: ManifestSignature;
  };
}

/* -------------------------------------------------------------------------- */
/*  Types — objects (N2/N4)                                                   */
/* -------------------------------------------------------------------------- */

/** DEK sealed under the zone master key (N3). */
export interface EncDekV04 {
  /** Zone-key id this DEK is sealed under ("zk" + 16 hex). */
  kid: string;
  /** XChaCha20-Poly1305 nonce, base64url. */
  n: string;
  /** Ciphertext (DEK), base64url. */
  c: string;
}

/** Section title+tags sealed under the SECTION DEK (self zone, N2). */
export interface TitleCipherV2 {
  n: string;
  ct: string;
}

export interface ShardEntryV04 {
  section_id: string;
  /** Clear title/tags — public & circle (v0.3 contract unchanged). */
  title?: string;
  tags?: string[];
  /** self only — AEAD(DEK) over jcs({title, tags?}); see titleAadV2. */
  title_cipher?: TitleCipherV2;
  blob_sha: string;
  sha256_of_plaintext: string;
  gamma_ref: string;
  /**
   * Best-effort STORED-blob size in bytes (P3 read-planning hints — same
   * contract as backend.ts). v0.4 writers SHOULD fill it: they hold the
   * ciphertext when building the entry, so it costs nothing and keeps
   * `ethos_list_sections` / `context_pack` planning hints alive on migrated
   * subjects. Excluded from server edit-detection fingerprints (it cannot
   * change without blob_sha changing).
   */
  approx_size_bytes?: number;
  /**
   * Absent on public entries, and on sections authored by a fenced delegate
   * that holds no zone key (N9.3) — ExtraWraps is then the only key path
   * until the owner's next edit/sealGrant resyncs it.
   */
  enc_dek?: EncDekV04;
}

export interface ZoneShardV04 {
  object: "zone_shard";
  v: 1;
  zone: Sphere;
  /** Sorted by section_id (bytewise) — sha determinism. */
  entries: ShardEntryV04[];
}

export interface KeyRingWrapV04 {
  /** v0.3 recipient label format unchanged: "granteeId#pubkeyMultibase" | "did#<zone>-kex". */
  recipient: string;
  /** §3.6 wrap over utf8(jcs({ kid, zone_key })) — zone_key base64url. */
  wrap: ZoneWrap;
}

export interface KeyRingV04 {
  object: "keyring";
  v: 1;
  zone: Sphere;
  kid: string;
  /** Sorted by recipient (bytewise). The owner kex label is ALWAYS present. */
  wraps: KeyRingWrapV04[];
}

export interface ExtraWrapsEntryV04 {
  section_id: string;
  /** §3.6 wraps over the raw section DEK — bit-identical to v0.3 wraps. */
  wraps: { recipient: string; wrap: ZoneWrap }[];
}

export interface ExtraWrapsV04 {
  object: "extra_wraps";
  v: 1;
  zone: Sphere;
  /** Sorted by section_id, wraps sorted by recipient. */
  entries: ExtraWrapsEntryV04[];
}

export type EthosObjectV04 = ZoneShardV04 | KeyRingV04 | ExtraWrapsV04;

/* -------------------------------------------------------------------------- */
/*  Objects — canonical bytes & shas (N1)                                     */
/* -------------------------------------------------------------------------- */

export function canonicalObjectBytesV04(obj: EthosObjectV04): Uint8Array {
  return new TextEncoder().encode(canonicalize(obj));
}

/** Content address of an object: sha256 hex (lowercase) of its JCS bytes. */
export function objectShaHexV04(obj: EthosObjectV04): string {
  return Buffer.from(sha256fn(canonicalObjectBytesV04(obj))).toString("hex");
}

/* -------------------------------------------------------------------------- */
/*  Sharding (N2) — deterministic, shared by writers and validators           */
/* -------------------------------------------------------------------------- */

export const SHARD_TARGET_SECTIONS = 128;
export const SHARD_COUNT_MAX = 64;

/** next_pow2(ceil(n/128)) clamped to [1, 64]. */
export function shardCountForN(n: number): number {
  if (!Number.isInteger(n) || n < 0) throw new Error(`invalid section count: ${n}`);
  const buckets = Math.max(1, Math.ceil(n / SHARD_TARGET_SECTIONS));
  let p = 1;
  while (p < buckets) p <<= 1;
  return Math.min(p, SHARD_COUNT_MAX);
}

/** u32be(sha256(utf8(section_id))[0..4]) mod shard_count. */
export function shardIndexForSection(sectionId: string, shardCount: number): number {
  if (!Number.isInteger(shardCount) || shardCount < 1) {
    throw new Error(`invalid shard_count: ${shardCount}`);
  }
  const h = sha256fn(new TextEncoder().encode(sectionId));
  const u32 = ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
  return u32 % shardCount;
}

/** Partition entries into shard_count sorted shards (entries sorted by id). */
export function shardEntriesV04(
  zone: Sphere,
  entries: readonly ShardEntryV04[],
  shardCount: number,
): ZoneShardV04[] {
  const shards: ShardEntryV04[][] = Array.from({ length: shardCount }, () => []);
  for (const e of entries) shards[shardIndexForSection(e.section_id, shardCount)]!.push(e);
  return shards.map((list) => ({
    object: "zone_shard" as const,
    v: 1 as const,
    zone,
    entries: [...list].sort((a, b) => (a.section_id < b.section_id ? -1 : a.section_id > b.section_id ? 1 : 0)),
  }));
}

/* -------------------------------------------------------------------------- */
/*  Zone master keys (N3/N4)                                                  */
/* -------------------------------------------------------------------------- */

export interface ZoneKeyV04 {
  kid: string;
  /** 32-byte XChaCha20-Poly1305 key. Caller owns zeroization. */
  key: Uint8Array;
}

export function generateZoneKeyV04(): ZoneKeyV04 {
  const kid = "zk" + Buffer.from(randomBytes(8)).toString("hex");
  return { kid, key: new Uint8Array(randomBytes(32)) };
}

/** Seal the zone key to one recipient — §3.6 wrap over jcs({kid, zone_key}). */
export function sealZoneKeyV04(
  zk: ZoneKeyV04,
  recipientLabel: string,
  recipientKexPk: Uint8Array,
): KeyRingWrapV04 {
  const payload = new TextEncoder().encode(
    canonicalize({ kid: zk.kid, zone_key: base64url(zk.key) }),
  );
  return { recipient: recipientLabel, wrap: wrapDek(payload, recipientLabel, recipientKexPk) };
}

/** Open a keyring wrap with my X25519 secret → {kid, key}. Throws on mismatch. */
export function openZoneKeyV04(entry: KeyRingWrapV04, myKexSk: Uint8Array): ZoneKeyV04 {
  const payload = unwrapDek(entry.wrap, myKexSk);
  const parsed = JSON.parse(new TextDecoder().decode(payload)) as {
    kid?: unknown;
    zone_key?: unknown;
  };
  if (typeof parsed.kid !== "string" || typeof parsed.zone_key !== "string") {
    throw new Error("keyring wrap payload malformed (expected {kid, zone_key})");
  }
  return { kid: parsed.kid, key: base64urlDecode(parsed.zone_key) };
}

/* -------------------------------------------------------------------------- */
/*  enc_dek (N3)                                                              */
/* -------------------------------------------------------------------------- */

export function dekAadV04(
  subjectDid: string,
  zone: Sphere,
  sectionId: string,
  kid: string,
): Uint8Array {
  return new TextEncoder().encode(
    `aithos-dek-v1\0${subjectDid}\0${zone}\0${sectionId}\0${kid}`,
  );
}

export function encryptDekV04(
  zk: ZoneKeyV04,
  dek: Uint8Array,
  subjectDid: string,
  zone: Sphere,
  sectionId: string,
): EncDekV04 {
  const nonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(zk.key);
  const c = aead.seal(nonce, dek, dekAadV04(subjectDid, zone, sectionId, zk.kid));
  return { kid: zk.kid, n: base64url(nonce), c: base64url(c) };
}

/** Throws when the AAD/kid/key don't match (tamper or wrong zone key). */
export function decryptDekV04(
  zoneKey: Uint8Array,
  encDek: EncDekV04,
  subjectDid: string,
  zone: Sphere,
  sectionId: string,
): Uint8Array {
  const aead = new XChaCha20Poly1305(zoneKey);
  const pt = aead.open(
    base64urlDecode(encDek.n),
    base64urlDecode(encDek.c),
    dekAadV04(subjectDid, zone, sectionId, encDek.kid),
  );
  if (!pt) throw new Error(`enc_dek open failed for section ${sectionId} (kid ${encDek.kid})`);
  return pt;
}

/* -------------------------------------------------------------------------- */
/*  Title cipher v2 (N2 — self)                                               */
/* -------------------------------------------------------------------------- */

export function titleAadV2(subjectDid: string, sectionId: string): Uint8Array {
  return new TextEncoder().encode(`aithos-title-v2\0${subjectDid}\0${sectionId}`);
}

export function encryptTitleV2(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  title: { title: string; tags?: string[] },
): TitleCipherV2 {
  const nonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(dek);
  const ct = aead.seal(
    nonce,
    new TextEncoder().encode(canonicalize(title)),
    titleAadV2(subjectDid, sectionId),
  );
  return { n: base64url(nonce), ct: base64url(ct) };
}

export function decryptTitleV2(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  tc: TitleCipherV2,
): { title: string; tags?: string[] } {
  const aead = new XChaCha20Poly1305(dek);
  const pt = aead.open(base64urlDecode(tc.n), base64urlDecode(tc.ct), titleAadV2(subjectDid, sectionId));
  if (!pt) throw new Error(`title_cipher open failed for section ${sectionId}`);
  return JSON.parse(new TextDecoder().decode(pt)) as { title: string; tags?: string[] };
}

/* -------------------------------------------------------------------------- */
/*  Manifest — canonical / hash / sign / verify (N5) — mirrors v0.3           */
/* -------------------------------------------------------------------------- */

export function canonicalManifestV04Bytes(m: ManifestV04): Uint8Array {
  const blanked: ManifestV04 = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  return new TextEncoder().encode(canonicalize(blanked));
}

export function canonicalManifestHashHexV04(m: ManifestV04): string {
  return Buffer.from(sha256fn(canonicalManifestV04Bytes(m))).toString("hex");
}

function toAuthor(subject: Identity | Author): Author {
  const a = subject as Author;
  if (a.kind === "owner" || a.kind === "delegate") return a;
  return ownerAuthor(subject as Identity);
}

export function signManifestV04(subject: Identity | Author, m: ManifestV04): ManifestV04 {
  const author = toAuthor(subject);
  const baseSig: ManifestSignature =
    author.kind === "owner"
      ? { alg: "ed25519", key: sphereDidUrl(author.identity, "public"), value: "" }
      : {
          alg: "ed25519",
          key: author.pubkeyMultibase,
          value: "",
          authorized_by: author.mandate.id,
        };
  const base: ManifestV04 = {
    ...m,
    integrity: { ...m.integrity, manifest_signature: baseSig },
  };
  const bytes = new TextEncoder().encode(canonicalize(base));
  const rawSig =
    author.kind === "owner"
      ? signWithSphere(author.identity, "public", bytes)
      : ed.sign(bytes, author.seed);
  return {
    ...base,
    integrity: {
      ...base.integrity,
      manifest_signature: { ...baseSig, value: base64url(rawSig) },
    },
  };
}

export interface VerifyV04SignatureOpts {
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

export function verifyManifestSignatureV04(
  m: ManifestV04,
  didDoc: DidDocument,
  opts: VerifyV04SignatureOpts = {},
): { ok: boolean; error?: string } {
  const sig = m.integrity.manifest_signature;
  let pk: Uint8Array;
  if (sig.authorized_by !== undefined) {
    if (!opts.resolveDelegatePubkey) {
      return {
        ok: false,
        error: `manifest is delegate-signed (authorized_by=${sig.authorized_by}) but no resolveDelegatePubkey provided`,
      };
    }
    try {
      pk = opts.resolveDelegatePubkey(sig.key, sig.authorized_by);
    } catch (e) {
      return { ok: false, error: `delegate key resolution failed: ${(e as Error).message}` };
    }
  } else {
    const vm = didDoc.verificationMethod.find((v) => v.id === sig.key);
    if (!vm) return { ok: false, error: `No verificationMethod for ${sig.key}` };
    pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  }
  const bytes = canonicalManifestV04Bytes(m);
  return ed.verify(base64urlDecode(sig.value), bytes, pk)
    ? { ok: true }
    : { ok: false, error: "manifest signature failed to verify" };
}

/* -------------------------------------------------------------------------- */
/*  Manifest assembly                                                          */
/* -------------------------------------------------------------------------- */

export interface BuildManifestV04Params {
  subjectDid: string;
  handle: string;
  displayName: string;
  bundleId: string;
  editionVersion: string;
  createdAt: string;
  supersedes: string | null;
  prevHash: string | null;
  height: number;
  zones: Record<Sphere, ZoneRefV04>;
  sha256OfDidJson: string;
  gamma?: GammaManifestAnchor;
}

/** Assemble an UNSIGNED v0.4 manifest (signature blanked; sign with signManifestV04). */
export function buildManifestV04(p: BuildManifestV04Params): ManifestV04 {
  return {
    aithos: AITHOS_VERSION_V04,
    bundle_id: p.bundleId,
    subject_did: p.subjectDid,
    subject_handle: p.handle,
    display_name: p.displayName,
    edition: {
      version: p.editionVersion,
      created_at: p.createdAt,
      supersedes: p.supersedes,
      prev_hash: p.prevHash,
      height: p.height,
    },
    zones: p.zones,
    ...(p.gamma ? { gamma: p.gamma } : {}),
    integrity: {
      sha256_of_did_json: p.sha256OfDidJson,
      manifest_signature: { alg: "ed25519", key: `${p.subjectDid}#public`, value: "" },
    },
  };
}
