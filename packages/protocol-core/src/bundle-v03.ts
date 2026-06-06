// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Bundle v0.3 — per-section encryption.
 *
 * Reference implementation of the draft
 * `spec/drafts/bundle-v0.3-per-section-encryption.md`. v0.2 (the zone-monolithic
 * format in `ethos.ts`) remains the WRITE DEFAULT; v0.3 is opt-in and selected
 * at the manifest level by `aithos: "0.3.0"` + per-zone `format_version: "v2"`.
 *
 * Where v0.2 encrypts each non-public zone as a single ciphertext under one
 * zone DEK, v0.3 splits every zone into independently-addressed per-section
 * blobs:
 *
 *   john-doe.ethos/
 *   ├── manifest.json            (v2 zone schema — §3.3′)
 *   ├── did.json
 *   ├── public/<section_id>.md   (plaintext markdown, one file per section)
 *   ├── circle/<section_id>.enc  (XChaCha20-Poly1305 ciphertext, one per section)
 *   └── self/<section_id>.enc
 *
 * A single code path handles every zone; the per-zone `encrypted` boolean gates
 * whether the AEAD layer runs ({@link writeSection} / {@link readSection}).
 *
 * AAD note (§3.4.3′, as amended in this implementation): the per-section AEAD
 * binds `subject_did ‖ section_id`, NOT the draft's per-edition `bundle_id`.
 * Binding a per-edition id would force re-encryption of every section on every
 * edition, defeating per-section addressing and breaking carry-forward (test
 * B3). Cross-edition replay resistance is supplied by the manifest signature +
 * `edition.prev_hash` chain; the AAD only needs to resist cross-SUBJECT and
 * cross-SECTION replay, which `subject_did ‖ section_id` does. See {@link sectionAad}.
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  rmSync,
  mkdtempSync,
  statSync,
  copyFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import AdmZip from "adm-zip";

import { canonicalize } from "./canonical.js";
import { base64url, base64urlDecode } from "./encoding.js";
import {
  type Sphere,
  SPHERE_FRAGMENTS,
  multibaseToEd25519PublicKey,
  sphereDidUrl,
  signWithSphere,
} from "./did.js";
import {
  type Identity,
  type DidDocument,
  verifyDidDocument,
} from "./identity.js";
import {
  type Section,
  type ZoneWrap,
  type ManifestSignature,
  type GammaManifestAnchor,
  AITHOS_VERSION_V03,
  wrapDek,
  unwrapDek,
  subjectRecipientFor,
  authorZoneWriteRecipients,
  activeDelegateGrantsForZone,
} from "./ethos.js";
import { sectionMatchesScope } from "./mandate.js";
import {
  type Author,
  ownerAuthor,
  authorSubjectDid,
  authorHandle,
  assertCanWrite,
} from "./author.js";
import { ensureDir, identityDir } from "./storage.js";

/** Upgrade an Identity OR an Author into an Author (mirrors ethos.ts's toAuthor). */
function toAuthor(subject: Identity | Author): Author {
  const a = subject as Author;
  if (a.kind === "owner" || a.kind === "delegate") return a;
  return ownerAuthor(subject as Identity);
}

// @noble/ed25519 v2 needs a sync SHA-512 for sync sign/verify. Idempotent with
// the same line in did.ts / identity.ts; repeated so this module's verify path
// works even if it is the first to touch `ed`.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/* -------------------------------------------------------------------------- */
/*  v2 zone schema types (§3.3.2′)                                            */
/* -------------------------------------------------------------------------- */

/** Per-section AEAD parameters (§3.4′). Present iff the zone is encrypted. */
export interface SectionCipher {
  alg: "xchacha20poly1305-ietf";
  /** base64url, 24 bytes. */
  nonce: string;
  /** Per-recipient DEK wraps (X25519-HKDF-SHA256-AEAD, §3.6 — shared with v0.2). */
  wraps: ZoneWrap[];
}

/** The plaintext sealed inside a section's {@link TitleCipher}. */
export interface SectionTitle {
  title: string;
  tags?: string[];
}

/**
 * A section's title+tags, sealed to that SECTION's recipients (§3.3.2′ revised).
 * For an encrypted-index zone (self), each section carries its own
 * `title_cipher` instead of the zone carrying one global index blob. Plaintext
 * is `jcs({ title, tags? })`; AAD = `"aithos-title-v1\0" ‖ subject_did ‖ "\0" ‖
 * section_id`. Because it is sealed to the same recipients as the section body,
 * whoever can read the body can read the title — and a section-scoped delegate
 * sees only its own sections' titles, never the others'.
 */
export interface TitleCipher {
  alg: "xchacha20poly1305-ietf";
  /** base64url, 24 bytes. */
  nonce: string;
  /** Per-recipient wraps (X25519-HKDF-SHA256-AEAD) — same recipient set as the body. */
  wraps: ZoneWrap[];
  /** base64url XChaCha20-Poly1305 ciphertext of `jcs({ title, tags? })`. */
  ct: string;
}

/** One section's manifest descriptor (§3.3.2′). */
export interface SectionDescriptor {
  section_id: string;
  /**
   * Section title in clear. Present for zones with a CLEAR index (public,
   * circle). MUST be absent when the zone's index is encrypted (self), where
   * the title lives in {@link title_cipher} instead.
   */
  title?: string;
  /** `<zone>/<section_id>.md` (public) or `<zone>/<section_id>.enc` (encrypted). */
  file: string;
  /** Hex SHA-256 of the section's plaintext markdown body (no prefix). */
  sha256_of_plaintext: string;
  /** REQUIRED iff the zone is encrypted; MUST be absent for public sections (B15). */
  cipher?: SectionCipher;
  gamma_ref: string;
  /** Clear tags. Like {@link title}, MUST be absent when the zone index is encrypted. */
  tags?: string[];
  /** Encrypted title+tags. REQUIRED iff the zone's index is encrypted; absent otherwise. */
  title_cipher?: TitleCipher;
}

/** A zone in the v0.3 per-section schema. Shared shape for all three zones. */
export interface BundleZoneV2 {
  format_version: "v2";
  /** `false` for public, `true` for circle/self. Fixed per zone identity. */
  encrypted: boolean;
  /**
   * `true` when each section's title/tags are encrypted into its own
   * `title_cipher` rather than carried in clear. Fixed per zone identity:
   * `self` → true, `public`/`circle` → absent/false. This is the circle-clear /
   * self-private compromise — the host sees circle titles but never self titles,
   * and a section-scoped delegate sees only the titles of sections it can read.
   */
  index_encrypted?: boolean;
  /** Ordered list of section descriptors (canonical display order). MAY be []. */
  sections: SectionDescriptor[];
}

/**
 * Per-zone index-privacy policy (fixed by zone identity). `self`'s index is
 * encrypted so only the subject can read their section titles; `public` and
 * `circle` keep a clear index (the host / circle can browse titles).
 */
export const ZONE_INDEX_ENCRYPTED: Record<Sphere, boolean> = {
  public: false,
  circle: false,
  self: true,
};

/** A v0.3 manifest. Mirrors the v0.2 `Manifest` but with v2 zones (§3.3′). */
export interface ManifestV03 {
  aithos: typeof AITHOS_VERSION_V03;
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
  zones: Record<Sphere, BundleZoneV2>;
  /** Gamma anchor — carried for forward-compat; deep gamma checks are §3.8′ #9 (deferred). */
  gamma?: GammaManifestAnchor;
  integrity: {
    sha256_of_did_json: string;
    manifest_signature: ManifestSignature;
  };
}

/** A recipient the section DEK is sealed to (subject sphere, or a delegate). */
export interface SectionRecipient {
  did: string;
  x25519PublicKey: Uint8Array;
}

/** A reader's decrypt credential: the DID URL it is wrapped under + its X25519 secret. */
export interface SectionReader {
  didUrl: string;
  x25519Secret: Uint8Array;
}

/* -------------------------------------------------------------------------- */
/*  Per-section AEAD (§3.4′)                                                  */
/* -------------------------------------------------------------------------- */

const NUL = new Uint8Array([0]);
// Literal label prefix INCLUDING the trailing NUL after "v1" (§3.4.3′).
const SECTION_AAD_PREFIX = new TextEncoder().encode("aithos-section-v1\0");

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function sha256hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return Buffer.from(sha256fn(bytes)).toString("hex");
}

/**
 * AEAD additional data for a section (§3.4.3′, as amended):
 *
 *   "aithos-section-v1\0" ‖ utf8(subject_did) ‖ "\0" ‖ utf8(section_id)
 *
 * Binds the ciphertext to the SUBJECT (stable across editions → unchanged
 * sections carry forward byte-identical, B3) and to the SECTION_ID (resists
 * swapping ciphertexts between sections of the same bundle, B4). subject_did
 * replaces the draft's per-edition bundle_id; see the module header for the
 * rationale.
 */
export function sectionAad(subjectDid: string, sectionId: string): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(SECTION_AAD_PREFIX, enc.encode(subjectDid), NUL, enc.encode(sectionId));
}

export interface EncryptedSection {
  ciphertext: Uint8Array;
  cipher: SectionCipher;
}

/**
 * Encrypt one section (§3.4.1′). Generates a FRESH per-section DEK and nonce
 * (each section is an independent random secret — §3.4.4′; no HKDF-from-a-zone-
 * master), seals the markdown under XChaCha20-Poly1305 with the section AAD,
 * and wraps the DEK to every recipient.
 */
export function encryptSection(
  plaintext: string,
  subjectDid: string,
  sectionId: string,
  recipients: SectionRecipient[],
): EncryptedSection {
  const dek = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(24));
  const aad = sectionAad(subjectDid, sectionId);
  const aead = new XChaCha20Poly1305(dek);
  const ciphertext = aead.seal(nonce, new TextEncoder().encode(plaintext), aad);
  const wraps = recipients.map((r) => wrapDek(dek, r.did, r.x25519PublicKey));
  dek.fill(0); // best-effort zeroize
  return {
    ciphertext,
    cipher: { alg: "xchacha20poly1305-ietf", nonce: base64url(nonce), wraps },
  };
}

/**
 * Decrypt one section (§3.4.2′). Finds the wrap for `myDidUrl`, unwraps the
 * per-section DEK, and opens the ciphertext under the section AAD. Throws if
 * there is no matching wrap or the AEAD tag does not verify (wrong key, wrong
 * subject, wrong section_id, or tampering).
 */
export function decryptSection(
  ciphertext: Uint8Array,
  cipher: SectionCipher,
  subjectDid: string,
  sectionId: string,
  myDidUrl: string,
  myX25519Secret: Uint8Array,
): string {
  const wrap = cipher.wraps.find((w) => w.recipient === myDidUrl);
  if (!wrap) throw new Error(`No wrap entry for ${myDidUrl} on section ${sectionId}`);
  const dek = unwrapDek(wrap, myX25519Secret);
  try {
    const aad = sectionAad(subjectDid, sectionId);
    const aead = new XChaCha20Poly1305(dek);
    const nonce = base64urlDecode(cipher.nonce);
    const plain = aead.open(nonce, ciphertext, aad);
    if (!plain) throw new Error("XChaCha20-Poly1305 authentication failed");
    return new TextDecoder().decode(plain);
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Per-section encrypted title (self) — sealed to the section's recipients    */
/* -------------------------------------------------------------------------- */

// Literal label prefix INCLUDING the trailing NUL after "v1".
const TITLE_AAD_PREFIX = new TextEncoder().encode("aithos-title-v1\0");

/**
 * AEAD additional data for a section title:
 *   "aithos-title-v1\0" ‖ utf8(subject_did) ‖ "\0" ‖ utf8(section_id)
 * Binds the title to the subject and the specific section (resists cross-subject
 * and cross-section replay; distinct prefix from the body AAD).
 */
export function titleAad(subjectDid: string, sectionId: string): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(TITLE_AAD_PREFIX, enc.encode(subjectDid), NUL, enc.encode(sectionId));
}

/** Seal a section's title/tags to `recipients` (the same set as the section body). */
export function encryptSectionTitle(
  meta: SectionTitle,
  subjectDid: string,
  sectionId: string,
  recipients: SectionRecipient[],
): TitleCipher {
  const dek = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(24));
  const aad = titleAad(subjectDid, sectionId);
  const aead = new XChaCha20Poly1305(dek);
  const ct = aead.seal(nonce, new TextEncoder().encode(canonicalize(meta)), aad);
  const wraps = recipients.map((r) => wrapDek(dek, r.did, r.x25519PublicKey));
  dek.fill(0);
  return { alg: "xchacha20poly1305-ietf", nonce: base64url(nonce), wraps, ct: base64url(ct) };
}

/** Decrypt a section's {@link TitleCipher}. Throws on no-wrap / tamper. */
export function decryptSectionTitle(
  title: TitleCipher,
  subjectDid: string,
  sectionId: string,
  reader: SectionReader,
): SectionTitle {
  const wrap = title.wraps.find((w) => w.recipient === reader.didUrl);
  if (!wrap) throw new Error(`No title wrap for ${reader.didUrl} on section ${sectionId}`);
  const dek = unwrapDek(wrap, reader.x25519Secret);
  try {
    const aad = titleAad(subjectDid, sectionId);
    const aead = new XChaCha20Poly1305(dek);
    const pt = aead.open(base64urlDecode(title.nonce), base64urlDecode(title.ct), aad);
    if (!pt) throw new Error("section title authentication failed");
    return JSON.parse(new TextDecoder().decode(pt)) as SectionTitle;
  } finally {
    dek.fill(0);
  }
}

/** A resolved index row for display: `title` is undefined when encrypted and no key was supplied. */
export interface ZoneIndexRow {
  section_id: string;
  title?: string;
  tags?: string[];
  /** True when the title is hidden (encrypted, no/failed key for this section). */
  title_hidden: boolean;
}

/**
 * Resolve a zone's section index for display. Clear-index zones (public,
 * circle) return titles directly from the descriptors. For the encrypted (self)
 * index, each section's title is decrypted from its own `title_cipher` when the
 * `reader` is one of that section's recipients — so a section-scoped delegate
 * sees the titles of exactly the sections it can read, the host sees none, and
 * the subject sees all.
 */
export function readZoneIndex(
  _zoneName: Sphere,
  zone: BundleZoneV2,
  subjectDid: string,
  reader?: SectionReader,
): ZoneIndexRow[] {
  if (!zone.index_encrypted) {
    return zone.sections.map((s) => ({
      section_id: s.section_id,
      title: s.title,
      ...(s.tags ? { tags: s.tags } : {}),
      title_hidden: false,
    }));
  }
  return zone.sections.map((s) => {
    if (reader && s.title_cipher) {
      try {
        const meta = decryptSectionTitle(s.title_cipher, subjectDid, s.section_id, reader);
        return {
          section_id: s.section_id,
          title: meta.title,
          ...(meta.tags ? { tags: meta.tags } : {}),
          title_hidden: false,
        };
      } catch {
        /* not a recipient of this section → hidden */
      }
    }
    return { section_id: s.section_id, title_hidden: true };
  });
}

/* -------------------------------------------------------------------------- */
/*  Per-section markdown (the §2.6 plaintext form of one section)            */
/* -------------------------------------------------------------------------- */

/**
 * Render one section to its canonical markdown form (§2.6 / §3.4.5′): the title
 * heading, an optional tags comment, then the body. This is the exact plaintext
 * that is written verbatim to `public/<id>.md` or fed into XChaCha20-Poly1305
 * for an encrypted zone. Identity (`section_id`) and provenance (`gamma_ref`)
 * live in the manifest, NOT in this plaintext — so a section's hash is over its
 * title/body/tags only, matching the gamma payload cross-check of §3.4.2′ #7.
 */
export function renderSectionMarkdown(section: {
  title: string;
  body: string;
  tags?: string[];
}): string {
  const parts: string[] = [`# ${section.title}`];
  if (section.tags && section.tags.length > 0) {
    parts.push(`<!-- tags: ${JSON.stringify(section.tags)} -->`);
  }
  parts.push("");
  parts.push(section.body);
  return parts.join("\n").replace(/\s+$/, "") + "\n";
}

/** Inverse of {@link renderSectionMarkdown}. */
export function parseSectionMarkdown(md: string): {
  title: string;
  body: string;
  tags?: string[];
} {
  const header = md.match(/^# (.+?)\s*\n/);
  if (!header) throw new Error("section markdown missing '# <title>' heading");
  const title = header[1].trim();
  let rest = md.slice(header[0].length);
  let tags: string[] | undefined;
  const tagsMatch = rest.match(/^<!-- tags:\s*(\[.*?\])\s*-->\s*\n/);
  if (tagsMatch) {
    try {
      tags = JSON.parse(tagsMatch[1]);
    } catch {
      /* ignore malformed tags */
    }
    rest = rest.slice(tagsMatch[0].length);
  }
  const body = rest.replace(/^\n+/, "").replace(/\s+$/, "");
  return { title, body, ...(tags ? { tags } : {}) };
}

/* -------------------------------------------------------------------------- */
/*  Unified writeSection / readSection (§ sequencing step 3)                  */
/* -------------------------------------------------------------------------- */

export interface SectionWriteCtx {
  /** Bundle root directory to write the blob under. */
  bundleDir: string;
  zone: Sphere;
  /** Gates the AEAD layer: false → plaintext .md, true → .enc ciphertext. */
  encrypted: boolean;
  /** When true, the title/tags are sealed into `title_cipher` instead of clear (self). */
  indexEncrypted: boolean;
  subjectDid: string;
  /** Recipients for the per-section DEK + title (encrypted zones only). */
  recipients: SectionRecipient[];
}

/**
 * Write one section's blob into the bundle and return its manifest descriptor.
 * Public → the markdown file is written directly; circle/self → the markdown is
 * encrypted with a fresh per-section DEK (§3.4.1′ / §3.4.5′). When the zone's
 * index is encrypted (self), the title/tags are sealed into a per-section
 * `title_cipher` (sealed to the same recipients) instead of left clear.
 */
export function writeSection(ctx: SectionWriteCtx, section: Section): SectionDescriptor {
  const plaintext = renderSectionMarkdown(section);
  const sha = sha256hex(plaintext);
  const ext = ctx.encrypted ? "enc" : "md";
  const file = `${ctx.zone}/${section.id}.${ext}`;
  ensureDir(join(ctx.bundleDir, ctx.zone));
  const abs = join(ctx.bundleDir, file);

  const desc: SectionDescriptor = {
    section_id: section.id,
    file,
    sha256_of_plaintext: sha,
    gamma_ref: section.gamma_ref,
  };
  if (ctx.indexEncrypted) {
    desc.title_cipher = encryptSectionTitle(
      { title: section.title, ...(section.tags && section.tags.length > 0 ? { tags: section.tags } : {}) },
      ctx.subjectDid,
      section.id,
      ctx.recipients,
    );
  } else {
    desc.title = section.title;
    if (section.tags && section.tags.length > 0) desc.tags = section.tags;
  }

  if (!ctx.encrypted) {
    writeFileSync(abs, plaintext, { mode: 0o600 });
    return desc;
  }

  const { ciphertext, cipher } = encryptSection(plaintext, ctx.subjectDid, section.id, ctx.recipients);
  writeFileSync(abs, ciphertext, { mode: 0o600 });
  return { ...desc, cipher };
}

export interface SectionReadResult {
  accessible: boolean;
  section?: Section;
  reason?: string;
}

/**
 * Read one section's blob back to a {@link Section}. Public → read + hash-check
 * the file directly; circle/self → require a `reader` whose key matches one of
 * the section's wraps, decrypt, then hash-check. Never throws: an inaccessible
 * section (no key, no matching wrap, decrypt failure, hash mismatch) is reported
 * via `{ accessible: false, reason }` so a caller can iterate a zone and read
 * the sections it is entitled to while skipping the rest (§3.4.2′ / B11).
 */
export function readSection(
  bundleDir: string,
  zone: BundleZoneV2,
  desc: SectionDescriptor,
  subjectDid: string,
  reader?: SectionReader,
): SectionReadResult {
  const abs = join(bundleDir, desc.file);
  if (!existsSync(abs)) return { accessible: false, reason: `file missing: ${desc.file}` };

  if (!zone.encrypted) {
    const bytes = readFileSync(abs);
    if (sha256hex(bytes) !== desc.sha256_of_plaintext) {
      return { accessible: false, reason: "public section hash mismatch" };
    }
    const parsed = parseSectionMarkdown(new TextDecoder().decode(bytes));
    return {
      accessible: true,
      section: { id: desc.section_id, gamma_ref: desc.gamma_ref, ...parsed },
    };
  }

  if (!desc.cipher) return { accessible: false, reason: "encrypted section missing cipher" };
  if (!reader) return { accessible: false, reason: "no reader key supplied" };
  if (!desc.cipher.wraps.some((w) => w.recipient === reader.didUrl)) {
    return { accessible: false, reason: `no wrap for ${reader.didUrl}` };
  }
  try {
    const ct = readFileSync(abs);
    const plaintext = decryptSection(
      ct,
      desc.cipher,
      subjectDid,
      desc.section_id,
      reader.didUrl,
      reader.x25519Secret,
    );
    if (sha256hex(plaintext) !== desc.sha256_of_plaintext) {
      return { accessible: false, reason: "decrypted hash mismatch" };
    }
    const parsed = parseSectionMarkdown(plaintext);
    return {
      accessible: true,
      section: { id: desc.section_id, gamma_ref: desc.gamma_ref, ...parsed },
    };
  } catch (e) {
    return { accessible: false, reason: (e as Error).message };
  }
}

/* -------------------------------------------------------------------------- */
/*  Manifest signing / hashing (owner path; §3.3′ + §3.8′ #5)                */
/* -------------------------------------------------------------------------- */

/** Canonical bytes of a manifest with the signature value blanked (JCS, RFC 8785). */
export function canonicalManifestV03Bytes(m: ManifestV03): Uint8Array {
  const blanked: ManifestV03 = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  return new TextEncoder().encode(canonicalize(blanked));
}

/** SHA-256 hex of the canonical (blank-sig) manifest — the `prev_hash` anchor. */
export function canonicalManifestHashHexV03(m: ManifestV03): string {
  return Buffer.from(sha256fn(canonicalManifestV03Bytes(m))).toString("hex");
}

/**
 * Sign a v0.3 manifest. Owner → the subject's `#public` sphere key. Delegate →
 * the delegate Ed25519 seed, with `manifest_signature.key` = the delegate
 * pubkey multibase and `authorized_by` = the mandate id (mirrors v0.2
 * `signManifest`). The canonical bytes include `key` + `authorized_by` (value
 * blanked) so the signature binds to both the signer and the mandate claimed.
 */
export function signManifestV03(subject: Identity | Author, m: ManifestV03): ManifestV03 {
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
  const base: ManifestV03 = {
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

/**
 * Resolver for a delegate's Ed25519 public key when the manifest signature
 * carries `authorized_by`. Returns the raw 32-byte key or throws. It is
 * expected to validate the mandate (signature + window + scope) before
 * returning — see `keystoreDelegateResolver`.
 */
export interface VerifyV03SignatureOpts {
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

/**
 * Verify the manifest signature (§3.8′ #5). Owner signatures verify against the
 * `#public` key in `did.json`; delegate signatures (`authorized_by`) resolve the
 * delegate pubkey via `opts.resolveDelegatePubkey`.
 */
export function verifyManifestSignatureV03(
  m: ManifestV03,
  didDoc: DidDocument,
  opts: VerifyV03SignatureOpts = {},
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
  const bytes = canonicalManifestV03Bytes(m);
  return ed.verify(base64urlDecode(sig.value), bytes, pk)
    ? { ok: true }
    : { ok: false, error: "manifest signature failed to verify" };
}

/* -------------------------------------------------------------------------- */
/*  buildManifest v2 + bundle authoring with carry-forward (§ step 4)        */
/* -------------------------------------------------------------------------- */

export interface BuildManifestV2Params {
  subjectDid: string;
  handle: string;
  displayName: string;
  bundleId: string;
  editionVersion: string;
  createdAt: string;
  supersedes: string | null;
  prevHash: string | null;
  height: number;
  zones: Record<Sphere, BundleZoneV2>;
  sha256OfDidJson: string;
}

/**
 * Assemble an UNSIGNED v0.3 manifest (signature value blank). The placeholder
 * signature key is the `#public` sphere URL of the subject; {@link signManifestV03}
 * overwrites `key`/`value` (and adds `authorized_by` for delegate signatures).
 */
export function buildManifestV2(p: BuildManifestV2Params): ManifestV03 {
  return {
    aithos: AITHOS_VERSION_V03,
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
    integrity: {
      sha256_of_did_json: p.sha256OfDidJson,
      manifest_signature: { alg: "ed25519", key: `${p.subjectDid}#public`, value: "" },
    },
  };
}

function allocEditionVersion(now: Date, prevVersion: string | undefined): string {
  const day = now.toISOString().slice(0, 10).replace(/-/g, ".");
  if (prevVersion) {
    const m = prevVersion.match(/^(\d{4}\.\d{2}\.\d{2})-(\d+)$/);
    if (m && m[1] === day) return `${day}-${parseInt(m[2], 10) + 1}`;
  }
  return `${day}-1`;
}

function recipientLabelsEqual(wraps: ZoneWrap[], recipients: SectionRecipient[]): boolean {
  const a = new Set(wraps.map((w) => w.recipient));
  if (a.size !== recipients.length) return false;
  for (const r of recipients) if (!a.has(r.did)) return false;
  return true;
}

/** Default recipients for an encrypted zone: the subject sphere only (§3.5.1′). */
export function defaultZoneRecipients(
  identity: Identity,
  zone: "circle" | "self",
): SectionRecipient[] {
  const r = subjectRecipientFor(identity, zone);
  return [{ did: r.did, x25519PublicKey: r.x25519PublicKey }];
}

/**
 * Resolve the PER-SECTION recipient function for an encrypted zone (§3.5.4′).
 * The returned function seals both the section body and its `title_cipher`.
 *
 *   - Public / unencrypted → no recipients.
 *   - Explicit `recipientsFor` override → used verbatim for every section.
 *   - Owner author → subject sphere + delegates whose `section_scope` matches the
 *     section (a section-scoped delegate is a recipient of — and sees the title
 *     of — exactly its matching sections).
 *   - Delegate author → zone-level (owner + the delegate itself), as §3.5.2′.
 */
function resolveZoneRecipients(
  author: Author,
  zone: Sphere,
  subjectDid: string,
  encrypted: boolean,
  recipientsFor: ((zone: "circle" | "self") => SectionRecipient[]) | undefined,
): (s: Section) => SectionRecipient[] {
  if (!encrypted) return () => [];

  const z = zone as "circle" | "self";
  if (recipientsFor) {
    const fixed = recipientsFor(z);
    return () => fixed;
  }

  if (author.kind === "owner") {
    const r = subjectRecipientFor(author.identity, z);
    const subjectRec: SectionRecipient = { did: r.did, x25519PublicKey: r.x25519PublicKey };
    const grants = activeDelegateGrantsForZone(subjectDid, zone);
    const asRec = (g: { did: string; x25519PublicKey: Uint8Array }): SectionRecipient => ({
      did: g.did,
      x25519PublicKey: g.x25519PublicKey,
    });
    return (s) => [
      subjectRec,
      ...grants
        .filter((g) => sectionMatchesScope({ id: s.id, tags: s.tags }, g.sectionScope))
        .map(asRec),
    ];
  }

  // Delegate author: zone-level recipients (owner + this delegate).
  const r = authorZoneWriteRecipients(author, z, subjectDid);
  return () => r;
}

export interface AuthorBundleV03Args {
  /** The owner identity. Provide this OR {@link author}. */
  identity?: Identity;
  /**
   * The author abstraction (owner or delegate). A `DelegateAuthor` may only
   * (re)author its mandate's `actor_sphere` zone; the other zones are carried
   * forward WHOLESALE from {@link prev} (their blobs are copied verbatim — no
   * decryption needed) and the manifest is signed with the delegate key +
   * `authorized_by`. When omitted, `identity` is wrapped as an owner author.
   */
  author?: Author;
  /** Bundle root directory to (re)write. Created if absent. */
  outDir: string;
  /**
   * Sections per zone, in canonical display order. A delegate need only supply
   * the zone they author (`actor_sphere`); other zones are ignored and carried
   * forward from `prev`.
   */
  zones: Partial<Record<Sphere, Section[]>>;
  now?: Date;
  /**
   * Previous v0.3 edition for the chain + carry-forward. `dir` is where the
   * prior edition's section blobs live (so unchanged sections can be copied
   * byte-identical instead of re-encrypted — the property B3 asserts).
   */
  prev?: { manifest: ManifestV03; dir: string };
  /**
   * Explicit predecessor edition link, used when the predecessor is NOT a v0.3
   * bundle (e.g. a v0.2 → v0.3 migration edition per §3.10.3′). Chains the
   * edition (supersedes / prev_hash / height) without carry-forward — every
   * section is freshly encrypted, since a v0.2 monolithic ciphertext cannot be
   * reused per-section. Ignored when `prev` is also supplied.
   */
  prevEdition?: {
    /** Predecessor `edition.version` (drives the new edition's N allocation). */
    version: string;
    /** Predecessor `bundle_id` → the new edition's `supersedes`. */
    bundleId: string;
    /** Hex SHA-256 of the predecessor's canonical (blank-sig) manifest, no prefix. */
    manifestHashHex: string;
    /** Predecessor `edition.height` (new height = this + 1). */
    height: number;
  };
  /** Override recipients per encrypted zone (default: subject only). */
  recipientsFor?: (zone: "circle" | "self") => SectionRecipient[];
}

/**
 * Author a complete v0.3 bundle directory: per-section blobs for all three
 * zones, `did.json`, and a signed v2 `manifest.json`.
 *
 * Carry-forward (the heart of v0.3's cost property): a section whose plaintext
 * hash, gamma_ref, and recipient set are unchanged from `prev` has its prior
 * blob copied verbatim and its prior manifest descriptor reused — so its
 * on-disk ciphertext is byte-identical across editions and only genuinely
 * changed sections pay the re-encryption cost (§3.5.3′ / B3 / B14).
 */
export function authorBundleV03(args: AuthorBundleV03Args): ManifestV03 {
  const { outDir } = args;
  if (!args.author && !args.identity) {
    throw new Error("authorBundleV03: provide either `identity` or `author`");
  }
  const author = args.author ?? ownerAuthor(args.identity!);
  const now = args.now ?? new Date();
  const createdAt = now.toISOString();
  const handle = authorHandle(author);
  const subjectDid = authorSubjectDid(author);
  const displayName =
    author.kind === "owner" ? author.identity.displayName : author.subject.displayName;

  // Edition chain: a v0.3 predecessor (`prev`) enables carry-forward; an
  // explicit `prevEdition` (e.g. a v0.2 migration) chains without it; neither
  // means this is edition 1.
  const carryPrev = args.prev;
  let supersedes: string | null;
  let prevHash: string | null;
  let height: number;
  let prevVersion: string | undefined;
  if (carryPrev) {
    supersedes = carryPrev.manifest.bundle_id;
    prevHash = "sha256:" + canonicalManifestHashHexV03(carryPrev.manifest);
    height = carryPrev.manifest.edition.height + 1;
    prevVersion = carryPrev.manifest.edition.version;
  } else if (args.prevEdition) {
    supersedes = args.prevEdition.bundleId;
    prevHash = "sha256:" + args.prevEdition.manifestHashHex;
    height = args.prevEdition.height + 1;
    prevVersion = args.prevEdition.version;
  } else {
    supersedes = null;
    prevHash = null;
    height = 1;
    prevVersion = undefined;
  }
  const editionVersion = allocEditionVersion(now, prevVersion);
  const bundleId = `urn:aithos:${handle}:${editionVersion}`;

  ensureDir(outDir);

  const zoneEntries: Partial<Record<Sphere, BundleZoneV2>> = {};
  for (const zone of SPHERE_FRAGMENTS) {
    // A delegate may only (re)author its mandate's actor_sphere; every other
    // zone is carried forward WHOLESALE from prev (copy all blobs + reuse the
    // prior zone entry verbatim — including the encrypted self index — without
    // decrypting anything the delegate is not entitled to read).
    const shouldAuthor =
      author.kind === "owner" || author.mandate.actor_sphere === zone;
    if (!shouldAuthor) {
      const prevZone = args.prev?.manifest.zones[zone];
      if (!prevZone) {
        throw new Error(
          `authorBundleV03: delegate cannot author zone ${zone} and has no prev edition to carry it forward`,
        );
      }
      if (prevZone.sections.length > 0) ensureDir(join(outDir, zone));
      for (const d of prevZone.sections) {
        copyFileSync(join(args.prev!.dir, d.file), join(outDir, d.file));
      }
      zoneEntries[zone] = prevZone;
      continue;
    }

    const encrypted = zone !== "public";
    if (encrypted) assertCanWrite(author, zone, now); // no-op for owner

    // Recipients are resolved PER SECTION (§3.5.4′): the subject always, plus
    // each delegate whose mandate's section_scope matches that section. The same
    // set seals the section's body AND its title_cipher, so a section-scoped
    // delegate sees only the titles of the sections it can read (§3.5.5′).
    const recipientsForSection = resolveZoneRecipients(author, zone, subjectDid, encrypted, args.recipientsFor);
    const indexEncrypted = ZONE_INDEX_ENCRYPTED[zone];
    const prevZone = args.prev?.manifest.zones[zone];
    const descriptors: SectionDescriptor[] = [];

    for (const section of args.zones[zone] ?? []) {
      const recipients = recipientsForSection(section);
      const plaintext = renderSectionMarkdown(section);
      const sha = sha256hex(plaintext);
      const prevDesc = prevZone?.sections.find((s) => s.section_id === section.id);

      const canCarry =
        !!args.prev &&
        !!prevDesc &&
        prevDesc.sha256_of_plaintext === sha &&
        prevDesc.gamma_ref === section.gamma_ref &&
        (!encrypted || recipientLabelsEqual(prevDesc.cipher?.wraps ?? [], recipients)) &&
        existsSync(join(args.prev.dir, prevDesc.file));

      if (canCarry && args.prev && prevDesc) {
        // Copy the prior blob verbatim → byte-identical ciphertext across
        // editions; reuse the prior descriptor (same file/nonce/wraps/title_cipher).
        ensureDir(join(outDir, zone)); // §3.2.2′: only create the subdir when non-empty
        copyFileSync(join(args.prev.dir, prevDesc.file), join(outDir, prevDesc.file));
        descriptors.push(prevDesc);
      } else {
        descriptors.push(
          writeSection({ bundleDir: outDir, zone, encrypted, indexEncrypted, subjectDid, recipients }, section),
        );
      }
    }

    zoneEntries[zone] = {
      format_version: "v2",
      encrypted,
      ...(indexEncrypted ? { index_encrypted: true } : {}),
      sections: descriptors,
    };
  }

  // did.json: copy the subject's signed DID document verbatim and hash its bytes.
  const didSrc = join(identityDir(handle), "did.json");
  const didContent = readFileSync(didSrc, "utf8");
  writeFileSync(join(outDir, "did.json"), didContent, { mode: 0o644 });
  const didHashHex = sha256hex(new TextEncoder().encode(didContent));

  const unsigned = buildManifestV2({
    subjectDid,
    handle,
    displayName,
    bundleId,
    editionVersion,
    createdAt,
    supersedes,
    prevHash,
    height,
    zones: zoneEntries as Record<Sphere, BundleZoneV2>,
    sha256OfDidJson: didHashHex,
  });

  const signed = signManifestV03(author, unsigned);
  writeFileSync(join(outDir, "manifest.json"), JSON.stringify(signed, null, 2) + "\n", {
    mode: 0o600,
  });
  return signed;
}

/* -------------------------------------------------------------------------- */
/*  patchEditionV03 — incremental edit without re-reading siblings           */
/* -------------------------------------------------------------------------- */

/** Per-zone patch: sections to add/replace, and section ids to delete. */
export interface ZonePatch {
  upserts?: Section[];
  deletes?: string[];
}

export interface PatchEditionV03Args {
  identity?: Identity;
  author?: Author;
  /** Bundle dir to write the new edition into. */
  outDir: string;
  /** Predecessor v0.3 edition (its blobs are the carry-forward source). */
  prev: { manifest: ManifestV03; dir: string };
  /** What changes, per zone. Zones absent from the patch carry forward unchanged. */
  patch: Partial<Record<Sphere, ZonePatch>>;
  now?: Date;
}

/**
 * Author a new edition by PATCHING the predecessor: changed/added sections are
 * (re)encrypted; every other section carries forward VERBATIM (blob + descriptor
 * + title_cipher) WITHOUT being decrypted. This is what lets a section-scoped
 * delegate add/edit/delete its own sections (it only reads the section it is
 * changing — never its siblings), and makes owner edits cheap (no whole-zone
 * decrypt). Because each self title lives in its own `title_cipher`, adding a
 * section just seals its title to the section's recipients — no global index to
 * rebuild.
 */
export function patchEditionV03(args: PatchEditionV03Args): ManifestV03 {
  if (!args.author && !args.identity) {
    throw new Error("patchEditionV03: provide either `identity` or `author`");
  }
  const author = args.author ?? ownerAuthor(args.identity!);
  const now = args.now ?? new Date();
  const createdAt = now.toISOString();
  const handle = authorHandle(author);
  const subjectDid = authorSubjectDid(author);
  const displayName =
    author.kind === "owner" ? author.identity.displayName : author.subject.displayName;
  const prev = args.prev.manifest;

  const editionVersion = allocEditionVersion(now, prev.edition.version);
  const bundleId = `urn:aithos:${handle}:${editionVersion}`;

  ensureDir(args.outDir);
  const copyBlob = (zone: Sphere, file: string) => {
    ensureDir(join(args.outDir, zone));
    copyFileSync(join(args.prev.dir, file), join(args.outDir, file));
  };

  const zoneEntries: Partial<Record<Sphere, BundleZoneV2>> = {};
  for (const zone of SPHERE_FRAGMENTS) {
    const prevZone = prev.zones[zone];
    const zp = args.patch[zone];
    const shouldAuthor = author.kind === "owner" || author.mandate.actor_sphere === zone;
    const hasChanges = !!zp && ((zp.upserts?.length ?? 0) > 0 || (zp.deletes?.length ?? 0) > 0);

    if (!shouldAuthor || !hasChanges) {
      // Carry the whole zone forward verbatim.
      for (const d of prevZone.sections) copyBlob(zone, d.file);
      zoneEntries[zone] = prevZone;
      continue;
    }

    const encrypted = zone !== "public";
    if (encrypted) assertCanWrite(author, zone, now);
    const indexEncrypted = ZONE_INDEX_ENCRYPTED[zone];
    const recipientsForSection = resolveZoneRecipients(author, zone, subjectDid, encrypted, undefined);
    const writeOne = (s: Section): SectionDescriptor =>
      writeSection(
        { bundleDir: args.outDir, zone, encrypted, indexEncrypted, subjectDid, recipients: recipientsForSection(s) },
        s,
      );

    const delSet = new Set(zp!.deletes ?? []);
    const upserts = new Map((zp!.upserts ?? []).map((s) => [s.id, s]));
    const descriptors: SectionDescriptor[] = [];

    for (const prevDesc of prevZone.sections) {
      if (delSet.has(prevDesc.section_id)) continue; // deleted
      const up = upserts.get(prevDesc.section_id);
      if (up) {
        descriptors.push(writeOne(up)); // modified
        upserts.delete(prevDesc.section_id);
      } else {
        copyBlob(zone, prevDesc.file); // carried forward verbatim
        descriptors.push(prevDesc);
      }
    }
    // Brand-new sections (upserts with no prior descriptor), in insertion order.
    for (const s of zp!.upserts ?? []) {
      if (upserts.has(s.id)) descriptors.push(writeOne(s));
    }

    zoneEntries[zone] = {
      format_version: "v2",
      encrypted,
      ...(indexEncrypted ? { index_encrypted: true } : {}),
      sections: descriptors,
    };
  }

  const didContent = readFileSync(join(identityDir(handle), "did.json"), "utf8");
  writeFileSync(join(args.outDir, "did.json"), didContent, { mode: 0o644 });
  const unsigned = buildManifestV2({
    subjectDid,
    handle,
    displayName,
    bundleId,
    editionVersion,
    createdAt,
    supersedes: prev.bundle_id,
    prevHash: "sha256:" + canonicalManifestHashHexV03(prev),
    height: prev.edition.height + 1,
    zones: zoneEntries as Record<Sphere, BundleZoneV2>,
    sha256OfDidJson: sha256hex(new TextEncoder().encode(didContent)),
  });
  const signed = signManifestV03(author, unsigned);
  writeFileSync(join(args.outDir, "manifest.json"), JSON.stringify(signed, null, 2) + "\n", { mode: 0o600 });
  return signed;
}

/* -------------------------------------------------------------------------- */
/*  verifyBundleV03 — §3.8′ checks 1–9                                        */
/* -------------------------------------------------------------------------- */

export interface BundleV03VerifyResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  bundle_id?: string;
  edition?: { version: string; height: number };
  subject_handle?: string;
  /** Encrypted zones the verifier could not open (no reader / no matching wrap). */
  zonesSkipped: Sphere[];
}

export interface BundleV03VerifyOpts {
  /** Reader credentials to attempt section decryption (enables the deep hash check + B11). */
  readers?: SectionReader[];
  /** Predecessor edition's manifest, to verify `edition.prev_hash` (§3.8′ #8). */
  predecessorManifest?: ManifestV03;
  /** Resolver for a delegate-signed manifest (`authorized_by`); see `keystoreDelegateResolver`. */
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

const SECTION_ID_RE = /^sec_[a-z0-9_-]+$/;

function findReader(
  readers: SectionReader[] | undefined,
  cipher: { wraps: ZoneWrap[] } | undefined,
): SectionReader | undefined {
  if (!readers || !cipher) return undefined;
  return readers.find((rd) => cipher.wraps.some((w) => w.recipient === rd.didUrl));
}

/**
 * Verify a v0.3 bundle directory against §3.8′ (checks 1–8; check 9, the gamma
 * cross-check, is deferred with the gamma-v0.3 integration). Returns structured
 * errors/warnings rather than throwing on a malformed-but-parseable bundle.
 */
export function verifyBundleV03Dir(
  dir: string,
  opts: BundleV03VerifyOpts = {},
): BundleV03VerifyResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const zonesSkipped: Sphere[] = [];

  const manifestPath = join(dir, "manifest.json");
  const didPath = join(dir, "did.json");
  for (const [label, p] of [
    ["manifest.json", manifestPath],
    ["did.json", didPath],
  ] as const) {
    if (!existsSync(p)) errors.push(`bundle missing required entry: ${label}`);
  }
  if (errors.length > 0) return { ok: false, errors, warnings, zonesSkipped };

  // Check 2a: manifest parses.
  let manifest: ManifestV03;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as ManifestV03;
  } catch (e) {
    return {
      ok: false,
      errors: [`manifest.json: not valid JSON (${(e as Error).message})`],
      warnings,
      zonesSkipped,
    };
  }
  if (manifest.aithos !== AITHOS_VERSION_V03) {
    errors.push(`manifest.aithos is not ${AITHOS_VERSION_V03} (got ${manifest.aithos})`);
  }

  // Check 3: did.json parses + root signature verifies.
  let didDoc: DidDocument;
  try {
    didDoc = JSON.parse(readFileSync(didPath, "utf8")) as DidDocument;
  } catch (e) {
    return {
      ok: false,
      errors: [`did.json: not valid JSON (${(e as Error).message})`],
      warnings,
      zonesSkipped,
    };
  }
  if (!verifyDidDocument(didDoc)) errors.push("did.json root signature does not verify");

  // Check 4: did.json hash ↔ manifest.integrity.sha256_of_did_json.
  const didContent = readFileSync(didPath, "utf8");
  const didHashHex = sha256hex(new TextEncoder().encode(didContent));
  if (didHashHex !== manifest.integrity?.sha256_of_did_json) {
    errors.push(
      `sha256_of_did_json mismatch: bundle=${didHashHex} manifest=${manifest.integrity?.sha256_of_did_json}`,
    );
  }
  if (manifest.subject_did !== didDoc.id) {
    errors.push(
      `manifest.subject_did (${manifest.subject_did}) differs from did.json id (${didDoc.id})`,
    );
  }

  // Check 5: manifest signature (owner #public, or delegate via resolver).
  const ms = verifyManifestSignatureV03(manifest, didDoc, {
    resolveDelegatePubkey: opts.resolveDelegatePubkey,
  });
  if (!ms.ok) errors.push(ms.error ?? "manifest signature failed");

  // §3.2.3′: forbidden v0.2 monolithic forms.
  for (const f of ["public.md", "circle.md.enc", "self.md.enc"]) {
    if (existsSync(join(dir, f))) {
      errors.push(`forbidden v0.2 monolithic file present: ${f} (§3.2.3′)`);
    }
  }

  // Check 6 + schema, per zone.
  for (const zone of SPHERE_FRAGMENTS) {
    const zm = manifest.zones?.[zone] as BundleZoneV2 | undefined;
    if (!zm) {
      errors.push(`manifest.zones.${zone} missing`);
      continue;
    }
    // §3.3.1′: a v1 zone inside a 0.3.0 bundle is malformed.
    const fv = (zm as { format_version?: string }).format_version;
    if (fv === "v1") {
      errors.push(`zone ${zone}: format_version "v1" inside a 0.3.0 bundle MUST be rejected (§3.3.1′)`);
      continue;
    }
    if (fv !== "v2") {
      errors.push(`zone ${zone}: unknown format_version ${JSON.stringify(fv)}`);
      continue;
    }
    const mustEncrypt = zone !== "public";
    if (zm.encrypted !== mustEncrypt) {
      errors.push(`zone ${zone}: encrypted must be ${mustEncrypt} (§3.3.2′)`);
    }
    if (!Array.isArray(zm.sections)) {
      errors.push(`zone ${zone}: sections must be an array`);
      continue;
    }
    // Index-privacy policy: fixed by zone identity (self → encrypted per-section titles).
    const indexEncrypted = ZONE_INDEX_ENCRYPTED[zone];
    if (!!zm.index_encrypted !== indexEncrypted) {
      errors.push(`zone ${zone}: index_encrypted must be ${indexEncrypted} (index policy)`);
    }
    const ext = mustEncrypt ? "enc" : "md";
    const badExt = mustEncrypt ? "md" : "enc";
    const declaredFiles = new Map<string, SectionDescriptor>();

    for (const sec of zm.sections) {
      if (!SECTION_ID_RE.test(sec.section_id ?? "")) {
        errors.push(`zone ${zone}: invalid section_id ${JSON.stringify(sec.section_id)} (§3.2.4′)`);
        continue;
      }
      const expectedFile = `${zone}/${sec.section_id}.${ext}`;
      if (sec.file !== expectedFile) {
        errors.push(
          `zone ${zone} section ${sec.section_id}: file must be ${expectedFile}, got ${JSON.stringify(sec.file)} (§3.2.4′)`,
        );
      }
      if (indexEncrypted) {
        // Titles/tags live only in the per-section title_cipher — clear copies forbidden.
        if (sec.title !== undefined) {
          errors.push(`zone ${zone} section ${sec.section_id}: clear title forbidden on an encrypted-index zone`);
        }
        if (sec.tags !== undefined) {
          errors.push(`zone ${zone} section ${sec.section_id}: clear tags forbidden on an encrypted-index zone`);
        }
        if (!sec.title_cipher) {
          errors.push(`zone ${zone} section ${sec.section_id}: missing title_cipher on an encrypted-index zone`);
        }
      } else {
        if (typeof sec.title !== "string" || sec.title.length === 0) {
          errors.push(`zone ${zone} section ${sec.section_id}: missing title`);
        }
        if (sec.title_cipher) {
          errors.push(`zone ${zone} section ${sec.section_id}: title_cipher present on a clear-index zone`);
        }
      }
      if (typeof sec.sha256_of_plaintext !== "string" || sec.sha256_of_plaintext.length === 0) {
        errors.push(`zone ${zone} section ${sec.section_id}: missing sha256_of_plaintext`);
      }
      if (typeof sec.gamma_ref !== "string" || sec.gamma_ref.length === 0) {
        errors.push(`zone ${zone} section ${sec.section_id}: missing gamma_ref`);
      }
      // §3.3.2′ / B15: cipher presence is fixed by zone identity.
      if (mustEncrypt && !sec.cipher) {
        errors.push(`zone ${zone} section ${sec.section_id}: missing cipher on encrypted zone`);
      }
      if (!mustEncrypt && sec.cipher) {
        errors.push(
          `zone ${zone} section ${sec.section_id}: forbidden cipher on public section (§3.3.2′ / B15)`,
        );
      }
      declaredFiles.set(`${sec.section_id}.${ext}`, sec);
    }

    // Orphan scan (§3.8′ #6 / B7) + wrong-extension files (§3.2.3′).
    const zoneDir = join(dir, zone);
    if (existsSync(zoneDir)) {
      for (const fn of readdirSync(zoneDir)) {
        const abs = join(zoneDir, fn);
        if (!statSync(abs).isFile()) {
          errors.push(`zone ${zone}: non-regular entry ${fn} (§3.2.3′)`);
          continue;
        }
        if (fn.endsWith(`.${badExt}`)) {
          errors.push(`zone ${zone}: forbidden .${badExt} file ${fn} in ${zone}/ (§3.2.3′)`);
          continue;
        }
        if (!declaredFiles.has(fn)) {
          errors.push(`zone ${zone}: orphan file ${fn} not listed in manifest (§3.8′ #6 / B7)`);
        }
      }
    }

    // Missing files (§3.8′ #6 / B8) + content checks.
    let decryptedAny = false;
    let encryptedSections = 0;
    for (const sec of zm.sections) {
      if (!SECTION_ID_RE.test(sec.section_id ?? "")) continue; // already reported
      const abs = join(dir, sec.file);
      if (!existsSync(abs)) {
        errors.push(
          `zone ${zone} section ${sec.section_id}: file ${sec.file} missing from bundle (§3.8′ #6 / B8)`,
        );
        continue;
      }
      if (!mustEncrypt) {
        // §3.8′ #6 / B13: public sections hash directly over the on-disk bytes.
        const hex = sha256hex(readFileSync(abs));
        if (hex !== sec.sha256_of_plaintext) {
          errors.push(
            `zone ${zone} section ${sec.section_id}: public sha256 mismatch (on-disk=${hex} manifest=${sec.sha256_of_plaintext})`,
          );
        }
      } else {
        encryptedSections++;
        const reader = findReader(opts.readers, sec.cipher);
        if (reader && sec.cipher) {
          try {
            const pt = decryptSection(
              readFileSync(abs),
              sec.cipher,
              manifest.subject_did,
              sec.section_id,
              reader.didUrl,
              reader.x25519Secret,
            );
            if (sha256hex(pt) !== sec.sha256_of_plaintext) {
              errors.push(`zone ${zone} section ${sec.section_id}: decrypted hash mismatch`);
            } else {
              decryptedAny = true;
            }
          } catch (e) {
            errors.push(
              `zone ${zone} section ${sec.section_id}: decrypt failed (${(e as Error).message})`,
            );
          }
        }
        // No reader → opaque-but-attested (§3.8′ #6 last bullet): the manifest
        // signature + file existence vouch for structural integrity.
      }
    }
    if (mustEncrypt && encryptedSections > 0 && !decryptedAny) {
      zonesSkipped.push(zone);
      warnings.push(
        `zone ${zone}: ${encryptedSections} encrypted section(s) not decrypted (no reader key) — opaque-but-attested`,
      );
    }

    // Per-section title integrity: where we hold the key, the title_cipher MUST
    // open (AEAD-authenticated). Sections we can't read leave their title opaque-
    // but-attested (committed by the manifest signature).
    if (indexEncrypted) {
      for (const sec of zm.sections) {
        if (!sec.title_cipher) continue;
        const tr = findReader(opts.readers, sec.title_cipher);
        if (!tr) continue;
        try {
          decryptSectionTitle(sec.title_cipher, manifest.subject_did, sec.section_id, tr);
        } catch (e) {
          errors.push(`zone ${zone} section ${sec.section_id}: title decrypt failed (${(e as Error).message})`);
        }
      }
    }
  }

  // Check 7: edition self-consistency.
  const ed0 = manifest.edition;
  if (!ed0 || !Number.isInteger(ed0.height) || ed0.height < 1) {
    errors.push("edition.height must be a positive integer");
  }
  if (ed0 && (ed0.prev_hash === null) !== (ed0.supersedes === null)) {
    errors.push("edition.prev_hash must be null iff edition.supersedes is null");
  }

  // Check 8: inter-edition link, when the predecessor is supplied.
  if (opts.predecessorManifest) {
    const expect = "sha256:" + canonicalManifestHashHexV03(opts.predecessorManifest);
    if (expect !== manifest.edition?.prev_hash) {
      errors.push(
        `edition.prev_hash does not match supplied predecessor: ${manifest.edition?.prev_hash} != ${expect} (§3.8′ #8)`,
      );
    }
  } else if (manifest.edition?.supersedes) {
    warnings.push(
      `edition supersedes ${manifest.edition.supersedes} — inter-edition link not checked (predecessor not supplied)`,
    );
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    bundle_id: manifest.bundle_id,
    edition: manifest.edition
      ? { version: manifest.edition.version, height: manifest.edition.height }
      : undefined,
    subject_handle: manifest.subject_handle,
    zonesSkipped,
  };
}

/**
 * Verify a v0.3 bundle at a filesystem path — either an unpacked directory or a
 * `.ethos` zip (detected by header). The zip is extracted to a private temp dir,
 * verified, then removed.
 */
export function verifyBundleV03AtPath(
  pathArg: string,
  opts: BundleV03VerifyOpts = {},
): BundleV03VerifyResult {
  if (!existsSync(pathArg)) throw new Error(`Bundle path not found: ${pathArg}`);

  if (statSync(pathArg).isDirectory()) {
    return verifyBundleV03Dir(pathArg, opts);
  }

  const tmp = mkdtempSync(join(tmpdir(), "aithos-verify-v03-"));
  try {
    const zip = new AdmZip(pathArg);
    for (const e of zip.getEntries()) {
      if (e.entryName.includes("..")) {
        throw new Error(`Unsafe zip entry name: ${e.entryName}`);
      }
    }
    zip.extractAllTo(tmp, /* overwrite */ true);
    return verifyBundleV03Dir(tmp, opts);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
