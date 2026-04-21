/**
 * Ethos module — the live on-disk representation of an Ethos document.
 *
 * Filesystem layout (under each identity dir):
 *
 *   ~/.aithos/identities/<handle>/ethos/
 *   ├── manifest.json            (current edition manifest — spec §3.3)
 *   ├── history/
 *   │   └── <edition>.manifest.json   (every past edition's manifest, for chain walks)
 *   ├── public/
 *   │   └── public.md            (plaintext markdown — spec §2.6)
 *   ├── circle/
 *   │   └── circle.md.enc        (XChaCha20-Poly1305 ciphertext — spec §3.4)
 *   ├── self/
 *   │   └── self.md.enc
 *   └── signatures/
 *       └── <section_id>.json    (per-section revision signatures — spec §3.2.5)
 *
 * The live folder is the source of truth for editing. The `.ethos` bundle
 * (spec §3) is derived from it via `aithos ethos pack`.
 *
 * Every edit creates a new edition:
 *   - `edition.version` is `YYYY.MM.DD-N` (auto-incrementing N within a day)
 *   - `edition.prev_hash` is sha256 of the previous edition's canonical manifest
 *     with the manifest signature value blanked
 *   - `edition.height` is prev.height + 1
 *
 * Integrity is verifiable end-to-end (§3.8) and resistant to tampering with any
 * past revision (§2.5.4.2).
 */

import { join } from "node:path";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  chmodSync,
  copyFileSync,
  unlinkSync,
} from "node:fs";
import * as ed from "@noble/ed25519";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import { randomBytes } from "node:crypto";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { x25519 } from "@noble/curves/ed25519.js";

import { canonicalize } from "./canonical.js";
import {
  type Identity,
  type DidDocument,
  base64url,
  base64urlDecode,
  sphereDidUrl,
  signWithSphere,
  rootDid,
  edSeedToX25519Secret,
  x25519PublicFromSecret,
  sha256Hex,
} from "./identity.js";
import {
  didUrlForKex,
  type Sphere,
  SPHERE_FRAGMENTS,
  multibaseToEd25519PublicKey,
  ed25519PublicKeyToMultibase,
  x25519PublicKeyToMultibase,
} from "./did.js";
import { ensureDir, identityDir, readJson, writeJson } from "./storage.js";
import { loadMandate, findRevocation } from "./mandate.js";
import {
  appendGammaEntry,
  buildGammaEntry,
  delegateGammaSigner,
  gammaHead,
  latestGammaForSection,
  readGammaLog,
  sphereGammaSigner,
  type GammaEntry,
  type GammaSigner,
} from "./gamma.js";

/* -------------------------------------------------------------------------- */
/*  Path helpers                                                              */
/* -------------------------------------------------------------------------- */

export function ethosDir(handle: string): string {
  return join(identityDir(handle), "ethos");
}

export function ethosZoneDir(handle: string, zone: Sphere): string {
  return join(ethosDir(handle), zone);
}

export function ethosZoneFile(handle: string, zone: Sphere): string {
  return zone === "public"
    ? join(ethosZoneDir(handle, zone), "public.md")
    : join(ethosZoneDir(handle, zone), `${zone}.md.enc`);
}

export function ethosSignaturesDir(handle: string): string {
  return join(ethosDir(handle), "signatures");
}

export function ethosHistoryDir(handle: string): string {
  return join(ethosDir(handle), "history");
}

export function ethosManifestPath(handle: string): string {
  return join(ethosDir(handle), "manifest.json");
}

/* -------------------------------------------------------------------------- */
/*  Document-form types                                                       */
/* -------------------------------------------------------------------------- */

export interface Revision {
  revision: number;
  at: string;
  body: string;
  prev_hash: string | null;
  hash: string;
  signature: { alg: "ed25519"; key: string; value: string };
  authorized_by?: string; // mandate id (delegated writes only)
}

export interface Section {
  id: string;
  title: string;
  revisions: Revision[];
  tags?: string[];
}

export interface ZoneDoc {
  sections: Section[];
}

export type Zones = Record<Sphere, ZoneDoc>;

/* -------------------------------------------------------------------------- */
/*  Manifest                                                                  */
/* -------------------------------------------------------------------------- */

export interface ZoneManifest {
  file: string;
  encrypted: boolean;
  sha256_of_plaintext: string; // hex without prefix
  section_titles: string[];
  cipher?: ZoneCipher; // only when encrypted
  signature: { alg: "ed25519"; key: string; value: string };
}

export interface ZoneWrap {
  recipient: string; // did URL fragment
  alg: "x25519-hkdf-sha256-aead";
  ephemeral_public: string; // multibase
  wrap_nonce: string; // base64url 24 bytes
  wrapped_key: string; // base64url (DEK + poly1305 tag)
}

export interface ZoneCipher {
  alg: "xchacha20poly1305-ietf";
  nonce: string; // base64url 24 bytes
  wraps: ZoneWrap[];
}

/**
 * Anchor to the gamma deep-memory log (§D draft).
 *
 * Each new edition snapshots the log's current head hash and length so the
 * manifest (which IS signed end-to-end) commits to the state of the log.
 * Off-box delivery (e.g. an S3 URL for the encrypted .jsonl.enc) can later
 * populate `url`; v0.1.0 keeps the log purely local and leaves `url` unset.
 */
export interface GammaManifestAnchor {
  head: string | null;   // sha256:<hex> of latest entry, null if log is empty
  count: number;         // total number of entries in the log
  url?: string;          // optional off-box location of the encrypted log
}

export interface Manifest {
  aithos: "0.1.0";
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
  zones: Record<Sphere, ZoneManifest>;
  gamma?: GammaManifestAnchor;
  integrity: {
    sha256_of_did_json: string; // hex
    manifest_signature: { alg: "ed25519"; key: string; value: string };
  };
}

/* -------------------------------------------------------------------------- */
/*  Signatures side-file                                                      */
/* -------------------------------------------------------------------------- */

export interface SignaturesFile {
  aithos: "0.1.0";
  section_id: string;
  zone: Sphere;
  revisions: Array<{
    revision: number;
    hash: string;
    signature_value: string;
  }>;
}

/* -------------------------------------------------------------------------- */
/*  Low-level IO                                                              */
/* -------------------------------------------------------------------------- */

export function ensureEthosLayout(handle: string): void {
  ensureDir(ethosDir(handle));
  for (const s of SPHERE_FRAGMENTS) ensureDir(ethosZoneDir(handle, s));
  ensureDir(ethosSignaturesDir(handle));
  ensureDir(ethosHistoryDir(handle));
}

export function readManifest(handle: string): Manifest {
  return readJson<Manifest>(ethosManifestPath(handle));
}

export function writeManifest(handle: string, m: Manifest): void {
  writeJson(ethosManifestPath(handle), m, 0o600);
}

export function readSignaturesFile(handle: string, sectionId: string): SignaturesFile | null {
  const p = join(ethosSignaturesDir(handle), `${sectionId}.json`);
  if (!existsSync(p)) return null;
  return readJson<SignaturesFile>(p);
}

export function writeSignaturesFile(handle: string, f: SignaturesFile): void {
  writeJson(join(ethosSignaturesDir(handle), `${f.section_id}.json`), f, 0o600);
}

export function listSignatureFiles(handle: string): string[] {
  const d = ethosSignaturesDir(handle);
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((n) => n.endsWith(".json"));
}

/* -------------------------------------------------------------------------- */
/*  Revision hash-chain primitives                                            */
/* -------------------------------------------------------------------------- */

/**
 * Compute the per-revision self-hash. Per spec §2.5.4 step 3:
 *   hash = sha256( jcs( revision with hash="" AND signature.value="" ) )
 */
export function computeRevisionHash(rev: Revision): string {
  const clone: Revision = {
    ...rev,
    hash: "",
    signature: { ...rev.signature, value: "" },
  };
  const bytes = new TextEncoder().encode(canonicalize(clone));
  return "sha256:" + Buffer.from(sha256fn(bytes)).toString("hex");
}

/**
 * Compute the revision signature. Per spec §2.5.4 step 5: sign the JCS form of
 * the revision object with `signature.value` replaced by "".
 * The caller is responsible for setting `hash` before calling.
 */
export function signRevisionBytes(rev: Revision): Uint8Array {
  const clone: Revision = { ...rev, signature: { ...rev.signature, value: "" } };
  return new TextEncoder().encode(canonicalize(clone));
}

/* -------------------------------------------------------------------------- */
/*  Markdown round-trip (spec §2.6)                                           */
/* -------------------------------------------------------------------------- */

export interface RenderContext {
  subjectDid: string;
  subjectHandle: string;
  editionVersion: string;
  createdAt: string;
}

/**
 * Document-form → markdown form, per spec §2.6.1.
 * The `signature_value` of each revision is NOT inlined — only a truncated
 * prefix goes in the HTML comment. The full value lives in `signatures/`.
 */
export function renderZoneMarkdown(zone: Sphere, doc: ZoneDoc, ctx: RenderContext): string {
  const fm = [
    "---",
    `aithos: "0.1.0"`,
    `zone: ${zone}`,
    `subject_did: ${ctx.subjectDid}`,
    `subject_handle: ${ctx.subjectHandle}`,
    `edition: ${ctx.editionVersion}`,
    `created_at: ${ctx.createdAt}`,
    "---",
    "",
  ].join("\n");

  const parts: string[] = [fm];

  for (const sec of doc.sections) {
    parts.push(`# ${sec.title} <!-- ${sec.id} -->`);
    if (sec.tags && sec.tags.length > 0) {
      parts.push(`<!-- tags: ${JSON.stringify(sec.tags)} -->`);
    }
    parts.push("");

    for (const rev of sec.revisions) {
      const sigPrefix = rev.signature.value.slice(0, 12);
      const metaBits = [
        `rev ${rev.revision}`,
        `at:${rev.at}`,
      ];
      if (rev.prev_hash) metaBits.push(`prev:${rev.prev_hash}`);
      metaBits.push(`hash:${rev.hash}`);
      metaBits.push(`sig:${sigPrefix}`);
      if (rev.authorized_by) metaBits.push(`authorized_by:${rev.authorized_by}`);

      parts.push(`<!-- ${metaBits.join(" · ")} -->`);
      parts.push("");
      parts.push(rev.body);
      parts.push("");
    }
  }

  // Trim trailing whitespace while preserving a final newline.
  return parts.join("\n").replace(/\s+$/, "") + "\n";
}

/** Markdown form → document form. Reconstitutes from markdown + signatures/ side-files. */
export function parseZoneMarkdown(
  markdown: string,
  sigFiles: Record<string, SignaturesFile>,
  expectedZone: Sphere,
  opts?: { subjectDid?: string; resolveMandateGranteePubkey?: (mandateId: string) => string },
): ZoneDoc {
  const fmMatch = markdown.match(/^---\n([\s\S]*?)\n---\n?/);
  if (!fmMatch) throw new Error("Zone markdown missing YAML frontmatter");
  const fm: Record<string, string> = {};
  for (const line of fmMatch[1].split("\n")) {
    const m = line.match(/^(\w+):\s*(.+)$/);
    if (m) fm[m[1]] = m[2].replace(/^"(.*)"$/, "$1");
  }
  if (fm.zone !== expectedZone) {
    throw new Error(`Zone markdown declares zone=${fm.zone}, expected ${expectedZone}`);
  }
  const subjectDid = opts?.subjectDid ?? fm.subject_did;
  const body = markdown.slice(fmMatch[0].length);

  const sections: Section[] = [];
  const sectionChunks = body.split(/(?=^# )/m).filter((c) => c.trim());
  for (const chunk of sectionChunks) {
    const header = chunk.match(/^# (.+?) <!-- (sec_[a-z0-9_-]+) -->\s*\n/);
    if (!header) continue;
    const title = header[1].trim();
    const id = header[2];
    const rest = chunk.slice(header[0].length);

    // Optional tags comment on its own line right after heading
    let tags: string[] | undefined;
    const tagsMatch = rest.match(/^<!-- tags:\s*(\[.*?\])\s*-->\s*\n/);
    let revisionsStart = 0;
    if (tagsMatch) {
      try {
        tags = JSON.parse(tagsMatch[1]);
      } catch {
        /* ignore malformed tags */
      }
      revisionsStart = tagsMatch[0].length;
    }

    // Revisions are delimited by <!-- rev N · ... --> lines.
    const revBlob = rest.slice(revisionsStart);
    const revisions: Revision[] = [];
    const revRegex = /<!-- rev (\d+) · ([^>]+?) -->\s*\n([\s\S]*?)(?=(?:<!-- rev \d+ · )|$)/g;
    let rm: RegExpExecArray | null;
    while ((rm = revRegex.exec(revBlob)) !== null) {
      const revNum = parseInt(rm[1], 10);
      const metaStr = rm[2];
      const bodyText = rm[3].trim();

      const meta: Record<string, string> = {};
      for (const kv of metaStr.split("·").map((s) => s.trim())) {
        const idx = kv.indexOf(":");
        if (idx > 0) meta[kv.slice(0, idx).trim()] = kv.slice(idx + 1).trim();
      }

      const sigFile = sigFiles[id];
      if (!sigFile) {
        throw new Error(`signatures/${id}.json not found; cannot round-trip section ${id}`);
      }
      const sigEntry = sigFile.revisions.find((r) => r.revision === revNum);
      if (!sigEntry) {
        throw new Error(`signatures/${id}.json has no entry for revision ${revNum}`);
      }

      const key = meta.authorized_by
        ? (opts?.resolveMandateGranteePubkey
            ? opts.resolveMandateGranteePubkey(meta.authorized_by)
            : "delegate")
        : `${subjectDid}#${expectedZone}`;

      const rev: Revision = {
        revision: revNum,
        at: meta.at,
        body: bodyText,
        prev_hash: meta.prev ?? null,
        hash: meta.hash,
        signature: {
          alg: "ed25519",
          key,
          value: sigEntry.signature_value,
        },
        ...(meta.authorized_by ? { authorized_by: meta.authorized_by } : {}),
      };
      revisions.push(rev);
    }

    sections.push({ id, title, revisions, ...(tags ? { tags } : {}) });
  }

  return { sections };
}

/** Resolve a mandate id to its grantee pubkey multibase by loading the mandate file. */
export function defaultMandateResolver(mandateId: string): string {
  const m = loadMandate(mandateId);
  if (!m.grantee.pubkey) {
    throw new Error(`Mandate ${mandateId} has no grantee.pubkey — cannot verify delegate signature`);
  }
  return m.grantee.pubkey;
}

/* -------------------------------------------------------------------------- */
/*  Encryption of circle/self zones (spec §3.4, §3.6)                         */
/* -------------------------------------------------------------------------- */

const ZONE_AAD_PREFIX = Buffer.from("aithos-zone-v1\0", "utf8");
const WRAP_SALT = new TextEncoder().encode("aithos-wrap-v1");

export interface EncryptedZone {
  ciphertext: Uint8Array;
  cipher: ZoneCipher;
}

export function encryptZone(
  plaintext: string,
  bundleId: string,
  recipients: Array<{ did: string; x25519PublicKey: Uint8Array }>,
): EncryptedZone {
  const dek = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(24));
  const aad = Buffer.concat([ZONE_AAD_PREFIX, Buffer.from(bundleId, "utf8")]);
  const cipher = new XChaCha20Poly1305(dek);
  const ciphertext = cipher.seal(nonce, new TextEncoder().encode(plaintext), aad);

  const wraps: ZoneWrap[] = recipients.map((r) => wrapDek(dek, r.did, r.x25519PublicKey));

  // Best-effort zeroize
  dek.fill(0);

  return {
    ciphertext,
    cipher: {
      alg: "xchacha20poly1305-ietf",
      nonce: base64url(nonce),
      wraps,
    },
  };
}

export function decryptZone(
  ciphertext: Uint8Array,
  cipher: ZoneCipher,
  bundleId: string,
  myDidUrl: string,
  myX25519Secret: Uint8Array,
): string {
  const wrap = cipher.wraps.find((w) => w.recipient === myDidUrl);
  if (!wrap) throw new Error(`No wrap entry for ${myDidUrl}`);
  const dek = unwrapDek(wrap, myX25519Secret);
  try {
    const aad = Buffer.concat([ZONE_AAD_PREFIX, Buffer.from(bundleId, "utf8")]);
    const aead = new XChaCha20Poly1305(dek);
    const nonce = base64urlDecode(cipher.nonce);
    const plain = aead.open(nonce, ciphertext, aad);
    if (!plain) throw new Error("XChaCha20-Poly1305 authentication failed");
    return new TextDecoder().decode(plain);
  } finally {
    dek.fill(0);
  }
}

function wrapDek(dek: Uint8Array, recipientDidUrl: string, recipientPk: Uint8Array): ZoneWrap {
  const esk = new Uint8Array(randomBytes(32));
  // clamp per X25519 convention (noble's x25519 internally clamps for scalarmult).
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientPk);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(recipientDidUrl), 32);

  const wrapNonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrapped = aead.seal(wrapNonce, dek, new TextEncoder().encode(recipientDidUrl));

  // zeroize
  esk.fill(0);
  (shared as Uint8Array).fill?.(0);
  wrapKey.fill(0);

  return {
    recipient: recipientDidUrl,
    alg: "x25519-hkdf-sha256-aead",
    ephemeral_public: x25519PublicKeyToMultibase(epk),
    wrap_nonce: base64url(wrapNonce),
    wrapped_key: base64url(wrapped),
  };
}

function unwrapDek(wrap: ZoneWrap, mySk: Uint8Array): Uint8Array {
  if (wrap.alg !== "x25519-hkdf-sha256-aead") {
    throw new Error(`Unsupported wrap alg: ${wrap.alg}`);
  }
  const epk = multibaseToX25519PublicKey(wrap.ephemeral_public);
  const shared = x25519.getSharedSecret(mySk, epk);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(wrap.recipient), 32);
  const aead = new XChaCha20Poly1305(wrapKey);
  const nonce = base64urlDecode(wrap.wrap_nonce);
  const out = aead.open(nonce, base64urlDecode(wrap.wrapped_key), new TextEncoder().encode(wrap.recipient));
  // zeroize
  (shared as Uint8Array).fill?.(0);
  wrapKey.fill(0);
  if (!out) throw new Error("DEK unwrap failed");
  return out;
}

function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const hkdf = new HKDF(SHA256, ikm, salt, info);
  return hkdf.expand(length);
}

function multibaseToX25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) throw new Error("Expected multibase z-prefixed");
  // Decode base58btc (reuse did.ts helpers would require changing exports; inline base58 decode).
  const decoded = base58decode(mb.slice(1));
  if (decoded[0] !== 0xec || decoded[1] !== 0x01) {
    throw new Error("Not an X25519 multicodec-prefixed multibase key");
  }
  return decoded.slice(2);
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

/* -------------------------------------------------------------------------- */
/*  Recipient derivation (subject-as-recipient, spec §3.5.1)                  */
/* -------------------------------------------------------------------------- */

export function subjectRecipientFor(identity: Identity, zone: "circle" | "self"): {
  did: string;
  x25519PublicKey: Uint8Array;
  x25519Secret: Uint8Array;
} {
  const sk = edSeedToX25519Secret(identity[zone].seed);
  const pk = x25519PublicFromSecret(sk);
  return {
    did: didUrlForKex(rootDid(identity), zone),
    x25519PublicKey: pk,
    x25519Secret: sk,
  };
}

/* -------------------------------------------------------------------------- */
/*  Edition version allocation                                                */
/* -------------------------------------------------------------------------- */

/**
 * Allocate a fresh `YYYY.MM.DD-N` version given the current manifest (if any).
 * Scans history/ to avoid colliding with prior editions.
 */
export function allocateEditionVersion(handle: string, now: Date = new Date()): string {
  const iso = now.toISOString();
  const day = iso.slice(0, 10).replace(/-/g, ".");
  const dir = ethosHistoryDir(handle);
  let maxN = 0;
  if (existsSync(dir)) {
    for (const fn of readdirSync(dir)) {
      const m = fn.match(new RegExp(`^${day.replace(/\./g, "\\.")}-(\\d+)\\.manifest\\.json$`));
      if (m) maxN = Math.max(maxN, parseInt(m[1], 10));
    }
  }
  return `${day}-${maxN + 1}`;
}

/* -------------------------------------------------------------------------- */
/*  Manifest signing                                                          */
/* -------------------------------------------------------------------------- */

export function signManifest(identity: Identity, m: Manifest): Manifest {
  const unsigned: Manifest = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = signWithSphere(identity, "public", bytes);
  return {
    ...unsigned,
    integrity: {
      ...unsigned.integrity,
      manifest_signature: {
        alg: "ed25519",
        key: sphereDidUrl(identity, "public"),
        value: base64url(sig),
      },
    },
  };
}

export function verifyManifestSignature(m: Manifest, didDoc: DidDocument): { ok: boolean; error?: string } {
  const sigKey = m.integrity.manifest_signature.key;
  const vm = didDoc.verificationMethod.find((v) => v.id === sigKey);
  if (!vm) return { ok: false, error: `No verificationMethod for ${sigKey}` };

  const unsigned: Manifest = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  const sig = base64urlDecode(m.integrity.manifest_signature.value);
  return ed.verify(sig, bytes, pk)
    ? { ok: true }
    : { ok: false, error: "manifest signature failed to verify" };
}

/** sha256 hex of the canonical form of the manifest with blanked sig — the prev_hash anchor. */
export function canonicalManifestHashHex(m: Manifest): string {
  const blanked: Manifest = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  const bytes = new TextEncoder().encode(canonicalize(blanked));
  return Buffer.from(sha256fn(bytes)).toString("hex");
}

/* -------------------------------------------------------------------------- */
/*  Zone signature (over the canonical zone document)                         */
/* -------------------------------------------------------------------------- */

export function signZone(identity: Identity, zone: Sphere, doc: ZoneDoc): { alg: "ed25519"; key: string; value: string } {
  const bytes = new TextEncoder().encode(canonicalize(doc));
  const sig = signWithSphere(identity, zone, bytes);
  return { alg: "ed25519", key: sphereDidUrl(identity, zone), value: base64url(sig) };
}

export function verifyZoneSignature(
  doc: ZoneDoc,
  sig: { alg: "ed25519"; key: string; value: string },
  didDoc: DidDocument,
): { ok: boolean; error?: string } {
  const vm = didDoc.verificationMethod.find((v) => v.id === sig.key);
  if (!vm) return { ok: false, error: `No verificationMethod for ${sig.key}` };
  const bytes = new TextEncoder().encode(canonicalize(doc));
  const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  const verified = ed.verify(base64urlDecode(sig.value), bytes, pk);
  return verified ? { ok: true } : { ok: false, error: "zone signature failed to verify" };
}

/* -------------------------------------------------------------------------- */
/*  Section-id generation                                                     */
/* -------------------------------------------------------------------------- */

export function newSectionId(): string {
  return "sec_" + randomHex(6);
}

function randomHex(bytes: number): string {
  return Buffer.from(randomBytes(bytes)).toString("hex").slice(0, bytes * 2);
}

/* -------------------------------------------------------------------------- */
/*  Bookkeeping: copy did.json into the ethos/ dir for bundling               */
/* -------------------------------------------------------------------------- */

export function snapshotDidJson(handle: string): { path: string; hashHex: string; content: string } {
  const src = join(identityDir(handle), "did.json");
  const dst = join(ethosDir(handle), "did.json");
  copyFileSync(src, dst);
  chmodSync(dst, 0o644);
  const content = readFileSync(dst, "utf8");
  const hashHex = Buffer.from(sha256fn(new TextEncoder().encode(content))).toString("hex");
  return { path: dst, hashHex, content };
}

/* -------------------------------------------------------------------------- */
/*  Public helpers for the commands                                           */
/* -------------------------------------------------------------------------- */

export function subjectHandleFromManifest(m: Manifest): string {
  return m.subject_handle;
}

export function loadZoneDoc(handle: string, zone: Sphere, identity?: Identity, manifest?: Manifest): ZoneDoc {
  const sigFiles = loadAllSignatureFiles(handle);
  const bodyPath = ethosZoneFile(handle, zone);
  if (!existsSync(bodyPath)) return { sections: [] };

  const m = manifest ?? readManifest(handle);
  const zm = m.zones[zone];
  let plaintext: string;
  if (!zm.encrypted) {
    plaintext = readFileSync(bodyPath, "utf8");
  } else {
    if (!identity) throw new Error(`Identity required to decrypt ${zone}`);
    if (zone === "public") throw new Error(`public zone should never be encrypted`);
    const recipient = subjectRecipientFor(identity, zone);
    const ct = readFileSync(bodyPath);
    if (!zm.cipher) throw new Error(`Manifest missing cipher for ${zone}`);
    plaintext = decryptZone(new Uint8Array(ct), zm.cipher, m.bundle_id, recipient.did, recipient.x25519Secret);
  }
  return parseZoneMarkdown(plaintext, sigFiles, zone, {
    subjectDid: m.subject_did,
    resolveMandateGranteePubkey: defaultMandateResolver,
  });
}

export function loadAllSignatureFiles(handle: string): Record<string, SignaturesFile> {
  const out: Record<string, SignaturesFile> = {};
  for (const fn of listSignatureFiles(handle)) {
    const f = readJson<SignaturesFile>(join(ethosSignaturesDir(handle), fn));
    out[f.section_id] = f;
  }
  return out;
}

export function writeZoneToDisk(
  handle: string,
  zone: Sphere,
  doc: ZoneDoc,
  identity: Identity,
  ctx: RenderContext,
  bundleId: string,
): { sha256Hex: string; cipher?: ZoneCipher; signature: { alg: "ed25519"; key: string; value: string }; sectionTitles: string[] } {
  const md = renderZoneMarkdown(zone, doc, ctx);
  const plaintextHashHex = Buffer.from(sha256fn(new TextEncoder().encode(md))).toString("hex");
  const sectionTitles = doc.sections.map((s) => s.title);
  const signature = signZone(identity, zone, doc);

  const filePath = ethosZoneFile(handle, zone);
  ensureDir(ethosZoneDir(handle, zone));
  if (zone === "public") {
    writeFileSync(filePath, md, { mode: 0o600 });
    chmodSync(filePath, 0o600);
    return { sha256Hex: plaintextHashHex, signature, sectionTitles };
  }

  const recipient = subjectRecipientFor(identity, zone as "circle" | "self");
  const { ciphertext, cipher } = encryptZone(md, bundleId, [
    { did: recipient.did, x25519PublicKey: recipient.x25519PublicKey },
  ]);
  writeFileSync(filePath, ciphertext, { mode: 0o600 });
  chmodSync(filePath, 0o600);
  return { sha256Hex: plaintextHashHex, cipher, signature, sectionTitles };
}

/**
 * Persist a new edition: re-render all three zones, rebuild the manifest,
 * sign it, archive the previous manifest under history/.
 */
export function persistEdition(
  handle: string,
  identity: Identity,
  zones: Zones,
  opts: { now?: Date; prevManifest?: Manifest | null } = {},
): Manifest {
  const now = opts.now ?? new Date();
  const createdAt = now.toISOString();
  const editionVersion = allocateEditionVersion(handle, now);
  const bundleId = `urn:aithos:${handle}:${editionVersion}`;
  const subjectDid = rootDid(identity);

  const ctx: RenderContext = {
    subjectDid,
    subjectHandle: handle,
    editionVersion,
    createdAt,
  };

  const zoneManifestEntries: Partial<Record<Sphere, ZoneManifest>> = {};
  for (const z of SPHERE_FRAGMENTS) {
    const out = writeZoneToDisk(handle, z, zones[z], identity, ctx, bundleId);
    const entry: ZoneManifest = {
      file: z === "public" ? "public.md" : `${z}.md.enc`,
      encrypted: z !== "public",
      sha256_of_plaintext: out.sha256Hex,
      section_titles: out.sectionTitles,
      signature: out.signature,
      ...(out.cipher ? { cipher: out.cipher } : {}),
    };
    zoneManifestEntries[z] = entry;
  }

  const didSnapshot = snapshotDidJson(handle);

  const prevManifest = opts.prevManifest === undefined ? safeLoadPreviousManifest(handle) : opts.prevManifest;
  const prevHash = prevManifest ? "sha256:" + canonicalManifestHashHex(prevManifest) : null;
  const height = prevManifest ? prevManifest.edition.height + 1 : 1;

  const supersedes = prevManifest ? prevManifest.bundle_id : null;

  // Snapshot gamma log state into the manifest so the signature commits to
  // the current head. `gamma` is omitted entirely when the log is absent on
  // disk, keeping pre-gamma manifests byte-identical.
  const gammaAnchor = safeReadGammaAnchor(handle, identity);

  const unsigned: Manifest = {
    aithos: "0.1.0",
    bundle_id: bundleId,
    subject_did: subjectDid,
    subject_handle: handle,
    display_name: identity.displayName,
    edition: {
      version: editionVersion,
      created_at: createdAt,
      supersedes,
      prev_hash: prevHash,
      height,
    },
    zones: zoneManifestEntries as Record<Sphere, ZoneManifest>,
    ...(gammaAnchor ? { gamma: gammaAnchor } : {}),
    integrity: {
      sha256_of_did_json: didSnapshot.hashHex,
      manifest_signature: {
        alg: "ed25519",
        key: sphereDidUrl(identity, "public"),
        value: "",
      },
    },
  };

  const signed = signManifest(identity, unsigned);
  writeManifest(handle, signed);

  // Archive.
  const archivePath = join(ethosHistoryDir(handle), `${editionVersion}.manifest.json`);
  writeJson(archivePath, signed, 0o600);

  return signed;
}

function safeLoadPreviousManifest(handle: string): Manifest | null {
  const p = ethosManifestPath(handle);
  if (!existsSync(p)) return null;
  try {
    return readJson<Manifest>(p);
  } catch {
    return null;
  }
}

/**
 * Best-effort read of the gamma log to produce a manifest anchor. Returns
 * `null` when no log is present (the common case for pre-gamma identities),
 * so `persistEdition` can omit the `gamma` field entirely and stay
 * byte-compatible with v0.1.0 manifests.
 */
function safeReadGammaAnchor(handle: string, identity: Identity): GammaManifestAnchor | null {
  try {
    const entries = readGammaLog(handle, identity);
    if (entries.length === 0) return null;
    return {
      head: entries[entries.length - 1].hash,
      count: entries.length,
    };
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*  Section / revision manipulation                                           */
/* -------------------------------------------------------------------------- */

export interface AddSectionArgs {
  handle: string;
  identity: Identity;
  zone: Sphere;
  title: string;
  body: string;
  tags?: string[];
  /**
   * If set, sign the initial revision via a delegate key authorized by a
   * write mandate. Otherwise sign directly with the zone's sphere key.
   */
  delegate?: {
    mandateId: string;
    keySeed: Uint8Array;
    keyMultibase: string; // must match mandate.grantee.pubkey
  };
  at?: Date;
}

export function addSection(
  args: AddSectionArgs,
): { section: Section; manifest: Manifest; gammaEntry: GammaEntry } {
  const zones = loadAllZones(args.handle, args.identity);
  const sectionId = newSectionId();
  while (zones[args.zone].sections.some((s) => s.id === sectionId)) {
    // defend against absurd collisions
    throw new Error("Section id collision, try again");
  }

  const at = args.at ?? new Date();
  const atIso = at.toISOString();

  const first: Revision = buildRevision({
    revisionNumber: 1,
    at: atIso,
    body: args.body,
    prevHash: null,
    zone: args.zone,
    identity: args.identity,
    delegate: args.delegate,
  });

  const section: Section = {
    id: sectionId,
    title: args.title,
    revisions: [first],
    ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
  };

  zones[args.zone].sections.push(section);

  // Write sig file
  const sigFile: SignaturesFile = {
    aithos: "0.1.0",
    section_id: sectionId,
    zone: args.zone,
    revisions: [
      {
        revision: 1,
        hash: first.hash,
        signature_value: first.signature.value,
      },
    ],
  };
  writeSignaturesFile(args.handle, sigFile);

  // Emit a `section.add` gamma entry. We do this before `persistEdition` so
  // the new edition's manifest (via `safeReadGammaAnchor`) already commits to
  // the freshly-appended head.
  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : sphereGammaSigner(args.identity, args.zone);
  const prevGammaHash = gammaHead(args.handle, args.identity);
  const gammaEntry = buildGammaEntry({
    subjectDid: rootDid(args.identity),
    zone: args.zone,
    op: "section.add",
    target: { section_id: sectionId },
    payload: {
      title: args.title,
      body: args.body,
      ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
    },
    prevGammaHash,
    signer: gammaSigner,
    at,
  });
  appendGammaEntry(args.handle, args.identity, gammaEntry);

  const manifest = persistEdition(args.handle, args.identity, zones, { now: at });
  return { section, manifest, gammaEntry };
}

export interface AddRevisionArgs {
  handle: string;
  identity: Identity;
  zone: Sphere;
  sectionId: string;
  body: string;
  delegate?: {
    mandateId: string;
    keySeed: Uint8Array;
    keyMultibase: string;
  };
  at?: Date;
}

export function addRevision(args: AddRevisionArgs): { revision: Revision; manifest: Manifest } {
  const zones = loadAllZones(args.handle, args.identity);
  const section = zones[args.zone].sections.find((s) => s.id === args.sectionId);
  if (!section) throw new Error(`Section ${args.sectionId} not found in ${args.zone}`);
  const prev = section.revisions[section.revisions.length - 1];

  const atIso = (args.at ?? new Date()).toISOString();
  if (new Date(atIso).getTime() <= new Date(prev.at).getTime()) {
    throw new Error(
      `New revision 'at' (${atIso}) must be strictly after previous revision's 'at' (${prev.at})`,
    );
  }

  const rev = buildRevision({
    revisionNumber: prev.revision + 1,
    at: atIso,
    body: args.body,
    prevHash: prev.hash,
    zone: args.zone,
    identity: args.identity,
    delegate: args.delegate,
  });
  section.revisions.push(rev);

  // Update sig file
  let sigFile = readSignaturesFile(args.handle, args.sectionId);
  if (!sigFile) {
    sigFile = { aithos: "0.1.0", section_id: args.sectionId, zone: args.zone, revisions: [] };
  }
  sigFile.revisions.push({
    revision: rev.revision,
    hash: rev.hash,
    signature_value: rev.signature.value,
  });
  writeSignaturesFile(args.handle, sigFile);

  const manifest = persistEdition(args.handle, args.identity, zones);
  return { revision: rev, manifest };
}

/* -------------------------------------------------------------------------- */
/*  Section deletion                                                          */
/* -------------------------------------------------------------------------- */

export interface DeleteSectionArgs {
  handle: string;
  identity: Identity;
  zone: Sphere;
  sectionId: string;
  /** Free-text reason; stored in the gamma entry payload for audit. */
  reason?: string;
  /** Delegate signer (same shape as addSection.delegate). */
  delegate?: {
    mandateId: string;
    keySeed: Uint8Array;
    keyMultibase: string;
  };
  at?: Date;
}

/**
 * Remove a section from its zone AND record the removal as a `section.delete`
 * entry in the gamma log.
 *
 * After this call:
 *   - the current edition no longer contains the section (pack/install sees
 *     it as if it never existed in the live doc),
 *   - the signatures/<section_id>.json file is deleted,
 *   - the gamma log retains the original `section.add` entry AND a new
 *     `section.delete` entry, both signed and hash-chained,
 *   - `manifest.gamma.head` is updated to the new delete entry's hash.
 *
 * Past editions archived under `ethos/history/` are unchanged — they still
 * reference the section by its titles and by the prior `gamma.head`, so the
 * edition chain remains byte-identical to what it was when that manifest was
 * signed.
 */
export function deleteSection(
  args: DeleteSectionArgs,
): { manifest: Manifest; gammaEntry: GammaEntry; deletedTitle: string } {
  const zones = loadAllZones(args.handle, args.identity);
  const zone = zones[args.zone];
  const idx = zone.sections.findIndex((s) => s.id === args.sectionId);
  if (idx < 0) {
    throw new Error(`Section ${args.sectionId} not found in zone ${args.zone}`);
  }
  const deleted = zone.sections[idx];
  zone.sections.splice(idx, 1);

  // Remove the side signatures file (best-effort: ignore if already gone).
  const sigPath = join(ethosSignaturesDir(args.handle), `${args.sectionId}.json`);
  try {
    if (existsSync(sigPath)) unlinkSync(sigPath);
  } catch {
    /* ignore — filesystem quirk, will be overwritten on next edition */
  }

  // Build the gamma entry. `prev_section_gamma` points at the most recent
  // gamma entry for this section (usually its own add, but could be a prior
  // modify). This lets per-section walks skip the global chain.
  const at = args.at ?? new Date();
  const existingLog = readGammaLog(args.handle, args.identity);
  const priorOnSection = latestGammaForSection(existingLog, args.sectionId);

  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : sphereGammaSigner(args.identity, args.zone);

  const prevGammaHash = gammaHead(args.handle, args.identity);
  const gammaEntry = buildGammaEntry({
    subjectDid: rootDid(args.identity),
    zone: args.zone,
    op: "section.delete",
    target: { section_id: args.sectionId },
    payload: {
      ...(args.reason ? { reason: args.reason } : {}),
    },
    prevGammaHash,
    ...(priorOnSection ? { prevSectionGamma: priorOnSection.id } : {}),
    signer: gammaSigner,
    at,
  });
  appendGammaEntry(args.handle, args.identity, gammaEntry);

  const manifest = persistEdition(args.handle, args.identity, zones, { now: at });
  return { manifest, gammaEntry, deletedTitle: deleted.title };
}

function buildRevision(params: {
  revisionNumber: number;
  at: string;
  body: string;
  prevHash: string | null;
  zone: Sphere;
  identity: Identity;
  delegate?: { mandateId: string; keySeed: Uint8Array; keyMultibase: string };
}): Revision {
  const sphereKeyUrl = sphereDidUrl(params.identity, params.zone);
  const base: Revision = {
    revision: params.revisionNumber,
    at: params.at,
    body: params.body,
    prev_hash: params.prevHash,
    hash: "",
    signature: {
      alg: "ed25519",
      key: params.delegate ? params.delegate.keyMultibase : sphereKeyUrl,
      value: "",
    },
    ...(params.delegate ? { authorized_by: params.delegate.mandateId } : {}),
  };
  base.hash = computeRevisionHash(base);
  const toSign = signRevisionBytes(base);
  const sig = params.delegate
    ? ed.sign(toSign, params.delegate.keySeed)
    : signWithSphere(params.identity, params.zone, toSign);
  base.signature.value = base64url(sig);
  return base;
}

export function loadAllZones(handle: string, identity: Identity): Zones {
  return {
    public: loadZoneDoc(handle, "public", identity),
    circle: loadZoneDoc(handle, "circle", identity),
    self: loadZoneDoc(handle, "self", identity),
  };
}

/* -------------------------------------------------------------------------- */
/*  Verification (spec §3.8 + §2.5.4.2)                                       */
/* -------------------------------------------------------------------------- */

export interface VerifyEthosResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

export function verifyEthos(
  handle: string,
  identity: Identity | null,
  didDoc: DidDocument,
): VerifyEthosResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const manifest = readManifest(handle);

  // Check 2: manifest structural validity (light)
  if (manifest.aithos !== "0.1.0") errors.push(`manifest.aithos is not 0.1.0`);

  // Check 3+4: did.json
  const didPath = join(ethosDir(handle), "did.json");
  if (!existsSync(didPath)) {
    errors.push("did.json snapshot missing from ethos/");
  } else {
    const didContent = readFileSync(didPath, "utf8");
    const didHashHex = Buffer.from(sha256fn(new TextEncoder().encode(didContent))).toString("hex");
    if (didHashHex !== manifest.integrity.sha256_of_did_json) {
      errors.push(`sha256_of_did_json mismatch: file=${didHashHex} manifest=${manifest.integrity.sha256_of_did_json}`);
    }
  }

  // Check 6: manifest signature
  const manSig = verifyManifestSignature(manifest, didDoc);
  if (!manSig.ok) errors.push(manSig.error ?? "manifest signature failed");

  // Check 5 + 7: zone integrity + section chain
  for (const z of SPHERE_FRAGMENTS) {
    const zm = manifest.zones[z];
    const loaded = safeLoadZone(handle, z, identity, manifest, errors);
    if (!loaded.doc) continue;
    if (loaded.skipped) {
      // Encrypted zone with no key available — verify what we can from the
      // public data (ciphertext hash, if we want later) but skip everything
      // that requires plaintext. Record it as a warning, not an error.
      warnings.push(
        `zone ${z}: skipped content checks (encrypted, no sphere key available) — manifest declares ${zm.section_titles.length} section(s)`,
      );
      continue;
    }
    const doc = loaded.doc;

    // 5: plaintext hash
    const md = renderZoneMarkdownFromDoc(z, doc, manifest);
    const hex = Buffer.from(sha256fn(new TextEncoder().encode(md))).toString("hex");
    if (hex !== zm.sha256_of_plaintext) {
      errors.push(`zone ${z}: sha256_of_plaintext mismatch (rendered=${hex} manifest=${zm.sha256_of_plaintext})`);
    }

    // section_titles consistency
    const actualTitles = doc.sections.map((s) => s.title);
    if (JSON.stringify(actualTitles) !== JSON.stringify(zm.section_titles)) {
      errors.push(`zone ${z}: section_titles mismatch`);
    }

    // zone signature
    const zs = verifyZoneSignature(doc, zm.signature, didDoc);
    if (!zs.ok) errors.push(`zone ${z}: ${zs.error}`);

    // section hash chains
    for (const sec of doc.sections) {
      const res = verifySectionChain(sec, z, didDoc, manifest);
      for (const e of res.errors) errors.push(`zone ${z} section ${sec.id}: ${e}`);
      for (const w of res.warnings) warnings.push(`zone ${z} section ${sec.id}: ${w}`);
    }

    // signatures/<sec>.json agreement
    for (const sec of doc.sections) {
      const sigFile = readSignaturesFile(handle, sec.id);
      if (!sigFile) {
        errors.push(`zone ${z} section ${sec.id}: signatures/${sec.id}.json missing`);
        continue;
      }
      if (sigFile.zone !== z) {
        errors.push(`zone ${z} section ${sec.id}: sig file records zone=${sigFile.zone}`);
      }
      for (const r of sec.revisions) {
        const entry = sigFile.revisions.find((e) => e.revision === r.revision);
        if (!entry) {
          errors.push(`section ${sec.id} rev ${r.revision}: no entry in signatures side-file`);
        } else if (entry.hash !== r.hash) {
          errors.push(`section ${sec.id} rev ${r.revision}: hash mismatch between chain and sig file`);
        } else if (entry.signature_value !== r.signature.value) {
          errors.push(`section ${sec.id} rev ${r.revision}: signature_value mismatch`);
        }
      }
    }
  }

  // Check 8: edition chain self-consistency
  if (manifest.edition.height < 1) errors.push("edition.height must be >= 1");
  if ((manifest.edition.prev_hash === null) !== (manifest.edition.supersedes === null)) {
    errors.push("edition.prev_hash must be null iff edition.supersedes is null");
  }

  // Check 9: if history/ contains the predecessor, verify the link.
  if (manifest.edition.supersedes) {
    const prevVersion = manifest.edition.supersedes.split(":").pop()!;
    const prevPath = join(ethosHistoryDir(handle), `${prevVersion}.manifest.json`);
    if (existsSync(prevPath)) {
      const prev = readJson<Manifest>(prevPath);
      const expected = "sha256:" + canonicalManifestHashHex(prev);
      if (expected !== manifest.edition.prev_hash) {
        errors.push(`edition.prev_hash mismatch with history/${prevVersion}.manifest.json`);
      }
    } else {
      warnings.push(`predecessor ${prevVersion} not in history/, inter-edition link unverified`);
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

function safeLoadZone(
  handle: string,
  zone: Sphere,
  identity: Identity | null,
  manifest: Manifest,
  errors: string[],
): { doc: ZoneDoc | null; skipped: boolean } {
  try {
    const zm = manifest.zones[zone];
    if (zm.encrypted && !identity) {
      // Cannot decrypt — the caller will note this as a warning and skip the
      // content-dependent checks for this zone.
      return { doc: { sections: [] }, skipped: true };
    }
    return {
      doc: loadZoneDoc(handle, zone, identity ?? undefined, manifest),
      skipped: false,
    };
  } catch (e) {
    errors.push(`zone ${zone}: failed to load (${(e as Error).message})`);
    return { doc: null, skipped: false };
  }
}

function renderZoneMarkdownFromDoc(zone: Sphere, doc: ZoneDoc, m: Manifest): string {
  return renderZoneMarkdown(zone, doc, {
    subjectDid: m.subject_did,
    subjectHandle: m.subject_handle,
    editionVersion: m.edition.version,
    createdAt: m.edition.created_at,
  });
}

export function verifySectionChain(
  section: Section,
  zone: Sphere,
  didDoc: DidDocument,
  manifest: Manifest,
): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const revs = section.revisions;
  if (revs.length === 0) return { errors: ["section has no revisions"], warnings };

  const expectedSphereKey = `${didDoc.id}#${zone}`;

  for (let i = 0; i < revs.length; i++) {
    const r = revs[i];
    if (r.revision !== i + 1) errors.push(`rev ${i + 1}: expected revision=${i + 1} got ${r.revision}`);

    // prev_hash
    if (i === 0) {
      if (r.prev_hash !== null) errors.push(`rev 1: prev_hash must be null`);
    } else {
      const prev = revs[i - 1];
      if (r.prev_hash !== prev.hash) errors.push(`rev ${r.revision}: prev_hash does not link`);
      if (new Date(r.at).getTime() <= new Date(prev.at).getTime()) {
        errors.push(`rev ${r.revision}: 'at' not strictly after previous`);
      }
    }

    // Re-compute hash
    const expectedHash = computeRevisionHash(r);
    if (expectedHash !== r.hash) errors.push(`rev ${r.revision}: hash does not match computed value`);

    // Resolve the verification public key.
    let pk: Uint8Array;
    if (r.authorized_by) {
      // Delegated: signature.key is the multibase of the delegate key, which
      // must also match mandate.grantee.pubkey (enforced at write time, and
      // re-checkable by cross-referencing the mandate file).
      try {
        pk = multibaseToEd25519PublicKey(r.signature.key);
      } catch (e) {
        errors.push(`rev ${r.revision}: bad delegate multibase "${r.signature.key}" (${(e as Error).message})`);
        continue;
      }
    } else {
      if (r.signature.key !== expectedSphereKey) {
        errors.push(`rev ${r.revision}: signature.key ${r.signature.key} does not match ${expectedSphereKey}`);
        continue;
      }
      const vm = didDoc.verificationMethod.find((v) => v.id === expectedSphereKey);
      if (!vm) {
        errors.push(`rev ${r.revision}: DID doc has no verificationMethod ${expectedSphereKey}`);
        continue;
      }
      pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    }

    // Signature check.
    const bytes = signRevisionBytes(r);
    const sig = base64urlDecode(r.signature.value);
    if (!ed.verify(sig, bytes, pk)) {
      errors.push(`rev ${r.revision}: signature failed to verify`);
    }

    // R8 — Prospective-revocation invariant (spec §3.8 check 7.5).
    //
    // Revocation does NOT retroactively invalidate past revisions: a revision
    // signed while the mandate was still valid remains valid forever (the
    // hash-chain is append-only). But a revision whose `at` is ≥ the
    // mandate's revoked_at means the writer either ignored the revocation or
    // forged a timestamp — that breaks the protocol and IS an error.
    //
    // Not-before / not-after are ALSO append-only invariants here: a
    // delegated signature outside the mandate's validity window is invalid,
    // period.
    if (r.authorized_by) {
      try {
        const m = loadMandate(r.authorized_by);
        const atMs = new Date(r.at).getTime();
        const nbMs = new Date(m.not_before).getTime();
        const naMs = new Date(m.not_after).getTime();
        if (atMs < nbMs) {
          errors.push(
            `rev ${r.revision}: signed at ${r.at} before mandate ${r.authorized_by} not_before=${m.not_before}`,
          );
        }
        if (atMs >= naMs) {
          errors.push(
            `rev ${r.revision}: signed at ${r.at} after mandate ${r.authorized_by} not_after=${m.not_after}`,
          );
        }
        const rev = findRevocation(r.authorized_by);
        if (rev) {
          const revokedMs = new Date(rev.revoked_at).getTime();
          if (atMs >= revokedMs) {
            errors.push(
              `rev ${r.revision}: signed at ${r.at} after mandate ${r.authorized_by} was revoked at ${rev.revoked_at} (reason: ${rev.reason})`,
            );
          } else {
            warnings.push(
              `rev ${r.revision}: signed by mandate ${r.authorized_by} which has since been revoked at ${rev.revoked_at} (reason: ${rev.reason}). Revision remains valid (prospective revocation).`,
            );
          }
        }
      } catch (e) {
        // Mandate file missing locally. Don't fail verification — the subject
        // may have pruned their mandate archive or this is an imported bundle.
        // Flag as a warning so auditors see it.
        warnings.push(
          `rev ${r.revision}: authorized_by=${r.authorized_by} but mandate file not found locally — cannot cross-check validity window or revocation status (${(e as Error).message})`,
        );
      }
    }
  }

  return { errors, warnings };
}
