/**
 * Ethos module — the live on-disk representation of an Ethos document.
 *
 * Filesystem layout (under each identity dir):
 *
 *   ~/.aithos/identities/<handle>/ethos/
 *   ├── manifest.json            (current edition manifest — spec §3.3)
 *   ├── history/
 *   │   └── <edition>.manifest.json   (every past edition's manifest)
 *   ├── public/
 *   │   └── public.md            (plaintext markdown — spec §2.6)
 *   ├── circle/
 *   │   └── circle.md.enc        (XChaCha20-Poly1305 ciphertext — spec §3.4)
 *   ├── self/
 *   │   └── self.md.enc
 *   └── gamma/
 *       └── gamma.jsonl.enc      (signed, hash-chained mutation log — spec §10)
 *
 * The live folder is the source of truth for what the subject *currently
 * looks like*. The gamma log is the source of truth for *how they got
 * there* — every add/modify/delete is a signed entry in a hash-chained
 * JSONL log, living side by side with the live doc (spec §10).
 *
 * The live sections carry only { id, title, body, tags?, gamma_ref }: no
 * embedded history. The `gamma_ref` points to the latest gamma entry
 * affecting the section, so every visible field is traceable back to the
 * signed mutation that produced it.
 *
 * Every edit creates a new edition:
 *   - `edition.version` is `YYYY.MM.DD-N` (auto-incrementing N within a day)
 *   - `edition.prev_hash` is sha256 of the previous edition's canonical manifest
 *     with the manifest signature value blanked
 *   - `edition.height` is prev.height + 1
 *   - `gamma.head` anchors the edition to the current tail of the log, so the
 *     signed manifest commits to the entire history (spec §10.2 / §10.7).
 */

import { join } from "node:path";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  chmodSync,
  copyFileSync,
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
} from "./identity.js";
import {
  didUrlForKex,
  type Sphere,
  SPHERE_FRAGMENTS,
  multibaseToEd25519PublicKey,
  x25519PublicKeyToMultibase,
} from "./did.js";
import { ensureDir, identityDir, readJson, writeJson } from "./storage.js";
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
import {
  type Author,
  assertCanWrite,
  authorSubjectDid,
  authorMandateId,
  ownerAuthor,
} from "./author.js";

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

export function ethosHistoryDir(handle: string): string {
  return join(ethosDir(handle), "history");
}

export function ethosManifestPath(handle: string): string {
  return join(ethosDir(handle), "manifest.json");
}

/* -------------------------------------------------------------------------- */
/*  Document-form types                                                       */
/* -------------------------------------------------------------------------- */

/**
 * A section in the live ethos document. Spec §2.5.1.
 *
 * No embedded revision history — every mutation is a signed entry in the
 * gamma log (spec §10). The `gamma_ref` field names the latest gamma entry
 * that produced the current state of this section, so readers can always
 * trace a visible field back to the signed mutation that authored it.
 */
export interface Section {
  id: string;
  title: string;
  body: string;
  tags?: string[];
  gamma_ref: string;
}

export interface ZoneDoc {
  sections: Section[];
}

export type Zones = Record<Sphere, ZoneDoc>;

/* -------------------------------------------------------------------------- */
/*  Manifest                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Signature carried by a zone manifest entry or the top-level manifest.
 *
 * `key` is either a sphere DID URL (owner signature) or a multibase-encoded
 * Ed25519 public key (delegate signature). When signed by a delegate,
 * `authorized_by` is set to the issuing mandate's id so verifiers can
 * resolve the delegate pubkey against a local mandate file.
 */
export interface ZoneSignature {
  alg: "ed25519";
  key: string;
  value: string;
  authorized_by?: string;
}

export interface ManifestSignature {
  alg: "ed25519";
  key: string;
  value: string;
  authorized_by?: string;
}

export interface ZoneManifest {
  file: string;
  encrypted: boolean;
  sha256_of_plaintext: string; // hex without prefix
  section_titles: string[];
  cipher?: ZoneCipher; // only when encrypted
  signature: ZoneSignature;
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
 * Anchor to the gamma deep-memory log (spec §10).
 *
 * Each new edition snapshots the log's current head hash and length so the
 * signed manifest commits to the state of the log (spec §10.3.5 / §10.7).
 * Off-box delivery (e.g. an S3 URL for the encrypted .jsonl.enc) can
 * populate `url`; otherwise the log lives purely local.
 */
export interface GammaManifestAnchor {
  head: string | null;   // sha256:<hex> of latest entry, null if log is empty
  count: number;         // total number of entries in the log
  url?: string;          // optional off-box location of the encrypted log
}

/**
 * Manifest version. Bumped to 0.2.0 for the gamma cutover: sections no
 * longer carry embedded revisions[], and `gamma` is REQUIRED as soon as the
 * ethos has any section (every section is born from a gamma entry).
 */
export const AITHOS_VERSION = "0.2.0" as const;
export type AithosVersion = typeof AITHOS_VERSION;

export interface Manifest {
  aithos: AithosVersion;
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
    manifest_signature: ManifestSignature;
  };
}

/* -------------------------------------------------------------------------- */
/*  Low-level IO                                                              */
/* -------------------------------------------------------------------------- */

export function ensureEthosLayout(handle: string): void {
  ensureDir(ethosDir(handle));
  for (const s of SPHERE_FRAGMENTS) ensureDir(ethosZoneDir(handle, s));
  ensureDir(ethosHistoryDir(handle));
}

export function readManifest(handle: string): Manifest {
  return readJson<Manifest>(ethosManifestPath(handle));
}

export function writeManifest(handle: string, m: Manifest): void {
  writeJson(ethosManifestPath(handle), m, 0o600);
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
 * Document-form → markdown form, per spec §2.6.1 (revised for v0.2.0).
 *
 * Each section is a heading whose HTML comment carries the section id AND
 * its gamma_ref — the id of the latest gamma entry affecting the section.
 * The body follows as plain markdown. No per-revision blocks; the gamma
 * log holds the signed history.
 */
export function renderZoneMarkdown(zone: Sphere, doc: ZoneDoc, ctx: RenderContext): string {
  const fm = [
    "---",
    `aithos: "${AITHOS_VERSION}"`,
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
    parts.push(`# ${sec.title} <!-- ${sec.id} · ${sec.gamma_ref} -->`);
    if (sec.tags && sec.tags.length > 0) {
      parts.push(`<!-- tags: ${JSON.stringify(sec.tags)} -->`);
    }
    parts.push("");
    parts.push(sec.body);
    parts.push("");
  }

  // Trim trailing whitespace while preserving a final newline.
  return parts.join("\n").replace(/\s+$/, "") + "\n";
}

/**
 * Markdown form → document form. Parses the v0.2.0 layout:
 *   `# <title> <!-- <sec_id> · <gamma_ref> -->`
 *   optional `<!-- tags: [...] -->`
 *   body until the next `# ` heading.
 */
export function parseZoneMarkdown(
  markdown: string,
  expectedZone: Sphere,
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
  const body = markdown.slice(fmMatch[0].length);

  const sections: Section[] = [];
  const sectionChunks = body.split(/(?=^# )/m).filter((c) => c.trim());
  for (const chunk of sectionChunks) {
    const header = chunk.match(
      /^# (.+?) <!-- (sec_[a-z0-9_-]+) · (gamma_[0-9A-Z]+) -->\s*\n/,
    );
    if (!header) {
      throw new Error(
        `Zone markdown: section heading missing section id / gamma_ref anchor; ` +
          `expected "# <title> <!-- sec_xxx · gamma_xxx -->"`,
      );
    }
    const title = header[1].trim();
    const id = header[2];
    const gammaRef = header[3];
    let rest = chunk.slice(header[0].length);

    // Optional tags comment on its own line right after heading.
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

    // Everything that remains (trimmed) is the section body.
    const sectionBody = rest.replace(/^\n+/, "").replace(/\s+$/, "");

    sections.push({
      id,
      title,
      body: sectionBody,
      gamma_ref: gammaRef,
      ...(tags ? { tags } : {}),
    });
  }

  return { sections };
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

/**
 * Sign the top-level manifest.
 *
 * Owner path: signed with the subject's public sphere key (unchanged).
 * Delegate path: signed with the delegate Ed25519 seed; the resulting
 * `manifest_signature` carries `authorized_by = mandate.id` so verifiers can
 * resolve the delegate pubkey against the issuing mandate.
 *
 * The canonical bytes include the `key` and `authorized_by` fields (with
 * `value` blanked), so the signature binds to both the signer identity and
 * the mandate it claims authority under — an attacker cannot swap
 * `authorized_by` post-facto without invalidating the signature.
 */
export function signManifest(subject: Identity | Author, m: Manifest): Manifest {
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

  const toSign: Manifest = {
    ...m,
    integrity: { ...m.integrity, manifest_signature: baseSig },
  };
  const bytes = new TextEncoder().encode(canonicalize(toSign));

  const rawSig =
    author.kind === "owner"
      ? signWithSphere(author.identity, "public", bytes)
      : ed.sign(bytes, author.seed);

  return {
    ...toSign,
    integrity: {
      ...toSign.integrity,
      manifest_signature: { ...baseSig, value: base64url(rawSig) },
    },
  };
}

export interface VerifySignatureOpts {
  /**
   * Resolver for delegate public keys when the signature carries
   * `authorized_by`. Returns the raw 32-byte Ed25519 public key or throws.
   * The resolver is expected to also validate the mandate (signature + time
   * window + scope) before returning; if any of those checks fail, it must
   * throw.
   */
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

export function verifyManifestSignature(
  m: Manifest,
  didDoc: DidDocument,
  opts: VerifySignatureOpts = {},
): { ok: boolean; error?: string } {
  const sig = m.integrity.manifest_signature;
  let pk: Uint8Array;
  if (sig.authorized_by !== undefined) {
    if (!opts.resolveDelegatePubkey) {
      return {
        ok: false,
        error: `manifest signature is delegate-signed (authorized_by=${sig.authorized_by}) but no resolveDelegatePubkey provided`,
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

  const unsigned: Manifest = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...sig, value: "" },
    },
  };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sigBytes = base64urlDecode(sig.value);
  return ed.verify(sigBytes, bytes, pk)
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

/**
 * Upgrade a bare Identity OR an Author into an Author. Accepts either shape
 * so legacy callers (owner-only) can keep passing an Identity and new code
 * can pass an Author directly.
 */
function toAuthor(subject: Identity | Author): Author {
  if ((subject as Author).kind === "owner" || (subject as Author).kind === "delegate") {
    return subject as Author;
  }
  return ownerAuthor(subject as Identity);
}

/* -------------------------------------------------------------------------- */
/*  Zone signature (over the canonical zone document)                         */
/* -------------------------------------------------------------------------- */

/**
 * Sign a zone document.
 *
 * Owner path: the sphere key matching the zone. Delegate path: the delegate
 * Ed25519 seed; the returned signature carries `authorized_by = mandate.id`.
 * Enforces `ethos.write.<zone>` scope + validity window before signing.
 */
export function signZone(
  subject: Identity | Author,
  zone: Sphere,
  doc: ZoneDoc,
): ZoneSignature {
  const author = toAuthor(subject);
  const bytes = new TextEncoder().encode(canonicalize(doc));
  if (author.kind === "owner") {
    const sig = signWithSphere(author.identity, zone, bytes);
    return {
      alg: "ed25519",
      key: sphereDidUrl(author.identity, zone),
      value: base64url(sig),
    };
  }
  assertCanWrite(author, zone);
  const sig = ed.sign(bytes, author.seed);
  return {
    alg: "ed25519",
    key: author.pubkeyMultibase,
    value: base64url(sig),
    authorized_by: author.mandate.id,
  };
}

export function verifyZoneSignature(
  doc: ZoneDoc,
  sig: ZoneSignature,
  didDoc: DidDocument,
  opts: VerifySignatureOpts = {},
): { ok: boolean; error?: string } {
  let pk: Uint8Array;
  if (sig.authorized_by !== undefined) {
    if (!opts.resolveDelegatePubkey) {
      return {
        ok: false,
        error: `zone signature is delegate-signed (authorized_by=${sig.authorized_by}) but no resolveDelegatePubkey provided`,
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
  const bytes = new TextEncoder().encode(canonicalize(doc));
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
  return parseZoneMarkdown(plaintext, zone);
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
  // the current head. In v0.2.0 the log IS the history; an ethos with any
  // section necessarily has a non-empty log. The anchor is omitted only
  // when the log is empty (fresh identity with no sections yet).
  const gammaAnchor = safeReadGammaAnchor(handle, identity);

  const unsigned: Manifest = {
    aithos: AITHOS_VERSION,
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
/*  Section mutation — gamma-backed (spec §10)                                */
/* -------------------------------------------------------------------------- */

/**
 * Shared shape for delegate-signer args across add / modify / delete.
 * A delegate is an agent's Ed25519 keypair authorized by a write mandate
 * (`ethos.write.<zone>`). The mandate's grantee.pubkey MUST equal
 * `keyMultibase`; the seed is used to sign the gamma entry directly.
 */
export interface DelegateSigner {
  mandateId: string;
  keySeed: Uint8Array;
  keyMultibase: string;
}

export interface AddSectionArgs {
  handle: string;
  identity: Identity;
  zone: Sphere;
  title: string;
  body: string;
  tags?: string[];
  delegate?: DelegateSigner;
  at?: Date;
}

/**
 * Append a new section to a zone.
 *
 * Flow:
 *   1. Emit a signed `section.add` gamma entry carrying the full title/body/tags.
 *   2. Use that entry's id as the section's `gamma_ref`.
 *   3. Add the section to the in-memory zone doc and persist a new edition.
 *
 * The gamma entry is appended FIRST so the edition's signed manifest already
 * commits to the updated `gamma.head` (spec §10.3.5). A crash between steps
 * 2 and 3 leaves the log ahead of the live doc — the next edition will
 * catch up.
 */
export function addSection(
  args: AddSectionArgs,
): { section: Section; manifest: Manifest; gammaEntry: GammaEntry } {
  const zones = loadAllZones(args.handle, args.identity);
  const sectionId = newSectionId();
  if (zones[args.zone].sections.some((s) => s.id === sectionId)) {
    throw new Error("Section id collision, try again");
  }

  const at = args.at ?? new Date();

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

  const section: Section = {
    id: sectionId,
    title: args.title,
    body: args.body,
    gamma_ref: gammaEntry.id,
    ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
  };
  zones[args.zone].sections.push(section);

  const manifest = persistEdition(args.handle, args.identity, zones, { now: at });
  return { section, manifest, gammaEntry };
}

/* -------------------------------------------------------------------------- */
/*  Section modification — replaces add-revision in v0.2.0                    */
/* -------------------------------------------------------------------------- */

export interface ModifySectionArgs {
  handle: string;
  identity: Identity;
  zone: Sphere;
  sectionId: string;
  /** New title. Omit to keep the existing title. */
  title?: string;
  /** New body. Omit to keep the existing body. */
  body?: string;
  /**
   * New tag set. Omit to keep existing tags. To CLEAR tags, pass [].
   * Any array (including []) is treated as the authoritative replacement.
   */
  tags?: string[];
  delegate?: DelegateSigner;
  at?: Date;
}

/**
 * Apply an in-place modification to a section.
 *
 * Semantics (spec §10.6.1, option (a)):
 *   - The payload of the emitted `section.modify` entry carries the FULL
 *     new value of each field being changed — not a diff. Readers replay
 *     the log by applying each payload as a straight replacement.
 *   - At least one of {title, body, tags} MUST be provided.
 *   - The section's `gamma_ref` is updated to point at the new entry.
 *
 * The prior `section.add` (and any earlier `section.modify` entries) remain
 * immutable in the log — that's the audit trail.
 */
export function modifySection(
  args: ModifySectionArgs,
): { section: Section; manifest: Manifest; gammaEntry: GammaEntry } {
  if (args.title === undefined && args.body === undefined && args.tags === undefined) {
    throw new Error("modifySection: must set at least one of {title, body, tags}");
  }

  const zones = loadAllZones(args.handle, args.identity);
  const section = zones[args.zone].sections.find((s) => s.id === args.sectionId);
  if (!section) {
    throw new Error(`Section ${args.sectionId} not found in zone ${args.zone}`);
  }

  const at = args.at ?? new Date();

  // Build payload containing only the fields that actually change. This
  // keeps the signed record honest: readers can see at a glance which
  // fields the writer intended to replace.
  const payload: Record<string, unknown> = {};
  if (args.title !== undefined) payload.title = args.title;
  if (args.body !== undefined) payload.body = args.body;
  if (args.tags !== undefined) payload.tags = args.tags;

  const existingLog = readGammaLog(args.handle, args.identity);
  const priorOnSection = latestGammaForSection(existingLog, args.sectionId);

  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : sphereGammaSigner(args.identity, args.zone);
  const prevGammaHash = gammaHead(args.handle, args.identity);

  const gammaEntry = buildGammaEntry({
    subjectDid: rootDid(args.identity),
    zone: args.zone,
    op: "section.modify",
    target: { section_id: args.sectionId },
    payload,
    prevGammaHash,
    ...(priorOnSection ? { prevSectionGamma: priorOnSection.id } : {}),
    signer: gammaSigner,
    at,
  });
  appendGammaEntry(args.handle, args.identity, gammaEntry);

  // Apply the change to the in-memory section.
  if (args.title !== undefined) section.title = args.title;
  if (args.body !== undefined) section.body = args.body;
  if (args.tags !== undefined) {
    if (args.tags.length === 0) delete section.tags;
    else section.tags = args.tags;
  }
  section.gamma_ref = gammaEntry.id;

  const manifest = persistEdition(args.handle, args.identity, zones, { now: at });
  return { section, manifest, gammaEntry };
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
  delegate?: DelegateSigner;
  at?: Date;
}

/**
 * Remove a section from its zone AND record the removal as a `section.delete`
 * entry in the gamma log.
 *
 * After this call:
 *   - the current edition no longer contains the section (pack/install sees
 *     it as if it never existed in the live doc),
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

export function loadAllZones(handle: string, identity: Identity): Zones {
  return {
    public: loadZoneDoc(handle, "public", identity),
    circle: loadZoneDoc(handle, "circle", identity),
    self: loadZoneDoc(handle, "self", identity),
  };
}

/* -------------------------------------------------------------------------- */
/*  Verification (spec §3.8 + §10.7)                                          */
/* -------------------------------------------------------------------------- */

export interface VerifyEthosResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Verify an installed ethos.
 *
 * In v0.2.0 the history of a section lives in the gamma log, not in the
 * live document. So section-level integrity has two layers:
 *
 *   - **Live view**: the rendered zone markdown must hash to the value
 *     declared in the manifest, and every section in the live doc must
 *     name a `gamma_ref` that exists in the gamma log with a matching
 *     section id.
 *   - **Mutation history**: the gamma log must be self-consistent (every
 *     entry's hash/signature verifies, every link chains to the previous
 *     entry's hash) and the manifest's `gamma.head` / `gamma.count` must
 *     agree with the log's actual tail.
 *
 * The deeper gamma-log walk (per-entry signature + chain) is performed by
 * `verifyGammaLog` from `gamma.ts`; this function only checks the light
 * anchor-vs-log consistency required by spec §10.7 (light tier). The CLI
 * wires in the full walk separately.
 */
export function verifyEthos(
  handle: string,
  identity: Identity | null,
  didDoc: DidDocument,
): VerifyEthosResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const manifest = readManifest(handle);

  // Check 2: manifest structural validity (light).
  if (manifest.aithos !== AITHOS_VERSION) {
    errors.push(`manifest.aithos is not ${AITHOS_VERSION}`);
  }

  // Check 3+4: did.json.
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

  // Check 6: manifest signature.
  const manSig = verifyManifestSignature(manifest, didDoc);
  if (!manSig.ok) errors.push(manSig.error ?? "manifest signature failed");

  // Collect gamma_refs we've seen in the live doc so we can cross-check
  // against the log below.
  const seenGammaRefs = new Set<string>();

  // Check 5 + 7: zone integrity (plaintext hash, zone signature, titles).
  for (const z of SPHERE_FRAGMENTS) {
    const zm = manifest.zones[z];
    const loaded = safeLoadZone(handle, z, identity, manifest, errors);
    if (!loaded.doc) continue;
    if (loaded.skipped) {
      warnings.push(
        `zone ${z}: skipped content checks (encrypted, no sphere key available) — manifest declares ${zm.section_titles.length} section(s)`,
      );
      continue;
    }
    const doc = loaded.doc;

    // 5: plaintext hash.
    const md = renderZoneMarkdownFromDoc(z, doc, manifest);
    const hex = Buffer.from(sha256fn(new TextEncoder().encode(md))).toString("hex");
    if (hex !== zm.sha256_of_plaintext) {
      errors.push(`zone ${z}: sha256_of_plaintext mismatch (rendered=${hex} manifest=${zm.sha256_of_plaintext})`);
    }

    // section_titles consistency.
    const actualTitles = doc.sections.map((s) => s.title);
    if (JSON.stringify(actualTitles) !== JSON.stringify(zm.section_titles)) {
      errors.push(`zone ${z}: section_titles mismatch`);
    }

    // Zone signature.
    const zs = verifyZoneSignature(doc, zm.signature, didDoc);
    if (!zs.ok) errors.push(`zone ${z}: ${zs.error}`);

    // Every section must name a gamma_ref.
    for (const sec of doc.sections) {
      if (!sec.gamma_ref) {
        errors.push(`zone ${z} section ${sec.id}: missing gamma_ref`);
        continue;
      }
      seenGammaRefs.add(sec.gamma_ref);
    }
  }

  // Check: gamma anchor consistency (spec §10.7 light tier).
  //
  // When the subject keys are available we walk the log and confirm head +
  // count. Otherwise we note the anchor but cannot verify it.
  if (identity) {
    try {
      const entries = readGammaLog(handle, identity);
      if (manifest.gamma) {
        if (manifest.gamma.count !== entries.length) {
          errors.push(
            `gamma.count mismatch: manifest=${manifest.gamma.count} log=${entries.length}`,
          );
        }
        const tailHash = entries.length === 0 ? null : entries[entries.length - 1].hash;
        if (manifest.gamma.head !== tailHash) {
          errors.push(
            `gamma.head mismatch: manifest=${manifest.gamma.head ?? "null"} log=${tailHash ?? "null"}`,
          );
        }
      } else if (entries.length > 0) {
        errors.push(
          `gamma log has ${entries.length} entr${entries.length === 1 ? "y" : "ies"} but manifest omits the gamma anchor`,
        );
      }

      // Every section's gamma_ref must exist in the log.
      if (seenGammaRefs.size > 0) {
        const ids = new Set(entries.map((e) => e.id));
        for (const ref of seenGammaRefs) {
          if (!ids.has(ref)) {
            errors.push(`section gamma_ref ${ref} not found in gamma log`);
          }
        }
      }
    } catch (e) {
      errors.push(`gamma log: failed to read (${(e as Error).message})`);
    }
  } else if (manifest.gamma) {
    warnings.push(
      `gamma anchor present (head=${manifest.gamma.head ?? "null"}, count=${manifest.gamma.count}) but no identity key available to verify the log`,
    );
  }

  // Check 8: edition chain self-consistency.
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

// v0.1.0's `verifySectionChain` is gone. The revision chain no longer
// exists in the live doc — history is held by the gamma log. See
// `verifyGammaLog` in gamma.ts for the per-entry + chain walk, and
// `verifyEthos` above for the light anchor-vs-log consistency check.
