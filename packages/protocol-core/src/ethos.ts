// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

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
  mkdirSync,
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
  edSeedToX25519Secret,
  x25519PublicFromSecret,
  ed25519PubToX25519Pub,
} from "./identity.js";
import {
  didUrlForKex,
  type Sphere,
  SPHERE_FRAGMENTS,
  multibaseToEd25519PublicKey,
  sphereDidUrl,
  signWithSphere,
  rootDid,
  x25519PublicKeyToMultibase,
} from "./did.js";
import {
  ensureDir,
  identityDir,
  listMandates,
  listRevocations,
  mandatesDir,
  revocationsDir,
  readJson,
  writeJson,
} from "./storage.js";
import {
  type Mandate,
  type Revocation,
  hasGammaReadScope,
  verifyMandate,
} from "./mandate.js";
import { findRevocation, loadMandate } from "./mandate-store.js";
import {
  appendGammaEntryOnDisk,
  buildGammaEntryV03,
  defaultGammaReaderKeys,
  delegateGammaRecipient,
  delegateGammaSigner,
  gammaHead,
  gammaHeadForAuthor,
  latestGammaIdForSection,
  readGammaHeaders,
  readGammaLog,
  sphereGammaSigner,
  type GammaEntry,
  type GammaEntryV03,
  type GammaReaderKey,
  type GammaSigner,
} from "./gamma.js";
import {
  type Author,
  assertCanWrite,
  authorGammaSigner,
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
/**
 * A party authorized to read gamma entries in the v0.3 format.
 *
 * On every v0.3 append, the writer seals the entry's per-entry symmetric key
 * to each reader in this list (using each reader's X25519 public key). Readers
 * added after an entry was appended cannot decrypt that entry — seal is
 * forward-only. Subject sphere keys are always present; delegate readers are
 * added by grant when a mandate carries `gamma.read`.
 */
export interface GammaReader {
  /** Stable identifier — `did:aithos:*#<sphere>` for subject, `urn:aithos:agent:*` for delegates. */
  recipient: string;
  /** Multibase-encoded X25519 public key this reader decrypts with. */
  pubkey: string;
  /** Mandate id that authorized this delegate reader. Absent for subject spheres. */
  via_mandate?: string;
  /** ISO-8601 timestamp the reader was added. Informative. */
  added_at: string;
}

export interface GammaManifestAnchor {
  head: string | null;   // sha256:<hex> of latest entry, null if log is empty
  count: number;         // total number of entries in the log
  url?: string;          // optional off-box location of the encrypted log
  /**
   * v0.3+ — recipients sealed into every future entry's envelopes list.
   * OPTIONAL for backward compatibility with v0.2 manifests. A v0.3 writer
   * populates this on every edition.
   */
  readers?: GammaReader[];
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
  subjectDid: string,
  recipients: Array<{ did: string; x25519PublicKey: Uint8Array }>,
): EncryptedZone {
  const dek = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(24));
  // AAD binds to the subject DID (stable across editions). Edition integrity
  // is already protected by the signed manifest + prev_hash chain, so tying
  // the ciphertext's AAD to a per-edition bundle_id would force delegates to
  // re-seal zones they cannot read — breaking carry-forward.
  const aad = Buffer.concat([ZONE_AAD_PREFIX, Buffer.from(subjectDid, "utf8")]);
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
  subjectDid: string,
  myDidUrl: string,
  myX25519Secret: Uint8Array,
): string {
  const wrap = cipher.wraps.find((w) => w.recipient === myDidUrl);
  if (!wrap) throw new Error(`No wrap entry for ${myDidUrl}`);
  const dek = unwrapDek(wrap, myX25519Secret);
  try {
    const aad = Buffer.concat([ZONE_AAD_PREFIX, Buffer.from(subjectDid, "utf8")]);
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
/*  Recipient derivation for Author                                           */
/* -------------------------------------------------------------------------- */

/**
 * Stable wrap-list label for a delegate's DEK entry.
 *
 * The `did` field on a ZoneWrap / GammaWrap is just a unique key for the
 * recipient — lookup is by string equality, not DID resolution. For owner
 * wraps we use `did:aithos:...#kex-<zone>`. For delegate wraps we use
 * `<grantee.id>#<delegate-pubkey-multibase>`, which is stable across
 * editions while remaining distinguishable from any sphere wrap.
 */
export function delegateWrapDid(granteeId: string, pubkeyMultibase: string): string {
  return `${granteeId}#${pubkeyMultibase}`;
}

/**
 * Derive the owner's sphere X25519 public key from public metadata — no
 * sphere seed required. Used on the delegate side to include the owner as
 * a wrap recipient so the owner can decrypt a bundle the delegate produced.
 */
function ownerSphereX25519Pub(
  metadata: { didDocument: DidDocument; sphereDids: Record<Sphere, string> },
  zone: Sphere,
): Uint8Array {
  const sphereVmId = metadata.sphereDids[zone];
  const vm = metadata.didDocument.verificationMethod.find((v) => v.id === sphereVmId);
  if (!vm) {
    throw new Error(`did.json has no verificationMethod for sphere ${zone}`);
  }
  const edPub = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  // Lazy import to avoid pulling identity.ts into this module's public surface.
  return ed25519PubToX25519Pub(edPub);
}

/**
 * Recipients to include when an author writes (and re-encrypts) an encrypted
 * zone.
 *
 *   - Owner: their own sphere X25519 pubkey (subject-as-recipient, §3.5.1)
 *     PLUS every active (non-revoked) delegate whose mandate covers this zone.
 *   - Delegate: BOTH the owner's sphere X25519 pubkey (so the owner can
 *     decrypt when the bundle returns) AND the delegate's own X25519 pubkey.
 *     Other delegates are not re-added by a delegate-side write: the delegate
 *     can't reconstruct their pubkeys without consulting their mandate files,
 *     which exist on disk only for authors who ran `issueMandateWithRewrap`.
 *
 * Revoked mandates are filtered out so a post-revocation re-render excludes
 * the delegate from the recipient set — which is exactly what
 * `repinAfterRevocation` leverages.
 */
export function authorZoneWriteRecipients(
  subject: Identity | Author,
  zone: "circle" | "self",
  subjectDid?: string,
): Array<{ did: string; x25519PublicKey: Uint8Array }> {
  const author = toAuthor(subject);
  if (author.kind === "owner") {
    const r = subjectRecipientFor(author.identity, zone);
    const out: Array<{ did: string; x25519PublicKey: Uint8Array }> = [
      { did: r.did, x25519PublicKey: r.x25519PublicKey },
    ];
    const did = subjectDid ?? rootDid(author.identity);
    for (const del of activeDelegatesForZone(did, zone)) {
      out.push(del);
    }
    return out;
  }
  const ownerPk = ownerSphereX25519Pub(author.subject, zone);
  const ownerDid = didUrlForKex(author.subject.did, zone);
  const delegatePk = ed25519PubToX25519Pub(multibaseToEd25519PublicKey(author.pubkeyMultibase));
  return [
    { did: ownerDid, x25519PublicKey: ownerPk },
    {
      did: delegateWrapDid(author.mandate.grantee.id, author.pubkeyMultibase),
      x25519PublicKey: delegatePk,
    },
  ];
}

/**
 * Enumerate delegate recipients authorised to read/write a given zone of a
 * specific subject. Returns { did: "<granteeId>#<pubkeyMb>", x25519PublicKey }
 * pairs, excluding any mandate that has a matching local revocation.
 *
 * This is the cornerstone of `issueMandateWithRewrap` / `repinAfterRevocation`:
 * the live mandate directory is the source of truth for who can decrypt the
 * current edition.
 */
export function activeDelegatesForZone(
  subjectDid: string,
  zone: Sphere,
): Array<{ did: string; x25519PublicKey: Uint8Array }> {
  const out: Array<{ did: string; x25519PublicKey: Uint8Array }> = [];
  if (!existsSync(mandatesDir())) return out;
  const readScope = `ethos.read.${zone}` as const;
  const writeScope = `ethos.write.${zone}` as const;
  for (const fn of listMandates()) {
    let m: Mandate;
    try {
      m = readJson<Mandate>(join(mandatesDir(), fn));
    } catch {
      continue;
    }
    if (m.issuer !== subjectDid) continue;
    const covers =
      m.scopes.includes(writeScope) ||
      m.scopes.includes(readScope) ||
      m.scopes.includes("ethos.read.all");
    if (!covers) continue;
    if (!m.grantee.pubkey) continue;
    if (findRevocation(m.id)) continue;
    let edPub: Uint8Array;
    try {
      edPub = multibaseToEd25519PublicKey(m.grantee.pubkey);
    } catch {
      continue;
    }
    const xPub = ed25519PubToX25519Pub(edPub);
    out.push({
      did: delegateWrapDid(m.grantee.id, m.grantee.pubkey),
      x25519PublicKey: xPub,
    });
  }
  return out;
}

/**
 * Recipient (did label + X25519 secret) an author uses to DECRYPT a zone
 * they're allowed to read. Owner → sphere secret. Delegate → their own
 * Ed25519-derived X25519 secret.
 */
export function authorZoneDecryptRecipient(
  subject: Identity | Author,
  zone: "circle" | "self",
): { did: string; x25519Secret: Uint8Array } {
  const author = toAuthor(subject);
  if (author.kind === "owner") {
    const r = subjectRecipientFor(author.identity, zone);
    return { did: r.did, x25519Secret: r.x25519Secret };
  }
  return {
    did: delegateWrapDid(author.mandate.grantee.id, author.pubkeyMultibase),
    x25519Secret: edSeedToX25519Secret(author.seed),
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

export function loadZoneDoc(
  handle: string,
  zone: Sphere,
  who?: Identity | Author,
  manifest?: Manifest,
): ZoneDoc {
  const bodyPath = ethosZoneFile(handle, zone);
  if (!existsSync(bodyPath)) return { sections: [] };
  return parseZoneMarkdown(loadZonePlaintext(handle, zone, who, manifest), zone);
}

/**
 * Return the raw plaintext markdown for a zone (decrypted if necessary),
 * without parsing it into a `ZoneDoc`. Used by `verifyEthos` to hash the
 * exact bytes that were written at edition-creation time, instead of
 * re-rendering them — re-rendering embeds the current manifest's edition
 * version in the frontmatter, which breaks hash equality for zones that
 * were carried forward from a previous edition.
 *
 * Returns "" for a zone that has no on-disk file (empty ethos).
 */
export function loadZonePlaintext(
  handle: string,
  zone: Sphere,
  who?: Identity | Author,
  manifest?: Manifest,
): string {
  const bodyPath = ethosZoneFile(handle, zone);
  if (!existsSync(bodyPath)) return "";

  const m = manifest ?? readManifest(handle);
  const zm = m.zones[zone];
  if (!zm.encrypted) {
    return readFileSync(bodyPath, "utf8");
  }
  if (!who) throw new Error(`Identity or Author required to decrypt ${zone}`);
  if (zone === "public") throw new Error(`public zone should never be encrypted`);
  const author = toAuthor(who);
  const recipient = authorZoneDecryptRecipient(author, zone as "circle" | "self");
  const ct = readFileSync(bodyPath);
  if (!zm.cipher) throw new Error(`Manifest missing cipher for ${zone}`);
  return decryptZone(
    new Uint8Array(ct),
    zm.cipher,
    m.subject_did,
    recipient.did,
    recipient.x25519Secret,
  );
}

export function writeZoneToDisk(
  handle: string,
  zone: Sphere,
  doc: ZoneDoc,
  subject: Identity | Author,
  ctx: RenderContext,
  subjectDid: string,
): { sha256Hex: string; cipher?: ZoneCipher; signature: ZoneSignature; sectionTitles: string[] } {
  const author = toAuthor(subject);
  const md = renderZoneMarkdown(zone, doc, ctx);
  const plaintextHashHex = Buffer.from(sha256fn(new TextEncoder().encode(md))).toString("hex");
  const sectionTitles = doc.sections.map((s) => s.title);
  const signature = signZone(author, zone, doc);

  const filePath = ethosZoneFile(handle, zone);
  ensureDir(ethosZoneDir(handle, zone));
  if (zone === "public") {
    writeFileSync(filePath, md, { mode: 0o600 });
    chmodSync(filePath, 0o600);
    return { sha256Hex: plaintextHashHex, signature, sectionTitles };
  }

  const recipients = authorZoneWriteRecipients(author, zone as "circle" | "self");
  const { ciphertext, cipher } = encryptZone(md, subjectDid, recipients);
  writeFileSync(filePath, ciphertext, { mode: 0o600 });
  chmodSync(filePath, 0o600);
  return { sha256Hex: plaintextHashHex, cipher, signature, sectionTitles };
}

/**
 * Persist a new edition: re-render the zone(s) the author is authorised on,
 * rebuild the manifest, sign it, archive the previous manifest under history/.
 *
 * Owner path: all three zones are re-rendered every edition (previous
 * behaviour). Delegate path: only `author.mandate.actor_sphere` is re-rendered
 * and re-signed — other zones carry their previous manifest entry forward
 * unchanged, because the delegate has no authority to re-sign them.
 */
export function persistEdition(
  handle: string,
  subject: Identity | Author,
  zones: Zones,
  opts: {
    now?: Date;
    prevManifest?: Manifest | null;
    /**
     * v0.3 — override the `gamma.readers` recorded in the new manifest
     * anchor. Use cases:
     *   - `issueMandateWithRewrap`: add a delegate reader when the mandate
     *     carries `gamma.read`.
     *   - `repinAfterRevocation`: filter out revoked delegate readers.
     *
     * When omitted, the new anchor carries forward `prevManifest.gamma.readers`
     * (or bootstraps from the owner's sphere keys on a fresh v0.3 identity).
     */
    gammaReadersOverride?: GammaReader[];
  } = {},
): Manifest {
  const author = toAuthor(subject);
  const now = opts.now ?? new Date();
  const createdAt = now.toISOString();
  const editionVersion = allocateEditionVersion(handle, now);
  const bundleId = `urn:aithos:${handle}:${editionVersion}`;
  const subjectDid = authorSubjectDid(author);
  const displayName =
    author.kind === "owner"
      ? author.identity.displayName
      : author.subject.displayName;

  const ctx: RenderContext = {
    subjectDid,
    subjectHandle: handle,
    editionVersion,
    createdAt,
  };

  const prevManifest =
    opts.prevManifest === undefined
      ? safeLoadPreviousManifest(handle)
      : opts.prevManifest;

  const zoneManifestEntries: Partial<Record<Sphere, ZoneManifest>> = {};
  for (const z of SPHERE_FRAGMENTS) {
    const shouldReRender =
      author.kind === "owner" || author.mandate.actor_sphere === z;

    if (!shouldReRender) {
      // Delegate without write-authority on this zone: carry forward the
      // previous manifest entry untouched. The on-disk ciphertext file is
      // left alone — nothing to re-write.
      if (!prevManifest) {
        throw new Error(
          `persistEdition: delegate is writing to ${author.kind === "delegate" ? author.mandate.actor_sphere : "?"} ` +
            `but zone ${z} has no previous manifest entry to carry forward`,
        );
      }
      zoneManifestEntries[z] = prevManifest.zones[z];
      continue;
    }

    const out = writeZoneToDisk(handle, z, zones[z], author, ctx, subjectDid);
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

  const prevHash = prevManifest
    ? "sha256:" + canonicalManifestHashHex(prevManifest)
    : null;
  const height = prevManifest ? prevManifest.edition.height + 1 : 1;
  const supersedes = prevManifest ? prevManifest.bundle_id : null;

  // Snapshot gamma log state into the manifest so the signature commits to
  // the current head. In v0.2.0 the log IS the history; an ethos with any
  // section necessarily has a non-empty log. The anchor is omitted only
  // when the log is empty (fresh identity with no sections yet).
  //
  // v0.3: the anchor also records `readers` — callers pass an override here
  // when the new edition changes the authorised reader set (grant with
  // `gamma.read`, or post-revocation repin).
  const gammaAnchor = safeReadGammaAnchor(
    handle,
    author,
    prevManifest,
    opts.gammaReadersOverride,
    now,
  );

  const unsignedSigKey =
    author.kind === "owner"
      ? sphereDidUrl(author.identity, "public")
      : author.pubkeyMultibase;

  const unsigned: Manifest = {
    aithos: AITHOS_VERSION,
    bundle_id: bundleId,
    subject_did: subjectDid,
    subject_handle: handle,
    display_name: displayName,
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
        key: unsignedSigKey,
        value: "",
        ...(author.kind === "delegate"
          ? { authorized_by: author.mandate.id }
          : {}),
      },
    },
  };

  const signed = signManifest(author, unsigned);
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
 * Compute the `GammaReader[]` list that the current edition should seal
 * future gamma entries to, and that `manifest.gamma.readers` should record.
 *
 * Precedence (highest first):
 *   1. Explicit `override` — used by `issueMandateWithRewrap` (add a
 *      delegate reader for a mandate with `gamma.read`) and by
 *      `repinAfterRevocation` (drop revoked delegate readers).
 *   2. Previous manifest's `gamma.readers` — the steady-state carry-forward
 *      path. Already filtered / augmented by the grant/revoke lifecycle.
 *   3. Bootstrap from `defaultGammaReaderKeys(identity)` — the three sphere
 *      X25519 pubkeys. Only the owner can bootstrap, because only the owner
 *      knows the sphere seeds. A delegate writing on a readers-less manifest
 *      is a bug (the owner must have bootstrapped on the previous edition).
 *
 * Returned list is never empty: either the prev manifest has readers, the
 * owner bootstraps to three, or the override was supplied explicitly. An
 * empty override is rejected because that would make every future gamma
 * entry unreadable by anyone.
 */
function computeGammaReaders(
  author: Author,
  prevManifest: Manifest | null | undefined,
  override?: GammaReader[],
  now: Date = new Date(),
): GammaReader[] {
  if (override) {
    if (override.length === 0) {
      throw new Error(
        "computeGammaReaders: override must not be empty — gamma entries would be unreadable",
      );
    }
    return override;
  }
  if (prevManifest?.gamma?.readers && prevManifest.gamma.readers.length > 0) {
    return prevManifest.gamma.readers;
  }
  if (author.kind !== "owner") {
    throw new Error(
      "computeGammaReaders: delegate cannot bootstrap gamma readers — " +
        "prev manifest must carry a non-empty gamma.readers list",
    );
  }
  const addedAt = now.toISOString();
  return defaultGammaReaderKeys(author.identity).map((k) => ({
    recipient: k.recipient,
    pubkey: k.pubkey,
    added_at: addedAt,
  }));
}

/**
 * Build a `GammaReader` entry for a mandate that carries `gamma.read`. The
 * mandate's `grantee.pubkey` is an Ed25519 multibase; we derive the matching
 * X25519 pubkey (same trick as zone DEK wraps, spec §3.5.2) and label the
 * recipient with the stable `<granteeId>#<pubkeyMb>` form so the envelope
 * lookup in `readGammaLogForAuthor` is deterministic.
 */
function gammaReaderFromMandate(m: Mandate, now: Date): GammaReader {
  if (!m.grantee.pubkey) {
    throw new Error(
      `gammaReaderFromMandate: mandate ${m.id} has no grantee.pubkey — nothing to seal to`,
    );
  }
  const edPub = multibaseToEd25519PublicKey(m.grantee.pubkey);
  const xPub = ed25519PubToX25519Pub(edPub);
  return {
    recipient: delegateGammaRecipient(m.grantee.id, m.grantee.pubkey),
    pubkey: x25519PublicKeyToMultibase(xPub),
    via_mandate: m.id,
    added_at: now.toISOString(),
  };
}

/**
 * Best-effort read of the gamma log to produce a manifest anchor. Returns
 * `null` when no log is present AND the caller did not request a readers
 * override (fresh identity, pre-gamma bundle, etc.), so `persistEdition`
 * can omit the `gamma` field entirely and stay byte-compatible with v0.1.0
 * manifests.
 *
 * v0.3: the anchor also carries `readers` — the authoritative list of
 * reader keys to seal every future gamma entry to. When a new edition is
 * persisted without appending any gamma entry (grant rewrap, revoke
 * repin), the anchor updates the readers list without touching `head` or
 * `count`.
 */
function safeReadGammaAnchor(
  handle: string,
  author: Author,
  prevManifest: Manifest | null | undefined,
  readersOverride?: GammaReader[],
  now: Date = new Date(),
): GammaManifestAnchor | null {
  // No decryption required: head/count come from the plaintext header list.
  let head: string | null;
  let count: number;
  try {
    const headers = readGammaHeaders(handle);
    head = headers.length === 0 ? null : headers[headers.length - 1].hash;
    count = headers.length;
  } catch {
    // Log unreadable or absent: fall back to prev anchor values.
    if (!prevManifest?.gamma && !readersOverride) return null;
    head = prevManifest?.gamma?.head ?? null;
    count = prevManifest?.gamma?.count ?? 0;
  }

  // Determine the readers list.
  let readers: GammaReader[] | undefined;
  if (readersOverride) {
    readers = readersOverride;
  } else if (prevManifest?.gamma?.readers) {
    readers = prevManifest.gamma.readers;
  } else if (head !== null && author.kind === "owner") {
    // v0.3 log exists on disk but prev manifest predates v0.3 readers —
    // bootstrap from the owner's sphere keys. Happens exactly once on the
    // first owner write after a v0.3 upgrade or a fresh identity's first
    // section.
    readers = computeGammaReaders(author, prevManifest, undefined, now);
  }

  // If the log is empty AND we have no readers info, keep legacy semantics.
  if (head === null && count === 0 && !readers) {
    return prevManifest?.gamma ?? null;
  }

  return {
    head,
    count,
    ...(readers ? { readers } : {}),
  };
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
  /**
   * Owner identity (legacy shape) OR Author (v0.2.1). Exactly one of
   * `identity` / `author` must be set; if both are set, `author` wins.
   * The `delegate` signer is the v0.2.0-style shim and still works for
   * owner-local callers that already hold their own delegate keypair.
   */
  identity?: Identity;
  author?: Author;
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
  const author = resolveAuthorArg(args);
  const zones = loadAllZones(args.handle, author);
  const sectionId = newSectionId();
  if (zones[args.zone].sections.some((s) => s.id === sectionId)) {
    throw new Error("Section id collision, try again");
  }

  const at = args.at ?? new Date();

  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : authorGammaSigner(author, args.zone);
  const prevGammaHash = gammaHeadForAuthor(args.handle, author);
  const prevManifest = safeLoadPreviousManifest(args.handle);
  const readers = computeGammaReaders(author, prevManifest, undefined, at);
  const gammaEntryV03 = buildGammaEntryV03({
    subjectDid: authorSubjectDid(author),
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
    readers,
    at,
  });
  appendGammaEntryOnDisk(args.handle, gammaEntryV03);

  const section: Section = {
    id: sectionId,
    title: args.title,
    body: args.body,
    gamma_ref: gammaEntryV03.public_header.id,
    ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
  };
  zones[args.zone].sections.push(section);

  const manifest = persistEdition(args.handle, author, zones, {
    now: at,
    prevManifest,
    gammaReadersOverride: readers,
  });
  const gammaEntry = gammaEntryV03ToLogical(gammaEntryV03, args.body, args.title, args.tags);
  return { section, manifest, gammaEntry };
}

/**
 * Convert a freshly-built v0.3 entry to the logical `GammaEntry` shape
 * returned by the mutation APIs. The writer has the plaintext payload on
 * hand, so this is a direct assembly — no decryption needed.
 *
 * Used by `addSection`/`modifySection`/`deleteSection` to keep their return
 * shape unchanged across the v0.2 → v0.3 cutover.
 */
function gammaEntryV03ToLogical(
  entry: GammaEntryV03,
  _body?: string,
  _title?: string,
  _tags?: string[],
): GammaEntry {
  // The payload on a v0.3 on-disk record is already encrypted; we can't
  // invert that here. But for the mutation-call return value, callers only
  // rely on { id, at, subject_did, zone, op, target, hash, signature,
  // prev_gamma_hash, prev_section_gamma? } — none of which are in the
  // ciphertext. So we return a logical view with payload={} and no
  // _access_denied marker (the caller's just-written plaintext is trivially
  // re-accessible; this return shape is for inspection, not authoritative
  // payload fetch).
  const h = entry.public_header;
  return {
    "aithos-gamma": h["aithos-gamma"],
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
    signature: {
      alg: entry.signature.alg,
      key: entry.signature.key,
      value: entry.signature.value,
    },
    ...(entry.signature.authorized_by ? { authorized_by: entry.signature.authorized_by } : {}),
  };
}

/**
 * Normalize a mutation call's `{ identity?, author? }` into a single Author.
 * Callers MUST supply exactly one; `author` takes precedence when both are
 * set (the legacy `identity` field is accepted only for b/w compat).
 */
function resolveAuthorArg(args: { identity?: Identity; author?: Author }): Author {
  if (args.author) return args.author;
  if (args.identity) return ownerAuthor(args.identity);
  throw new Error(
    "addSection/modifySection/deleteSection require one of { identity, author }",
  );
}

/* -------------------------------------------------------------------------- */
/*  Section modification — replaces add-revision in v0.2.0                    */
/* -------------------------------------------------------------------------- */

export interface ModifySectionArgs {
  handle: string;
  /** Owner identity (legacy) OR v0.2.1 Author. Exactly one must be set. */
  identity?: Identity;
  author?: Author;
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

  const author = resolveAuthorArg(args);
  const zones = loadAllZones(args.handle, author);
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

  // Walk headers (plaintext) — no envelope lookup needed to find the latest
  // gamma entry for a given section id. This is append-without-read-friendly:
  // a delegate with `ethos.write.<zone>` but no `gamma.read` can still chain
  // correctly to the prior on-section entry.
  const prevSectionGammaId = latestGammaIdForSection(args.handle, args.sectionId);

  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : authorGammaSigner(author, args.zone);
  const prevGammaHash = gammaHeadForAuthor(args.handle, author);

  const prevManifest = safeLoadPreviousManifest(args.handle);
  const readers = computeGammaReaders(author, prevManifest, undefined, at);
  const gammaEntryV03 = buildGammaEntryV03({
    subjectDid: authorSubjectDid(author),
    zone: args.zone,
    op: "section.modify",
    target: { section_id: args.sectionId },
    payload,
    prevGammaHash,
    ...(prevSectionGammaId ? { prevSectionGamma: prevSectionGammaId } : {}),
    signer: gammaSigner,
    readers,
    at,
  });
  appendGammaEntryOnDisk(args.handle, gammaEntryV03);

  // Apply the change to the in-memory section.
  if (args.title !== undefined) section.title = args.title;
  if (args.body !== undefined) section.body = args.body;
  if (args.tags !== undefined) {
    if (args.tags.length === 0) delete section.tags;
    else section.tags = args.tags;
  }
  section.gamma_ref = gammaEntryV03.public_header.id;

  const manifest = persistEdition(args.handle, author, zones, {
    now: at,
    prevManifest,
    gammaReadersOverride: readers,
  });
  const gammaEntry = gammaEntryV03ToLogical(gammaEntryV03);
  return { section, manifest, gammaEntry };
}

/* -------------------------------------------------------------------------- */
/*  Section deletion                                                          */
/* -------------------------------------------------------------------------- */

export interface DeleteSectionArgs {
  handle: string;
  /** Owner identity (legacy) OR v0.2.1 Author. Exactly one must be set. */
  identity?: Identity;
  author?: Author;
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
  const author = resolveAuthorArg(args);
  const zones = loadAllZones(args.handle, author);
  const zone = zones[args.zone];
  const idx = zone.sections.findIndex((s) => s.id === args.sectionId);
  if (idx < 0) {
    throw new Error(`Section ${args.sectionId} not found in zone ${args.zone}`);
  }
  const deleted = zone.sections[idx];
  zone.sections.splice(idx, 1);

  // Build the gamma entry. `prev_section_gamma` points at the most recent
  // gamma entry for this section (usually its own add, but could be a prior
  // modify). This lets per-section walks skip the global chain. Resolved
  // from headers only — no decryption required.
  const at = args.at ?? new Date();
  const prevSectionGammaId = latestGammaIdForSection(args.handle, args.sectionId);

  const gammaSigner: GammaSigner = args.delegate
    ? delegateGammaSigner(args.delegate.mandateId, args.delegate.keySeed, args.delegate.keyMultibase)
    : authorGammaSigner(author, args.zone);

  const prevGammaHash = gammaHeadForAuthor(args.handle, author);
  const prevManifest = safeLoadPreviousManifest(args.handle);
  const readers = computeGammaReaders(author, prevManifest, undefined, at);
  const gammaEntryV03 = buildGammaEntryV03({
    subjectDid: authorSubjectDid(author),
    zone: args.zone,
    op: "section.delete",
    target: { section_id: args.sectionId },
    payload: {
      ...(args.reason ? { reason: args.reason } : {}),
    },
    prevGammaHash,
    ...(prevSectionGammaId ? { prevSectionGamma: prevSectionGammaId } : {}),
    signer: gammaSigner,
    readers,
    at,
  });
  appendGammaEntryOnDisk(args.handle, gammaEntryV03);

  const manifest = persistEdition(args.handle, author, zones, {
    now: at,
    prevManifest,
    gammaReadersOverride: readers,
  });
  const gammaEntry = gammaEntryV03ToLogical(gammaEntryV03);
  return { manifest, gammaEntry, deletedTitle: deleted.title };
}

/**
 * Load every zone the author can see.
 *
 * Owner: all three zones (public + circle + self).
 *
 * Delegate: only the mandate's `actor_sphere` is decrypted through the
 * delegate wrap. The other two zones come back as empty docs — we do NOT
 * decrypt them under the delegate key (they aren't wrapped for the delegate
 * anyway) because a delegate operating on a tracked install has no
 * authority to re-sign them. `persistEdition` carries those zones' manifest
 * entries forward from the previous manifest untouched.
 */
/* -------------------------------------------------------------------------- */
/*  Mandate lifecycle — rewrap on issue / repin on revocation                 */
/* -------------------------------------------------------------------------- */

export interface IssueMandateWithRewrapArgs {
  handle: string;
  /** Owner of the subject — must hold the sphere seeds of the mandate's zone. */
  identity: Identity;
  /** Freshly-issued mandate. Assumed to already be on disk (writeMandate). */
  mandate: Mandate;
  at?: Date;
}

/**
 * Make a freshly-issued mandate effective on the current encrypted state.
 *
 * The mandate alone is only a signed grant on paper — it doesn't change the
 * zone ciphertext. A delegate handed the bundle as-is couldn't decrypt
 * their zone because their X25519 pubkey isn't on the DEK wrap list yet.
 * This function repairs that: it re-renders the subject's zones under a
 * recipient set that now includes the delegate.
 *
 * v0.3 (gamma): the gamma log is NOT rewrapped. Every gamma entry is sealed
 * per-entry to a fixed recipient set at append time, and the rewrap idea
 * from v0.2 (single DEK for the whole log → every delegate gets full
 * history) is gone by design. Instead, if the mandate carries `gamma.read`,
 * we add the grantee to `manifest.gamma.readers` so that FUTURE gamma
 * entries will be sealed to them. Past entries remain unreadable — the
 * protocol only grants forward-looking read access.
 *
 * Without `gamma.read` in the mandate's scopes, the grantee never appears
 * on any gamma envelope. A write-only delegate can append correct, signed
 * entries using only `manifest.gamma.readers` (the public reader list) +
 * their Ed25519 seed — no plaintext ever crosses their process.
 *
 * Owner-only: the subject must hold the sphere seeds. Call AFTER
 * `writeMandate(mandate)` so that `activeDelegatesForZone` can see the
 * live mandate.
 */
export function issueMandateWithRewrap(args: IssueMandateWithRewrapArgs): Manifest {
  const author = ownerAuthor(args.identity);
  const zones = loadAllZones(args.handle, author);
  const now = args.at ?? new Date();
  const prevManifest = safeLoadPreviousManifest(args.handle);

  // Compute gamma readers override only when the mandate carries gamma.read.
  // Write-only mandates do NOT grant any gamma access — that's the core
  // cryptographic property of the v0.3 format.
  let gammaReadersOverride: GammaReader[] | undefined;
  if (hasGammaReadScope(args.mandate.scopes) && args.mandate.grantee.pubkey) {
    const existing = prevManifest?.gamma?.readers ?? [];
    let base: GammaReader[];
    if (existing.length > 0) {
      base = [...existing];
    } else {
      // No prior readers list (fresh v0.3 bootstrap) — seed with the owner's
      // three sphere keys so the new reader joins an already-complete base.
      base = defaultGammaReaderKeys(args.identity).map((k) => ({
        recipient: k.recipient,
        pubkey: k.pubkey,
        added_at: now.toISOString(),
      }));
    }
    const newReader = gammaReaderFromMandate(args.mandate, now);
    if (!base.some((r) => r.recipient === newReader.recipient)) {
      base.push(newReader);
    }
    gammaReadersOverride = base;
  }

  return persistEdition(args.handle, author, zones, {
    now,
    prevManifest,
    ...(gammaReadersOverride ? { gammaReadersOverride } : {}),
  });
}

export interface RepinAfterRevocationArgs {
  handle: string;
  identity: Identity;
  revocation: Revocation;
  at?: Date;
}

/**
 * Rotate the DEKs so a revoked delegate can no longer decrypt the current
 * edition. The revocation must already be on disk (writeRevocation) so that
 * `activeDelegatesForZone` / the gamma rewrap helper omits the revoked key
 * from the new recipient set.
 *
 * Owner-only. Note this does NOT affect previously-shipped bundles — those
 * ciphertexts remain decryptable by the delegate. The protocol's safety
 * boundary is "from this edition onward".
 */
export function repinAfterRevocation(args: RepinAfterRevocationArgs): Manifest {
  const author = ownerAuthor(args.identity);
  const zones = loadAllZones(args.handle, author);
  const now = args.at ?? new Date();
  const prevManifest = safeLoadPreviousManifest(args.handle);

  // Drop revoked delegate readers from the gamma readers list. Subject sphere
  // readers (no `via_mandate`) are always kept.
  //
  // Note: this only affects FUTURE gamma entries. Past entries were sealed
  // at append time under the then-valid reader set — the revoked delegate
  // can still decrypt entries they received before revocation from any
  // bundle copy they kept. That's a fundamental limit of any copy-permitting
  // system and matches the zone DEK behaviour.
  let gammaReadersOverride: GammaReader[] | undefined;
  const prev = prevManifest?.gamma?.readers;
  if (prev && prev.length > 0) {
    const filtered = prev.filter(
      (r) => !r.via_mandate || !findRevocation(r.via_mandate),
    );
    if (filtered.length !== prev.length) {
      gammaReadersOverride = filtered;
    }
  }

  return persistEdition(args.handle, author, zones, {
    now,
    prevManifest,
    ...(gammaReadersOverride ? { gammaReadersOverride } : {}),
  });
}

/* -------------------------------------------------------------------------- */
/*  Pack / install primitives (flat-bundle layout — see bundle.ts)            */
/* -------------------------------------------------------------------------- */

export interface PackEthosToDirArgs {
  handle: string;
  /** Owner identity (legacy shape) OR v0.2.1 Author. `author` wins if both set. */
  identity?: Identity;
  author?: Author;
  /** Destination directory — will be created if it doesn't exist. */
  outDir: string;
}

/**
 * Copy the installed-ethos layout into the flat bundle layout that
 * `installBundleFromDir` and `verifyBundleAtPath` understand:
 *
 *   <outDir>/
 *   ├── manifest.json
 *   ├── did.json
 *   ├── public.md
 *   ├── circle.md.enc         (if present)
 *   ├── self.md.enc           (if present)
 *   └── gamma.jsonl.enc       (if present)
 *
 * `author` is accepted for API symmetry with the mutation calls; today the
 * pack operation only touches on-disk bytes (no re-signing), so any valid
 * author is fine. We just need exactly one of `identity` / `author` so the
 * call shape matches the rest of the Author-taking APIs.
 */
export function packEthosToDir(args: PackEthosToDirArgs): void {
  // Force consistent arg shape — we don't actually use the resolved author,
  // but rejecting calls with neither `identity` nor `author` keeps API usage
  // disciplined and matches the mutation-call convention.
  resolveAuthorArg(args);

  mkdirSync(args.outDir, { recursive: true });

  const srcDir = ethosDir(args.handle);
  const copyIfExists = (src: string, dst: string): void => {
    if (!existsSync(src)) return;
    copyFileSync(src, dst);
    chmodSync(dst, 0o644);
  };

  copyIfExists(join(srcDir, "manifest.json"), join(args.outDir, "manifest.json"));
  copyIfExists(join(srcDir, "did.json"), join(args.outDir, "did.json"));
  copyIfExists(
    join(ethosZoneDir(args.handle, "public"), "public.md"),
    join(args.outDir, "public.md"),
  );
  copyIfExists(
    join(ethosZoneDir(args.handle, "circle"), "circle.md.enc"),
    join(args.outDir, "circle.md.enc"),
  );
  copyIfExists(
    join(ethosZoneDir(args.handle, "self"), "self.md.enc"),
    join(args.outDir, "self.md.enc"),
  );
  copyIfExists(
    join(srcDir, "gamma", "gamma.jsonl.enc"),
    join(args.outDir, "gamma.jsonl.enc"),
  );
}

export interface InstallBundleFromDirArgs {
  bundleDir: string;
  /** Local handle to install under. */
  as: string;
  /**
   * Overwrite an existing install when true. Preserves `*.sealed.json` seed
   * files so an owner can re-install their own bundle without losing keys.
   */
  force?: boolean;
}

/**
 * Import a flat bundle directory (as produced by `packEthosToDir`) into the
 * local keystore as handle `as`. Result is a tracked install: `did.json` and
 * `ethos/*` present, but no sealed seed files — unless an owner install
 * already exists at that handle and `force: true` was passed, in which case
 * the existing sealed seeds are preserved.
 */
export function installBundleFromDir(args: InstallBundleFromDirArgs): void {
  const bundleDir = args.bundleDir;
  if (!existsSync(bundleDir)) {
    throw new Error(`installBundleFromDir: bundle dir not found: ${bundleDir}`);
  }
  const manifestSrc = join(bundleDir, "manifest.json");
  const didSrc = join(bundleDir, "did.json");
  if (!existsSync(manifestSrc) || !existsSync(didSrc)) {
    throw new Error(
      `installBundleFromDir: bundle at ${bundleDir} is missing manifest.json or did.json`,
    );
  }

  const targetDir = identityDir(args.as);
  const targetEthos = ethosDir(args.as);

  if (existsSync(targetDir) && !args.force) {
    throw new Error(
      `installBundleFromDir: identity "${args.as}" already exists at ${targetDir}. ` +
        `Pass { force: true } to overwrite (sealed seeds are preserved).`,
    );
  }

  ensureDir(targetDir);
  ensureEthosLayout(args.as);

  // Install top-level files.
  copyFileSync(didSrc, join(targetDir, "did.json"));
  chmodSync(join(targetDir, "did.json"), 0o644);
  copyFileSync(didSrc, join(targetEthos, "did.json"));
  chmodSync(join(targetEthos, "did.json"), 0o644);

  copyFileSync(manifestSrc, join(targetEthos, "manifest.json"));
  chmodSync(join(targetEthos, "manifest.json"), 0o600);

  const copyIfPresent = (src: string, dst: string, mode: number): void => {
    if (!existsSync(src)) return;
    copyFileSync(src, dst);
    chmodSync(dst, mode);
  };

  copyIfPresent(
    join(bundleDir, "public.md"),
    join(ethosZoneDir(args.as, "public"), "public.md"),
    0o600,
  );
  copyIfPresent(
    join(bundleDir, "circle.md.enc"),
    join(ethosZoneDir(args.as, "circle"), "circle.md.enc"),
    0o600,
  );
  copyIfPresent(
    join(bundleDir, "self.md.enc"),
    join(ethosZoneDir(args.as, "self"), "self.md.enc"),
    0o600,
  );
  ensureDir(join(ethosDir(args.as), "gamma"));
  copyIfPresent(
    join(bundleDir, "gamma.jsonl.enc"),
    join(ethosDir(args.as), "gamma", "gamma.jsonl.enc"),
    0o600,
  );
}

export function loadAllZones(handle: string, who: Identity | Author): Zones {
  const author = toAuthor(who);
  if (author.kind === "owner") {
    return {
      public: loadZoneDoc(handle, "public", author),
      circle: loadZoneDoc(handle, "circle", author),
      self: loadZoneDoc(handle, "self", author),
    };
  }
  const target = author.mandate.actor_sphere;
  return {
    public: target === "public" ? loadZoneDoc(handle, "public", author) : { sections: [] },
    circle: target === "circle" ? loadZoneDoc(handle, "circle", author) : { sections: [] },
    self: target === "self" ? loadZoneDoc(handle, "self", author) : { sections: [] },
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
 * Build a delegate-key resolver that consults the local keystore. Looks up the
 * mandate keyed by `authorized_by`, re-verifies its signature against the DID
 * doc, enforces the local revocation list, and returns the raw Ed25519 public
 * key to verify against. Signatures from an unknown, revoked, or mis-scoped
 * mandate cause the resolver to throw, which the calling verify-* function
 * surfaces as a "delegate key resolution failed" error.
 *
 * Pass this to {@link verifyManifestSignature} / {@link verifyZoneSignature}
 * (and {@link verifyBundleAtPath}) any time the receiving keystore has the
 * mandates installed locally.
 */
export function keystoreDelegateResolver(
  didDoc: DidDocument,
): (keyId: string, mandateId: string) => Uint8Array {
  return (keyId, mandateId) => {
    const m = loadMandate(mandateId);
    const mv = verifyMandate(m, didDoc);
    if (!mv.ok) {
      throw new Error(`mandate ${mandateId} invalid: ${mv.errors.join("; ")}`);
    }
    if (findRevocation(mandateId)) {
      throw new Error(`mandate ${mandateId} has been revoked`);
    }
    if (!m.grantee.pubkey || m.grantee.pubkey !== keyId) {
      throw new Error(
        `signature key ${keyId} does not match mandate grantee.pubkey=${m.grantee.pubkey ?? "<unset>"}`,
      );
    }
    return multibaseToEd25519PublicKey(keyId);
  };
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

  // Delegate-aware signature resolver — see {@link keystoreDelegateResolver}.
  const opts: VerifySignatureOpts = {
    resolveDelegatePubkey: keystoreDelegateResolver(didDoc),
  };

  // Check 6: manifest signature.
  const manSig = verifyManifestSignature(manifest, didDoc, opts);
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

    // 5: plaintext hash. We hash the actual on-disk plaintext (decrypted for
    // private zones) rather than re-rendering `doc`, because the rendered
    // frontmatter embeds edition metadata — a carry-forward zone authored in
    // edition N but present in manifest N+k would fail equality if we
    // re-rendered with edition N+k's context. The bytes written at write
    // time are the bytes hashed into `sha256_of_plaintext`.
    try {
      const plaintext = loadZonePlaintext(handle, z, identity ?? undefined, manifest);
      const hex = Buffer.from(
        sha256fn(new TextEncoder().encode(plaintext)),
      ).toString("hex");
      if (hex !== zm.sha256_of_plaintext) {
        errors.push(
          `zone ${z}: sha256_of_plaintext mismatch (on-disk=${hex} manifest=${zm.sha256_of_plaintext})`,
        );
      }
    } catch (e) {
      errors.push(`zone ${z}: failed to hash plaintext (${(e as Error).message})`);
    }

    // section_titles consistency.
    const actualTitles = doc.sections.map((s) => s.title);
    if (JSON.stringify(actualTitles) !== JSON.stringify(zm.section_titles)) {
      errors.push(`zone ${z}: section_titles mismatch`);
    }

    // Zone signature. Pass the mandate-aware resolver so delegate-signed
    // zones verify when the issuing mandate is on disk and not revoked.
    const zs = verifyZoneSignature(doc, zm.signature, didDoc, opts);
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
