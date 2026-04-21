/**
 * Gamma log — the subject's deep-memory log of every ethos mutation.
 *
 * See `spec/drafts/gamma-deep-memory.md`.
 *
 * Storage layout:
 *
 *   ~/.aithos/identities/<handle>/ethos/
 *   └── gamma/
 *       └── gamma.jsonl.enc     (single unified encrypted log — §D.4)
 *
 * - Plaintext form is JSONL: one JCS-canonicalized `GammaEntry` per line.
 * - The whole plaintext is sealed under XChaCha20-Poly1305 with a per-file
 *   DEK, and the DEK is wrapped for N recipients (default: the three sphere
 *   keys, so the subject always holds the keys).
 * - Append = decrypt the whole file, append a new canonical line, reseal
 *   under a fresh nonce, write atomically (write-temp + rename).
 *
 * The log is a single global chain: each entry's `prev_gamma_hash` is the
 * `hash` of the immediately preceding entry, regardless of zone. The manifest
 * carries `gamma.head` = the hash of the latest entry, anchoring the bundle
 * to the log (§D.4.5).
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
  signWithSphere,
  sphereDidUrl,
  rootDid,
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
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * The set of operations defined in v0.1.0 of the gamma draft (§D.6).
 * Unknown ops are permitted under an `x-` prefix for experimentation but MUST
 * cause a full-node verifier to reject the log otherwise.
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

/**
 * A gamma entry — the atomic unit of the log. One append = one entry.
 *
 * Hash-and-sign convention (mirrors §2.5.4 for revisions):
 *   1. Build the entry with `hash = ""` and `signature.value = ""`.
 *   2. Compute `hash = "sha256:" + hex(sha256(jcs(entry)))`.
 *   3. With `hash` populated and `signature.value = ""`, canonicalize and sign.
 *   4. Set `signature.value` to base64url(signature).
 *
 * The signature therefore commits to the hash and, transitively, to every
 * other field of the entry.
 */
export interface GammaEntry {
  "aithos-gamma": "0.1.0";
  id: string; // gamma_<26-char Crockford-base32 ULID>
  at: string; // RFC 3339 UTC
  subject_did: string;
  zone: Sphere;
  op: GammaOp;
  target: Record<string, unknown>;
  payload: Record<string, unknown>;
  prev_gamma_hash: string | null;
  prev_section_gamma?: string; // id of previous gamma entry on the same section
  hash: string; // "sha256:<hex>"
  signature: { alg: "ed25519"; key: string; value: string };
  authorized_by?: string; // mandate id; REQUIRED iff signature.key is a delegate key
  note?: string; // free-text informative annotation
}

/**
 * On-disk envelope wrapping the encrypted JSONL plaintext.
 */
export interface GammaFile {
  "aithos-gamma-file": "0.1.0";
  cipher: GammaCipher;
  ciphertext: string; // base64url
}

export interface GammaCipher {
  alg: "xchacha20poly1305-ietf";
  nonce: string; // base64url, 24 bytes
  wraps: GammaWrap[];
}

export interface GammaWrap {
  recipient: string; // did URL with #public / #circle / #self (or an agent's key fragment)
  alg: "x25519-hkdf-sha256-aead";
  ephemeral_public: string; // multibase
  wrap_nonce: string; // base64url, 24 bytes
  wrapped_key: string; // base64url
}

/* -------------------------------------------------------------------------- */
/*  ID generation                                                             */
/* -------------------------------------------------------------------------- */

export function newGammaId(): string {
  return `gamma_${ulid()}`;
}

/* -------------------------------------------------------------------------- */
/*  Hash-and-sign primitives                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Compute the per-entry self-hash (§D.5 hash-and-sign convention step 2).
 */
export function computeGammaHash(entry: GammaEntry): string {
  const blanked: GammaEntry = {
    ...entry,
    hash: "",
    signature: { ...entry.signature, value: "" },
  };
  const bytes = new TextEncoder().encode(canonicalize(blanked));
  return "sha256:" + Buffer.from(sha256fn(bytes)).toString("hex");
}

/**
 * Bytes to sign (§D.5 step 3): the entry with `signature.value = ""` but
 * `hash` populated. The signature therefore commits to the hash.
 */
export function signableGammaBytes(entry: GammaEntry): Uint8Array {
  const blanked: GammaEntry = {
    ...entry,
    signature: { ...entry.signature, value: "" },
  };
  return new TextEncoder().encode(canonicalize(blanked));
}

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

/**
 * Build a signed gamma entry from its content fields. Handles hash + sig
 * computation per §D.5. Does NOT append to any log.
 */
export interface BuildGammaEntryInput {
  subjectDid: string;
  zone: Sphere;
  op: GammaOp;
  target: Record<string, unknown>;
  payload: Record<string, unknown>;
  prevGammaHash: string | null;
  prevSectionGamma?: string;
  signer: GammaSigner;
  at?: Date;
  note?: string;
  /** Override the generated id (tests / deterministic fixtures). */
  id?: string;
}

export function buildGammaEntry(input: BuildGammaEntryInput): GammaEntry {
  const at = (input.at ?? new Date()).toISOString();
  const base: GammaEntry = {
    "aithos-gamma": "0.1.0",
    id: input.id ?? newGammaId(),
    at,
    subject_did: input.subjectDid,
    zone: input.zone,
    op: input.op,
    target: input.target,
    payload: input.payload,
    prev_gamma_hash: input.prevGammaHash,
    ...(input.prevSectionGamma ? { prev_section_gamma: input.prevSectionGamma } : {}),
    ...(input.signer.mandateId ? { authorized_by: input.signer.mandateId } : {}),
    ...(input.note ? { note: input.note } : {}),
    hash: "",
    signature: { alg: "ed25519", key: input.signer.keyId, value: "" },
  };
  base.hash = computeGammaHash(base);
  const sig = input.signer.sign(signableGammaBytes(base));
  base.signature.value = base64url(sig);
  return base;
}

/**
 * Verify a single entry: self-hash matches, signature verifies against the
 * expected key from the subject's DID document, `at` strictly increases
 * relative to `prev`.
 *
 * This does NOT verify the chain as a whole — see `verifyGammaLog`.
 */
export interface VerifyGammaEntryContext {
  /** The DID document of the subject; used to resolve `signature.key`. */
  didDoc: DidDocument;
  /** The entry immediately preceding this one in the log, if any. */
  prev: GammaEntry | null;
  /**
   * Resolver for delegate public keys when `signature.key` is not a sphere
   * key (i.e. when `authorized_by` is present). Returns raw 32-byte Ed25519
   * public key or throws.
   */
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

export interface VerifyGammaEntryResult {
  ok: boolean;
  error?: string;
}

export function verifyGammaEntry(entry: GammaEntry, ctx: VerifyGammaEntryContext): VerifyGammaEntryResult {
  // Hash integrity.
  const expectedHash = computeGammaHash(entry);
  if (expectedHash !== entry.hash) {
    return { ok: false, error: `hash mismatch (expected ${expectedHash}, got ${entry.hash})` };
  }

  // Chain link.
  if (ctx.prev === null) {
    if (entry.prev_gamma_hash !== null) {
      return { ok: false, error: "first entry must have prev_gamma_hash = null" };
    }
  } else {
    if (entry.prev_gamma_hash !== ctx.prev.hash) {
      return {
        ok: false,
        error: `prev_gamma_hash mismatch (expected ${ctx.prev.hash}, got ${entry.prev_gamma_hash})`,
      };
    }
    if (new Date(entry.at).getTime() <= new Date(ctx.prev.at).getTime()) {
      return {
        ok: false,
        error: `at (${entry.at}) must be strictly after prev.at (${ctx.prev.at})`,
      };
    }
  }

  // Signature.
  let pubkey: Uint8Array;
  if (entry.authorized_by !== undefined) {
    if (!ctx.resolveDelegatePubkey) {
      return { ok: false, error: `entry is delegated but no resolveDelegatePubkey provided` };
    }
    try {
      pubkey = ctx.resolveDelegatePubkey(entry.signature.key, entry.authorized_by);
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
  const toVerify = signableGammaBytes(entry);
  const verified = ed.verify(sigBytes, toVerify, pubkey);
  if (!verified) return { ok: false, error: "signature failed to verify" };

  return { ok: true };
}

/* -------------------------------------------------------------------------- */
/*  Encryption envelope                                                       */
/* -------------------------------------------------------------------------- */

/**
 * AAD prefix for gamma-file encryption. Bound to subject_did so the ciphertext
 * is cryptographically tied to the owning subject; a bundle_id is NOT used
 * here because the log spans editions.
 */
const GAMMA_AAD_PREFIX = Buffer.from("aithos-gamma-v1\0", "utf8");
const WRAP_SALT = new TextEncoder().encode("aithos-wrap-v1");

export interface GammaRecipient {
  did: string; // recipient DID URL (e.g. did:aithos:...#self)
  x25519PublicKey: Uint8Array;
}

export interface DecryptedGammaRecipient {
  did: string;
  x25519Secret: Uint8Array;
}

function gammaAad(subjectDid: string): Uint8Array {
  return Buffer.concat([GAMMA_AAD_PREFIX, Buffer.from(subjectDid, "utf8")]);
}

function wrapDek(dek: Uint8Array, recipientDidUrl: string, recipientPk: Uint8Array): GammaWrap {
  const esk = new Uint8Array(randomBytes(32));
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientPk);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(recipientDidUrl), 32);

  const wrapNonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(wrapKey);
  const wrapped = aead.seal(wrapNonce, dek, new TextEncoder().encode(recipientDidUrl));

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

function unwrapDek(wrap: GammaWrap, mySk: Uint8Array): Uint8Array {
  if (wrap.alg !== "x25519-hkdf-sha256-aead") {
    throw new Error(`Unsupported gamma wrap alg: ${wrap.alg}`);
  }
  const epk = multibaseToX25519PublicKey(wrap.ephemeral_public);
  const shared = x25519.getSharedSecret(mySk, epk);
  const wrapKey = hkdfSha256(shared, WRAP_SALT, new TextEncoder().encode(wrap.recipient), 32);
  const aead = new XChaCha20Poly1305(wrapKey);
  const nonce = base64urlDecode(wrap.wrap_nonce);
  const out = aead.open(
    nonce,
    base64urlDecode(wrap.wrapped_key),
    new TextEncoder().encode(wrap.recipient),
  );
  (shared as Uint8Array).fill?.(0);
  wrapKey.fill(0);
  if (!out) throw new Error("gamma DEK unwrap failed");
  return out;
}

/**
 * Seal a plaintext JSONL log under a fresh DEK, wrapping the DEK for each of
 * the supplied recipients. Returns the serializable `GammaFile` envelope.
 */
export function sealGammaFile(
  plaintext: string,
  subjectDid: string,
  recipients: GammaRecipient[],
): GammaFile {
  if (recipients.length === 0) {
    throw new Error("sealGammaFile: at least one recipient required");
  }
  const dek = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(24));
  const aad = gammaAad(subjectDid);
  const cipher = new XChaCha20Poly1305(dek);
  const ciphertext = cipher.seal(nonce, new TextEncoder().encode(plaintext), aad);

  const wraps = recipients.map((r) => wrapDek(dek, r.did, r.x25519PublicKey));

  dek.fill(0);

  return {
    "aithos-gamma-file": "0.1.0",
    cipher: {
      alg: "xchacha20poly1305-ietf",
      nonce: base64url(nonce),
      wraps,
    },
    ciphertext: base64url(ciphertext),
  };
}

/**
 * Open a gamma file: decrypt using the supplied recipient's X25519 secret.
 * Returns the plaintext JSONL as a string (may be empty).
 */
export function openGammaFile(
  file: GammaFile,
  subjectDid: string,
  me: DecryptedGammaRecipient,
): string {
  const wrap = file.cipher.wraps.find((w) => w.recipient === me.did);
  if (!wrap) throw new Error(`openGammaFile: no wrap for ${me.did}`);
  const dek = unwrapDek(wrap, me.x25519Secret);
  try {
    const aad = gammaAad(subjectDid);
    const aead = new XChaCha20Poly1305(dek);
    const nonce = base64urlDecode(file.cipher.nonce);
    const ct = base64urlDecode(file.ciphertext);
    const plain = aead.open(nonce, ct, aad);
    if (!plain) throw new Error("XChaCha20-Poly1305 authentication failed on gamma file");
    return new TextDecoder().decode(plain);
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Subject-as-recipient convenience                                          */
/* -------------------------------------------------------------------------- */

/**
 * Default recipient set for a new gamma file: all three sphere keys. The
 * subject holds all three seeds, so they can always decrypt. Future mandates
 * that grant gamma read to an agent add additional wraps; the three sphere
 * wraps remain.
 */
export function defaultGammaRecipients(identity: Identity): GammaRecipient[] {
  return SPHERE_FRAGMENTS.map((s) => {
    const sk = edSeedToX25519Secret(identity[s].seed);
    const pk = x25519PublicFromSecret(sk);
    sk.fill(0);
    return {
      did: didUrlForKex(rootDid(identity), s),
      x25519PublicKey: pk,
    };
  });
}

/**
 * Return one of the subject's decryption identities. Any of the three
 * sphere-derived X25519 secrets can open a default-wrapped gamma file.
 */
export function subjectGammaRecipient(identity: Identity, zone: Sphere): DecryptedGammaRecipient {
  return {
    did: didUrlForKex(rootDid(identity), zone),
    x25519Secret: edSeedToX25519Secret(identity[zone].seed),
  };
}

/* -------------------------------------------------------------------------- */
/*  JSONL <-> entries                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Serialize an entry to its canonical JSON line (no trailing newline).
 */
export function entryToJsonLine(entry: GammaEntry): string {
  return canonicalize(entry);
}

/**
 * Parse JSONL plaintext (as produced by repeated `entryToJsonLine + "\n"`
 * appends) into entries in order. Empty trailing newlines are tolerated;
 * empty lines in the middle are an error.
 */
export function parseJsonlLog(plaintext: string): GammaEntry[] {
  if (plaintext.length === 0) return [];
  const lines = plaintext.split("\n");
  // Allow a trailing empty string from a final "\n".
  if (lines[lines.length - 1] === "") lines.pop();
  const out: GammaEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) {
      throw new Error(`gamma log: empty line at index ${i}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch (e) {
      throw new Error(`gamma log: invalid JSON at line ${i + 1}: ${(e as Error).message}`);
    }
    out.push(parsed as GammaEntry);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  File IO                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Ensure the gamma directory exists for the given handle.
 */
export function ensureGammaDir(handle: string): void {
  ensureDir(gammaDir(handle));
}

/**
 * Read the gamma file envelope from disk. Returns null if the file does not
 * exist yet (fresh identity with no history).
 */
export function readGammaFile(handle: string): GammaFile | null {
  const p = gammaFilePath(handle);
  if (!existsSync(p)) return null;
  const raw = readFileSync(p, "utf8");
  return JSON.parse(raw) as GammaFile;
}

/**
 * Write the gamma file envelope to disk atomically (temp + rename).
 */
export function writeGammaFile(handle: string, file: GammaFile, mode: number = 0o600): void {
  ensureGammaDir(handle);
  const p = gammaFilePath(handle);
  const tmp = p + ".tmp";
  writeFileSync(tmp, JSON.stringify(file, null, 2) + "\n", { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, p);
}

/**
 * Read the plaintext JSONL of the gamma log for a given handle.
 * Returns "" if no file yet.
 */
export function readGammaPlaintext(handle: string, identity: Identity): string {
  const file = readGammaFile(handle);
  if (!file) return "";
  const me = subjectGammaRecipient(identity, "self");
  try {
    return openGammaFile(file, rootDid(identity), me);
  } finally {
    me.x25519Secret.fill(0);
  }
}

/**
 * Load all gamma entries for a handle, in order. Returns [] if no log yet.
 */
export function readGammaLog(handle: string, identity: Identity): GammaEntry[] {
  const plaintext = readGammaPlaintext(handle, identity);
  return parseJsonlLog(plaintext);
}

/**
 * Append a single entry to the log:
 *   1. Decrypt current log (empty if none).
 *   2. Append `jcs(entry) + "\n"`.
 *   3. Reseal under fresh nonce; rewrite the envelope atomically.
 *
 * The caller is responsible for having built `entry` with the correct
 * `prev_gamma_hash` (typically from `gammaHead(handle, identity)`).
 */
export function appendGammaEntry(
  handle: string,
  identity: Identity,
  entry: GammaEntry,
): void {
  const current = readGammaPlaintext(handle, identity);
  const next = current + entryToJsonLine(entry) + "\n";
  const recipients = defaultGammaRecipients(identity);
  const file = sealGammaFile(next, rootDid(identity), recipients);
  writeGammaFile(handle, file);
}

/* -------------------------------------------------------------------------- */
/*  Author-aware helpers (v0.2.1)                                             */
/* -------------------------------------------------------------------------- */

/**
 * Decrypt the gamma log's JSONL plaintext using whichever recipient the
 * author holds a secret for.
 *
 * Owner: same behaviour as `readGammaPlaintext(handle, identity)`.
 * Delegate: looks up the wrap whose recipient matches
 *   `<mandate.grantee.id>#<pubkeyMultibase>` — set by
 *   `issueMandateWithRewrap` — and decrypts with the delegate's X25519
 *   secret derived from their Ed25519 seed.
 *
 * Throws if the author holds no secret matching any wrap on disk.
 */
export function readGammaPlaintextForAuthor(handle: string, author: Author): string {
  if (author.kind === "owner") return readGammaPlaintext(handle, author.identity);
  const file = readGammaFile(handle);
  if (!file) return "";
  const recipientDid = `${author.mandate.grantee.id}#${author.pubkeyMultibase}`;
  const me: DecryptedGammaRecipient = {
    did: recipientDid,
    x25519Secret: edSeedToX25519Secret(author.seed),
  };
  try {
    return openGammaFile(file, author.subject.did, me);
  } finally {
    me.x25519Secret.fill(0);
  }
}

/** Same as `readGammaLog` but accepts an Author. */
export function readGammaLogForAuthor(handle: string, author: Author): GammaEntry[] {
  return parseJsonlLog(readGammaPlaintextForAuthor(handle, author));
}

/** Same as `gammaHead` but accepts an Author. */
export function gammaHeadForAuthor(handle: string, author: Author): string | null {
  const entries = readGammaLogForAuthor(handle, author);
  if (entries.length === 0) return null;
  return entries[entries.length - 1].hash;
}

/**
 * Derive the full recipient list for resealing the gamma log when the
 * delegate appends, reconstructing public keys from metadata that does NOT
 * require the delegate to hold sphere seeds:
 *   - The owner's three sphere X25519 pubkeys from `did.json` (Edwards→Montgomery).
 *   - The delegate's own X25519 pubkey, from their multibase Ed25519 pubkey.
 *
 * Rationale: the wraps stored on disk don't include the raw recipient X25519
 * pubkey (only an ephemeral one per-wrap), so we can't simply "carry
 * existing wraps forward". We recompute them from the published DID
 * document instead. This keeps the owner decryption path alive across
 * delegate edits.
 */
export function delegateGammaRecipients(author: Author & { kind: "delegate" }): GammaRecipient[] {
  const doc = author.subject.didDocument;
  const recipients: GammaRecipient[] = [];
  for (const s of SPHERE_FRAGMENTS) {
    const sphereVmId = author.subject.sphereDids[s];
    const vm = doc.verificationMethod.find((v) => v.id === sphereVmId);
    if (!vm) {
      throw new Error(
        `delegateGammaRecipients: did.json has no verificationMethod for sphere ${s}`,
      );
    }
    const edPub = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    const xPub = ed25519PubToX25519Pub(edPub);
    recipients.push({ did: didUrlForKex(author.subject.did, s), x25519PublicKey: xPub });
  }
  const delegateEdPub = multibaseToEd25519PublicKey(author.pubkeyMultibase);
  const delegateXPub = ed25519PubToX25519Pub(delegateEdPub);
  recipients.push({
    did: `${author.mandate.grantee.id}#${author.pubkeyMultibase}`,
    x25519PublicKey: delegateXPub,
  });
  return recipients;
}

/**
 * Append a gamma entry on behalf of an author. Owner path mirrors the
 * legacy `appendGammaEntry`; delegate path decrypts via their wrap, reseals
 * under the full recipient set reconstructed via `delegateGammaRecipients`.
 */
export function appendGammaEntryForAuthor(
  handle: string,
  author: Author,
  entry: GammaEntry,
): void {
  if (author.kind === "owner") {
    appendGammaEntry(handle, author.identity, entry);
    return;
  }
  const current = readGammaPlaintextForAuthor(handle, author);
  const next = current + entryToJsonLine(entry) + "\n";
  const recipients = delegateGammaRecipients(author);
  const file = sealGammaFile(next, author.subject.did, recipients);
  writeGammaFile(handle, file);
}

/* -------------------------------------------------------------------------- */
/*  Chain navigation helpers                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Return the head hash of the gamma chain: the `hash` field of the latest
 * entry, or `null` if the log is empty.
 *
 * This is the value the manifest's `gamma.head` MUST equal.
 */
export function gammaHead(handle: string, identity: Identity): string | null {
  const entries = readGammaLog(handle, identity);
  if (entries.length === 0) return null;
  return entries[entries.length - 1].hash;
}

/**
 * Return the latest gamma entry for a given section (by id), scanning the
 * full log. Returns null if the section has no entries.
 */
export function latestGammaForSection(
  entries: GammaEntry[],
  sectionId: string,
): GammaEntry | null {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    if (typeof e.target?.section_id === "string" && e.target.section_id === sectionId) {
      return e;
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/*  Whole-chain verification                                                  */
/* -------------------------------------------------------------------------- */

export interface VerifyGammaLogResult {
  ok: boolean;
  count: number;
  errors: Array<{ index: number; entryId: string; error: string }>;
}

/**
 * Walk the log in order and verify every entry (hash + chain + signature).
 */
export function verifyGammaLog(
  entries: GammaEntry[],
  didDoc: DidDocument,
  opts: { resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array } = {},
): VerifyGammaLogResult {
  const errors: VerifyGammaLogResult["errors"] = [];
  let prev: GammaEntry | null = null;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const res = verifyGammaEntry(entry, {
      didDoc,
      prev,
      resolveDelegatePubkey: opts.resolveDelegatePubkey,
    });
    if (!res.ok) {
      errors.push({ index: i, entryId: entry.id, error: res.error ?? "unknown error" });
    }
    prev = entry;
  }
  return { ok: errors.length === 0, count: entries.length, errors };
}

/* -------------------------------------------------------------------------- */
/*  Local copy of x25519 multibase decoder (same impl as ethos.ts)            */
/* -------------------------------------------------------------------------- */

function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const hkdf = new HKDF(SHA256, ikm, salt, info);
  return hkdf.expand(length);
}

function multibaseToX25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) throw new Error("Expected multibase z-prefixed");
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
