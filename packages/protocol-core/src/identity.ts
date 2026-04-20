/**
 * Identity primitives — key generation, DID document assembly, sealed-seed
 * storage, signing.
 *
 * Each Aithos identity is a quadruple of Ed25519 key pairs:
 *   - root    (signs the DID document only)
 *   - public  (signs public-zone revisions and public-sphere mandates)
 *   - circle  (signs circle-zone revisions and circle-sphere mandates)
 *   - self    (signs self-zone revisions and self-sphere mandates)
 *
 * Each sphere additionally exposes an X25519 key pair derived from the same
 * seed, used for zone-key wrapping. The conversion is Ed25519-seed → X25519
 * (libsodium's crypto_sign_ed25519_sk_to_curve25519), implemented here with
 * the underlying scalar/curve operations from @noble libraries.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { existsSync, writeFileSync, readFileSync, chmodSync } from "node:fs";

import {
  didAithosForRootKey,
  didUrlForSphere,
  didUrlForKex,
  ed25519PublicKeyToMultibase,
  x25519PublicKeyToMultibase,
  multibaseToEd25519PublicKey,
  SPHERE_FRAGMENTS,
  type Sphere,
} from "./did.js";
import { canonicalize } from "./canonical.js";
import { ensureDir, identityDir, writeJson, readJson } from "./storage.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/* -------------------------------------------------------------------------- */
/*  Primitives                                                                */
/* -------------------------------------------------------------------------- */

export interface KeyPair {
  seed: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export function generateKeyPair(): KeyPair {
  const seed = new Uint8Array(randomBytes(32));
  const publicKey = ed.getPublicKey(seed);
  return { seed, publicKey };
}

/**
 * Ed25519 seed → X25519 key pair, per libsodium's ed25519_sk_to_curve25519.
 * The public key is the Montgomery form; the private key is the SHA-512 first
 * half with the standard curve25519 clamp.
 */
export function edSeedToX25519Secret(seed: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const sk = h.slice(0, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return sk;
}

/** X25519 public key from a clamped scalar, using @noble/ed25519 internals. */
export function x25519PublicFromSecret(sk: Uint8Array): Uint8Array {
  // @noble/ed25519 ships an x25519 subroutine via ed.etc — we recompute using
  // the curve25519 base point. @noble has a small helper via
  // `ed.etc.getSharedSecret`-adjacent API, but the cleanest path is to
  // directly use the "x25519" module if present. For portability we use
  // scalarMult with BASE_POINT_U = 9.
  // Implementation: use @noble's built-in `x25519` equivalent through
  // `ed.etc.scalarMult`. In @noble/ed25519 v2 it's not exposed, so we'll
  // defer to a tiny inline implementation.
  return scalarMultBase(sk);
}

// Tiny X25519 scalarmult-base implementation. Correct enough for deriving
// public keys from a seed; not constant-time, not suitable for signing in a
// hostile environment, but fine for key publication.
function scalarMultBase(k: Uint8Array): Uint8Array {
  return scalarMult(k, new Uint8Array([9, ...new Uint8Array(31)]));
}

function scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array {
  const P = 2n ** 255n - 19n;
  const a24 = 121665n;

  const cswap = (swap: bigint, a: bigint, b: bigint): [bigint, bigint] => {
    const d = (0n - swap) & ((1n << 255n) - 1n);
    const t = d & (a ^ b);
    return [a ^ t, b ^ t];
  };

  const fromLE = (u8: Uint8Array): bigint => {
    let x = 0n;
    for (let i = u8.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(u8[i]);
    return x;
  };
  const toLE = (x: bigint): Uint8Array => {
    const u = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      u[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return u;
  };

  const scalar = new Uint8Array(n);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;

  const x1 = fromLE(p) % P;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  for (let t = 254; t >= 0; t--) {
    const kt = BigInt((scalar[t >>> 3] >> (t & 7)) & 1);
    swap ^= kt;
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    swap = kt;

    const A = (x2 + z2) % P;
    const AA = (A * A) % P;
    const B = ((P + x2 - z2) % P) % P;
    const BB = (B * B) % P;
    const E = ((P + AA - BB) % P) % P;
    const C = (x3 + z3) % P;
    const D = ((P + x3 - z3) % P) % P;
    const DA = (D * A) % P;
    const CB = (C * B) % P;
    x3 = ((DA + CB) * (DA + CB)) % P;
    z3 = (x1 * (((P + DA - CB) % P) * ((P + DA - CB) % P)) % P) % P;
    x2 = (AA * BB) % P;
    z2 = (E * (AA + ((a24 * E) % P)) % P) % P;
  }

  [x2, x3] = cswap(swap, x2, x3);
  [z2, z3] = cswap(swap, z2, z3);

  // x2 / z2 mod P
  const inv = modPow(z2, P - 2n, P);
  const res = (x2 * inv) % P;
  return toLE(res);
}

function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  let base = b % m;
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m;
    exp >>= 1n;
    base = (base * base) % m;
  }
  return r;
}

/* -------------------------------------------------------------------------- */
/*  Identity creation and storage                                             */
/* -------------------------------------------------------------------------- */

export interface StoredSeed {
  aithos: "0.1.0";
  role: "root" | Sphere;
  seed_hex: string; // stored in cleartext in v0.1.0 — see SECURITY NOTE in storage.ts
  created_at: string;
}

export interface Identity {
  handle: string;
  displayName: string;
  root: KeyPair;
  public: KeyPair;
  circle: KeyPair;
  self: KeyPair;
}

export function createIdentity(handle: string, displayName: string): Identity {
  return {
    handle,
    displayName,
    root: generateKeyPair(),
    public: generateKeyPair(),
    circle: generateKeyPair(),
    self: generateKeyPair(),
  };
}

export function writeIdentityToDisk(id: Identity): { dir: string; did: string } {
  const dir = identityDir(id.handle);
  ensureDir(dir);

  const now = new Date().toISOString();
  const write = (role: "root" | Sphere, kp: KeyPair) => {
    const seed: StoredSeed = {
      aithos: "0.1.0",
      role,
      seed_hex: Buffer.from(kp.seed).toString("hex"),
      created_at: now,
    };
    writeJson(join(dir, `${role}.sealed.json`), seed, 0o600);
  };

  write("root", id.root);
  write("public", id.public);
  write("circle", id.circle);
  write("self", id.self);

  const did = didAithosForRootKey(id.root.publicKey);
  const didDoc = buildDidDocument(id);
  const signedDidDoc = signDidDocument(didDoc, id.root);
  writeFileSync(join(dir, "did.json"), JSON.stringify(signedDidDoc, null, 2) + "\n");
  chmodSync(join(dir, "did.json"), 0o644);

  return { dir, did };
}

/**
 * A tracked identity is one we hold the public data for — `did.json` plus
 * whatever is in `ethos/` — but for which we do NOT possess the private
 * sphere seeds. This is the normal state when you've imported someone else's
 * ethos bundle to follow or verify it.
 *
 * Tracked identities can:
 *   - have their metadata listed (handle, DID, public sphere keys)
 *   - have their `public` zone read (plaintext, signature-verifiable)
 *   - have their ethos partially verified (public zone + manifest signature)
 *
 * Tracked identities CANNOT:
 *   - decrypt circle/self zones (no sphere secret)
 *   - issue mandates / revocations / rotations (no sphere secret)
 *   - append new revisions under either the sphere key or a delegate (the
 *     write-mandate flow still requires the subject's sphere key to have
 *     previously issued the mandate, which implies owned state)
 *
 * The distinction is purely an on-disk one: sealed seed files present ⇒ owned.
 * Missing one or more ⇒ tracked.
 */
export class TrackedIdentityError extends Error {
  constructor(handle: string, missing: string[]) {
    super(
      `identity "${handle}" is tracked-only — this operation requires the private ` +
        `sphere key(s), but the following sealed seed file(s) are missing: ` +
        missing.join(", ") +
        `. Tracked identities can be introspected (DID, public zone, signatures) ` +
        `but cannot sign, decrypt, or write.`,
    );
    this.name = "TrackedIdentityError";
  }
}

/** True if any of the four sealed seed files is missing on disk. */
export function isTrackedIdentity(handle: string): boolean {
  const dir = identityDir(handle);
  if (!existsSync(dir)) return false; // absent, not tracked
  const required = ["root", ...SPHERE_FRAGMENTS] as const;
  return required.some((r) => !existsSync(join(dir, `${r}.sealed.json`)));
}

/**
 * Public, read-only view of an identity, derived entirely from `did.json`.
 * Anyone who has downloaded the identity's DID document can reconstruct this.
 */
export interface IdentityMetadata {
  handle: string;
  displayName: string;
  did: string;
  tracked: boolean;
  sphereDids: Record<Sphere, string>;
  /** Ed25519 public key per sphere, multibase-encoded. */
  sphereKeys: Record<Sphere, string>;
  didDocument: DidDocument;
}

/**
 * Load an identity's public metadata (did.json only). Works for both owned and
 * tracked identities. Throws only if `did.json` is missing.
 */
export function loadIdentityMetadata(handle: string): IdentityMetadata {
  const dir = identityDir(handle);
  if (!existsSync(dir)) throw new Error(`Identity not found: ${handle}`);

  const didPath = join(dir, "did.json");
  if (!existsSync(didPath)) {
    throw new Error(
      `identity "${handle}" has no did.json — nothing to load. The directory ` +
        `exists at ${dir} but is empty or corrupted.`,
    );
  }
  const didDoc = readJson<DidDocument>(didPath);
  const displayName = didDoc.aithos?.display_name ?? handle;

  const sphereKey = (sphere: Sphere): string => {
    const vm = didDoc.verificationMethod?.find((v) => v.id.endsWith(`#${sphere}`));
    if (!vm) throw new Error(`did.json for ${handle} has no verificationMethod for sphere ${sphere}`);
    return vm.publicKeyMultibase;
  };
  const sphereDid = (sphere: Sphere): string => {
    const vm = didDoc.verificationMethod?.find((v) => v.id.endsWith(`#${sphere}`));
    if (!vm) throw new Error(`did.json for ${handle} has no verificationMethod for sphere ${sphere}`);
    return vm.id;
  };

  return {
    handle,
    displayName,
    did: didDoc.id,
    tracked: isTrackedIdentity(handle),
    sphereDids: {
      public: sphereDid("public"),
      circle: sphereDid("circle"),
      self: sphereDid("self"),
    },
    sphereKeys: {
      public: sphereKey("public"),
      circle: sphereKey("circle"),
      self: sphereKey("self"),
    },
    didDocument: didDoc,
  };
}

export function loadIdentity(handle: string): Identity {
  const dir = identityDir(handle);
  if (!existsSync(dir)) throw new Error(`Identity not found: ${handle}`);

  // Detect tracked identities upfront and surface a friendly error instead of
  // a raw ENOENT from deep inside readJson.
  const required = ["root", ...SPHERE_FRAGMENTS] as const;
  const missing = required
    .filter((r) => !existsSync(join(dir, `${r}.sealed.json`)))
    .map((r) => `${r}.sealed.json`);
  if (missing.length > 0) throw new TrackedIdentityError(handle, missing);

  const loadSeed = (role: "root" | Sphere): KeyPair => {
    const stored = readJson<StoredSeed>(join(dir, `${role}.sealed.json`));
    const seed = Uint8Array.from(Buffer.from(stored.seed_hex, "hex"));
    return { seed, publicKey: ed.getPublicKey(seed) };
  };

  // Display name is recovered from did.json
  const didDoc = readJson<DidDocument>(join(dir, "did.json"));
  const displayName = didDoc.aithos?.display_name ?? handle;

  return {
    handle,
    displayName,
    root: loadSeed("root"),
    public: loadSeed("public"),
    circle: loadSeed("circle"),
    self: loadSeed("self"),
  };
}

/* -------------------------------------------------------------------------- */
/*  DID document                                                              */
/* -------------------------------------------------------------------------- */

export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethod[];
  keyAgreement: VerificationMethod[];
  service?: Service[];
  aithos: { version: "0.1.0"; display_name?: string; created_at: string; rotated: RotatedEntry[] };
  proof?: Proof;
}

interface VerificationMethod {
  id: string;
  type: "Ed25519VerificationKey2020" | "X25519KeyAgreementKey2020";
  controller: string;
  publicKeyMultibase: string;
}

interface Service {
  id: string;
  type: string;
  serviceEndpoint: string;
}

interface Proof {
  type: "Ed25519Signature2020";
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  proofValue: string; // base64url
}

interface RotatedEntry {
  sphere: Sphere;
  previous_key: string;
  rotated_at: string;
  reason: string;
}

function buildDidDocument(id: Identity): DidDocument {
  const did = didAithosForRootKey(id.root.publicKey);

  const verificationMethod: VerificationMethod[] = SPHERE_FRAGMENTS.map((sphere) => ({
    id: didUrlForSphere(did, sphere),
    type: "Ed25519VerificationKey2020",
    controller: did,
    publicKeyMultibase: ed25519PublicKeyToMultibase(id[sphere].publicKey),
  }));

  const keyAgreement: VerificationMethod[] = SPHERE_FRAGMENTS.map((sphere) => {
    const xPriv = edSeedToX25519Secret(id[sphere].seed);
    const xPub = x25519PublicFromSecret(xPriv);
    return {
      id: didUrlForKex(did, sphere),
      type: "X25519KeyAgreementKey2020",
      controller: did,
      publicKeyMultibase: x25519PublicKeyToMultibase(xPub),
    };
  });

  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://aithos.dev/spec/v0.1"],
    id: did,
    verificationMethod,
    keyAgreement,
    aithos: {
      version: "0.1.0",
      display_name: id.displayName,
      created_at: new Date().toISOString(),
      rotated: [],
    },
  };
}

function signDidDocument(doc: DidDocument, rootKey: KeyPair): DidDocument {
  const unsigned: DidDocument = {
    ...doc,
    proof: {
      type: "Ed25519Signature2020",
      created: new Date().toISOString(),
      verificationMethod: `${doc.id}#root`,
      proofPurpose: "assertionMethod",
      proofValue: "",
    },
  };

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = ed.sign(bytes, rootKey.seed);
  unsigned.proof!.proofValue = base64url(sig);
  return unsigned;
}

export function verifyDidDocument(doc: DidDocument): boolean {
  if (!doc.proof || doc.proof.verificationMethod !== `${doc.id}#root`) return false;
  const rootPk = multibaseToEd25519PublicKey(doc.id.slice("did:aithos:".length));
  const unsigned: DidDocument = { ...doc, proof: { ...doc.proof, proofValue: "" } };
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = base64urlDecode(doc.proof.proofValue);
  return ed.verify(sig, bytes, rootPk);
}

/* -------------------------------------------------------------------------- */
/*  Signing helpers                                                           */
/* -------------------------------------------------------------------------- */

export function signWithSphere(identity: Identity, sphere: Sphere, payload: Uint8Array): Uint8Array {
  return ed.sign(payload, identity[sphere].seed);
}

export function sphereDidUrl(identity: Identity, sphere: Sphere): string {
  return didUrlForSphere(didAithosForRootKey(identity.root.publicKey), sphere);
}

export function rootDid(identity: Identity): string {
  return didAithosForRootKey(identity.root.publicKey);
}

/* -------------------------------------------------------------------------- */
/*  Encoding                                                                  */
/* -------------------------------------------------------------------------- */

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function base64urlDecode(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return "sha256:" + Buffer.from(sha256(bytes)).toString("hex");
}
