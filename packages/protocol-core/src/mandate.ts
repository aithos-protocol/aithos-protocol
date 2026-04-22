/**
 * Mandates, revocations, and action artifacts.
 *
 * Implements §4 (Mandates) and §5.4 (Action artifacts) of the protocol.
 * Mandates are signed by the issuer's sphere key that matches `actor_sphere`.
 * Revocations are signed by the same sphere key that issued the mandate.
 * Action artifacts are signed by the agent's own Ed25519 key, and may carry a
 * subject counter-signature for binding actions.
 */

import * as ed from "@noble/ed25519";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { ulid } from "ulid";

import { canonicalize } from "./canonical.js";
import {
  type Identity,
  type DidDocument,
  base64url,
  base64urlDecode,
  rootDid,
  sphereDidUrl,
  signWithSphere,
  sha256Hex,
} from "./identity.js";
import type { Sphere } from "./did.js";
import {
  mandatesDir,
  revocationsDir,
  ensureDir,
  writeJson,
  readJson,
} from "./storage.js";
import { multibaseToEd25519PublicKey } from "./did.js";

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface Grantee {
  id: string;
  label?: string;
  pubkey?: string; // multibase z… Ed25519 key
}

export interface MandateConstraints {
  domains?: string[];
  rate_limit?: Record<string, number>;
  require_counter_sign?: string[];
}

/**
 * Mandate envelope versions understood by this library.
 *
 * `0.1.0` — pre-delegate-E2E format shipped in v0.1.x / v0.2.0.
 * `0.2.1` — adds forbidden-scope enforcement (mandate.issue, mandate.revoke,
 *           identity.rotate-keys, identity.destroy) and the explicit
 *           `ethos.read.{public,circle,self}` scope family.
 * `0.3.0` — introduces the `gamma.read` scope. Decouples gamma read access
 *           from `ethos.write.*`: possession of a write scope no longer
 *           implies visibility of the gamma log. A mandate carrying
 *           `gamma.read` adds its grantee pubkey to `manifest.gamma.readers`;
 *           future gamma entries seal their per-entry key to that pubkey.
 *           See `spec/drafts/gamma-v0.3-per-entry-envelopes.md`.
 *
 * New mandates are minted at the latest version; the verifier accepts all
 * three past envelopes for backward compatibility.
 */
export const MANDATE_VERSION_CURRENT = "0.3.0" as const;
export type MandateVersion = "0.1.0" | "0.2.1" | "0.3.0";

export interface Mandate {
  "aithos-mandate": MandateVersion;
  id: string;
  issuer: string;
  issued_by_key: string;
  grantee: Grantee;
  actor_sphere: Sphere;
  scopes: string[];
  constraints?: MandateConstraints;
  not_before: string;
  not_after: string;
  issued_at: string;
  nonce: string;
  signature: {
    alg: "ed25519";
    key: string;
    value: string; // base64url
  };
}

export interface Revocation {
  "aithos-revocation": "0.1.0";
  mandate_id: string;
  issuer: string;
  issued_by_key: string;
  revoked_at: string;
  reason: string;
  signature: {
    alg: "ed25519";
    key: string;
    value: string;
  };
}

export interface ActionArtifact {
  "aithos-action": "0.1.0";
  id: string;
  mandate_id: string;
  issued_at: string;
  actor: {
    id: string;
    pubkey: string;
  };
  action: {
    verb: string;
    target: Record<string, unknown>;
    content_hash: string;
    summary: string;
  };
  signature: {
    alg: "ed25519";
    key: string;
    value: string;
  };
  counter_signature: {
    alg: "ed25519";
    key: string;
    value: string;
  } | null;
}

/* -------------------------------------------------------------------------- */
/*  TTL parsing                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Parse a duration string into seconds. Accepts `<n>s`, `<n>m`, `<n>h`, `<n>d`,
 * `<n>w`. No composite forms ("1d12h") in v0.1.0.
 */
export function parseTtl(s: string): number {
  const m = s.match(/^(\d+)([smhdw])$/);
  if (!m) throw new Error(`Invalid TTL: ${s}. Expected e.g. 60s, 15m, 2h, 7d, 4w.`);
  const n = parseInt(m[1], 10);
  const unit = m[2];
  const factor = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[unit]!;
  return n * factor;
}

/* -------------------------------------------------------------------------- */
/*  Mandate creation                                                          */
/* -------------------------------------------------------------------------- */

export interface CreateMandateArgs {
  issuer: Identity;
  actorSphere: Sphere;
  grantee: Grantee;
  scopes: string[];
  ttlSeconds: number;
  constraints?: MandateConstraints;
  notBefore?: Date; // defaults to now
}

export function createMandate(args: CreateMandateArgs): Mandate {
  validateScopesAgainstSphere(args.scopes, args.actorSphere);

  // Write mandates MUST bind to a specific delegate key (§4.5.4).
  if (hasWriteScope(args.scopes) && !args.grantee.pubkey) {
    throw new Error(
      `Write mandate requires grantee.pubkey (the delegate key). Generate one with \`aithos delegate-key\` and pass it via --pubkey.`,
    );
  }

  const now = args.notBefore ?? new Date();
  const notAfter = new Date(now.getTime() + args.ttlSeconds * 1000);
  const nonce = base64url(randomBytes(9)); // 72 bits of entropy

  const unsigned: Mandate = {
    "aithos-mandate": MANDATE_VERSION_CURRENT,
    id: `mandate_${ulid()}`,
    issuer: rootDid(args.issuer),
    issued_by_key: sphereDidUrl(args.issuer, args.actorSphere),
    grantee: args.grantee,
    actor_sphere: args.actorSphere,
    scopes: args.scopes,
    ...(args.constraints ? { constraints: args.constraints } : {}),
    not_before: now.toISOString(),
    not_after: notAfter.toISOString(),
    issued_at: new Date().toISOString(),
    nonce,
    signature: {
      alg: "ed25519",
      key: sphereDidUrl(args.issuer, args.actorSphere),
      value: "",
    },
  };

  const sig = signWithSphere(
    args.issuer,
    args.actorSphere,
    new TextEncoder().encode(canonicalize(unsigned)),
  );
  unsigned.signature.value = base64url(sig);
  return unsigned;
}

/**
 * Scopes a mandate may NEVER carry, regardless of signing sphere.
 *
 * These cover operations whose cryptographic root must remain with the
 * subject: issuing further mandates, revoking them, rotating identity keys,
 * and destroying the identity. Even the `self` sphere (which is otherwise a
 * superset) cannot delegate them — a delegate that could issue new mandates
 * would be indistinguishable from the subject.
 */
export const FORBIDDEN_SCOPES: ReadonlySet<string> = new Set([
  "mandate.issue",
  "mandate.revoke",
  "identity.rotate-keys",
  "identity.destroy",
]);

function validateScopesAgainstSphere(scopes: string[], sphere: Sphere): void {
  // Hard-ban of scopes no mandate may ever carry (v0.2.1).
  for (const s of scopes) {
    if (FORBIDDEN_SCOPES.has(s)) {
      throw new Error(
        `Scope "${s}" is forbidden and cannot be granted by a mandate. ` +
          `This operation must be performed directly by the subject with their root/sphere keys.`,
      );
    }
  }

  // Write scopes must match the signing sphere.
  for (const s of scopes) {
    if (s === "ethos.write.public" && sphere !== "public") {
      throw new Error(
        `Scope ${s} requires actor_sphere=public (got ${sphere}). A write mandate must be signed by the sphere it writes to.`,
      );
    }
    if (s === "ethos.write.circle" && sphere !== "circle") {
      throw new Error(
        `Scope ${s} requires actor_sphere=circle (got ${sphere}).`,
      );
    }
    if (s === "ethos.write.self" && sphere !== "self") {
      throw new Error(
        `Scope ${s} requires actor_sphere=self (got ${sphere}).`,
      );
    }
  }

  if (sphere === "public") {
    for (const s of scopes) {
      const ok =
        s === "ethos.read.public" ||
        s === "ethos.read.all" ||
        s === "ethos.write.public" ||
        s === "gamma.read";
      if (!ok) {
        throw new Error(
          `Scope ${s} is not permitted for the public sphere. Only ethos.read.public, ethos.read.all, ethos.write.public, and gamma.read are allowed.`,
        );
      }
    }
  }
  if (sphere === "circle") {
    for (const s of scopes) {
      if (s === "ethos.read.self") {
        throw new Error(`Scope ethos.read.self cannot be granted on a circle mandate.`);
      }
    }
  }
  // self: permitted everywhere (minus the FORBIDDEN_SCOPES check above)
}

/** Identify whether any of the given scopes is a write scope. */
export function hasWriteScope(scopes: string[]): boolean {
  return scopes.some((s) => s.startsWith("ethos.write."));
}

/**
 * Identify whether the scope set grants gamma read access.
 *
 * In v0.3, gamma read is explicit — `ethos.write.*` no longer implies it.
 * A delegate with a write scope alone can append gamma entries (via per-entry
 * envelope seal to `manifest.gamma.readers`, no decryption needed) but cannot
 * read past history.
 */
export function hasGammaReadScope(scopes: string[]): boolean {
  return scopes.includes("gamma.read");
}

export function writeMandate(m: Mandate): string {
  ensureDir(mandatesDir());
  const path = join(mandatesDir(), `${m.id}.json`);
  writeJson(path, m, 0o600);
  return path;
}

export function loadMandate(mandateId: string): Mandate {
  const path = join(mandatesDir(), `${mandateId}.json`);
  if (!existsSync(path)) throw new Error(`Mandate not found: ${mandateId}`);
  return readJson<Mandate>(path);
}

/* -------------------------------------------------------------------------- */
/*  Verification                                                              */
/* -------------------------------------------------------------------------- */

export interface VerifyResult {
  ok: boolean;
  errors: string[];
}

/**
 * Verify a mandate's structure, signature, and time window against a DID document.
 * Does NOT consult a revocation list — caller provides that separately.
 */
export function verifyMandate(
  mandate: Mandate,
  didDoc: DidDocument,
  now: Date = new Date(),
): VerifyResult {
  const errors: string[] = [];

  if (
    mandate["aithos-mandate"] !== "0.1.0" &&
    mandate["aithos-mandate"] !== "0.2.1" &&
    mandate["aithos-mandate"] !== MANDATE_VERSION_CURRENT
  ) {
    errors.push(`Unsupported mandate version: ${mandate["aithos-mandate"]}`);
  }

  // Forbidden-scope enforcement applies at verify time regardless of the
  // envelope version: a v0.1.0 mandate that somehow carries a forbidden scope
  // must still be rejected, because the subject never had the right to
  // delegate it.
  for (const s of mandate.scopes) {
    if (FORBIDDEN_SCOPES.has(s)) {
      errors.push(
        `Mandate carries forbidden scope "${s}". These operations cannot be delegated.`,
      );
    }
  }
  if (mandate.issuer !== didDoc.id) {
    errors.push(`issuer ${mandate.issuer} does not match did document ${didDoc.id}`);
  }
  const expected = `${didDoc.id}#${mandate.actor_sphere}`;
  if (mandate.issued_by_key !== expected) {
    errors.push(
      `issued_by_key ${mandate.issued_by_key} does not match actor_sphere (expected ${expected})`,
    );
  }

  const vm = didDoc.verificationMethod.find((v) => v.id === mandate.issued_by_key);
  if (!vm) {
    errors.push(`No verificationMethod found for ${mandate.issued_by_key}`);
    return { ok: false, errors };
  }

  const nb = new Date(mandate.not_before);
  const na = new Date(mandate.not_after);
  if (now < nb) errors.push(`Mandate not yet valid (not_before=${mandate.not_before})`);
  if (now >= na) errors.push(`Mandate has expired (not_after=${mandate.not_after})`);

  // Signature
  try {
    const toVerify: Mandate = {
      ...mandate,
      signature: { ...mandate.signature, value: "" },
    };
    const bytes = new TextEncoder().encode(canonicalize(toVerify));
    const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    const sig = base64urlDecode(mandate.signature.value);
    if (!ed.verify(sig, bytes, pk)) {
      errors.push("Mandate signature verification failed");
    }
  } catch (e) {
    errors.push(`Signature check errored: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors };
}

/* -------------------------------------------------------------------------- */
/*  Revocation                                                                */
/* -------------------------------------------------------------------------- */

export interface RevokeMandateArgs {
  issuer: Identity;
  mandate: Mandate;
  reason: string;
  revokedAt?: Date;
}

export function createRevocation(args: RevokeMandateArgs): Revocation {
  const revokedAt = (args.revokedAt ?? new Date()).toISOString();

  // Sphere to sign with must match the one that issued the mandate.
  const issuedBy = args.mandate.issued_by_key;
  const match = issuedBy.match(/#(public|circle|self)$/);
  if (!match) throw new Error(`Cannot determine sphere from issued_by_key: ${issuedBy}`);
  const sphere = match[1] as Sphere;

  const unsigned: Revocation = {
    "aithos-revocation": "0.1.0",
    mandate_id: args.mandate.id,
    issuer: args.mandate.issuer,
    issued_by_key: issuedBy,
    revoked_at: revokedAt,
    reason: args.reason,
    signature: { alg: "ed25519", key: issuedBy, value: "" },
  };

  const sig = signWithSphere(
    args.issuer,
    sphere,
    new TextEncoder().encode(canonicalize(unsigned)),
  );
  unsigned.signature.value = base64url(sig);
  return unsigned;
}

export function writeRevocation(r: Revocation): string {
  ensureDir(revocationsDir());
  const path = join(revocationsDir(), `revocation_${r.mandate_id.replace(/^mandate_/, "")}.json`);
  writeJson(path, r, 0o600);
  return path;
}

export function loadRevocation(path: string): Revocation {
  return readJson<Revocation>(path);
}

/**
 * Return the local revocation for a mandate id, or null if none is on disk.
 *
 * The expected on-disk name is `revocation_<ULID>.json` in `revocationsDir()`,
 * where `<ULID>` is the mandate id with its `mandate_` prefix stripped — this
 * matches what `writeRevocation` produces.
 */
export function findRevocation(mandateId: string): Revocation | null {
  const ulidPart = mandateId.replace(/^mandate_/, "");
  const path = join(revocationsDir(), `revocation_${ulidPart}.json`);
  if (!existsSync(path)) return null;
  return readJson<Revocation>(path);
}

export function verifyRevocation(
  rev: Revocation,
  didDoc: DidDocument,
): VerifyResult {
  const errors: string[] = [];
  if (rev.issuer !== didDoc.id) {
    errors.push(`issuer ${rev.issuer} does not match did document ${didDoc.id}`);
  }
  const vm = didDoc.verificationMethod.find((v) => v.id === rev.issued_by_key);
  if (!vm) {
    errors.push(`No verificationMethod for ${rev.issued_by_key}`);
    return { ok: false, errors };
  }

  try {
    const toVerify: Revocation = { ...rev, signature: { ...rev.signature, value: "" } };
    const bytes = new TextEncoder().encode(canonicalize(toVerify));
    const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    const sig = base64urlDecode(rev.signature.value);
    if (!ed.verify(sig, bytes, pk)) errors.push("Revocation signature verification failed");
  } catch (e) {
    errors.push(`Revocation signature check errored: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors };
}

/* -------------------------------------------------------------------------- */
/*  Action artifacts                                                          */
/* -------------------------------------------------------------------------- */

export interface SignActionArgs {
  mandate: Mandate;
  agentSeed: Uint8Array; // 32 bytes
  agentId: string;
  verb: string;
  target: Record<string, unknown>;
  contentBytes: Uint8Array; // the actual body the hash is over
  summary: string;
  issuedAt?: Date;
}

export function signActionArtifact(args: SignActionArgs): ActionArtifact {
  if (!args.mandate.scopes.includes(args.verb)) {
    throw new Error(`Verb ${args.verb} is not in the mandate's scopes`);
  }
  if (args.mandate.grantee.id !== args.agentId) {
    throw new Error(
      `Actor id ${args.agentId} does not match mandate grantee ${args.mandate.grantee.id}`,
    );
  }

  const agentPk = ed.getPublicKey(args.agentSeed);
  const multibasePk = encodeEd25519Multibase(agentPk);
  if (args.mandate.grantee.pubkey && args.mandate.grantee.pubkey !== multibasePk) {
    throw new Error("Actor pubkey does not match mandate grantee.pubkey");
  }

  const unsigned: ActionArtifact = {
    "aithos-action": "0.1.0",
    id: `action_${ulid()}`,
    mandate_id: args.mandate.id,
    issued_at: (args.issuedAt ?? new Date()).toISOString(),
    actor: { id: args.agentId, pubkey: multibasePk },
    action: {
      verb: args.verb,
      target: args.target,
      content_hash: sha256Hex(args.contentBytes),
      summary: args.summary.length > 280 ? args.summary.slice(0, 280) : args.summary,
    },
    signature: { alg: "ed25519", key: multibasePk, value: "" },
    counter_signature: null,
  };

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = ed.sign(bytes, args.agentSeed);
  unsigned.signature.value = base64url(sig);
  return unsigned;
}

/**
 * Attach a counter-signature from the subject's mandated sphere key. Required
 * when the action's verb appears in mandate.constraints.require_counter_sign.
 */
export function counterSignAction(
  artifact: ActionArtifact,
  subject: Identity,
  mandate: Mandate,
): ActionArtifact {
  const sphere = mandate.actor_sphere;
  const sphereKey = sphereDidUrl(subject, sphere);
  const toSign: ActionArtifact = {
    ...artifact,
    counter_signature: { alg: "ed25519", key: sphereKey, value: "" },
  };
  const bytes = new TextEncoder().encode(canonicalize(toSign));
  const sig = signWithSphere(subject, sphere, bytes);
  return {
    ...toSign,
    counter_signature: { alg: "ed25519", key: sphereKey, value: base64url(sig) },
  };
}

export function verifyActionArtifact(
  artifact: ActionArtifact,
  mandate: Mandate,
  didDoc: DidDocument,
): VerifyResult {
  const errors: string[] = [];

  if (artifact.mandate_id !== mandate.id) errors.push(`mandate_id mismatch`);
  if (!mandate.scopes.includes(artifact.action.verb)) {
    errors.push(`verb ${artifact.action.verb} not in mandate scopes`);
  }
  if (artifact.actor.id !== mandate.grantee.id) {
    errors.push(`actor.id ${artifact.actor.id} does not match mandate grantee`);
  }
  if (mandate.grantee.pubkey && artifact.actor.pubkey !== mandate.grantee.pubkey) {
    errors.push(`actor.pubkey does not match mandate grantee.pubkey`);
  }

  // Verify mandate itself at artifact's issued_at
  const mandateCheck = verifyMandate(mandate, didDoc, new Date(artifact.issued_at));
  if (!mandateCheck.ok) errors.push(...mandateCheck.errors.map((e) => `mandate: ${e}`));

  // Verify agent signature
  try {
    const toVerify: ActionArtifact = {
      ...artifact,
      signature: { ...artifact.signature, value: "" },
      counter_signature: artifact.counter_signature
        ? { ...artifact.counter_signature, value: "" }
        : null,
    };
    const bytes = new TextEncoder().encode(canonicalize(toVerify));
    const agentPk = multibaseToEd25519PublicKey(artifact.actor.pubkey);
    const sig = base64urlDecode(artifact.signature.value);
    if (!ed.verify(sig, bytes, agentPk)) errors.push("Agent signature invalid");

    // Counter-signature if required
    const requiresCs = mandate.constraints?.require_counter_sign?.includes(artifact.action.verb);
    if (requiresCs) {
      if (!artifact.counter_signature) {
        errors.push("Counter-signature required by mandate but missing");
      } else {
        const sphereVm = didDoc.verificationMethod.find(
          (v) => v.id === artifact.counter_signature!.key,
        );
        if (!sphereVm) {
          errors.push(`Counter-signature key ${artifact.counter_signature.key} not in DID doc`);
        } else {
          const csBytes = new TextEncoder().encode(canonicalize({
            ...artifact,
            signature: { ...artifact.signature, value: artifact.signature.value },
            counter_signature: { ...artifact.counter_signature, value: "" },
          }));
          const cs = base64urlDecode(artifact.counter_signature.value);
          const pk = multibaseToEd25519PublicKey(sphereVm.publicKeyMultibase);
          if (!ed.verify(cs, csBytes, pk)) errors.push("Counter-signature invalid");
        }
      }
    }
  } catch (e) {
    errors.push(`Signature check errored: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors };
}

/* -------------------------------------------------------------------------- */
/*  Local helpers                                                             */
/* -------------------------------------------------------------------------- */

function encodeEd25519Multibase(pk: Uint8Array): string {
  // duplicated from did.ts to avoid a circular import dance; kept tiny.
  // did.ts is the authority; this is a local mirror.
  const prefixed = new Uint8Array(2 + pk.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pk, 2);
  // base58btc
  return "z" + base58btc(prefixed);
}

function base58btc(bytes: Uint8Array): string {
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  // Count leading zeros
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // Convert to base58
  const input = Array.from(bytes);
  const b58: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let carry = input[i];
    for (let j = 0; j < b58.length; j++) {
      carry += b58[j] << 8;
      b58[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      b58.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < zeros; i++) out += "1";
  for (let i = b58.length - 1; i >= 0; i--) out += ALPHA[b58[i]];
  return out;
}
