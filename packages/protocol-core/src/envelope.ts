// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Signed-envelope helpers — spec chapter 11 (`spec/11-signed-requests.md`).
 *
 * Every write to a platform endpoint (§10.6, §12) is authenticated by a
 * short-lived, self-contained, per-request envelope carrying an Ed25519
 * signature. There is no session, no bearer token, no cookie. This module
 * is the single source of truth for:
 *
 *   - `SignedEnvelope` / `EnvelopeProof`             — the on-the-wire shape (§11.2)
 *   - `signEnvelope` / `signEnvelopeWithMandate`     — the client helpers (§11.9)
 *   - `verifyEnvelope`                               — the 9-step server check (§11.4)
 *
 * The module is deliberately pure-logic: replay state, DID resolution, and
 * revocation lookups are injected through a context object. That lets the
 * same code run in the CLI (filesystem-backed), the reference Lambda
 * (DynamoDB-backed), and future hosts.
 */

import * as ed from "@noble/ed25519";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import { ulid } from "ulid";

import { canonicalize } from "./canonical.js";
import {
  multibaseToEd25519PublicKey,
  ed25519PublicKeyToMultibase,
} from "./did.js";
import {
  base64url,
  base64urlDecode,
  type DidDocument,
} from "./identity.js";
import {
  verifyMandate,
  type Mandate,
  type Revocation,
} from "./mandate.js";

/* -------------------------------------------------------------------------- */
/*  Envelope shape (§11.2)                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Envelope format version currently understood.
 *
 * Spec §11 revision note (v0.2.0): the envelope shape is stable; what evolves
 * is the `params` payload sitting beside it, which the envelope only covers
 * through `params_hash`.
 */
export const ENVELOPE_VERSION = "0.1.0" as const;

export interface EnvelopeProof {
  readonly type: "Ed25519Signature2020";
  /**
   * Either a DID URL into the issuer's verification method set
   * (e.g. `did:aithos:z6Mk…#public`) when the subject signs directly, OR a
   * bare multibase Ed25519 public key when a delegate signs — in the latter
   * case `SignedEnvelope.mandate` is REQUIRED (§11.6).
   */
  readonly verificationMethod: string;
  readonly created: string; // RFC 3339
  readonly proofValue: string; // base64url(Ed25519 signature, 64 bytes)
}

/**
 * Optional sponsorship reference — draft §13.6.
 *
 * Present when the consumer expects a specific `SponsorshipMandate` to fund
 * the call. The authority MUST cross-check `hash` against the canonical copy
 * of the mandate and reject on mismatch, defeating any attempt to widen caps
 * by tampering with a local copy. When the field is absent, the authority MAY
 * still auto-discover an eligible sponsorship from its own index; the field is
 * an explicit hint, not the sole gate.
 *
 * NOT YET NORMATIVE — pending promotion of `sponsorship-mandate-v0.1` draft.
 */
export interface SponsorshipReference {
  readonly id: string;
  /** Canonical hash of the mandate, format `"sha256:" + hex`. */
  readonly hash: string;
}

export interface SignedEnvelope {
  readonly "aithos-envelope": "0.1.0";
  readonly iss: string;
  readonly aud: string;
  readonly method: string;
  readonly iat: number;
  readonly exp: number;
  readonly nonce: string;
  /** `"sha256-" + lowercase hex SHA-256 of rfc8785(params without _envelope)`. */
  readonly params_hash: string;
  readonly mandate?: Mandate;
  /** Draft §13.6 — sponsorship reference, optional and back-compatible. */
  readonly sponsorship?: SponsorshipReference;
  readonly proof: EnvelopeProof;
}

/* -------------------------------------------------------------------------- */
/*  Error taxonomy (subset of §10.9 relevant to envelope verification)         */
/* -------------------------------------------------------------------------- */

export type EnvelopeErrorCode =
  | -32010 // AITHOS_BAD_ENVELOPE
  | -32011 // AITHOS_BAD_SIGNATURE
  | -32012 // AITHOS_REPLAY_DETECTED
  | -32013 // AITHOS_STALE_ENVELOPE
  | -32040 // AITHOS_MANDATE_INVALID
  | -32041 // AITHOS_MANDATE_REVOKED
  | -32042 // AITHOS_INSUFFICIENT_SCOPE
  | -32603; // internal (replay cache outage)

export interface AithosError {
  readonly code: EnvelopeErrorCode;
  readonly message: string;
  readonly data?: Record<string, unknown>;
}

/* -------------------------------------------------------------------------- */
/*  §11.6 / §11.7 root-only enforcement                                       */
/* -------------------------------------------------------------------------- */

/**
 * Methods that MUST be signed by `#root` when the subject signs directly
 * (no mandate). Spec §11.7 signing-purpose table. Some of these are also
 * non-delegable (see `NEVER_DELEGABLE_METHODS`); others (`publish_tombstone`)
 * may be delegated to an agent carrying the appropriate scope.
 */
export const ROOT_ONLY_DIRECT_METHODS: ReadonlySet<string> = new Set([
  "aithos.publish_identity",
  "aithos.rotate_sphere_key",
  "aithos.publish_tombstone",
]);

/**
 * Methods that can NEVER be invoked under a mandate. Spec §11.6 last two
 * rows — "never delegable". An envelope carrying a mandate for one of these
 * MUST be rejected with `AITHOS_INSUFFICIENT_SCOPE`.
 */
export const NEVER_DELEGABLE_METHODS: ReadonlySet<string> = new Set([
  "aithos.publish_identity",
  "aithos.rotate_sphere_key",
]);

/* -------------------------------------------------------------------------- */
/*  params_hash                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Compute the `params_hash` field for a given tool payload.
 *
 * The payload MUST be `params` WITHOUT `_envelope` — the envelope cannot
 * hash itself (circular reference). In practice both the signer and the
 * verifier strip `_envelope` via destructuring before calling this helper.
 */
export function envelopeParamsHash(params: unknown): string {
  const canonical = canonicalize(params);
  const digest = sha256fn(new TextEncoder().encode(canonical));
  return "sha256-" + bytesToHex(digest);
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/* -------------------------------------------------------------------------- */
/*  Canonical form for signing (§5.1.1 substituted-value pattern)             */
/* -------------------------------------------------------------------------- */

/**
 * Canonical JSON bytes covered by `proof.proofValue`. Matches the
 * substitute-then-canonicalize pattern from §5.1.1: blank the signature
 * field, JCS-canonicalize, produce UTF-8 bytes, sign/verify those bytes.
 */
export function envelopeSigningBytes(env: SignedEnvelope): Uint8Array {
  const substituted: SignedEnvelope = {
    ...env,
    proof: { ...env.proof, proofValue: "" },
  };
  return new TextEncoder().encode(canonicalize(substituted));
}

/* -------------------------------------------------------------------------- */
/*  Signer helpers (§11.9)                                                    */
/* -------------------------------------------------------------------------- */

export interface SignEnvelopeArgs {
  /** Subject DID whose state will be mutated — never the delegate's DID. */
  readonly iss: string;
  /** Absolute URL of the target endpoint (scheme + host + path, no query, no fragment). */
  readonly aud: string;
  /** Fully-qualified tool name, identical to the JSON-RPC `method`. */
  readonly method: string;
  /** Tool payload (i.e. `params` WITHOUT `_envelope`). */
  readonly params: unknown;
  /**
   * Ed25519 signing material for one of the subject's sphere keys.
   *
   *   - `seed`: the 32-byte private seed.
   *   - `verificationMethod`: DID URL into the subject's DID document
   *     verification method set — e.g. `did:aithos:<mb>#public`.
   */
  readonly sphereKey: {
    readonly seed: Uint8Array;
    readonly verificationMethod: string;
  };
  /** Envelope lifetime. Defaults to 60s (§11.10 recommends short TTLs). */
  readonly ttlSeconds?: number;
  /** Clock override for deterministic testing. */
  readonly now?: Date;
  /** Nonce override. Defaults to a freshly minted ULID. */
  readonly nonce?: string;
  /**
   * Optional sponsorship reference — draft §13.6. When present, the field is
   * carried in the signed envelope and the authority may apply the indicated
   * sponsorship if eligible.
   */
  readonly sponsorship?: SponsorshipReference;
}

export function signEnvelope(args: SignEnvelopeArgs): SignedEnvelope {
  return buildAndSignEnvelope({
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    params: args.params,
    ttlSeconds: args.ttlSeconds,
    now: args.now,
    nonce: args.nonce,
    signerSeed: args.sphereKey.seed,
    verificationMethod: args.sphereKey.verificationMethod,
    mandate: undefined,
    sponsorship: args.sponsorship,
  });
}

export interface SignEnvelopeWithMandateArgs {
  readonly iss: string;
  readonly aud: string;
  readonly method: string;
  readonly params: unknown;
  /**
   * Ed25519 signing material for the delegate key named in the mandate's
   * `grantee.pubkey`. `pubkeyMultibase` is the `z…` form (matches
   * `mandate.grantee.pubkey` exactly).
   */
  readonly delegateKey: {
    readonly seed: Uint8Array;
    readonly pubkeyMultibase: string;
  };
  readonly mandate: Mandate;
  readonly ttlSeconds?: number;
  readonly now?: Date;
  readonly nonce?: string;
  /** Optional sponsorship reference — draft §13.6. */
  readonly sponsorship?: SponsorshipReference;
}

export function signEnvelopeWithMandate(
  args: SignEnvelopeWithMandateArgs,
): SignedEnvelope {
  if (
    args.mandate.grantee.pubkey &&
    args.mandate.grantee.pubkey !== args.delegateKey.pubkeyMultibase
  ) {
    throw new Error(
      `Delegate key multibase ${args.delegateKey.pubkeyMultibase} does not match ` +
        `mandate.grantee.pubkey ${args.mandate.grantee.pubkey}`,
    );
  }
  return buildAndSignEnvelope({
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    params: args.params,
    ttlSeconds: args.ttlSeconds,
    now: args.now,
    nonce: args.nonce,
    signerSeed: args.delegateKey.seed,
    verificationMethod: args.delegateKey.pubkeyMultibase,
    mandate: args.mandate,
    sponsorship: args.sponsorship,
  });
}

/**
 * Build the canonical UNSIGNED envelope — every field populated except
 * `proof.proofValue`, which is left blank (`""`) per the §5.1.1
 * substitute-then-canonicalize pattern. This is the single source of truth
 * for envelope assembly: both the seed-based signers and the pluggable
 * async signer ({@link signEnvelopeWith}) build their bytes from here, so
 * any signing path produces byte-identical wire output for identical input.
 *
 * Callers obtain the bytes to sign via {@link envelopeSigningBytes} and
 * attach the resulting signature with {@link attachProof}.
 */
export function buildUnsignedEnvelope(args: {
  iss: string;
  aud: string;
  method: string;
  params: unknown;
  ttlSeconds: number | undefined;
  now: Date | undefined;
  nonce: string | undefined;
  verificationMethod: string;
  mandate: Mandate | undefined;
  sponsorship: SponsorshipReference | undefined;
}): SignedEnvelope {
  const now = args.now ?? new Date();
  const ttl = args.ttlSeconds ?? 60;
  if (ttl < 1 || ttl > 300) {
    throw new Error(
      `ttlSeconds out of protocol range [1, 300]: got ${ttl} (spec §11.3)`,
    );
  }
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + ttl;

  return {
    "aithos-envelope": ENVELOPE_VERSION,
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    iat,
    exp,
    nonce: args.nonce ?? ulid(),
    params_hash: envelopeParamsHash(args.params),
    ...(args.mandate !== undefined ? { mandate: args.mandate } : {}),
    ...(args.sponsorship !== undefined
      ? { sponsorship: args.sponsorship }
      : {}),
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: args.verificationMethod,
      created: now.toISOString(),
      proofValue: "",
    },
  };
}

/** Attach a raw Ed25519 signature to an unsigned envelope (base64url proofValue). */
export function attachProof(
  unsigned: SignedEnvelope,
  signature: Uint8Array,
): SignedEnvelope {
  return {
    ...unsigned,
    proof: { ...unsigned.proof, proofValue: base64url(signature) },
  };
}

/**
 * Pluggable-signer envelope helper. Identical wire output to
 * {@link signEnvelope} / {@link signEnvelopeWithMandate} but the Ed25519
 * signing operation is injected as an async callback instead of taking a
 * raw seed. This lets hosts that hold non-extractable keys (e.g. WebCrypto
 * `crypto.subtle`, the Aithos SDK's `EnvelopeSigner`) sign without ever
 * surfacing seed bytes — while sharing this module's canonicalization so
 * their envelopes can never drift from the seed-based path.
 *
 * For an owner-path call, pass the subject's `did#sphere` as
 * `verificationMethod` and omit `mandate`. For a delegate-path call, pass
 * the delegate's bare multibase as `verificationMethod` and the signed
 * `mandate`; the `sign` callback MUST use the delegate's key.
 */
export interface SignEnvelopeWithArgs {
  readonly iss: string;
  readonly aud: string;
  readonly method: string;
  readonly params: unknown;
  /** `did#sphere` (owner path) or bare multibase (delegate path). */
  readonly verificationMethod: string;
  /** Sign the given canonical bytes with the appropriate Ed25519 key. */
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array> | Uint8Array;
  readonly ttlSeconds?: number;
  readonly now?: Date;
  readonly nonce?: string;
  /** Present only on the delegate path (§11.6). */
  readonly mandate?: Mandate;
  /** Optional sponsorship reference — draft §13.6. */
  readonly sponsorship?: SponsorshipReference;
}

export async function signEnvelopeWith(
  args: SignEnvelopeWithArgs,
): Promise<SignedEnvelope> {
  const unsigned = buildUnsignedEnvelope({
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    params: args.params,
    ttlSeconds: args.ttlSeconds,
    now: args.now,
    nonce: args.nonce,
    verificationMethod: args.verificationMethod,
    mandate: args.mandate,
    sponsorship: args.sponsorship,
  });
  const signature = await args.sign(envelopeSigningBytes(unsigned));
  return attachProof(unsigned, signature);
}

function buildAndSignEnvelope(args: {
  iss: string;
  aud: string;
  method: string;
  params: unknown;
  ttlSeconds: number | undefined;
  now: Date | undefined;
  nonce: string | undefined;
  signerSeed: Uint8Array;
  verificationMethod: string;
  mandate: Mandate | undefined;
  sponsorship: SponsorshipReference | undefined;
}): SignedEnvelope {
  const unsigned = buildUnsignedEnvelope({
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    params: args.params,
    ttlSeconds: args.ttlSeconds,
    now: args.now,
    nonce: args.nonce,
    verificationMethod: args.verificationMethod,
    mandate: args.mandate,
    sponsorship: args.sponsorship,
  });
  const sig = ed.sign(envelopeSigningBytes(unsigned), args.signerSeed);
  return attachProof(unsigned, sig);
}

/* -------------------------------------------------------------------------- */
/*  Verification (§11.4 — nine steps)                                         */
/* -------------------------------------------------------------------------- */

/**
 * Replay-protection cache contract — spec §11.5.
 *
 * `putIfAbsent` MUST perform an atomic conditional insert:
 *   - `true`  → the key was new and has been committed with TTL `expiresAtSeconds`.
 *   - `false` → the key already existed; the caller MUST reject the request.
 *
 * A throw from this method is treated as "cache unreachable", which per
 * §11.10 MUST fail closed (internal error `-32603`) rather than letting the
 * write through.
 */
export interface EnvelopeReplayCache {
  putIfAbsent(key: string, expiresAtSeconds: number): Promise<boolean>;
}

export interface VerifyEnvelopeContext {
  /** Server canonical URL for the path that received the request. */
  readonly expectedAud: string;
  /** JSON-RPC `method` the client invoked. */
  readonly expectedMethod: string;
  /** Tool payload, `_envelope` already stripped (§11.4 step 5). */
  readonly params: unknown;
  /** Unix seconds. Defaults to `Math.floor(Date.now() / 1000)`. */
  readonly nowSeconds?: number;
  /** Fetch the current DID document of `iss`. Return `null` when unresolvable. */
  resolveIssuerDoc(iss: string): Promise<DidDocument | null>;
  /** Look up a local revocation for the given mandate id. Optional; absent ≡ none. */
  findRevocation?(mandateId: string): Promise<Revocation | null>;
  /** Replay cache — spec §11.5. */
  readonly replay: EnvelopeReplayCache;
}

export type VerifyEnvelopeResult =
  | {
      readonly ok: true;
      readonly issuer: string;
      readonly mandateId?: string;
      /** Resolved signer Ed25519 public key (32 bytes). Useful for per-tool audit. */
      readonly signerKey: Uint8Array;
    }
  | { readonly ok: false; readonly error: AithosError };

const ok = (
  issuer: string,
  signerKey: Uint8Array,
  mandateId: string | undefined,
): VerifyEnvelopeResult => ({
  ok: true,
  issuer,
  signerKey,
  ...(mandateId !== undefined ? { mandateId } : {}),
});

const err = (
  code: EnvelopeErrorCode,
  message: string,
  data?: Record<string, unknown>,
): VerifyEnvelopeResult => ({
  ok: false,
  error: { code, message, ...(data ? { data } : {}) },
});

/**
 * Verify a signed envelope, performing the 9 steps of spec §11.4 in order.
 *
 * The first failure short-circuits; later steps are NOT run. That matches
 * what the spec asks for ("MUST perform these steps, in order") and keeps
 * side-effects — specifically the replay-cache commit — gated behind all
 * prior checks passing.
 *
 * On success, returns the verified issuer DID, optional mandate id, and the
 * raw 32-byte Ed25519 public key that was used to sign. Callers are still
 * responsible for enforcing payload-level scope rules (§11.6, §11.7 per-zone
 * checks) that the envelope alone cannot know about.
 */
export async function verifyEnvelope(
  envelope: SignedEnvelope,
  ctx: VerifyEnvelopeContext,
): Promise<VerifyEnvelopeResult> {
  // ─── Step 1: schema check ────────────────────────────────────────────────
  const schemaError = checkSchema(envelope);
  if (schemaError) return err(-32010, schemaError);

  // ─── Step 2: audience check ──────────────────────────────────────────────
  if (normalizeAud(envelope.aud) !== normalizeAud(ctx.expectedAud)) {
    return err(-32010, "envelope.aud does not match the request endpoint", {
      got: envelope.aud,
      expected: ctx.expectedAud,
    });
  }

  // ─── Step 3: method check ────────────────────────────────────────────────
  if (envelope.method !== ctx.expectedMethod) {
    return err(
      -32010,
      "envelope.method does not match the JSON-RPC method",
      { got: envelope.method, expected: ctx.expectedMethod },
    );
  }

  // ─── Step 4: TTL check (§11.3) ───────────────────────────────────────────
  const now = ctx.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (envelope.iat < now - 30 || envelope.iat > now + 30) {
    return err(-32013, "envelope.iat is outside the ±30s clock-skew window", {
      iat: envelope.iat,
      now,
    });
  }
  if (envelope.exp <= now) {
    return err(-32013, "envelope has expired", { exp: envelope.exp, now });
  }
  const ttl = envelope.exp - envelope.iat;
  if (ttl < 1 || ttl > 300) {
    return err(-32013, "envelope TTL (exp - iat) is outside [1, 300]s", {
      ttl,
    });
  }

  // ─── Step 5: params_hash check ───────────────────────────────────────────
  const expectedHash = envelopeParamsHash(ctx.params);
  if (envelope.params_hash !== expectedHash) {
    return err(-32010, "envelope.params_hash does not match the request params", {
      got: envelope.params_hash,
      expected: expectedHash,
    });
  }

  // ─── Step 6: signer resolution ───────────────────────────────────────────
  //
  // Two mutually-exclusive paths:
  //   (a) no mandate: proof.verificationMethod MUST be a DID URL resolvable
  //       against the issuer's DID document. The §11.7 root-only check is
  //       enforced here (a mandate-less envelope calling `publish_identity`
  //       MUST carry a `#root` proof).
  //   (b) with mandate: proof.verificationMethod MUST equal
  //       mandate.grantee.pubkey; the mandate itself MUST verify against the
  //       issuer's DID doc, be in its time window, not revoked, and
  //       (§11.7) NOT authorize a root-only method.
  //
  const issuerDoc = await ctx.resolveIssuerDoc(envelope.iss);
  if (!issuerDoc) {
    return err(-32011, `cannot resolve DID document for iss=${envelope.iss}`);
  }
  if (issuerDoc.id !== envelope.iss) {
    return err(-32011, "resolved DID document id does not match envelope.iss", {
      resolved: issuerDoc.id,
      iss: envelope.iss,
    });
  }

  let signerPk: Uint8Array;
  let mandateId: string | undefined;

  if (envelope.mandate === undefined || envelope.mandate === null) {
    // Path (a): direct sphere-key signature.
    const vm = envelope.proof.verificationMethod;
    const sphereKey = issuerDoc.verificationMethod.find((v) => v.id === vm);
    if (!sphereKey) {
      return err(
        -32011,
        `proof.verificationMethod ${vm} not found in issuer DID document`,
      );
    }
    if (sphereKey.type !== "Ed25519VerificationKey2020") {
      return err(
        -32011,
        `verification method ${vm} is not an Ed25519 key (type=${sphereKey.type})`,
      );
    }
    // Root-only enforcement (§11.7): direct-signed calls to these methods
    // MUST use the #root sphere. Delegate-signed calls for these methods are
    // handled by NEVER_DELEGABLE_METHODS in the mandate branch below.
    if (ROOT_ONLY_DIRECT_METHODS.has(envelope.method) && !vm.endsWith("#root")) {
      return err(
        -32011,
        `method ${envelope.method} is root-only and MUST be signed by #root`,
        { verificationMethod: vm },
      );
    }
    try {
      signerPk = multibaseToEd25519PublicKey(sphereKey.publicKeyMultibase);
    } catch (e) {
      return err(
        -32011,
        `failed to decode sphere public key: ${(e as Error).message}`,
      );
    }
  } else {
    // Path (b): delegate signature under a mandate.
    if (NEVER_DELEGABLE_METHODS.has(envelope.method)) {
      return err(
        -32042,
        `method ${envelope.method} is never delegable (spec §11.6); ` +
          `mandate-authorized envelope refused`,
      );
    }
    const mandate = envelope.mandate;
    if (mandate.issuer !== envelope.iss) {
      return err(
        -32040,
        `mandate.issuer ${mandate.issuer} does not match envelope.iss ${envelope.iss}`,
      );
    }
    if (
      mandate.grantee.pubkey === undefined ||
      mandate.grantee.pubkey !== envelope.proof.verificationMethod
    ) {
      return err(
        -32040,
        "proof.verificationMethod does not match mandate.grantee.pubkey",
        {
          proofVm: envelope.proof.verificationMethod,
          mandateGranteePubkey: mandate.grantee.pubkey,
        },
      );
    }

    // Mandate signature, time window, and subject binding.
    const envelopeCreated = new Date(envelope.proof.created);
    const verifiedAt = Number.isNaN(envelopeCreated.getTime())
      ? new Date(now * 1000)
      : envelopeCreated;
    const mandateCheck = verifyMandate(mandate, issuerDoc, verifiedAt);
    if (!mandateCheck.ok) {
      return err(-32040, "mandate did not verify", {
        errors: mandateCheck.errors,
      });
    }

    // Revocation (optional lookup — absence is not an error).
    if (ctx.findRevocation) {
      const rev = await ctx.findRevocation(mandate.id);
      if (rev) {
        return err(-32041, `mandate ${mandate.id} has been revoked`, {
          revokedAt: rev.revoked_at,
          reason: rev.reason,
        });
      }
    }

    try {
      signerPk = multibaseToEd25519PublicKey(mandate.grantee.pubkey);
    } catch (e) {
      return err(
        -32040,
        `failed to decode mandate.grantee.pubkey: ${(e as Error).message}`,
      );
    }
    mandateId = mandate.id;
  }

  // ─── Step 7: signature verification ──────────────────────────────────────
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64urlDecode(envelope.proof.proofValue);
  } catch (e) {
    return err(-32011, `proof.proofValue is not valid base64url: ${(e as Error).message}`);
  }
  if (sigBytes.byteLength !== 64) {
    return err(-32011, "proof.proofValue is not a 64-byte Ed25519 signature");
  }
  let sigOk = false;
  try {
    sigOk = ed.verify(sigBytes, envelopeSigningBytes(envelope), signerPk);
  } catch (e) {
    return err(-32011, `signature verification errored: ${(e as Error).message}`);
  }
  if (!sigOk) return err(-32011, "envelope signature did not verify");

  // ─── Step 8 + 9: replay check + commit nonce (§11.5) ─────────────────────
  //
  // Atomic conditional insert: `putIfAbsent` returns false when the nonce is
  // already present (replay), true when it committed a new entry. Per
  // §11.5.2/§11.10 the TTL is `exp + 30s` and a cache outage fails closed.
  //
  const replayKey = `aithos.envelope.v1:${envelope.iss}:${envelope.nonce}`;
  const expiresAt = envelope.exp + 30;
  let committed: boolean;
  try {
    committed = await ctx.replay.putIfAbsent(replayKey, expiresAt);
  } catch (e) {
    // §11.10 "Replay cache outages": MUST fail closed.
    return err(
      -32603,
      `replay cache unreachable — failing closed: ${(e as Error).message}`,
    );
  }
  if (!committed) {
    return err(-32012, "envelope nonce has already been consumed", {
      nonce: envelope.nonce,
    });
  }

  return ok(envelope.iss, signerPk, mandateId);
}

/* -------------------------------------------------------------------------- */
/*  Schema & URL helpers                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Minimal schema check per §11.4 step 1. We only inspect envelope-level
 * fields here; mandate/proof-signature substance is checked in later steps.
 * Returns a human-readable failure reason or `null` when the shape is OK.
 */
function checkSchema(env: unknown): string | null {
  if (env === null || typeof env !== "object") return "envelope is not an object";
  const e = env as Record<string, unknown>;
  if (e["aithos-envelope"] !== ENVELOPE_VERSION) {
    return `aithos-envelope must be "${ENVELOPE_VERSION}"`;
  }
  for (const s of ["iss", "aud", "method", "nonce", "params_hash"] as const) {
    if (typeof e[s] !== "string" || (e[s] as string).length === 0) {
      return `${s} must be a non-empty string`;
    }
  }
  for (const n of ["iat", "exp"] as const) {
    if (typeof e[n] !== "number" || !Number.isFinite(e[n]) || !Number.isInteger(e[n])) {
      return `${n} must be a finite integer`;
    }
  }
  if (!(e.params_hash as string).startsWith("sha256-")) {
    return 'params_hash must start with "sha256-"';
  }
  const proof = e.proof;
  if (proof === null || typeof proof !== "object") {
    return "proof is required and must be an object";
  }
  const p = proof as Record<string, unknown>;
  if (p.type !== "Ed25519Signature2020") {
    return 'proof.type must be "Ed25519Signature2020"';
  }
  for (const s of ["verificationMethod", "created", "proofValue"] as const) {
    if (typeof p[s] !== "string" || (p[s] as string).length === 0) {
      return `proof.${s} must be a non-empty string`;
    }
  }
  if (e.mandate !== undefined && e.mandate !== null && typeof e.mandate !== "object") {
    return "mandate, when present, must be an object";
  }
  return null;
}

/**
 * Normalize two URLs so they compare equal iff they point to the same
 * endpoint modulo trailing slash and host casing (spec §11.4 step 2).
 * Query string and fragment are ignored — §11.2 pins `aud` to the absolute
 * endpoint URL without them, and the normalizer enforces that on both sides.
 */
function normalizeAud(u: string): string {
  try {
    const url = new URL(u);
    const host = url.host.toLowerCase();
    let pathname = url.pathname;
    if (pathname.length > 1 && pathname.endsWith("/")) {
      pathname = pathname.slice(0, -1);
    }
    return `${url.protocol}//${host}${pathname}`;
  } catch {
    // Fall back to a lower-cased raw string so we still compare deterministically.
    return u.toLowerCase();
  }
}

/* -------------------------------------------------------------------------- */
/*  Convenience: multibase-from-seed                                          */
/* -------------------------------------------------------------------------- */

/**
 * Helper for callers that start from a raw Ed25519 seed and need the
 * multibase form (`z…`) that mandates and envelope proofs reference.
 */
export function delegateMultibaseFromSeed(seed: Uint8Array): string {
  return ed25519PublicKeyToMultibase(ed.getPublicKey(seed));
}
