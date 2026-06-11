// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Envelope authentication for the assets PDS — owner-only in v0.1.
 *
 * Reuses `verifyEnvelope` from @aithos/protocol-core for the canonical
 * 9-step spec §11.4 check. For v0.1 we only accept envelopes signed
 * by one of the subject's sphere keys (no mandate path).
 *
 * Mandate-based delegate auth (chapter 04 of the assets spec) lands in
 * v0.2 of this backend and will mirror data-backend/lambda/auth/authenticate.ts.
 */

import {
  verifyEnvelope,
  type SignedEnvelope,
  type EnvelopeReplayCache,
} from "@aithos/protocol-core/envelope";
import { ed25519PublicKeyToMultibase } from "@aithos/protocol-core/did";

import { RpcError } from "../jsonrpc.js";
import {
  AITHOS_BAD_ENVELOPE,
  AITHOS_BAD_SIGNATURE,
  AITHOS_ENVELOPE_EXPIRED,
  AITHOS_REPLAY_DETECTED,
} from "../errors.js";
import { resolveIssuerDoc } from "./did-resolver.js";
import { assertOwnerDataSphere } from "@aithos/pds-auth";
import { atomicAddNonce } from "./replay.js";

/* -------------------------------------------------------------------------- */
/*  Caller — what every handler receives                                      */
/* -------------------------------------------------------------------------- */

export interface Caller {
  /** Subject DID — the principal whose state is being operated on. */
  readonly subjectDid: string;
  /** Owner-only in v0.1. Reserved for "delegate" in v0.2. */
  readonly mode: "owner";
  /** Signer Ed25519 pubkey in multibase form (z…). */
  readonly signerPubkeyMultibase: string;
  /** Envelope nonce of this call — useful as a gamma audit trace. */
  readonly envelopeNonce: string;
  /** Per-call params with `_envelope` stripped. */
  readonly params: Record<string, unknown>;
  /** Method that was called, for handler-side logging. */
  readonly method: string;
}

/* -------------------------------------------------------------------------- */
/*  Replay-cache adapter for verifyEnvelope                                   */
/* -------------------------------------------------------------------------- */

/**
 * EnvelopeReplayCache implementation backed by our DDB nonce table.
 *
 * The verifyEnvelope contract expects `putIfAbsent(key, expiresAt)`
 * to return `true` on first sight and `false` on replay — exactly
 * what atomicAddNonce already provides.
 */
const replayCache: EnvelopeReplayCache = {
  async putIfAbsent(key: string, expiresAtSeconds: number): Promise<boolean> {
    // Split the replay cache "key" produced by @aithos/protocol-core
    // ("<iss>#<nonce>") into its two halves. atomicAddNonce currently
    // accepts them separately for symmetry with the DDB schema; we
    // re-pack the key as the partition key inside atomicAddNonce.
    const hashIdx = key.indexOf("#");
    const issuer = hashIdx >= 0 ? key.substring(0, hashIdx) : key;
    const nonce = hashIdx >= 0 ? key.substring(hashIdx + 1) : "";
    return atomicAddNonce({
      issuer,
      nonce,
      expiresAtEpoch: expiresAtSeconds,
    });
  },
};

/* -------------------------------------------------------------------------- */
/*  authenticate()                                                            */
/* -------------------------------------------------------------------------- */

export interface AuthenticateInput {
  readonly method: string;
  readonly rawParams: Record<string, unknown>;
  /**
   * Server-side audience URL(s) the envelope's `aud` MUST match. A single
   * value, or — during the edge migration — a set of acceptable endpoints
   * (vanity + origin host) for dual-aud verification.
   */
  readonly expectedAud: string | readonly string[];
}

/**
 * Canonicalize an audience URL for comparison. Mirrors protocol-core's
 * internal `normalizeAud` (not exported): lowercases the host and strips a
 * single trailing slash from the pathname. Used only to pick the matching
 * candidate out of a dual-aud set; the authoritative check still runs inside
 * verifyEnvelope on the value we hand it.
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
    return u.toLowerCase();
  }
}

/**
 * Verify the envelope, atomically record the nonce to defend against
 * replays, and return a Caller. Throws RpcError on any failure.
 */
export async function authenticate(input: AuthenticateInput): Promise<Caller> {
  const envelope = input.rawParams._envelope;
  if (envelope === undefined || envelope === null) {
    throw new RpcError(
      AITHOS_BAD_ENVELOPE,
      "AITHOS_BAD_ENVELOPE: params._envelope is required for authenticated calls",
    );
  }
  if (typeof envelope !== "object") {
    throw new RpcError(
      AITHOS_BAD_ENVELOPE,
      "AITHOS_BAD_ENVELOPE: _envelope must be an object",
    );
  }

  // Strip `_envelope` so params_hash matches what the client signed.
  const { _envelope, ...businessParams } = input.rawParams as {
    _envelope: unknown;
  } & Record<string, unknown>;
  void _envelope;

  // Dual-aud resolution. `expectedAud` may be a set of acceptable endpoints
  // (vanity + origin host). protocol-core's verifyEnvelope compares against a
  // single value, so pick the accepted candidate whose normalized form equals
  // the envelope's `aud` and hand THAT to the verifier; if none matches, pass
  // the first candidate so the canonical mismatch error fires.
  const acceptedAud = Array.isArray(input.expectedAud)
    ? input.expectedAud
    : [input.expectedAud];
  const envAud = (envelope as { aud?: unknown }).aud;
  const matchedAud =
    typeof envAud === "string"
      ? acceptedAud.find((a) => normalizeAud(a) === normalizeAud(envAud))
      : undefined;

  const result = await verifyEnvelope(envelope as SignedEnvelope, {
    expectedAud: matchedAud ?? acceptedAud[0],
    expectedMethod: input.method,
    params: businessParams,
    nowSeconds: Math.floor(Date.now() / 1000),
    resolveIssuerDoc,
    replay: replayCache,
  });

  if (!result.ok) {
    // protocol-core uses numeric error codes -32010/-32011/-32012/-32013
    // for envelope failures. We re-emit them under the same wire codes
    // (assets-backend's AITHOS_BAD_ENVELOPE etc. share the same numeric
    // values per spec/assets/05-api-primitives.md §5.5).
    throw new RpcError(
      result.error.code,
      result.error.message,
      result.error.data,
    );
  }
  // Silence unused-warnings when we're tempted to consume these
  // constants directly (kept here for clarity and future v0.2 use).
  void AITHOS_BAD_ENVELOPE;
  void AITHOS_BAD_SIGNATURE;
  void AITHOS_ENVELOPE_EXPIRED;
  void AITHOS_REPLAY_DETECTED;

  // For v0.1 owner-only mode, the envelope's iss is the subject_did.
  // Mandate-bearing envelopes (result.mandateId !== undefined) are
  // rejected — that path lands in v0.2.
  if (result.mandateId !== undefined) {
    throw new RpcError(
      AITHOS_BAD_ENVELOPE,
      "mandate-based delegate auth is not implemented in v0.1 of the assets PDS",
    );
  }

  // M1 — sphere lock: reject the three Ethos spheres (#public/#circle/#self);
  // #data (intended), #root and did:key canonical VMs are allowed.
  assertOwnerDataSphere(envelope as SignedEnvelope);

  // Re-extract the envelope's nonce field for the audit trace.
  const env = envelope as SignedEnvelope;

  return {
    subjectDid: result.issuer,
    mode: "owner",
    signerPubkeyMultibase: ed25519PublicKeyToMultibase(result.signerKey),
    envelopeNonce: env.nonce,
    params: businessParams,
    method: input.method,
  };
}
