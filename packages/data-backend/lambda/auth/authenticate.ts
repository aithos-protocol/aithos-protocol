// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * authenticate(): the middleware that runs before every dispatch in
 * the Lambda router.
 *
 * Reads `_envelope` from `params`, runs the 9-step verifyEnvelope path
 * from @aithos/protocol-core, extracts a `Caller` object that handlers
 * use to enforce per-operation rules.
 *
 * On failure: throws RpcError with the JSON-RPC error code mandated by
 * the spec (§10.9). The router maps these to HTTP responses.
 */

import {
  verifyEnvelope,
  type SignedEnvelope,
  type VerifyEnvelopeContext,
} from "@aithos/protocol-core/envelope";
import { ed25519PublicKeyToMultibase } from "@aithos/protocol-core/did";

import { RpcError } from "../jsonrpc.js";
import { resolveIssuerDoc, withSphereOverride } from "./did-resolver.js";
import { replayCache } from "./nonce-store.js";
import { findRevocation } from "./revocations.js";

/**
 * Authenticated caller. Returned by `authenticate()`; passed to every
 * handler in place of raw `params`.
 */
export interface Caller {
  /** Subject DID — the principal whose state is being operated on. */
  readonly subjectDid: string;
  /** "owner" when signed by a sphere key, "delegate" when via a mandate. */
  readonly mode: "owner" | "delegate";
  /** Mandate id, present iff mode === "delegate". */
  readonly mandateId?: string;
  /** Mandate scopes, present iff mode === "delegate". */
  readonly mandateScopes?: readonly string[];
  /** Mandate (full document), present iff mode === "delegate". */
  readonly mandate?: SignedEnvelope["mandate"];
  /** Signer Ed25519 pubkey in multibase form. */
  readonly signerPubkeyMultibase: string;
  /** Envelope nonce of this call — used as the gamma audit trace. */
  readonly envelopeNonce: string;
  /** Per-call params, with `_envelope` stripped. */
  readonly params: Record<string, unknown>;
}

interface AuthenticateInput {
  /** Raw JSON-RPC method (e.g. "aithos.data.insert_record"). */
  readonly method: string;
  /** Raw JSON-RPC params (still contains `_envelope`). */
  readonly rawParams: Record<string, unknown>;
  /**
   * Server-side audience URL — what the envelope's `aud` field MUST
   * match. Built from the HTTP request URL.
   */
  readonly expectedAud: string;
}

/**
 * Run the spec §11.4 envelope-verification path on the incoming
 * params. Returns a `Caller`; throws RpcError on any failure.
 *
 * The router calls this BEFORE dispatching to a handler. Handlers
 * never see the raw envelope and never make their own auth checks.
 */
export async function authenticate(input: AuthenticateInput): Promise<Caller> {
  const envelope = input.rawParams._envelope;
  if (envelope === undefined || envelope === null) {
    throw new RpcError(
      -32010,
      "AITHOS_BAD_ENVELOPE: params._envelope is required for authenticated calls",
    );
  }
  if (typeof envelope !== "object") {
    throw new RpcError(-32010, "AITHOS_BAD_ENVELOPE: _envelope must be an object");
  }

  // Strip _envelope so the params_hash check covers only the business payload.
  const { _envelope, ...businessParams } = input.rawParams as {
    _envelope: unknown;
  } & Record<string, unknown>;
  void _envelope;

  // HOTFIX-A2a-RESOLVER — `_subject_sphere_pubkeys` extension
  // ─────────────────────────────────────────────────────────
  // Callers (e.g. Linkedone backend signing delegate-path envelopes
  // on behalf of a custodial did:aithos user) can pass the user's 4
  // real sphere pubkeys via this params extension to enable mandate
  // signature verification — the PDS's local did:aithos synthesis
  // alone cannot recover per-sphere pubkeys (it only has the root
  // pubkey from the multibase). The field IS part of params_hash (so
  // it's covered by the envelope signature, can't be tampered with by
  // a passive attacker), but we read it BEFORE running verifyEnvelope
  // to wire up the resolver — the verifier will then re-hash params
  // with the field included and find a match.
  //
  // Defense: extracted value must be a plain object whose 4 keys are
  // multibase strings; anything else is silently ignored (the call
  // falls back to plain did:aithos synthesis, which is fine for
  // owner-path-#root envelopes and only fails for mandates as before).
  //
  // TODO retire once Aithos has a real did:aithos HTTP registry
  // resolver (audit MEDIUM "did:aithos resolver stubbed").
  const subjectDid =
    typeof (envelope as { iss?: unknown }).iss === "string"
      ? ((envelope as { iss: string }).iss)
      : null;
  const rawSphereKeys = businessParams._subject_sphere_pubkeys;
  const enrichedResolver =
    subjectDid &&
    subjectDid.startsWith("did:aithos:") &&
    rawSphereKeys !== undefined &&
    rawSphereKeys !== null &&
    typeof rawSphereKeys === "object"
      ? withSphereOverride(
          resolveIssuerDoc,
          subjectDid,
          rawSphereKeys as Partial<
            Record<"root" | "public" | "circle" | "self", unknown>
          >,
        )
      : resolveIssuerDoc;

  const ctx: VerifyEnvelopeContext = {
    expectedAud: input.expectedAud,
    expectedMethod: input.method,
    params: businessParams,
    resolveIssuerDoc: enrichedResolver,
    findRevocation: async (mandateId) => {
      const rev = await findRevocation(mandateId);
      if (!rev) return null;
      // Project to the Revocation shape the verifier expects. The
      // verifier reads only `revoked_at` and `reason` from this object,
      // so the other fields are placeholders that satisfy the type.
      return {
        "aithos-revocation": "0.1.0",
        mandate_id: mandateId,
        issuer: "",
        issued_by_key: "",
        revoked_at: rev.revoked_at,
        reason: rev.reason ?? "revoked",
        signature: { alg: "ed25519", key: "", value: "" },
      } as unknown as Awaited<ReturnType<NonNullable<VerifyEnvelopeContext["findRevocation"]>>>;
    },
    replay: replayCache,
  };

  const result = await verifyEnvelope(envelope as SignedEnvelope, ctx);
  if (!result.ok) {
    throw new RpcError(result.error.code, result.error.message, result.error.data);
  }

  const mandateId = result.mandateId;
  const mandate = (envelope as SignedEnvelope).mandate;
  const mode: "owner" | "delegate" = mandateId ? "delegate" : "owner";

  // Strip the HOTFIX-A2a-RESOLVER extension from the params we hand to
  // handlers — it was used for sig verification and has no business
  // meaning. Keeps handlers ignorant of this transitional plumbing.
  const { _subject_sphere_pubkeys: _hotfixStripped, ...handlerParams } =
    businessParams as Record<string, unknown>;
  void _hotfixStripped;

  return {
    subjectDid: result.issuer,
    mode,
    ...(mandateId ? { mandateId } : {}),
    ...(mandate ? { mandate, mandateScopes: mandate.scopes } : {}),
    signerPubkeyMultibase: ed25519PublicKeyToMultibase(result.signerKey),
    envelopeNonce: (envelope as SignedEnvelope).nonce,
    params: handlerParams,
  };
}

/**
 * Enforce that a mandate-bearing caller has a scope covering the requested
 * action on a specific collection.
 *
 * For owner mode this is a no-op (the owner has all scopes implicitly).
 *
 * For delegate mode, looks for a scope matching one of:
 *   - `data.<collection>.<action>` — exact collection match
 *   - `data.*.<action>`              — wildcard collection
 *   - `data.<collection>.admin`      — admin implies write implies read
 *
 * Throws RpcError(-32042, AITHOS_INSUFFICIENT_SCOPE) on miss.
 */
export function requireScope(
  caller: Caller,
  collectionName: string,
  action: "read" | "write" | "admin",
): void {
  if (caller.mode === "owner") return;

  const scopes = caller.mandateScopes ?? [];
  const needed: string[] = [];
  needed.push(`data.${collectionName}.${action}`);
  needed.push(`data.*.${action}`);
  if (action === "read" || action === "write") {
    needed.push(`data.${collectionName}.admin`);
    needed.push(`data.*.admin`);
  }
  if (action === "read") {
    needed.push(`data.${collectionName}.write`);
    needed.push(`data.*.write`);
  }

  // The mandate's scopes may carry filter suffixes — see spec §4.2.3.
  // Filter enforcement on the payload itself is done by handlers; here
  // we only check that the base scope is present.
  const has = scopes.some((s) => {
    // Strip filter suffix `.<key>:<value>` for the base comparison.
    const base = s.split(".").slice(0, 3).join(".");
    return needed.includes(base);
  });

  if (!has) {
    throw new RpcError(
      -32042,
      `AITHOS_INSUFFICIENT_SCOPE: mandate does not grant data.${collectionName}.${action}`,
      { required: needed, granted: scopes },
    );
  }
}

/**
 * Confirm that the caller is operating on their own subject (owner mode)
 * OR that the mandate was issued by the target subject (delegate mode).
 *
 * Throws RpcError(-32042) when a caller tries to operate on a subject
 * that isn't them and that didn't grant them a mandate.
 */
export function requireSubjectMatch(
  caller: Caller,
  targetSubjectDid: string,
): void {
  if (caller.subjectDid !== targetSubjectDid) {
    throw new RpcError(
      -32042,
      `AITHOS_INSUFFICIENT_SCOPE: envelope iss (${caller.subjectDid}) does not match target subject (${targetSubjectDid})`,
    );
  }
}
