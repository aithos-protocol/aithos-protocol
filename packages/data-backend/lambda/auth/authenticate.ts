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
import type { DidDocument } from "@aithos/protocol-core/identity";

import { RpcError } from "../jsonrpc.js";
import { resolveIssuerDoc, invalidateDidCache } from "./did-resolver.js";
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
  /**
   * DID resolver a handler uses to verify a mandate or decode a DID
   * document. Resolves purely from the subject's published DID document
   * (or did:key synthesis) — never from caller-supplied key material.
   */
  readonly resolveIssuerDoc: (did: string) => Promise<DidDocument | null>;
}

interface AuthenticateInput {
  /** Raw JSON-RPC method (e.g. "aithos.data.insert_record"). */
  readonly method: string;
  /** Raw JSON-RPC params (still contains `_envelope`). */
  readonly rawParams: Record<string, unknown>;
  /**
   * Server-side audience URL(s) — what the envelope's `aud` field MUST
   * match. Built from the HTTP request URL. May be a single value or, during
   * the edge migration, a set of acceptable endpoints (vanity + origin host).
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
 * Run the spec §11.4 envelope-verification path on the incoming
 * params. Returns a `Caller`; throws RpcError on any failure.
 *
 * The router calls this BEFORE dispatching to a handler. Handlers
 * never see the raw envelope and never make their own auth checks.
 */
/**
 * Sphere lock for OWNER-mode data ops. The hole this closes: an Ethos sphere
 * key (#public/#circle/#self) writing data records. We therefore REJECT those
 * three spheres and allow everything else a verified envelope can carry:
 *   - #data  — the protocol-intended owner data key (the normal path);
 *   - #root  — the cold master (used by the legacy CMK migration / rotate_cmk);
 *   - a did:key canonical VM (#<multibase>) — throwaway demo identities.
 * The signature itself is already verified by verifyEnvelope; this is the
 * policy gate on WHICH sphere may sign data ops (spec/data/02-key-hierarchy.md).
 * Throws RpcError(-32012) on an Ethos-sphere signature.
 */
const ETHOS_SPHERES = new Set(["public", "circle", "self"]);
export function assertOwnerDataSphere(envelope: SignedEnvelope): void {
  const vm =
    (envelope as { proof?: { verificationMethod?: unknown } }).proof
      ?.verificationMethod;
  const vmStr = typeof vm === "string" ? vm : "";
  const hash = vmStr.lastIndexOf("#");
  const fragment = hash >= 0 ? vmStr.slice(hash + 1) : "";
  if (ETHOS_SPHERES.has(fragment)) {
    throw new RpcError(
      -32012,
      `AITHOS_WRONG_SPHERE: owner data operations cannot be signed under the ` +
        `Ethos sphere #${fragment}; use the #data sphere ` +
        `(auth.ownerDataClient() signs #data).`,
    );
  }
}

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

  // Dual-aud resolution. `expectedAud` may be a set of acceptable endpoints
  // (vanity + origin host) during the edge migration. protocol-core's
  // verifyEnvelope only compares against a single value, so we pick the
  // accepted candidate whose normalized form equals the envelope's `aud` and
  // hand THAT to the verifier (its step-2 check then trivially matches). If
  // none matches, we pass the first candidate so the canonical mismatch error
  // fires with a meaningful `expected`.
  const acceptedAud = Array.isArray(input.expectedAud)
    ? input.expectedAud
    : [input.expectedAud];
  const envAud = (envelope as { aud?: unknown }).aud;
  const matchedAud =
    typeof envAud === "string"
      ? acceptedAud.find((a) => normalizeAud(a) === normalizeAud(envAud))
      : undefined;

  const ctx: VerifyEnvelopeContext = {
    expectedAud: matchedAud ?? acceptedAud[0],
    expectedMethod: input.method,
    params: businessParams,
    resolveIssuerDoc,
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

  // B5 — kill-switch freshness: a delegate (mandate-bearing) call must see the
  // subject's CURRENT revocation epoch, so drop any cached did.json for the
  // issuer before verification re-fetches it. Owner calls keep the warm cache.
  if ((envelope as { mandate?: unknown }).mandate) {
    const iss = (envelope as { iss?: unknown }).iss;
    if (typeof iss === "string" && iss.length > 0) invalidateDidCache(iss);
  }

  const result = await verifyEnvelope(envelope as SignedEnvelope, ctx);
  if (!result.ok) {
    throw new RpcError(result.error.code, result.error.message, result.error.data);
  }

  const mandateId = result.mandateId;
  const mandate = (envelope as SignedEnvelope).mandate;
  const mode: "owner" | "delegate" = mandateId ? "delegate" : "owner";

  // M1 — sphere lock: owner data ops may NOT be signed under an Ethos sphere
  // (#public/#circle/#self); #data is the intended key (#root and did:key
  // canonical VMs are allowed). Delegate calls use a bare-multibase VM and are
  // governed by mandate scopes instead, so the check is owner-only.
  if (mode === "owner") {
    assertOwnerDataSphere(envelope as SignedEnvelope);
  }

  // Drop the legacy `_subject_sphere_pubkeys` field if a stale client still
  // sends it — it is no longer honoured (the resolver trusts only the
  // published DID document). Stripped so handlers never see it.
  const { _subject_sphere_pubkeys: _legacyStripped, ...handlerParams } =
    businessParams as Record<string, unknown>;
  void _legacyStripped;

  return {
    subjectDid: result.issuer,
    mode,
    ...(mandateId ? { mandateId } : {}),
    ...(mandate ? { mandate, mandateScopes: mandate.scopes } : {}),
    signerPubkeyMultibase: ed25519PublicKeyToMultibase(result.signerKey),
    envelopeNonce: (envelope as SignedEnvelope).nonce,
    params: handlerParams,
    resolveIssuerDoc,
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
 * The `"append"` action is the **lateral** insert-only capability. It is
 * satisfied by `data.<col>.append` (or wildcard), and ALSO by a `write` /
 * `admin` scope (those strictly include insert). Crucially, `append` is NOT
 * in the `needed` set of read/write/admin, so a pure-append mandate can
 * insert but can never read, list, update, or delete — it is never a write
 * scope. This makes the "deposit without read" invariant structural.
 *
 * Throws RpcError(-32042, AITHOS_INSUFFICIENT_SCOPE) on miss.
 */
export function requireScope(
  caller: Caller,
  collectionName: string,
  action: "read" | "write" | "admin" | "append",
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
  if (action === "append") {
    // Insert is also permitted by a full write/admin scope — those strictly
    // include the ability to add a record. (The reverse is NOT true: append
    // never satisfies read/write/admin.)
    needed.push(`data.${collectionName}.write`);
    needed.push(`data.*.write`);
    needed.push(`data.${collectionName}.admin`);
    needed.push(`data.*.admin`);
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
