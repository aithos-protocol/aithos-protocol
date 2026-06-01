// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Sponsorship mandates and consumption receipts — draft §13.
 *
 * Implements `spec/drafts/sponsorship-mandate-v0.1.md`. Defines two new signed
 * objects:
 *
 *   - `SponsorshipMandate` — signed by a sponsor declaring the budget it will
 *     absorb for operations performed by consumers within explicit scope.
 *   - `ConsumptionReceipt` — signed by an accounting authority on every debit,
 *     binding sponsor, consumer, envelope, and amount into a single signed
 *     attestation.
 *
 * In addition, this module exposes a pure eligibility function used by an
 * authority's routing decision: `evaluateEligibility(input)` returns whether
 * a candidate sponsorship may cover a given envelope under the current usage
 * snapshot, and why if not.
 *
 * This module is pure logic — no filesystem, no network. Storage of mandates,
 * receipts, and the consumption ledger is the responsibility of the authority
 * implementation (see the platform compute-proxy).
 *
 * **NOT YET NORMATIVE.** Until §13 of the spec is promoted from draft, this
 * module's API is experimental and may change.
 */

import * as ed from "@noble/ed25519";
import { randomBytes } from "node:crypto";
import { ulid } from "ulid";

import { canonicalize } from "./canonical.js";
import {
  base64url,
  base64urlDecode,
  sha256Hex,
  type Identity,
  type DidDocument,
} from "./identity.js";
import {
  multibaseToEd25519PublicKey,
  signWithSphere,
  sphereDidUrl,
  rootDid,
} from "./did.js";
import type { Sphere } from "./did.js";
import type { Revocation, VerifyResult } from "./mandate.js";

/* -------------------------------------------------------------------------- */
/*  Versions                                                                  */
/* -------------------------------------------------------------------------- */

export const SPONSORSHIP_MANDATE_VERSION_CURRENT = "0.1.0" as const;
export const CONSUMPTION_RECEIPT_VERSION_CURRENT = "0.1.0" as const;

export type SponsorshipMandateVersion = "0.1.0";
export type ConsumptionReceiptVersion = "0.1.0";

/* -------------------------------------------------------------------------- */
/*  SponsorshipMandate                                                        */
/* -------------------------------------------------------------------------- */

export type AudienceSet = "open" | "list";

export interface SponsorshipAudience {
  app_did: string;
  audience_set: AudienceSet;
  /** REQUIRED iff `audience_set === "list"`. Each entry is a consumer DID. */
  consumers?: readonly string[];
}

/**
 * Budget object — see §13.3.4. All caps are denominated in `unit`. A `null`
 * cap means "no cap of this kind"; the authority falls through to the next
 * constraint.
 */
export interface SponsorshipBudget {
  unit: string;
  per_user_cap: number;
  /** If non-null, `per_user_cap` is enforced over this sliding window. */
  per_user_window_seconds: number | null;
  per_day_total_cap: number;
  /** If non-null, lifetime cap on total sponsored consumption across all consumers. */
  pool_cap_total: number | null;
}

export interface AccountingAuthority {
  did: string;
  endpoint: string;
}

export interface SponsorshipMandate {
  "aithos-sponsorship-mandate": SponsorshipMandateVersion;
  id: string;
  issuer: string;
  issued_by_key: string;
  audience: SponsorshipAudience;
  scopes: readonly string[];
  allowed_methods: readonly string[];
  allowed_models?: readonly string[];
  budget: SponsorshipBudget;
  accounting_authority: AccountingAuthority;
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

export interface CreateSponsorshipMandateArgs {
  /** Sponsor identity. Signs the mandate. */
  issuer: Identity;
  /** Which sphere key signs. Conventionally `"public"` since the mandate is publicly resolvable. */
  sphere?: Sphere;
  audience: SponsorshipAudience;
  scopes: readonly string[];
  allowedMethods: readonly string[];
  allowedModels?: readonly string[];
  budget: SponsorshipBudget;
  accountingAuthority: AccountingAuthority;
  /** Defaults to now. */
  notBefore?: Date;
  ttlSeconds: number;
}

export function createSponsorshipMandate(
  args: CreateSponsorshipMandateArgs,
): SponsorshipMandate {
  validateBudget(args.budget);
  validateAudience(args.audience);
  if (args.scopes.length === 0) throw new Error("scopes must be non-empty");
  if (args.allowedMethods.length === 0)
    throw new Error("allowed_methods must be non-empty");
  if (args.allowedModels !== undefined && args.allowedModels.length === 0) {
    throw new Error(
      "allowed_models, if provided, must be non-empty (omit to allow any model)",
    );
  }

  const sphere: Sphere = args.sphere ?? "public";
  const nb = args.notBefore ?? new Date();
  const na = new Date(nb.getTime() + args.ttlSeconds * 1000);
  if (na <= nb) {
    throw new Error("not_after must be strictly after not_before");
  }
  const nonce = base64url(randomBytes(9)); // 72 bits of entropy

  const unsigned: SponsorshipMandate = {
    "aithos-sponsorship-mandate": SPONSORSHIP_MANDATE_VERSION_CURRENT,
    id: `spons_${ulid()}`,
    issuer: rootDid(args.issuer),
    issued_by_key: sphereDidUrl(args.issuer, sphere),
    audience: args.audience,
    scopes: args.scopes,
    allowed_methods: args.allowedMethods,
    ...(args.allowedModels ? { allowed_models: args.allowedModels } : {}),
    budget: args.budget,
    accounting_authority: args.accountingAuthority,
    not_before: nb.toISOString(),
    not_after: na.toISOString(),
    issued_at: new Date().toISOString(),
    nonce,
    signature: {
      alg: "ed25519",
      key: sphereDidUrl(args.issuer, sphere),
      value: "",
    },
  };

  const sig = signWithSphere(
    args.issuer,
    sphere,
    new TextEncoder().encode(canonicalize(unsigned)),
  );
  unsigned.signature.value = base64url(sig);
  return unsigned;
}

export interface VerifySponsorshipMandateOptions {
  /** Defaults to `new Date()`. */
  now?: Date;
}

/**
 * Verify a sponsorship mandate's structure, signature, and time window against
 * the sponsor's DID document. Does NOT consult a revocation list — caller
 * provides that separately, exactly as for action mandates (§4.7).
 */
export function verifySponsorshipMandate(
  mandate: SponsorshipMandate,
  sponsorDidDoc: DidDocument,
  options: VerifySponsorshipMandateOptions = {},
): VerifyResult {
  const errors: string[] = [];
  const now = options.now ?? new Date();

  if (
    mandate["aithos-sponsorship-mandate"] !==
    SPONSORSHIP_MANDATE_VERSION_CURRENT
  ) {
    errors.push(
      `Unsupported sponsorship-mandate version: ${mandate["aithos-sponsorship-mandate"]}`,
    );
  }

  if (mandate.issuer !== sponsorDidDoc.id) {
    errors.push(
      `issuer ${mandate.issuer} does not match did document ${sponsorDidDoc.id}`,
    );
  }

  try {
    validateBudget(mandate.budget);
  } catch (e) {
    errors.push((e as Error).message);
  }
  try {
    validateAudience(mandate.audience);
  } catch (e) {
    errors.push((e as Error).message);
  }

  if (!mandate.scopes || mandate.scopes.length === 0) {
    errors.push("scopes must be non-empty");
  }
  if (!mandate.allowed_methods || mandate.allowed_methods.length === 0) {
    errors.push("allowed_methods must be non-empty");
  }

  const nb = new Date(mandate.not_before);
  const na = new Date(mandate.not_after);
  if (Number.isNaN(nb.getTime()) || Number.isNaN(na.getTime())) {
    errors.push("not_before/not_after must be RFC-3339 dates");
  } else {
    if (na <= nb) errors.push("not_after must be strictly after not_before");
    if (now < nb)
      errors.push(
        `Sponsorship not yet valid (not_before=${mandate.not_before})`,
      );
    if (now >= na)
      errors.push(`Sponsorship has expired (not_after=${mandate.not_after})`);
  }

  const vm = sponsorDidDoc.verificationMethod.find(
    (v) => v.id === mandate.issued_by_key,
  );
  if (!vm) {
    errors.push(`No verificationMethod for ${mandate.issued_by_key}`);
    return { ok: false, errors };
  }

  try {
    const toVerify: SponsorshipMandate = {
      ...mandate,
      signature: { ...mandate.signature, value: "" },
    };
    const bytes = new TextEncoder().encode(canonicalize(toVerify));
    const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    const sig = base64urlDecode(mandate.signature.value);
    if (!ed.verify(sig, bytes, pk)) {
      errors.push("Sponsorship-mandate signature verification failed");
    }
  } catch (e) {
    errors.push(`Signature check errored: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Canonical hash of a sponsorship mandate, with `signature.value` cleared.
 *
 * This is the value an envelope's `sponsorship.hash` and a receipt's
 * `sponsorship_hash` MUST commit to. Tampering with any byte of the mandate
 * shifts the hash and breaks subsequent verification.
 */
export function sponsorshipMandateHash(mandate: SponsorshipMandate): string {
  const blank: SponsorshipMandate = {
    ...mandate,
    signature: { ...mandate.signature, value: "" },
  };
  const bytes = new TextEncoder().encode(canonicalize(blank));
  // `sha256Hex` already prefixes the result with `"sha256:"`.
  return sha256Hex(bytes);
}

/* -------------------------------------------------------------------------- */
/*  ConsumptionReceipt                                                        */
/* -------------------------------------------------------------------------- */

export type FundedBy = "sponsored" | "purchase" | "grant";

/**
 * Optional snapshot of relevant counters after the debit. Useful for clients
 * that want to display remaining quota without a separate roundtrip.
 *
 * `user_consumed_window`, `user_cap_remaining`, and `pool_consumed_lifetime`
 * MAY be null when the relevant constraint is not applicable (e.g. no window
 * configured, or fallback receipt with no sponsorship in scope).
 */
export interface LedgerAfter {
  user_consumed_lifetime: number;
  user_consumed_window: number | null;
  user_cap_remaining: number | null;
  pool_consumed_lifetime: number | null;
  pool_consumed_today: number;
}

export interface ConsumptionReceipt {
  "aithos-consumption-receipt": ConsumptionReceiptVersion;
  id: string;
  /** Populated iff funded_by === "sponsored". */
  sponsorship_id: string | null;
  sponsorship_hash: string | null;
  sponsor_did: string | null;
  consumer_did: string;
  app_did: string;
  method: string;
  envelope_nonce: string;
  envelope_hash: string;
  funded_by: FundedBy;
  amount: number;
  unit: string;
  ledger_after?: LedgerAfter;
  timestamp: string;
  issued_by: string;
  issued_by_key: string;
  signature: {
    alg: "ed25519";
    key: string;
    value: string;
  };
}

export interface CreateConsumptionReceiptArgs {
  /** The authority's own identity. Signs the receipt. */
  authority: Identity;
  /** Which sphere of the authority signs. Defaults to `"public"`. */
  authoritySphere?: Sphere;
  sponsorshipId: string | null;
  sponsorshipHash: string | null;
  sponsorDid: string | null;
  consumerDid: string;
  appDid: string;
  method: string;
  envelopeNonce: string;
  envelopeHash: string;
  fundedBy: FundedBy;
  amount: number;
  unit: string;
  ledgerAfter?: LedgerAfter;
  timestamp?: Date;
}

export function createConsumptionReceipt(
  args: CreateConsumptionReceiptArgs,
): ConsumptionReceipt {
  if (!Number.isFinite(args.amount) || args.amount <= 0) {
    throw new Error("amount must be a positive number");
  }
  if (!Number.isInteger(args.amount)) {
    throw new Error("amount must be an integer (unit is implementation-defined; receipts are integral)");
  }
  if (!args.unit || typeof args.unit !== "string") {
    throw new Error("unit must be a non-empty string");
  }
  if (!args.consumerDid || !args.appDid || !args.method) {
    throw new Error("consumerDid, appDid, and method are required");
  }
  if (!args.envelopeNonce || !args.envelopeHash) {
    throw new Error("envelopeNonce and envelopeHash are required");
  }

  if (args.fundedBy === "sponsored") {
    if (!args.sponsorshipId || !args.sponsorshipHash || !args.sponsorDid) {
      throw new Error(
        "sponsored receipts MUST carry sponsorship_id, sponsorship_hash, and sponsor_did",
      );
    }
  } else {
    if (args.sponsorshipId || args.sponsorshipHash || args.sponsorDid) {
      throw new Error(
        "non-sponsored receipts MUST NOT carry sponsorship_id, sponsorship_hash, or sponsor_did",
      );
    }
  }

  const sphere: Sphere = args.authoritySphere ?? "public";

  const unsigned: ConsumptionReceipt = {
    "aithos-consumption-receipt": CONSUMPTION_RECEIPT_VERSION_CURRENT,
    id: `rcpt_${ulid()}`,
    sponsorship_id: args.sponsorshipId,
    sponsorship_hash: args.sponsorshipHash,
    sponsor_did: args.sponsorDid,
    consumer_did: args.consumerDid,
    app_did: args.appDid,
    method: args.method,
    envelope_nonce: args.envelopeNonce,
    envelope_hash: args.envelopeHash,
    funded_by: args.fundedBy,
    amount: args.amount,
    unit: args.unit,
    ...(args.ledgerAfter ? { ledger_after: args.ledgerAfter } : {}),
    timestamp: (args.timestamp ?? new Date()).toISOString(),
    issued_by: rootDid(args.authority),
    issued_by_key: sphereDidUrl(args.authority, sphere),
    signature: {
      alg: "ed25519",
      key: sphereDidUrl(args.authority, sphere),
      value: "",
    },
  };

  const sig = signWithSphere(
    args.authority,
    sphere,
    new TextEncoder().encode(canonicalize(unsigned)),
  );
  unsigned.signature.value = base64url(sig);
  return unsigned;
}

/**
 * Verify a consumption receipt against the authority's DID document.
 *
 * The verifier checks: schema, version, internal consistency (sponsored vs
 * fallback fields), `issued_by`/`issued_by_key` match, and the Ed25519
 * signature against the authority's published public key.
 *
 * It does NOT cross-check against the original sponsorship mandate (that
 * requires fetching the mandate via §13.3.6 URLs). Callers that need full
 * end-to-end verification SHOULD fetch the mandate by `sponsorship_id`, verify
 * the mandate per `verifySponsorshipMandate`, recompute its hash via
 * `sponsorshipMandateHash`, and compare to `receipt.sponsorship_hash`.
 */
export function verifyConsumptionReceipt(
  receipt: ConsumptionReceipt,
  authorityDidDoc: DidDocument,
): VerifyResult {
  const errors: string[] = [];

  if (
    receipt["aithos-consumption-receipt"] !==
    CONSUMPTION_RECEIPT_VERSION_CURRENT
  ) {
    errors.push(
      `Unsupported consumption-receipt version: ${receipt["aithos-consumption-receipt"]}`,
    );
  }

  if (receipt.issued_by !== authorityDidDoc.id) {
    errors.push(
      `issued_by ${receipt.issued_by} does not match authority did document ${authorityDidDoc.id}`,
    );
  }

  if (!Number.isInteger(receipt.amount) || receipt.amount <= 0) {
    errors.push("amount must be a positive integer");
  }

  const consistency = checkSponsoredConsistency(receipt);
  if (consistency) errors.push(consistency);

  const vm = authorityDidDoc.verificationMethod.find(
    (v) => v.id === receipt.issued_by_key,
  );
  if (!vm) {
    errors.push(`No verificationMethod for ${receipt.issued_by_key}`);
    return { ok: false, errors };
  }

  try {
    const toVerify: ConsumptionReceipt = {
      ...receipt,
      signature: { ...receipt.signature, value: "" },
    };
    const bytes = new TextEncoder().encode(canonicalize(toVerify));
    const pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
    const sig = base64urlDecode(receipt.signature.value);
    if (!ed.verify(sig, bytes, pk)) {
      errors.push("Consumption-receipt signature verification failed");
    }
  } catch (e) {
    errors.push(`Signature check errored: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors };
}

function checkSponsoredConsistency(r: ConsumptionReceipt): string | null {
  if (r.funded_by === "sponsored") {
    if (!r.sponsorship_id || !r.sponsorship_hash || !r.sponsor_did) {
      return "sponsored receipts MUST carry sponsorship_id, sponsorship_hash, and sponsor_did";
    }
  } else {
    if (r.sponsorship_id || r.sponsorship_hash || r.sponsor_did) {
      return "non-sponsored receipts MUST NOT carry sponsorship_id, sponsorship_hash, or sponsor_did";
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/*  Eligibility — pure routing decision                                       */
/* -------------------------------------------------------------------------- */

/**
 * Usage snapshot the authority MUST gather from its ledger before deciding
 * whether a sponsorship covers a call. All counters are in the mandate's
 * `budget.unit`.
 */
export interface SponsorshipUsageSnapshot {
  consumerConsumedLifetime: number;
  consumerConsumedWindow?: number;
  consumerWindowStartedAt?: Date;
  poolConsumedToday: number;
  poolConsumedLifetime: number;
  sponsorWalletBalance: number;
}

export type EligibilityReason =
  | "ok"
  | "expired"
  | "not_yet_valid"
  | "method_blocked"
  | "model_blocked"
  | "audience_excluded"
  | "per_user_cap_reached"
  | "per_user_window_cap_reached"
  | "per_day_cap_reached"
  | "pool_cap_reached"
  | "wallet_insufficient";

export interface EligibilityInput {
  mandate: SponsorshipMandate;
  consumerDid: string;
  method: string;
  /** Required iff the mandate carries `allowed_models`. */
  model?: string;
  estimatedAmount: number;
  usage: SponsorshipUsageSnapshot;
  /** Defaults to `new Date()`. */
  now?: Date;
}

export interface EligibilityDecision {
  ok: boolean;
  reason: EligibilityReason;
}

/**
 * Decide whether a sponsorship mandate can cover a given operation under the
 * current usage snapshot. Pure function — no side effects, no I/O.
 *
 * The authority calls this AFTER having verified the mandate's signature and
 * checked that it is not revoked. This function does not re-verify the
 * mandate; it only applies the scope and budget rules.
 *
 * Checks are evaluated in the order specified in §13.7 of the draft. The
 * first failing check determines the `reason`.
 */
export function evaluateEligibility(
  input: EligibilityInput,
): EligibilityDecision {
  const { mandate, consumerDid, method, model, estimatedAmount, usage } = input;
  const now = input.now ?? new Date();

  if (!Number.isInteger(estimatedAmount) || estimatedAmount <= 0) {
    throw new Error("estimatedAmount must be a positive integer");
  }

  const nb = new Date(mandate.not_before);
  const na = new Date(mandate.not_after);
  if (now < nb) return { ok: false, reason: "not_yet_valid" };
  if (now >= na) return { ok: false, reason: "expired" };

  if (!mandate.allowed_methods.includes(method)) {
    return { ok: false, reason: "method_blocked" };
  }
  if (model && mandate.allowed_models && !mandate.allowed_models.includes(model)) {
    return { ok: false, reason: "model_blocked" };
  }

  if (mandate.audience.audience_set === "list") {
    if (
      !mandate.audience.consumers ||
      !mandate.audience.consumers.includes(consumerDid)
    ) {
      return { ok: false, reason: "audience_excluded" };
    }
  }

  if (
    usage.consumerConsumedLifetime + estimatedAmount >
    mandate.budget.per_user_cap
  ) {
    return { ok: false, reason: "per_user_cap_reached" };
  }
  if (
    mandate.budget.per_user_window_seconds != null &&
    usage.consumerConsumedWindow != null
  ) {
    if (
      usage.consumerConsumedWindow + estimatedAmount >
      mandate.budget.per_user_cap
    ) {
      return { ok: false, reason: "per_user_window_cap_reached" };
    }
  }
  if (usage.poolConsumedToday + estimatedAmount > mandate.budget.per_day_total_cap) {
    return { ok: false, reason: "per_day_cap_reached" };
  }
  if (
    mandate.budget.pool_cap_total != null &&
    usage.poolConsumedLifetime + estimatedAmount >
      mandate.budget.pool_cap_total
  ) {
    return { ok: false, reason: "pool_cap_reached" };
  }
  if (usage.sponsorWalletBalance < estimatedAmount) {
    return { ok: false, reason: "wallet_insufficient" };
  }
  return { ok: true, reason: "ok" };
}

/* -------------------------------------------------------------------------- */
/*  Sponsorship revocation                                                    */
/* -------------------------------------------------------------------------- */

export interface RevokeSponsorshipArgs {
  /** Sponsor identity — must match `mandate.issuer`. */
  issuer: Identity;
  mandate: SponsorshipMandate;
  reason: string;
  revokedAt?: Date;
}

/**
 * Build a §4.6-style revocation document targeting a sponsorship mandate.
 *
 * The output reuses the existing `Revocation` shape with `mandate_kind` set
 * to `"sponsorship-mandate"`. Authorities MUST consult this list before
 * authorizing a sponsored debit (§13.9).
 */
export function createSponsorshipRevocation(
  args: RevokeSponsorshipArgs,
): Revocation {
  const revokedAt = (args.revokedAt ?? new Date()).toISOString();

  const issuedBy = args.mandate.issued_by_key;
  const match = issuedBy.match(/#(public|circle|self)$/);
  if (!match) {
    throw new Error(`Cannot determine sphere from issued_by_key: ${issuedBy}`);
  }
  const sphere = match[1] as Sphere;

  const unsigned: Revocation = {
    "aithos-revocation": "0.1.0",
    mandate_id: args.mandate.id,
    mandate_kind: "sponsorship-mandate",
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

/* -------------------------------------------------------------------------- */
/*  Validation helpers                                                        */
/* -------------------------------------------------------------------------- */

function validateBudget(b: SponsorshipBudget): void {
  if (!b.unit || typeof b.unit !== "string") {
    throw new Error("budget.unit must be a non-empty string");
  }
  if (!Number.isInteger(b.per_user_cap) || b.per_user_cap < 0) {
    throw new Error("budget.per_user_cap must be a non-negative integer");
  }
  if (b.per_user_window_seconds !== null) {
    if (
      !Number.isInteger(b.per_user_window_seconds) ||
      b.per_user_window_seconds <= 0
    ) {
      throw new Error(
        "budget.per_user_window_seconds must be null or a positive integer",
      );
    }
  }
  if (!Number.isInteger(b.per_day_total_cap) || b.per_day_total_cap < 0) {
    throw new Error("budget.per_day_total_cap must be a non-negative integer");
  }
  if (b.pool_cap_total !== null) {
    if (!Number.isInteger(b.pool_cap_total) || b.pool_cap_total < 0) {
      throw new Error(
        "budget.pool_cap_total must be null or a non-negative integer",
      );
    }
  }
}

function validateAudience(a: SponsorshipAudience): void {
  if (!a.app_did || typeof a.app_did !== "string") {
    throw new Error("audience.app_did must be a DID string");
  }
  if (a.audience_set === "open") {
    if (a.consumers !== undefined) {
      throw new Error(
        "audience.consumers MUST be absent when audience_set is 'open'",
      );
    }
  } else if (a.audience_set === "list") {
    if (!Array.isArray(a.consumers) || a.consumers.length === 0) {
      throw new Error(
        "audience.consumers MUST be a non-empty array when audience_set is 'list'",
      );
    }
  } else {
    throw new Error(
      `audience.audience_set must be 'open' or 'list' (got: ${a.audience_set as string})`,
    );
  }
}
