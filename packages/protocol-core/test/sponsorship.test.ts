// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Tests for `SponsorshipMandate` and `ConsumptionReceipt` — draft §13.
 *
 * Round-trips sign+verify, exercises the eligibility decision tree, and checks
 * that tampering with any byte invalidates the signature. Like envelope.test,
 * these tests build keys + DID documents in memory — `sponsorship.ts` is pure
 * logic and never touches the filesystem.
 */
import { describe, test } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

import {
  createSponsorshipMandate,
  verifySponsorshipMandate,
  sponsorshipMandateHash,
  createConsumptionReceipt,
  verifyConsumptionReceipt,
  createSponsorshipRevocation,
  evaluateEligibility,
  SPONSORSHIP_MANDATE_VERSION_CURRENT,
  CONSUMPTION_RECEIPT_VERSION_CURRENT,
  type SponsorshipMandate,
  type SponsorshipUsageSnapshot,
} from "../src/sponsorship.ts";
import {
  ed25519PublicKeyToMultibase,
  didAithosForRootKey,
} from "../src/did.ts";
import type { DidDocument, Identity } from "../src/identity.ts";

/* -------------------------------------------------------------------------- */
/*  In-memory subject builder                                                 */
/* -------------------------------------------------------------------------- */

function makeSubject(): {
  identity: Identity;
  didDoc: DidDocument;
  vm: (sphere: "public" | "circle" | "self" | "root") => string;
} {
  const rootSeed = Uint8Array.from(randomBytes(32));
  const publicSeed = Uint8Array.from(randomBytes(32));
  const circleSeed = Uint8Array.from(randomBytes(32));
  const selfSeed = Uint8Array.from(randomBytes(32));

  const rootPk = ed.getPublicKey(rootSeed);
  const publicPk = ed.getPublicKey(publicSeed);
  const circlePk = ed.getPublicKey(circleSeed);
  const selfPk = ed.getPublicKey(selfSeed);

  const did = didAithosForRootKey(rootPk);
  const vm = (s: "public" | "circle" | "self" | "root") => `${did}#${s}`;

  const didDoc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      { id: vm("root"), type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: ed25519PublicKeyToMultibase(rootPk) },
      { id: vm("public"), type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: ed25519PublicKeyToMultibase(publicPk) },
      { id: vm("circle"), type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: ed25519PublicKeyToMultibase(circlePk) },
      { id: vm("self"), type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: ed25519PublicKeyToMultibase(selfPk) },
    ],
    keyAgreement: [],
    aithos: { version: "0.1.0", created_at: new Date().toISOString(), rotated: [] },
  } as unknown as DidDocument;

  const identity = {
    handle: "test",
    root: { seed: rootSeed, publicKey: rootPk },
    public: { seed: publicSeed, publicKey: publicPk },
    circle: { seed: circleSeed, publicKey: circlePk },
    self: { seed: selfSeed, publicKey: selfPk },
    didDocument: didDoc,
    tracked: false,
  } as unknown as Identity;

  return { identity, didDoc, vm };
}

function makeBudget() {
  return {
    unit: "aithos.mc",
    per_user_cap: 2000,
    per_user_window_seconds: null,
    per_day_total_cap: 50_000,
    pool_cap_total: 100_000,
  };
}

function makeAuthority() {
  return { did: "did:aithos:compute-authority-v1", endpoint: "https://compute.aithos.be" };
}

/* -------------------------------------------------------------------------- */
/*  SponsorshipMandate                                                        */
/* -------------------------------------------------------------------------- */

describe("createSponsorshipMandate + verifySponsorshipMandate", () => {
  test("happy path: round-trip sign and verify", () => {
    const sponsor = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      allowedModels: ["claude-haiku-4-5"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });

    assert.equal(m["aithos-sponsorship-mandate"], SPONSORSHIP_MANDATE_VERSION_CURRENT);
    assert.match(m.id, /^spons_[0-9A-Z]+$/);
    assert.equal(m.issuer, sponsor.didDoc.id);
    assert.equal(m.issued_by_key, sponsor.vm("public"));

    const res = verifySponsorshipMandate(m, sponsor.didDoc);
    assert.deepEqual(res.errors, []);
    assert.equal(res.ok, true);
  });

  test("signature is bound to the canonical bytes — tampering rejected", () => {
    const sponsor = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });

    const tampered: SponsorshipMandate = {
      ...m,
      budget: { ...m.budget, per_user_cap: 99_999_999 },
    };
    const res = verifySponsorshipMandate(tampered, sponsor.didDoc);
    assert.equal(res.ok, false);
    assert.ok(res.errors.some((e) => e.includes("signature verification failed")));
  });

  test("wrong issuer DID document is rejected", () => {
    const sponsor = makeSubject();
    const otherSubject = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    const res = verifySponsorshipMandate(m, otherSubject.didDoc);
    assert.equal(res.ok, false);
    assert.ok(res.errors.some((e) => e.includes("does not match did document")));
  });

  test("expired mandate fails verify (now > not_after)", () => {
    const sponsor = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 60,
    });
    const future = new Date(Date.now() + 120 * 1000);
    const res = verifySponsorshipMandate(m, sponsor.didDoc, { now: future });
    assert.equal(res.ok, false);
    assert.ok(res.errors.some((e) => e.includes("expired")));
  });

  test("not_yet_valid (now < not_before) fails verify", () => {
    const sponsor = makeSubject();
    const future = new Date(Date.now() + 3600 * 1000);
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      notBefore: future,
      ttlSeconds: 60,
    });
    const res = verifySponsorshipMandate(m, sponsor.didDoc);
    assert.equal(res.ok, false);
    assert.ok(res.errors.some((e) => e.includes("not yet valid")));
  });

  test("audience_set=list with empty consumers throws at create time", () => {
    const sponsor = makeSubject();
    assert.throws(
      () =>
        createSponsorshipMandate({
          issuer: sponsor.identity,
          audience: { app_did: "did:aithos:dev-app-X", audience_set: "list", consumers: [] },
          scopes: ["compute.invoke"],
          allowedMethods: ["aithos.compute_invoke"],
          budget: makeBudget(),
          accountingAuthority: makeAuthority(),
          ttlSeconds: 60,
        }),
      /consumers MUST be a non-empty array/,
    );
  });

  test("audience_set=open with consumers throws at create time", () => {
    const sponsor = makeSubject();
    assert.throws(
      () =>
        createSponsorshipMandate({
          issuer: sponsor.identity,
          audience: { app_did: "did:aithos:dev-app-X", audience_set: "open", consumers: ["did:aithos:foo"] },
          scopes: ["compute.invoke"],
          allowedMethods: ["aithos.compute_invoke"],
          budget: makeBudget(),
          accountingAuthority: makeAuthority(),
          ttlSeconds: 60,
        }),
      /consumers MUST be absent/,
    );
  });

  test("negative budget caps rejected", () => {
    const sponsor = makeSubject();
    assert.throws(
      () =>
        createSponsorshipMandate({
          issuer: sponsor.identity,
          audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
          scopes: ["compute.invoke"],
          allowedMethods: ["aithos.compute_invoke"],
          budget: { ...makeBudget(), per_user_cap: -1 },
          accountingAuthority: makeAuthority(),
          ttlSeconds: 60,
        }),
      /per_user_cap must be a non-negative integer/,
    );
  });

  test("sponsorshipMandateHash is deterministic and changes on any byte tamper", () => {
    const sponsor = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    const h1 = sponsorshipMandateHash(m);
    const h2 = sponsorshipMandateHash(m);
    assert.equal(h1, h2);
    assert.match(h1, /^sha256:[0-9a-f]{64}$/);

    const tampered: SponsorshipMandate = {
      ...m,
      budget: { ...m.budget, per_user_cap: 9999 },
    };
    const h3 = sponsorshipMandateHash(tampered);
    assert.notEqual(h1, h3);
  });
});

/* -------------------------------------------------------------------------- */
/*  ConsumptionReceipt                                                        */
/* -------------------------------------------------------------------------- */

describe("createConsumptionReceipt + verifyConsumptionReceipt", () => {
  function makeSponsoredReceiptInputs() {
    const sponsor = makeSubject();
    const consumer = makeSubject();
    const authority = makeSubject();
    const mandate = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    return { sponsor, consumer, authority, mandate };
  }

  test("happy path: sponsored receipt round-trips sign+verify", () => {
    const { sponsor, consumer, authority, mandate } = makeSponsoredReceiptInputs();
    const r = createConsumptionReceipt({
      authority: authority.identity,
      sponsorshipId: mandate.id,
      sponsorshipHash: sponsorshipMandateHash(mandate),
      sponsorDid: sponsor.didDoc.id,
      consumerDid: consumer.didDoc.id,
      appDid: "did:aithos:dev-app-X",
      method: "aithos.compute_invoke",
      envelopeNonce: "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
      envelopeHash: "sha256:" + "e5".padEnd(64, "0"),
      fundedBy: "sponsored",
      amount: 47,
      unit: "aithos.mc",
      ledgerAfter: {
        user_consumed_lifetime: 47,
        user_consumed_window: null,
        user_cap_remaining: 1953,
        pool_consumed_lifetime: 47,
        pool_consumed_today: 47,
      },
    });

    assert.equal(r["aithos-consumption-receipt"], CONSUMPTION_RECEIPT_VERSION_CURRENT);
    assert.equal(r.funded_by, "sponsored");
    assert.equal(r.amount, 47);
    assert.equal(r.issued_by, authority.didDoc.id);

    const res = verifyConsumptionReceipt(r, authority.didDoc);
    assert.deepEqual(res.errors, []);
    assert.equal(res.ok, true);
  });

  test("fallback receipt (purchase) has no sponsor fields", () => {
    const consumer = makeSubject();
    const authority = makeSubject();
    const r = createConsumptionReceipt({
      authority: authority.identity,
      sponsorshipId: null,
      sponsorshipHash: null,
      sponsorDid: null,
      consumerDid: consumer.didDoc.id,
      appDid: "did:aithos:dev-app-X",
      method: "aithos.compute_invoke",
      envelopeNonce: "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
      envelopeHash: "sha256:" + "e5".padEnd(64, "0"),
      fundedBy: "purchase",
      amount: 47,
      unit: "aithos.mc",
    });

    assert.equal(r.funded_by, "purchase");
    assert.equal(r.sponsorship_id, null);
    assert.equal(r.sponsor_did, null);
    const res = verifyConsumptionReceipt(r, authority.didDoc);
    assert.deepEqual(res.errors, []);
  });

  test("sponsored receipt missing sponsor_did is rejected at create", () => {
    const { consumer, authority, mandate } = makeSponsoredReceiptInputs();
    assert.throws(
      () =>
        createConsumptionReceipt({
          authority: authority.identity,
          sponsorshipId: mandate.id,
          sponsorshipHash: sponsorshipMandateHash(mandate),
          sponsorDid: null, // ← missing
          consumerDid: consumer.didDoc.id,
          appDid: "did:aithos:dev-app-X",
          method: "aithos.compute_invoke",
          envelopeNonce: "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
          envelopeHash: "sha256:" + "00".padEnd(64, "0"),
          fundedBy: "sponsored",
          amount: 47,
          unit: "aithos.mc",
        }),
      /sponsored receipts MUST carry sponsorship_id/,
    );
  });

  test("tampering with amount invalidates signature", () => {
    const { sponsor, consumer, authority, mandate } = makeSponsoredReceiptInputs();
    const r = createConsumptionReceipt({
      authority: authority.identity,
      sponsorshipId: mandate.id,
      sponsorshipHash: sponsorshipMandateHash(mandate),
      sponsorDid: sponsor.didDoc.id,
      consumerDid: consumer.didDoc.id,
      appDid: "did:aithos:dev-app-X",
      method: "aithos.compute_invoke",
      envelopeNonce: "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
      envelopeHash: "sha256:" + "e5".padEnd(64, "0"),
      fundedBy: "sponsored",
      amount: 47,
      unit: "aithos.mc",
    });
    const tampered = { ...r, amount: 9999 };
    const res = verifyConsumptionReceipt(tampered, authority.didDoc);
    assert.equal(res.ok, false);
    assert.ok(res.errors.some((e) => e.includes("signature verification failed")));
  });

  test("non-zero, non-integer amount rejected", () => {
    const authority = makeSubject();
    const consumer = makeSubject();
    assert.throws(
      () =>
        createConsumptionReceipt({
          authority: authority.identity,
          sponsorshipId: null,
          sponsorshipHash: null,
          sponsorDid: null,
          consumerDid: consumer.didDoc.id,
          appDid: "did:aithos:dev-app-X",
          method: "aithos.compute_invoke",
          envelopeNonce: "01J7VV6Q9GZX9XX4N7B0V8YQRJ",
          envelopeHash: "sha256:" + "00".padEnd(64, "0"),
          fundedBy: "purchase",
          amount: 0.5,
          unit: "aithos.mc",
        }),
      /amount must be an integer/,
    );
  });
});

/* -------------------------------------------------------------------------- */
/*  Sponsorship revocation                                                    */
/* -------------------------------------------------------------------------- */

describe("createSponsorshipRevocation", () => {
  test("revocation carries mandate_kind=sponsorship-mandate", () => {
    const sponsor = makeSubject();
    const m = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    const r = createSponsorshipRevocation({
      issuer: sponsor.identity,
      mandate: m,
      reason: "superseded",
    });
    assert.equal(r.mandate_id, m.id);
    assert.equal(r.mandate_kind, "sponsorship-mandate");
    assert.equal(r.issuer, sponsor.didDoc.id);
    assert.equal(r.reason, "superseded");
    assert.equal(r.signature.alg, "ed25519");
    assert.ok(r.signature.value.length > 0);
  });
});

/* -------------------------------------------------------------------------- */
/*  Eligibility                                                               */
/* -------------------------------------------------------------------------- */

describe("evaluateEligibility", () => {
  function setup(): {
    mandate: SponsorshipMandate;
    consumerDid: string;
    usage: SponsorshipUsageSnapshot;
  } {
    const sponsor = makeSubject();
    const consumer = makeSubject();
    const mandate = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: { app_did: "did:aithos:dev-app-X", audience_set: "open" },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      allowedModels: ["claude-haiku-4-5"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    return {
      mandate,
      consumerDid: consumer.didDoc.id,
      usage: {
        consumerConsumedLifetime: 0,
        poolConsumedToday: 0,
        poolConsumedLifetime: 0,
        sponsorWalletBalance: 100_000,
      },
    };
  }

  test("ok when all caps respected", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 47,
      usage,
    });
    assert.deepEqual(d, { ok: true, reason: "ok" });
  });

  test("method_blocked when method not in allowed_methods", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke_image",
      estimatedAmount: 47,
      usage,
    });
    assert.equal(d.reason, "method_blocked");
    assert.equal(d.ok, false);
  });

  test("model_blocked when model not in allowed_models", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-opus-4-7",
      estimatedAmount: 47,
      usage,
    });
    assert.equal(d.reason, "model_blocked");
  });

  test("per_user_cap_reached when adding estimate would exceed cap", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 1,
      usage: { ...usage, consumerConsumedLifetime: 2000 },
    });
    assert.equal(d.reason, "per_user_cap_reached");
  });

  test("per_day_cap_reached", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 1,
      usage: { ...usage, poolConsumedToday: 50_000 },
    });
    assert.equal(d.reason, "per_day_cap_reached");
  });

  test("pool_cap_reached", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 1,
      usage: { ...usage, poolConsumedLifetime: 100_000 },
    });
    assert.equal(d.reason, "pool_cap_reached");
  });

  test("wallet_insufficient when sponsor balance < estimate", () => {
    const { mandate, consumerDid, usage } = setup();
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 47,
      usage: { ...usage, sponsorWalletBalance: 10 },
    });
    assert.equal(d.reason, "wallet_insufficient");
  });

  test("expired when now > not_after", () => {
    const { mandate, consumerDid, usage } = setup();
    const future = new Date(Date.now() + 90_000 * 1000); // > 1 day
    const d = evaluateEligibility({
      mandate,
      consumerDid,
      method: "aithos.compute_invoke",
      model: "claude-haiku-4-5",
      estimatedAmount: 1,
      usage,
      now: future,
    });
    assert.equal(d.reason, "expired");
  });

  test("audience_excluded when audience_set=list and consumer not listed", () => {
    const sponsor = makeSubject();
    const allowed = makeSubject();
    const stranger = makeSubject();
    const mandate = createSponsorshipMandate({
      issuer: sponsor.identity,
      audience: {
        app_did: "did:aithos:dev-app-X",
        audience_set: "list",
        consumers: [allowed.didDoc.id],
      },
      scopes: ["compute.invoke"],
      allowedMethods: ["aithos.compute_invoke"],
      budget: makeBudget(),
      accountingAuthority: makeAuthority(),
      ttlSeconds: 86_400,
    });
    const usage: SponsorshipUsageSnapshot = {
      consumerConsumedLifetime: 0,
      poolConsumedToday: 0,
      poolConsumedLifetime: 0,
      sponsorWalletBalance: 100_000,
    };
    const d = evaluateEligibility({
      mandate,
      consumerDid: stranger.didDoc.id,
      method: "aithos.compute_invoke",
      estimatedAmount: 1,
      usage,
    });
    assert.equal(d.reason, "audience_excluded");

    const dOk = evaluateEligibility({
      mandate,
      consumerDid: allowed.didDoc.id,
      method: "aithos.compute_invoke",
      estimatedAmount: 1,
      usage,
    });
    assert.equal(dOk.ok, true);
  });
});
