/**
 * Tests for signed-envelope helpers — spec §11.
 *
 * Every envelope-verification step in §11.4 is exercised at least once: schema,
 * audience, method, TTL, params_hash, signer-resolution, signature, replay.
 * A second set of tests covers the mandate path (§11.6) and the root-only
 * rules of §11.7.
 *
 * Tests construct keys + DID documents in-memory rather than going through the
 * filesystem-backed keystore — `envelope.ts` is pure logic and has no disk
 * side-effects, so `freshKeystore()` is not required here.
 */
import { describe, test, beforeEach } from "node:test";
import { strict as assert } from "node:assert";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

// @noble/ed25519 v2 needs an explicit sync SHA-512 hook before `ed.sign`
// / `ed.verify` can be called synchronously. This is a per-process setup.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

import {
  signEnvelope,
  signEnvelopeWithMandate,
  verifyEnvelope,
  envelopeParamsHash,
  ENVELOPE_VERSION,
  ROOT_ONLY_DIRECT_METHODS,
  NEVER_DELEGABLE_METHODS,
  type SignedEnvelope,
  type EnvelopeReplayCache,
  type VerifyEnvelopeContext,
} from "../src/envelope.ts";
import {
  createMandate,
  type Mandate,
} from "../src/mandate.ts";
import {
  ed25519PublicKeyToMultibase,
  didAithosForRootKey,
} from "../src/did.ts";
import type { DidDocument, Identity } from "../src/identity.ts";

/* -------------------------------------------------------------------------- */
/*  In-memory fixtures                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Build a minimal Identity + DidDocument in-memory. Enough keys to sign
 * envelopes and issue mandates; no disk touch.
 */
function makeSubject(): {
  identity: Identity;
  didDoc: DidDocument;
  sphereVm: (sphere: "public" | "circle" | "self" | "root") => string;
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
  const sphereVm = (s: "public" | "circle" | "self" | "root") => `${did}#${s}`;

  // Only the fields envelope.ts reads (id, verificationMethod). The full
  // Identity / DidDocument types are larger, but the verifier doesn't touch
  // the other fields.
  const didDoc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [
      {
        id: sphereVm("root"),
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: ed25519PublicKeyToMultibase(rootPk),
      },
      {
        id: sphereVm("public"),
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: ed25519PublicKeyToMultibase(publicPk),
      },
      {
        id: sphereVm("circle"),
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: ed25519PublicKeyToMultibase(circlePk),
      },
      {
        id: sphereVm("self"),
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: ed25519PublicKeyToMultibase(selfPk),
      },
    ],
    keyAgreement: [],
    aithos: {
      version: "0.1.0",
      created_at: new Date().toISOString(),
      rotated: [],
    },
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

  return { identity, didDoc, sphereVm };
}

/** In-memory replay cache: a plain Set. */
function makeReplay(): EnvelopeReplayCache & { seen: Set<string> } {
  const seen = new Set<string>();
  return {
    seen,
    async putIfAbsent(key: string, _expiresAt: number) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

/** Build a verification context backed by a single-subject resolver. */
function ctxFor(
  didDoc: DidDocument,
  method: string,
  params: unknown,
  overrides: Partial<VerifyEnvelopeContext> = {},
): VerifyEnvelopeContext {
  return {
    expectedAud: "https://api.test.invalid/mcp/primitives/write",
    expectedMethod: method,
    params,
    nowSeconds: Math.floor(Date.now() / 1000),
    resolveIssuerDoc: async (iss) => (iss === didDoc.id ? didDoc : null),
    replay: makeReplay(),
    ...overrides,
  };
}

/* -------------------------------------------------------------------------- */
/*  Happy path                                                                */
/* -------------------------------------------------------------------------- */

describe("signEnvelope + verifyEnvelope — direct sphere-key signing", () => {
  test("happy path: sign with #public, verify, resolve issuer + signerKey", async () => {
    const { identity, didDoc, sphereVm } = makeSubject();
    const params = { handle: "alice", zone: "public" };

    const env = signEnvelope({
      iss: didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_ethos_edition",
      params,
      sphereKey: {
        seed: identity.public.seed,
        verificationMethod: sphereVm("public"),
      },
    });

    const ctx = ctxFor(didDoc, "aithos.publish_ethos_edition", params);
    const res = await verifyEnvelope(env, ctx);

    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.issuer, didDoc.id);
      assert.equal(res.mandateId, undefined);
      assert.equal(res.signerKey.byteLength, 32);
    }
  });

  test("envelope shape matches §11.2", () => {
    const { identity, didDoc, sphereVm } = makeSubject();
    const env = signEnvelope({
      iss: didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_ethos_edition",
      params: { x: 1 },
      sphereKey: {
        seed: identity.public.seed,
        verificationMethod: sphereVm("public"),
      },
    });
    assert.equal(env["aithos-envelope"], ENVELOPE_VERSION);
    assert.equal(env.iss, didDoc.id);
    assert.ok(env.params_hash.startsWith("sha256-"));
    assert.equal(env.params_hash, envelopeParamsHash({ x: 1 }));
    assert.equal(env.proof.type, "Ed25519Signature2020");
    assert.equal(env.proof.verificationMethod, sphereVm("public"));
    assert.equal(typeof env.proof.proofValue, "string");
    assert.ok(env.proof.proofValue.length > 0);
    assert.ok(env.exp - env.iat === 60);
  });
});

/* -------------------------------------------------------------------------- */
/*  §11.4 — per-step failure modes                                            */
/* -------------------------------------------------------------------------- */

describe("verifyEnvelope — §11.4 failure modes", () => {
  function signBasic(
    params: unknown = { x: 1 },
    opts: {
      aud?: string;
      method?: string;
      nonce?: string;
      now?: Date;
      ttlSeconds?: number;
    } = {},
  ) {
    const { identity, didDoc, sphereVm } = makeSubject();
    const env = signEnvelope({
      iss: didDoc.id,
      aud: opts.aud ?? "https://api.test.invalid/mcp/primitives/write",
      method: opts.method ?? "aithos.publish_ethos_edition",
      params,
      sphereKey: {
        seed: identity.public.seed,
        verificationMethod: sphereVm("public"),
      },
      nonce: opts.nonce,
      now: opts.now,
      ttlSeconds: opts.ttlSeconds,
    });
    return { env, didDoc };
  }

  test("step 1 — schema: wrong aithos-envelope version → -32010", async () => {
    const { env, didDoc } = signBasic();
    const mutated = { ...env, "aithos-envelope": "0.2.0" as "0.1.0" };
    const res = await verifyEnvelope(mutated, ctxFor(didDoc, env.method, { x: 1 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32010);
  });

  test("step 2 — audience mismatch → -32010", async () => {
    const { env, didDoc } = signBasic();
    const ctx = ctxFor(didDoc, env.method, { x: 1 }, {
      expectedAud: "https://api.other.invalid/mcp/primitives/write",
    });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32010);
  });

  test("step 2 — aud normalization: trailing slash and host case → accepted", async () => {
    const { env, didDoc } = signBasic();
    const ctx = ctxFor(didDoc, env.method, { x: 1 }, {
      expectedAud: "https://API.TEST.invalid/mcp/primitives/write/",
    });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, true);
  });

  test("step 3 — method mismatch → -32010", async () => {
    const { env, didDoc } = signBasic();
    const ctx = ctxFor(didDoc, "aithos.publish_mandate", { x: 1 });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32010);
  });

  test("step 4 — expired envelope → -32013", async () => {
    const { env, didDoc } = signBasic({ x: 1 }, { now: new Date(Date.now() - 600_000) });
    const res = await verifyEnvelope(env, ctxFor(didDoc, env.method, { x: 1 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32013);
  });

  test("step 4 — iat in the future beyond skew → -32013", async () => {
    const { env, didDoc } = signBasic({ x: 1 }, { now: new Date(Date.now() + 120_000) });
    const res = await verifyEnvelope(env, ctxFor(didDoc, env.method, { x: 1 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32013);
  });

  test("step 4 — tampered exp beyond 300s budget → -32013", async () => {
    const { env, didDoc } = signBasic();
    const mutated = { ...env, exp: env.iat + 600 };
    const res = await verifyEnvelope(mutated, ctxFor(didDoc, env.method, { x: 1 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32013);
  });

  test("step 5 — params_hash mismatch when server received different params → -32010", async () => {
    const { env, didDoc } = signBasic({ x: 1 });
    const res = await verifyEnvelope(env, ctxFor(didDoc, env.method, { x: 2 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32010);
  });

  test("step 6 — unknown issuer → -32011", async () => {
    const { env, didDoc } = signBasic();
    const ctx = ctxFor(didDoc, env.method, { x: 1 }, {
      resolveIssuerDoc: async () => null,
    });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32011);
  });

  test("step 6 — verificationMethod not in DID document → -32011", async () => {
    const { env, didDoc } = signBasic();
    const otherSubject = makeSubject();
    // Point the resolver at a different DID doc that doesn't contain our sphere key
    const ctx = ctxFor(didDoc, env.method, { x: 1 }, {
      resolveIssuerDoc: async () => ({ ...otherSubject.didDoc, id: didDoc.id }),
    });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32011);
  });

  test("step 7 — tampered signature → -32011", async () => {
    const { env, didDoc } = signBasic();
    const mutated: SignedEnvelope = {
      ...env,
      proof: { ...env.proof, proofValue: env.proof.proofValue.slice(0, -4) + "AAAA" },
    };
    const res = await verifyEnvelope(mutated, ctxFor(didDoc, env.method, { x: 1 }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32011);
  });

  test("step 8 — replay: second verify with same nonce → -32012", async () => {
    const { env, didDoc } = signBasic();
    const replay = makeReplay();
    const ctx1 = ctxFor(didDoc, env.method, { x: 1 }, { replay });
    const ctx2 = ctxFor(didDoc, env.method, { x: 1 }, { replay });
    const first = await verifyEnvelope(env, ctx1);
    assert.equal(first.ok, true);
    const second = await verifyEnvelope(env, ctx2);
    assert.equal(second.ok, false);
    if (!second.ok) assert.equal(second.error.code, -32012);
  });

  test("replay cache outage fails closed → -32603", async () => {
    const { env, didDoc } = signBasic();
    const ctx = ctxFor(didDoc, env.method, { x: 1 }, {
      replay: {
        async putIfAbsent() {
          throw new Error("dynamodb unreachable");
        },
      },
    });
    const res = await verifyEnvelope(env, ctx);
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32603);
  });
});

/* -------------------------------------------------------------------------- */
/*  §11.7 — root-only direct signing                                          */
/* -------------------------------------------------------------------------- */

describe("root-only direct methods (§11.7)", () => {
  test("publish_identity signed with #public → -32011", async () => {
    const { identity, didDoc, sphereVm } = makeSubject();
    const env = signEnvelope({
      iss: didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_identity",
      params: { did: didDoc.id },
      sphereKey: {
        seed: identity.public.seed,
        verificationMethod: sphereVm("public"),
      },
    });
    const res = await verifyEnvelope(env, ctxFor(didDoc, "aithos.publish_identity", { did: didDoc.id }));
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32011);
  });

  test("publish_identity signed with #root → accepted", async () => {
    const { identity, didDoc, sphereVm } = makeSubject();
    const env = signEnvelope({
      iss: didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_identity",
      params: { did: didDoc.id },
      sphereKey: {
        seed: identity.root.seed,
        verificationMethod: sphereVm("root"),
      },
    });
    const res = await verifyEnvelope(env, ctxFor(didDoc, "aithos.publish_identity", { did: didDoc.id }));
    assert.equal(res.ok, true);
  });

  test("ROOT_ONLY_DIRECT_METHODS set matches spec §11.7", () => {
    assert.ok(ROOT_ONLY_DIRECT_METHODS.has("aithos.publish_identity"));
    assert.ok(ROOT_ONLY_DIRECT_METHODS.has("aithos.rotate_sphere_key"));
    assert.ok(ROOT_ONLY_DIRECT_METHODS.has("aithos.publish_tombstone"));
  });
});

/* -------------------------------------------------------------------------- */
/*  §11.6 — delegate path under a mandate                                     */
/* -------------------------------------------------------------------------- */

describe("signEnvelopeWithMandate — delegate path (§11.6)", () => {
  function mintDelegateMandate(subject: ReturnType<typeof makeSubject>) {
    const delegateSeed = Uint8Array.from(randomBytes(32));
    const delegatePk = ed.getPublicKey(delegateSeed);
    const delegateMb = ed25519PublicKeyToMultibase(delegatePk);

    const mandate = createMandate({
      issuer: subject.identity,
      actorSphere: "public",
      grantee: {
        id: "urn:aithos:agent:test",
        pubkey: delegateMb,
      },
      scopes: ["ethos.write.public"],
      ttlSeconds: 24 * 60 * 60, // 1 day
    });

    return { delegateSeed, delegateMb, mandate };
  }

  test("happy path: delegate-signed envelope, mandate verified, mandateId returned", async () => {
    const subject = makeSubject();
    const { delegateSeed, delegateMb, mandate } = mintDelegateMandate(subject);

    const env = signEnvelopeWithMandate({
      iss: subject.didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_ethos_edition",
      params: { zone: "public", section: "s1" },
      delegateKey: { seed: delegateSeed, pubkeyMultibase: delegateMb },
      mandate,
    });

    const res = await verifyEnvelope(
      env,
      ctxFor(subject.didDoc, "aithos.publish_ethos_edition", {
        zone: "public",
        section: "s1",
      }),
    );
    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.issuer, subject.didDoc.id);
      assert.equal(res.mandateId, mandate.id);
    }
  });

  test("never-delegable method with mandate → -32042", async () => {
    const subject = makeSubject();
    const { delegateSeed, delegateMb, mandate } = mintDelegateMandate(subject);

    const env = signEnvelopeWithMandate({
      iss: subject.didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_identity",
      params: { did: subject.didDoc.id },
      delegateKey: { seed: delegateSeed, pubkeyMultibase: delegateMb },
      mandate,
    });

    const res = await verifyEnvelope(
      env,
      ctxFor(subject.didDoc, "aithos.publish_identity", { did: subject.didDoc.id }),
    );
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32042);
  });

  test("mandate issuer mismatch with envelope.iss → -32040", async () => {
    const subject = makeSubject();
    const attacker = makeSubject();
    const { delegateSeed, delegateMb, mandate } = mintDelegateMandate(subject);

    const env = signEnvelopeWithMandate({
      iss: attacker.didDoc.id, // wrong — should be subject
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_ethos_edition",
      params: { x: 1 },
      delegateKey: { seed: delegateSeed, pubkeyMultibase: delegateMb },
      mandate,
    });

    // Resolver knows the attacker's DID too, to make the check reach the
    // mandate step rather than fail at issuer resolution.
    const res = await verifyEnvelope(env, {
      expectedAud: "https://api.test.invalid/mcp/primitives/write",
      expectedMethod: "aithos.publish_ethos_edition",
      params: { x: 1 },
      resolveIssuerDoc: async (iss) =>
        iss === subject.didDoc.id
          ? subject.didDoc
          : iss === attacker.didDoc.id
            ? attacker.didDoc
            : null,
      replay: makeReplay(),
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32040);
  });

  test("delegate key mismatch with mandate.grantee.pubkey → -32040", async () => {
    const subject = makeSubject();
    const { mandate } = mintDelegateMandate(subject);
    const wrongSeed = Uint8Array.from(randomBytes(32));
    const wrongMb = ed25519PublicKeyToMultibase(ed.getPublicKey(wrongSeed));

    // Build the envelope by hand so we can put the wrong VM in `proof`
    // while keeping `mandate.grantee.pubkey` pointing at the original key.
    // signEnvelopeWithMandate itself refuses this combination at sign time.
    assert.throws(() =>
      signEnvelopeWithMandate({
        iss: subject.didDoc.id,
        aud: "https://api.test.invalid/mcp/primitives/write",
        method: "aithos.publish_ethos_edition",
        params: { x: 1 },
        delegateKey: { seed: wrongSeed, pubkeyMultibase: wrongMb },
        mandate,
      }),
    );
  });

  test("revoked mandate → -32041", async () => {
    const subject = makeSubject();
    const { delegateSeed, delegateMb, mandate } = mintDelegateMandate(subject);

    const env = signEnvelopeWithMandate({
      iss: subject.didDoc.id,
      aud: "https://api.test.invalid/mcp/primitives/write",
      method: "aithos.publish_ethos_edition",
      params: { x: 1 },
      delegateKey: { seed: delegateSeed, pubkeyMultibase: delegateMb },
      mandate,
    });

    const res = await verifyEnvelope(env, {
      expectedAud: "https://api.test.invalid/mcp/primitives/write",
      expectedMethod: "aithos.publish_ethos_edition",
      params: { x: 1 },
      resolveIssuerDoc: async () => subject.didDoc,
      findRevocation: async (id) =>
        id === mandate.id
          ? {
              "aithos-revocation": "0.1.0",
              mandate_id: mandate.id,
              issuer: mandate.issuer,
              issued_by_key: mandate.issued_by_key,
              revoked_at: new Date().toISOString(),
              reason: "test-revoked",
              signature: { alg: "ed25519", key: mandate.issued_by_key, value: "" },
            }
          : null,
      replay: makeReplay(),
    });
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.error.code, -32041);
  });

  test("NEVER_DELEGABLE_METHODS set matches spec §11.6", () => {
    assert.ok(NEVER_DELEGABLE_METHODS.has("aithos.publish_identity"));
    assert.ok(NEVER_DELEGABLE_METHODS.has("aithos.rotate_sphere_key"));
    // publish_tombstone IS delegable (via scope identity.tombstone)
    assert.equal(NEVER_DELEGABLE_METHODS.has("aithos.publish_tombstone"), false);
  });
});

/* -------------------------------------------------------------------------- */
/*  Misc                                                                      */
/* -------------------------------------------------------------------------- */

describe("envelopeParamsHash — canonicalization", () => {
  test("hash is stable under key reordering (RFC 8785)", () => {
    const a = envelopeParamsHash({ a: 1, b: 2, c: 3 });
    const b = envelopeParamsHash({ c: 3, a: 1, b: 2 });
    assert.equal(a, b);
  });

  test("hash changes when a nested value changes", () => {
    const a = envelopeParamsHash({ x: { y: 1 } });
    const b = envelopeParamsHash({ x: { y: 2 } });
    assert.notEqual(a, b);
  });

  test("hash output format: sha256- + 64 lowercase hex chars", () => {
    const h = envelopeParamsHash({ x: 1 });
    assert.match(h, /^sha256-[0-9a-f]{64}$/);
  });
});
