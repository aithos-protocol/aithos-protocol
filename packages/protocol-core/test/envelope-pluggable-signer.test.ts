// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Conformance: the pluggable async signer (`signEnvelopeWith`) MUST produce
 * byte-identical wire output to the seed-based `signEnvelope` /
 * `signEnvelopeWithMandate` for identical input. This is the guarantee that
 * lets the Aithos SDK migrate its bespoke `signOwnerEnvelope` onto this module
 * (sharing one canonicalization) without changing a single byte on the wire —
 * the server keeps accepting the same envelopes.
 */
import { describe, test } from "node:test";
import { strict as assert } from "node:assert";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import {
  signEnvelope,
  signEnvelopeWith,
  buildUnsignedEnvelope,
  envelopeSigningBytes,
  attachProof,
} from "../src/envelope.ts";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const SEED = new Uint8Array(32).fill(7);
const NOW = new Date("2026-05-31T12:00:00.000Z");
const NONCE = "01J0CONFORMANCE000000000000";
const ISS = "did:aithos:z6MkConformanceTestSubject";
const VM = `${ISS}#public`;

const common = {
  iss: ISS,
  aud: "https://api.aithos.be/mcp/primitives/write",
  method: "aithos.data.insert_record",
  // Deliberately unsorted keys + nesting to exercise canonicalization.
  params: { b: 2, a: 1, nested: { y: [3, 1, 2], x: "z" } },
  ttlSeconds: 60,
  now: NOW,
  nonce: NONCE,
};

describe("signEnvelopeWith — pluggable async signer conformance", () => {
  test("owner path: byte-identical to seed-based signEnvelope", async () => {
    const viaSeed = signEnvelope({
      ...common,
      sphereKey: { seed: SEED, verificationMethod: VM },
    });
    const viaAsync = await signEnvelopeWith({
      ...common,
      verificationMethod: VM,
      sign: async (bytes) => ed.sign(bytes, SEED),
    });
    assert.deepEqual(viaAsync, viaSeed);
    assert.equal(JSON.stringify(viaAsync), JSON.stringify(viaSeed));
  });

  test("sync sign callback is also accepted", async () => {
    const viaSeed = signEnvelope({
      ...common,
      sphereKey: { seed: SEED, verificationMethod: VM },
    });
    const viaSync = await signEnvelopeWith({
      ...common,
      verificationMethod: VM,
      sign: (bytes) => ed.sign(bytes, SEED), // returns Uint8Array, not a Promise
    });
    assert.equal(JSON.stringify(viaSync), JSON.stringify(viaSeed));
  });

  test("buildUnsignedEnvelope + envelopeSigningBytes + attachProof compose to the same result", async () => {
    const viaSeed = signEnvelope({
      ...common,
      sphereKey: { seed: SEED, verificationMethod: VM },
    });
    const unsigned = buildUnsignedEnvelope({
      ...common,
      verificationMethod: VM,
      mandate: undefined,
      sponsorship: undefined,
    });
    assert.equal(unsigned.proof.proofValue, "");
    const sig = ed.sign(envelopeSigningBytes(unsigned), SEED);
    const signed = attachProof(unsigned, sig);
    assert.equal(JSON.stringify(signed), JSON.stringify(viaSeed));
  });

  test("produces a non-empty base64url proofValue", async () => {
    const env = await signEnvelopeWith({
      ...common,
      verificationMethod: VM,
      sign: async (bytes) => ed.sign(bytes, SEED),
    });
    assert.equal(env.proof.proofValue.length, 86); // 64-byte Ed25519 sig, base64url, no padding
    assert.match(env.proof.proofValue, /^[A-Za-z0-9_-]+$/);
  });
});
