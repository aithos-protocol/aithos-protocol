// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Unit tests for pure modules of the assets-backend that have no AWS
 * dependency. Covers:
 *   - URN composition + parsing
 *   - DynamoDB key helpers
 *   - Purge GSI shard sharding determinism
 *   - Error code mapping
 *   - Media-type allow-list logic
 *
 * AWS-bound integration tests live in `test-e2e/` and require a
 * deployed stack to run.
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";

import {
  urnForAsset,
  parseAssetUrn,
  pkForSubject,
  skForAsset,
  gsi1pkForSubject,
  gsi1skForSha,
  gsi2pkForPurge,
  gsi2skForLastReferencedAt,
  s3KeyForAsset,
} from "../lambda/ddb.js";

import { isMediaTypeAllowed } from "../lambda/media-types.js";

import { pickEnvelope } from "../lambda/handlers/uploads.js";

import {
  notFound,
  invalidParams,
  hashMismatch,
  quotaExceeded,
  sizeCapExceeded,
  mediaTypeRejected,
  stillReferenced,
  uploadNotFound,
  AITHOS_NOT_FOUND,
  AITHOS_ASSETS_QUOTA_EXCEEDED,
  AITHOS_ASSETS_HASH_MISMATCH,
} from "../lambda/errors.js";

/* -------------------------------------------------------------------------- */
/*  URN roundtrip                                                              */
/* -------------------------------------------------------------------------- */

describe("URN composition and parsing", () => {
  it("composes and parses a typical URN", () => {
    const did = "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9";
    const id = "asset_01J9YB2X7Q1K3P4R5S6T7U8V9W";
    const urn = urnForAsset(did, id);
    assert.equal(urn, `urn:aithos:asset:${did}:${id}`);
    const parsed = parseAssetUrn(urn);
    assert.deepEqual(parsed, { subjectDid: did, assetId: id });
  });

  it("parses URNs with colons inside the DID (did:aithos:…)", () => {
    const urn = "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J9";
    const parsed = parseAssetUrn(urn);
    assert.equal(parsed?.subjectDid, "did:aithos:z6Mkr…");
    assert.equal(parsed?.assetId, "asset_01J9");
  });

  it("returns null on malformed URNs", () => {
    assert.equal(parseAssetUrn("not-a-urn"), null);
    assert.equal(parseAssetUrn("urn:aithos:something:bad"), null);
    assert.equal(parseAssetUrn("urn:aithos:asset:just-the-did"), null);
  });
});

/* -------------------------------------------------------------------------- */
/*  DDB key helpers                                                            */
/* -------------------------------------------------------------------------- */

describe("DDB key helpers", () => {
  it("pk format is subj#<did>", () => {
    assert.equal(pkForSubject("did:key:abc"), "subj#did:key:abc");
  });

  it("sk format is asset#<id>", () => {
    assert.equal(skForAsset("asset_01J"), "asset#asset_01J");
  });

  it("gsi1 keys bind subject and lowercased sha256", () => {
    assert.equal(gsi1pkForSubject("did:key:abc"), "subj#did:key:abc");
    assert.equal(
      gsi1skForSha("ABCDEF" + "0".repeat(58)),
      "sha256#abcdef" + "0".repeat(58),
    );
  });

  it("purge GSI shards are stable and bounded", () => {
    const shards = new Set<string>();
    for (let i = 0; i < 50; i++) {
      shards.add(gsi2pkForPurge(`asset_X${i.toString(16)}`));
    }
    // We sharded into at most 8 buckets per the helper.
    assert.ok(shards.size <= 8);
    assert.ok(shards.size >= 2); // randomness from ULIDs covers multiple shards
  });

  it("purge GSI SK preserves chronological order by ISO timestamp", () => {
    const a = gsi2skForLastReferencedAt("2026-01-01T00:00:00Z", "asset_A");
    const b = gsi2skForLastReferencedAt("2026-06-01T00:00:00Z", "asset_B");
    assert.ok(a < b);
  });

  it("S3 key contains subject and asset_id with raw.bin suffix", () => {
    const key = s3KeyForAsset("did:key:abc", "asset_01J");
    assert.equal(key, "did:key:abc/asset_01J/raw.bin");
  });
});

/* -------------------------------------------------------------------------- */
/*  Media type allow-list                                                      */
/* -------------------------------------------------------------------------- */

describe("Media-type allow-list", () => {
  it("allows standard image and document types", () => {
    assert.ok(isMediaTypeAllowed("image/png"));
    assert.ok(isMediaTypeAllowed("image/jpeg"));
    assert.ok(isMediaTypeAllowed("application/pdf"));
    assert.ok(isMediaTypeAllowed("text/markdown"));
    assert.ok(isMediaTypeAllowed("video/mp4"));
  });

  it("rejects active-content media types", () => {
    assert.ok(!isMediaTypeAllowed("text/html"));
    assert.ok(!isMediaTypeAllowed("application/javascript"));
    assert.ok(!isMediaTypeAllowed("text/javascript"));
    assert.ok(!isMediaTypeAllowed("application/x-shockwave-flash"));
  });

  it("rejects unknown / unsupported types", () => {
    assert.ok(!isMediaTypeAllowed("application/x-custom-format"));
    assert.ok(!isMediaTypeAllowed(""));
  });
});

/* -------------------------------------------------------------------------- */
/*  Error code constructors                                                    */
/* -------------------------------------------------------------------------- */

describe("Error constructors", () => {
  it("notFound carries AITHOS_NOT_FOUND code", () => {
    const e = notFound();
    assert.equal(e.code, AITHOS_NOT_FOUND);
    assert.equal(e.code, -32020);
  });

  it("hashMismatch carries the expected/observed pair in data", () => {
    const e = hashMismatch("expected_hash", "observed_hash");
    assert.equal(e.code, AITHOS_ASSETS_HASH_MISMATCH);
    assert.equal(e.code, -32030);
    assert.deepEqual(e.data, { expected: "expected_hash", observed: "observed_hash" });
  });

  it("quotaExceeded carries used/limit in data", () => {
    const e = quotaExceeded(6_000_000_000, 5_368_709_120);
    assert.equal(e.code, AITHOS_ASSETS_QUOTA_EXCEEDED);
    assert.equal(e.code, -32038);
    assert.deepEqual(e.data, {
      used_bytes: 6_000_000_000,
      limit_bytes: 5_368_709_120,
    });
  });

  it("sizeCapExceeded carries declared/cap", () => {
    const e = sizeCapExceeded(200_000_000, 100_000_000);
    assert.equal(e.code, -32037);
    assert.deepEqual(e.data, {
      declared_bytes: 200_000_000,
      cap_bytes: 100_000_000,
    });
  });

  it("mediaTypeRejected carries the offending media type", () => {
    const e = mediaTypeRejected("text/html");
    assert.equal(e.code, -32036);
    assert.deepEqual(e.data, { media_type: "text/html" });
  });

  it("stillReferenced reports the current count", () => {
    const e = stillReferenced(3);
    assert.equal(e.code, -32033);
    assert.deepEqual(e.data, { reference_count: 3 });
  });

  it("uploadNotFound mentions the session", () => {
    const e = uploadNotFound("upl_xyz");
    assert.equal(e.code, -32032);
    assert.ok(e.message.includes("upl_xyz"));
  });

  it("invalidParams uses standard JSON-RPC -32602", () => {
    const e = invalidParams("foo is required");
    assert.equal(e.code, -32602);
    assert.equal(e.message, "foo is required");
  });
});

/* -------------------------------------------------------------------------- */
/*  pickEnvelope — complete_upload AMK envelope selection                     */
/* -------------------------------------------------------------------------- */

describe("pickEnvelope (complete_upload AMK envelope selection)", () => {
  const placeholder = {
    alg: "xchacha20poly1305-ietf",
    nonce: "",
    wraps: [],
  };
  const real = {
    alg: "xchacha20poly1305-ietf",
    nonce: "AAAA",
    wraps: [
      {
        kid: "did:key:z6Mk…#kex",
        epk: "AAAA",
        ct: "BBBB",
        recipient: "did:key:z6Mk…",
      },
    ],
  };

  it("prefers the complete-time envelope when it has non-empty wraps", () => {
    assert.deepEqual(pickEnvelope(real, placeholder), real);
  });

  it("falls back to init-time envelope when complete-time wraps[] is empty", () => {
    // Legacy SDK only sends amk_envelope at init.
    assert.deepEqual(pickEnvelope(undefined, placeholder), placeholder);
    // Complete-time wraps explicitly empty → still fall back.
    assert.deepEqual(pickEnvelope(placeholder, placeholder), placeholder);
  });

  it("falls back to init-time envelope when complete-time is missing", () => {
    assert.deepEqual(pickEnvelope(undefined, real), real);
    assert.deepEqual(pickEnvelope(null, real), real);
  });

  it("returns undefined when neither envelope is provided", () => {
    assert.equal(pickEnvelope(undefined, undefined), undefined);
    assert.equal(pickEnvelope(undefined, null), undefined);
    assert.equal(pickEnvelope(null, null), undefined);
  });

  it("ignores non-object inputs", () => {
    // Strings, numbers, arrays without `wraps` field → treated as no
    // envelope.
    assert.equal(pickEnvelope("not-an-envelope", undefined), undefined);
    assert.equal(pickEnvelope(42, undefined), undefined);
    assert.equal(pickEnvelope([], undefined), undefined);
  });
});
