// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Unit tests for the pure helpers behind aithos.data.register_schema
 * (A2b). The DDB-backed handler itself is exercised by the e2e suite
 * (test-e2e/schema-flow.mjs once extended) ; these tests pin the
 * shape-validation logic so a regression in the regex or structural
 * walker fails before deploy.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  VENDOR_SCHEMA_ID,
  SEMVER,
  validateSchemaDoc,
  canonicalSha256,
} from "../lambda/handlers/schemas.js";
import type { AithosSchema } from "../lambda/schemas/registry.js";

/* -------------------------------------------------------------------------- */
/*  VENDOR_SCHEMA_ID                                                          */
/* -------------------------------------------------------------------------- */

describe("VENDOR_SCHEMA_ID regex", () => {
  const accepts = [
    "aithos.x.linkedone.post.v1",
    "aithos.x.acme.invoice.v12",
    "aithos.x.a.b.v1",
    "aithos.x.vendor_with_underscore.name-with-dash.v1",
    "aithos.x.linkedone.post.v100",
  ];
  for (const id of accepts) {
    it(`accepts "${id}"`, () => {
      assert.equal(VENDOR_SCHEMA_ID.test(id), true);
    });
  }

  const rejects = [
    // Core namespace — must go through PR review.
    "aithos.contacts.v1",
    "aithos.messages.v1",
    // Missing x. infix.
    "aithos.vendor.name.v1",
    // Uppercase.
    "aithos.x.LinkedOne.post.v1",
    "aithos.x.linkedone.Post.v1",
    // No version.
    "aithos.x.linkedone.post",
    // v0 not allowed.
    "aithos.x.linkedone.post.v0",
    // Leading digit on vendor / name.
    "aithos.x.1vendor.post.v1",
    "aithos.x.vendor.1post.v1",
    // Different namespace prefix.
    "did:web:vendor.com:post.v1",
    "com.acme.post.v1",
    // Empty segments.
    "aithos.x..post.v1",
    "aithos.x.vendor..v1",
    // Trailing junk.
    "aithos.x.linkedone.post.v1.x",
  ];
  for (const id of rejects) {
    it(`rejects "${id}"`, () => {
      assert.equal(VENDOR_SCHEMA_ID.test(id), false);
    });
  }
});

/* -------------------------------------------------------------------------- */
/*  SEMVER                                                                    */
/* -------------------------------------------------------------------------- */

describe("SEMVER regex", () => {
  const accepts = [
    "0.0.0",
    "1.0.0",
    "10.20.30",
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-rc.1+build.5",
    "0.1.0-alpha.35",
  ];
  for (const v of accepts) {
    it(`accepts "${v}"`, () => {
      assert.equal(SEMVER.test(v), true);
    });
  }

  const rejects = [
    "",
    "1",
    "1.0",
    "01.0.0", // leading zero
    "1.0.0.0",
    "v1.0.0",
    "1.0.0-",
    "1.0.0+",
    "latest",
  ];
  for (const v of rejects) {
    it(`rejects "${v}"`, () => {
      assert.equal(SEMVER.test(v), false);
    });
  }
});

/* -------------------------------------------------------------------------- */
/*  validateSchemaDoc                                                          */
/* -------------------------------------------------------------------------- */

function validDoc(): AithosSchema {
  return {
    "aithos:schema": "aithos.x.linkedone.post.v1",
    "aithos:version": "1.0.0",
    title: "LinkedOne post",
    type: "object",
    additionalProperties: false,
    required: ["title"],
    properties: {
      title: {
        type: "string",
        minLength: 1,
        maxLength: 280,
        "aithos:indexable": true,
      },
      body: {
        type: "string",
        "aithos:encrypted": true,
      },
      created_at: {
        type: "string",
        format: "date-time",
        "aithos:indexable": true,
        "aithos:auto": "on_insert",
      },
    },
  };
}

describe("validateSchemaDoc", () => {
  it("accepts a well-formed vendor schema", () => {
    assert.equal(validateSchemaDoc(validDoc()), null);
  });

  it("rejects a top-level key the validator doesn't know", () => {
    const bad = { ...validDoc(), unknownKey: true } as unknown as AithosSchema;
    const err = validateSchemaDoc(bad);
    assert.match(err ?? "", /unsupported top-level key/);
  });

  it("rejects additionalProperties of non-boolean type", () => {
    const bad = {
      ...validDoc(),
      additionalProperties: "no" as unknown as boolean,
    } as AithosSchema;
    const err = validateSchemaDoc(bad);
    assert.match(err ?? "", /additionalProperties must be a boolean/);
  });

  it("rejects required[] containing a non-string", () => {
    const bad = {
      ...validDoc(),
      required: ["title", 42] as unknown as readonly string[],
    } as AithosSchema;
    const err = validateSchemaDoc(bad);
    assert.match(err ?? "", /required\[\] entries must be strings/);
  });

  it("rejects a field that is both indexable and encrypted", () => {
    const doc = validDoc();
    (doc.properties.title as Record<string, unknown>)["aithos:encrypted"] = true;
    const err = validateSchemaDoc(doc);
    assert.match(err ?? "", /both indexable and encrypted/);
  });

  it("rejects an aithos:auto with an unsupported lifecycle value", () => {
    const doc = validDoc();
    (doc.properties.created_at as Record<string, unknown>)["aithos:auto"] = "on_random";
    const err = validateSchemaDoc(doc);
    assert.match(err ?? "", /aithos:auto must be "on_insert" or "on_modify"/);
  });

  it("rejects a properties.* entry with an unsupported keyword", () => {
    const doc = validDoc();
    (doc.properties.title as Record<string, unknown>)["weirdKey"] = 1;
    const err = validateSchemaDoc(doc);
    assert.match(err ?? "", /properties\.title\.weirdKey is not a supported keyword/);
  });
});

/* -------------------------------------------------------------------------- */
/*  canonicalSha256 — idempotency                                              */
/* -------------------------------------------------------------------------- */

describe("canonicalSha256", () => {
  it("returns the same digest regardless of key order (JCS)", () => {
    const a = canonicalSha256({ b: 2, a: 1, c: [3, 4] });
    const b = canonicalSha256({ a: 1, c: [3, 4], b: 2 });
    assert.equal(a, b);
    assert.match(a, /^sha256:[0-9a-f]{64}$/);
  });

  it("returns DIFFERENT digests for semantically different docs", () => {
    const a = canonicalSha256({ x: 1 });
    const b = canonicalSha256({ x: 2 });
    assert.notEqual(a, b);
  });

  it("treats nested key reorderings as identical", () => {
    const a = canonicalSha256({ outer: { z: 1, a: 2 } });
    const b = canonicalSha256({ outer: { a: 2, z: 1 } });
    assert.equal(a, b);
  });

  it("is stable across array element order (arrays are ordered)", () => {
    const a = canonicalSha256({ tags: ["a", "b"] });
    const b = canonicalSha256({ tags: ["b", "a"] });
    assert.notEqual(a, b);
  });
});
