// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * Smoke test — proves the test runner picks up tests, imports work through
 * the tsx loader, and a fresh keystore can be created and torn down.
 */

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";

import { freshKeystore, cleanupKeystore } from "./helpers.ts";

test("freshKeystore creates an isolated directory and sets AITHOS_HOME", () => {
  const dir = freshKeystore();
  try {
    assert.equal(process.env.AITHOS_HOME, dir);
    assert.ok(existsSync(dir));
  } finally {
    cleanupKeystore(dir);
  }
});

test("core import resolves through tsx with a freshly-set keystore", async () => {
  const dir = freshKeystore();
  try {
    const core = await import("../src/index.js");
    assert.equal(typeof core.createIdentity, "function");
    assert.equal(typeof core.writeIdentityToDisk, "function");
    // AITHOS_HOME must be frozen to our tmp dir, not ~/.aithos
    assert.equal(core.AITHOS_HOME, dir);
  } finally {
    cleanupKeystore(dir);
  }
});
