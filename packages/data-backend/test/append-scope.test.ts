// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * requireScope() enforcement for the lateral `data.<collection>.append`
 * capability.
 *
 *  - an append-only mandate may insert, but NOT read/list/update/delete;
 *  - a write/admin mandate may also insert (write ⊃ insert);
 *  - a read-only mandate may NOT insert;
 *  - append never satisfies read/write/admin (no read leak);
 *  - the owner may do anything.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { requireScope, type Caller } from "../lambda/auth/authenticate.js";
import { RpcError } from "../lambda/jsonrpc.js";

const COL = "mandats_patients";

function delegate(scopes: string[]): Caller {
  return {
    subjectDid: "did:aithos:owner",
    mode: "delegate",
    mandateId: "mandate_test",
    mandateScopes: scopes,
    signerPubkeyMultibase: "zStub",
    envelopeNonce: "nonce",
    params: {},
    resolveIssuerDoc: async () => null,
  } as Caller;
}

function owner(): Caller {
  return {
    subjectDid: "did:aithos:owner",
    mode: "owner",
    signerPubkeyMultibase: "zStub",
    envelopeNonce: "nonce",
    params: {},
    resolveIssuerDoc: async () => null,
  } as Caller;
}

function allowed(c: Caller, action: "read" | "write" | "admin" | "append"): boolean {
  try {
    requireScope(c, COL, action);
    return true;
  } catch (e) {
    if (e instanceof RpcError && e.code === -32042) return false;
    throw e;
  }
}

describe("requireScope — append (insert-only) capability", () => {
  it("append mandate: insert allowed, read/write/admin denied", () => {
    const c = delegate([`data.${COL}.append`]);
    assert.equal(allowed(c, "append"), true);
    assert.equal(allowed(c, "read"), false);
    assert.equal(allowed(c, "write"), false);
    assert.equal(allowed(c, "admin"), false);
  });

  it("write mandate also satisfies insert (write ⊃ insert)", () => {
    const c = delegate([`data.${COL}.write`]);
    assert.equal(allowed(c, "append"), true);
    assert.equal(allowed(c, "read"), true);
    assert.equal(allowed(c, "write"), true);
  });

  it("admin mandate satisfies insert", () => {
    const c = delegate([`data.${COL}.admin`]);
    assert.equal(allowed(c, "append"), true);
  });

  it("read mandate does NOT satisfy insert", () => {
    const c = delegate([`data.${COL}.read`]);
    assert.equal(allowed(c, "append"), false);
    assert.equal(allowed(c, "read"), true);
  });

  it("append scope for a different collection does not leak", () => {
    const c = delegate([`data.other.append`]);
    assert.equal(allowed(c, "append"), false);
  });

  it("wildcard data.*.append satisfies insert on any collection", () => {
    const c = delegate([`data.*.append`]);
    assert.equal(allowed(c, "append"), true);
    assert.equal(allowed(c, "read"), false);
  });

  it("owner may do anything", () => {
    const c = owner();
    assert.equal(allowed(c, "append"), true);
    assert.equal(allowed(c, "read"), true);
    assert.equal(allowed(c, "write"), true);
    assert.equal(allowed(c, "admin"), true);
  });
});
