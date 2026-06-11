// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// M1 — owner data sphere lock. The PDS must refuse owner data ops signed under
// an Ethos sphere (#public/#circle/#self) while allowing #data (intended),
// #root (master / migration) and did:key canonical VMs. Pure fragment check;
// the signature itself is verified upstream by verifyEnvelope.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { assertOwnerDataSphere } from "../lambda/auth/authenticate.js";
import { RpcError } from "../lambda/jsonrpc.js";

function env(vm: string): never | { proof: { verificationMethod: string } } {
  return { proof: { verificationMethod: vm } };
}

describe("M1 · owner data sphere lock", () => {
  for (const sphere of ["public", "circle", "self"]) {
    it(`rejects #${sphere} (Ethos sphere)`, () => {
      assert.throws(
        // deno-lint-ignore no-explicit-any
        () => assertOwnerDataSphere(env(`did:aithos:zX#${sphere}`) as never),
        (e: unknown) =>
          e instanceof RpcError &&
          e.code === -32012 &&
          /WRONG_SPHERE/.test((e as Error).message),
      );
    });
  }

  it("allows #data (the intended owner data key)", () => {
    assert.doesNotThrow(() => assertOwnerDataSphere(env("did:aithos:zX#data") as never));
  });

  it("allows #root (cold master — legacy CMK migration / rotate_cmk)", () => {
    assert.doesNotThrow(() => assertOwnerDataSphere(env("did:aithos:zX#root") as never));
  });

  it("allows a did:key canonical VM (#<multibase>)", () => {
    assert.doesNotThrow(() =>
      assertOwnerDataSphere(env("did:key:z6Mkxyz#z6Mkxyz") as never),
    );
  });
});
