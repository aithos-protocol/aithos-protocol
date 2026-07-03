// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Security regression: over the HTTP transport the server is constructed WITHOUT
 * a HostIo (see bin.ts `nodeServerOptions`), so a bearer-authenticated client
 * cannot make the server read arbitrary local files named in tool arguments
 * (LFI / CWE-22, e.g. agent_key: "/…/identities/<victim>/self.sealed.json").
 *
 * This test pins the fail-closed contract the HTTP path relies on: with no io,
 * path-form agent keys and mandates throw a clear error and never touch the
 * filesystem, while id-form mandates still resolve through the storage backend.
 *
 * Runs directly on source via tsx (no build needed); auth.ts imports only types.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";

import { loadAgentKey, resolveMandate, type HostIo } from "../src/auth.ts";
import type { AithosStorage, Mandate } from "@aithos/protocol-core";

// A HostIo that would leak files if it were ever consulted — the tests assert
// it is NOT consulted for the no-io (HTTP) path, and IS gated by containment
// for the confined case.
function spyIo(readReturn = '{"seed_hex":"00"}'): HostIo & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    readTextFile: async (p: string) => {
      reads.push(p);
      return readReturn;
    },
    resolvePath: (p: string) => p,
  };
}

// Minimal storage stub: id-form mandate resolution must still work.
function storageStub(mandate: Mandate): AithosStorage {
  return {
    loadMandate: async (id: string) => {
      assert.equal(id, mandate.id);
      return mandate;
    },
  } as unknown as AithosStorage;
}

const FAKE_MANDATE = { id: "mandate_01TEST", scopes: [] } as unknown as Mandate;

describe("HTTP transport LFI guard (no HostIo injected)", () => {
  test("path-form agent_key throws and never reads the filesystem when io is absent", async () => {
    await assert.rejects(
      () => loadAgentKey("/home/victim/.aithos/identities/x/self.sealed.json", undefined),
      /host file access|cannot read/i,
    );
  });

  test("path-form mandate throws (resolves by id only) when io is absent", async () => {
    await assert.rejects(
      () =>
        resolveMandate(
          storageStub(FAKE_MANDATE),
          "/etc/passwd",
          undefined,
        ),
      /host file access|by id only/i,
    );
  });

  test("id-form mandate still resolves through storage without io", async () => {
    const { mandate, mandatePath } = await resolveMandate(
      storageStub(FAKE_MANDATE),
      "mandate_01TEST",
      undefined,
    );
    assert.equal(mandate.id, "mandate_01TEST");
    assert.equal(mandatePath, "mandate:mandate_01TEST");
  });

  test("sanity: when io IS present (stdio), path-form agent_key does read via io", async () => {
    const io = spyIo();
    const { key } = await loadAgentKey("/some/key.json", io);
    assert.equal(key.seed_hex, "00");
    assert.deepEqual(io.reads, ["/some/key.json"]);
  });
});
