// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Revocation / TTL watcher (PLAN-CONTAINER P1.3, SPEC-container §13.9 L2):
 * a sidecar OUTSIDE the cage that, on revocation or on reaching not_after,
 * pauses then stops the runtime. Hygiene, not the security boundary (L1
 * fail-closed already cut every call) — hence best-effort and clock-injected.
 *
 * "A container never outlives its mandate": here we prove the watcher enacts it.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { RevocationWatcher } from "../src/watcher.ts";

function fakeCage() {
  const events = [];
  return {
    events,
    pause: async () => events.push("pause"),
    stop: async () => events.push("stop"),
  };
}

describe("RevocationWatcher", () => {
  test("does nothing while the mandate is live and unrevoked", async () => {
    const cage = fakeCage();
    const w = new RevocationWatcher({
      cage,
      notAfter: new Date(Date.now() + 3600_000).toISOString(),
      isRevoked: async () => false,
      now: () => Date.now(),
    });
    await w.check();
    assert.deepEqual(cage.events, []);
  });

  test("on revocation: pause THEN stop, in order (revoke = unplug)", async () => {
    const cage = fakeCage();
    let revoked = false;
    const w = new RevocationWatcher({
      cage,
      notAfter: new Date(Date.now() + 3600_000).toISOString(),
      isRevoked: async () => revoked,
      now: () => Date.now(),
    });
    await w.check();
    assert.deepEqual(cage.events, []);
    revoked = true;
    await w.check();
    assert.deepEqual(cage.events, ["pause", "stop"]);
  });

  test("on reaching not_after: the cage is stopped (TTL = container TTL)", async () => {
    const cage = fakeCage();
    let clock = Date.parse("2026-01-01T00:00:00Z");
    const w = new RevocationWatcher({
      cage,
      notAfter: "2026-01-01T00:00:10Z",
      isRevoked: async () => false,
      now: () => clock,
    });
    await w.check();
    assert.deepEqual(cage.events, [], "still within window");
    clock = Date.parse("2026-01-01T00:00:11Z"); // past not_after
    await w.check();
    assert.deepEqual(cage.events, ["pause", "stop"]);
  });

  test("acts once: a second check after teardown does not re-stop", async () => {
    const cage = fakeCage();
    const w = new RevocationWatcher({
      cage,
      notAfter: new Date(Date.now() + 3600_000).toISOString(),
      isRevoked: async () => true,
      now: () => Date.now(),
    });
    await w.check();
    await w.check();
    assert.deepEqual(cage.events, ["pause", "stop"], "exactly one pause+stop");
  });

  test("best-effort: a revocation-lookup failure never throws out of check()", async () => {
    const cage = fakeCage();
    const w = new RevocationWatcher({
      cage,
      notAfter: new Date(Date.now() + 3600_000).toISOString(),
      isRevoked: async () => {
        throw new Error("revocation authority unreachable");
      },
      now: () => Date.now(),
      log: () => {},
    });
    await w.check(); // must not reject — L1 remains the security boundary
    assert.deepEqual(cage.events, [], "no action taken on a lookup error");
  });

  test("runUntilDone polls on an interval then resolves when it acts", async () => {
    const cage = fakeCage();
    let ticks = 0;
    const w = new RevocationWatcher({
      cage,
      notAfter: new Date(Date.now() + 3600_000).toISOString(),
      isRevoked: async () => ++ticks >= 3, // revoked on the 3rd poll
      now: () => Date.now(),
      pollMs: 1,
      sleep: async () => {},
      log: () => {},
    });
    await w.runUntilDone();
    assert.deepEqual(cage.events, ["pause", "stop"]);
    assert.equal(ticks, 3);
  });
});
