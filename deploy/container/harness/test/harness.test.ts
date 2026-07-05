// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Harness loop (PLAN-CONTAINER P1.2, SPEC-container §13.8.3): the deterministic
 * supervisor. Per iteration it polls the mailbox, CLAIMS one mission atomically
 * (W2 — no double execution), spawns a FRESH agent run bound to the mission,
 * and records the terminal status + report (W1). Escalations become
 * waiting_input (W3). Revocation/shutdown interrupts cleanly.
 *
 * The mailbox and the agent runner are injected: no gateway, no Claude Code, no
 * clock flakiness — the loop's contract is pinned deterministically.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { Harness } from "../src/harness.ts";
import { InMemoryMailbox } from "../src/mailbox.ts";

/** A runner scripted per mission id. */
function scriptedRunner(script) {
  const runs = [];
  return {
    runs,
    run: async (mission, ctx) => {
      runs.push({ id: mission.id, missionEnvId: ctx.missionId });
      const outcome = script[mission.id] ?? { kind: "done", report: "ok" };
      if (typeof outcome === "function") return outcome(mission, ctx);
      return outcome;
    },
  };
}

describe("Harness.tickOnce", () => {
  test("claims a pending mission, runs it, writes done + report (W1)", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "do the thing" },
    ]);
    const runner = scriptedRunner({ m1: { kind: "done", report: "did the thing" } });
    const h = new Harness({ mailbox: mb, runner });

    const ran = await h.tickOnce();
    assert.equal(ran, 1, "one mission ran");

    const m = await mb.get("m1");
    assert.equal(m.status, "done");
    assert.equal(m.result, "did the thing");
    assert.equal(runner.runs.length, 1);
  });

  test("passes a mission id into the run environment (gamma correlation)", async () => {
    const mb = new InMemoryMailbox([
      { id: "mX", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = scriptedRunner({});
    const h = new Harness({ mailbox: mb, runner });
    await h.tickOnce();
    assert.equal(runner.runs[0].missionEnvId, "mX");
  });

  test("a failing run is recorded failed, never done (W1)", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = scriptedRunner({ m1: { kind: "failed", report: "boom" } });
    const h = new Harness({ mailbox: mb, runner });
    await h.tickOnce();
    const m = await mb.get("m1");
    assert.equal(m.status, "failed");
    assert.equal(m.result, "boom");
  });

  test("a thrown run is caught and recorded failed (the loop never dies)", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = {
      run: async () => {
        throw new Error("runner exploded");
      },
    };
    const h = new Harness({ mailbox: mb, runner });
    await h.tickOnce();
    const m = await mb.get("m1");
    assert.equal(m.status, "failed");
    assert.match(m.result ?? "", /runner exploded/);
  });

  test("an escalation becomes waiting_input with the question (W3)", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = scriptedRunner({
      m1: { kind: "needs_input", question: "approve refund of 200€?" },
    });
    const h = new Harness({ mailbox: mb, runner });
    await h.tickOnce();
    const m = await mb.get("m1");
    assert.equal(m.status, "waiting_input");
    assert.equal(m.question, "approve refund of 200€?");
  });

  test("waiting_input missions are NOT picked up until re-queued to pending", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "waiting_input", payload: "p", question: "?" },
    ]);
    const runner = scriptedRunner({});
    const h = new Harness({ mailbox: mb, runner });
    const ran = await h.tickOnce();
    assert.equal(ran, 0, "nothing runs");
    assert.equal(runner.runs.length, 0);

    // Human answers → back to pending with context; now it runs.
    await mb.answer("m1", "yes, go ahead");
    const ran2 = await h.tickOnce();
    assert.equal(ran2, 1);
    assert.equal((await mb.get("m1")).status, "done");
  });

  test("claim-before-run: two harnesses on one mailbox never double-execute (W2)", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
      { id: "m2", type: "mission", status: "pending", payload: "p" },
    ]);
    const runnerA = scriptedRunner({});
    const runnerB = scriptedRunner({});
    const a = new Harness({ mailbox: mb, runner: runnerA });
    const b = new Harness({ mailbox: mb, runner: runnerB });

    // Drain concurrently.
    await Promise.all([a.drain(), b.drain()]);

    const allRuns = [...runnerA.runs, ...runnerB.runs].map((r) => r.id).sort();
    assert.deepEqual(allRuns, ["m1", "m2"], "each mission ran exactly once across both");
    assert.equal((await mb.get("m1")).status, "done");
    assert.equal((await mb.get("m2")).status, "done");
  });

  test("tickOnce claims at most one mission per tick", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
      { id: "m2", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = scriptedRunner({});
    const h = new Harness({ mailbox: mb, runner });
    await h.tickOnce();
    assert.equal(runner.runs.length, 1, "one per tick");
    await h.tickOnce();
    assert.equal(runner.runs.length, 2);
    await h.tickOnce();
    assert.equal(runner.runs.length, 2, "nothing left");
  });
});

describe("Harness.run (loop) + shutdown", () => {
  test("drains all pending then a stop signal ends the loop", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
      { id: "m2", type: "mission", status: "pending", payload: "p" },
      { id: "m3", type: "mission", status: "pending", payload: "p" },
    ]);
    const runner = scriptedRunner({});
    const h = new Harness({ mailbox: mb, runner, tickMs: 1 });

    const loop = h.run();
    await h.drain(); // process everything
    h.stop(); // request shutdown
    await loop;

    for (const id of ["m1", "m2", "m3"]) {
      assert.equal((await mb.get(id)).status, "done");
    }
  });

  test("an in-flight mission interrupted by shutdown is recorded interrupted, not lost", async () => {
    const mb = new InMemoryMailbox([
      { id: "m1", type: "mission", status: "pending", payload: "p" },
    ]);
    let release;
    const gate = new Promise((r) => (release = r));
    const runner = {
      run: async () => {
        await gate; // hang until we let go
        return { kind: "interrupted", report: "stopped mid-flight" };
      },
    };
    const h = new Harness({ mailbox: mb, runner });
    const p = h.tickOnce();
    release();
    await p;
    const m = await mb.get("m1");
    assert.equal(m.status, "interrupted");
  });
});
