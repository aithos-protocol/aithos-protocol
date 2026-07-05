// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mission section state machine (PLAN-CONTAINER P1.1, SPEC-container §13.8.2).
 * Statuses are written by the HARNESS only (W1); these are the pure transition
 * rules it obeys.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  parseMissionSection,
  canTransition,
  nextStatus,
  isTerminal,
  MISSION_STATUSES,
} from "../src/mission.ts";

describe("parseMissionSection", () => {
  test("accepts a minimal pending mission", () => {
    const m = parseMissionSection({
      id: "m1",
      type: "mission",
      status: "pending",
      payload: "relance les 3 prospects dormants",
    });
    assert.equal(m.id, "m1");
    assert.equal(m.status, "pending");
    assert.equal(m.payload, "relance les 3 prospects dormants");
  });

  test("rejects a non-mission section", () => {
    assert.throws(
      () => parseMissionSection({ id: "x", type: "note", status: "pending", payload: "" }),
      /type must be "mission"/,
    );
  });

  test("rejects an unknown status", () => {
    assert.throws(
      () => parseMissionSection({ id: "x", type: "mission", status: "sleeping", payload: "p" }),
      /status/,
    );
  });

  test("rejects a missing id", () => {
    assert.throws(
      () => parseMissionSection({ type: "mission", status: "pending", payload: "p" }),
      /id/,
    );
  });

  test("carries result / question / mission_ref through", () => {
    const m = parseMissionSection({
      id: "m2",
      type: "mission",
      status: "waiting_input",
      payload: "p",
      question: "which invoice?",
      mission_ref: "m1",
    });
    assert.equal(m.question, "which invoice?");
    assert.equal(m.mission_ref, "m1");
  });
});

describe("state machine (W1)", () => {
  test("the legal happy path: pending → in_progress → done", () => {
    assert.ok(canTransition("pending", "in_progress"));
    assert.ok(canTransition("in_progress", "done"));
  });

  test("in_progress may fail, escalate, or be interrupted", () => {
    for (const to of ["failed", "waiting_input", "interrupted"]) {
      assert.ok(canTransition("in_progress", to), `in_progress → ${to}`);
    }
  });

  test("waiting_input returns to pending when a human responds", () => {
    assert.ok(canTransition("waiting_input", "pending"));
  });

  test("a claimed mission cannot be claimed again (no in_progress → in_progress)", () => {
    assert.ok(!canTransition("in_progress", "in_progress"));
  });

  test("terminal states are terminal", () => {
    assert.ok(isTerminal("done"));
    assert.ok(isTerminal("failed"));
    assert.ok(!isTerminal("pending"));
    assert.ok(!isTerminal("in_progress"));
    for (const from of ["done", "failed"]) {
      for (const to of MISSION_STATUSES) {
        assert.ok(!canTransition(from, to), `${from} is terminal, no → ${to}`);
      }
    }
  });

  test("nextStatus maps a run outcome to the right terminal/escalation status", () => {
    assert.equal(nextStatus({ kind: "done" }), "done");
    assert.equal(nextStatus({ kind: "failed" }), "failed");
    assert.equal(nextStatus({ kind: "needs_input" }), "waiting_input");
    assert.equal(nextStatus({ kind: "interrupted" }), "interrupted");
  });
});
