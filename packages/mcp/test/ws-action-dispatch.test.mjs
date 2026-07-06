// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * wsActionDispatch — the real browser-agent transport. Drives a stub WS "hand"
 * that speaks the run_action contract (and checks the bearer at the handshake),
 * asserting: the exact run_action message is sent, a run_report maps to ok, a
 * run_stopped maps to a failed RunReport, a bad bearer is refused, and a silent
 * hand times out (fail closed).
 */
import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { WebSocketServer } from "ws";

const { wsActionDispatch } = await import("../src/action-federation.ts");

/** A stub hand: optional bearer gate + a canned reply computed from the message. */
async function stubHand({ bearer, reply }) {
  const received = [];
  const wss = new WebSocketServer({
    port: 0,
    verifyClient: (info, cb) => {
      if (bearer && info.req.headers["authorization"] !== `Bearer ${bearer}`) {
        return cb(false, 401, "unauthorized");
      }
      cb(true);
    },
  });
  await new Promise((r) => wss.on("listening", r));
  wss.on("connection", (ws) => {
    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());
      received.push(msg);
      if (reply) ws.send(JSON.stringify(reply(msg)));
    });
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    received,
    close: () => new Promise((r) => wss.close(r)),
  };
}

const ENVELOPE = { "aithos-envelope": "0.1.0", nonce: "n-123" };

describe("wsActionDispatch", () => {
  test("sends the run_action message and maps a run_report to ok", async () => {
    const hand = await stubHand({
      reply: (m) => ({
        type: "run_report",
        ok: true,
        action_id: m.action_id,
        steps_done: 3,
        events: ["done"],
      }),
    });
    try {
      const dispatch = wsActionDispatch(hand.url);
      const report = await dispatch({
        envelope: ENVELOPE,
        action: { id: "inscription" },
        params: { nom: "Sophie" },
      });
      assert.equal(report.ok, true);
      assert.equal(report.type, "run_report");
      assert.equal(report.steps_done, 3);
      // the exact wire message the hand received
      assert.deepEqual(hand.received[0], {
        type: "run_action",
        action_id: "inscription",
        params: { nom: "Sophie" },
        envelope: ENVELOPE,
      });
    } finally {
      await hand.close();
    }
  });

  test("maps run_stopped to a failed RunReport carrying the reason", async () => {
    const hand = await stubHand({
      reply: () => ({ type: "run_stopped", ok: false, step: 2, phase: "precondition", reason: "form not found" }),
    });
    try {
      const report = await wsActionDispatch(hand.url)({
        envelope: ENVELOPE,
        action: { id: "inscription" },
        params: {},
      });
      assert.equal(report.ok, false);
      assert.equal(report.type, "run_stopped");
      assert.match(report.error, /form not found/);
    } finally {
      await hand.close();
    }
  });

  test("a wrong bearer is refused at the handshake (fail closed)", async () => {
    const hand = await stubHand({ bearer: "correct-token", reply: () => ({ type: "run_report", ok: true }) });
    try {
      const report = await wsActionDispatch(hand.url, { bearer: "WRONG" })({
        envelope: ENVELOPE,
        action: { id: "inscription" },
        params: {},
      });
      assert.equal(report.ok, false);
      assert.match(report.error, /401/);
      assert.equal(hand.received.length, 0, "nothing was dispatched to the hand");
    } finally {
      await hand.close();
    }
  });

  test("the correct bearer is accepted", async () => {
    const hand = await stubHand({
      bearer: "correct-token",
      reply: () => ({ type: "run_report", ok: true, steps_done: 1, events: [] }),
    });
    try {
      const report = await wsActionDispatch(hand.url, { bearer: "correct-token" })({
        envelope: ENVELOPE,
        action: { id: "inscription" },
        params: {},
      });
      assert.equal(report.ok, true);
    } finally {
      await hand.close();
    }
  });

  test("a silent hand times out and fails closed", async () => {
    const hand = await stubHand({ reply: null }); // never answers
    try {
      const report = await wsActionDispatch(hand.url, { timeoutMs: 200 })({
        envelope: ENVELOPE,
        action: { id: "inscription" },
        params: {},
      });
      assert.equal(report.ok, false);
      assert.match(report.error, /timed out/);
    } finally {
      await hand.close();
    }
  });
});
