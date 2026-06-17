// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
// Unit tests for the provisional Linkedone broker module (pure orchestration).

import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  scheduleViaLinkedone,
  LinkedoneBrokerError,
  COMPOSE_AND_SCHEDULE_METHOD,
} from "../dist/linkedone-broker.js";

const FUTURE = new Date(Date.now() + 3600_000).toISOString();

function mockFetch(status, body) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  fn.calls = calls;
  return fn;
}

test("happy path: signs, POSTs to compose-and-schedule, returns result", async () => {
  const fetchImpl = mockFetch(200, { ok: true, postId: "post_01", scheduledAt: FUTURE, scheduleArn: "arn:sched" });
  let signed = null;
  const res = await scheduleViaLinkedone({
    apiBase: "https://api.linkedone.fr",
    content: "Hello world",
    scheduledAt: FUTURE,
    signDelegate: async (a) => { signed = a; return { fake: "envelope" }; },
    fetchImpl,
  });
  assert.equal(res.ok, true);
  assert.equal(res.postId, "post_01");
  assert.equal(res.scheduleArn, "arn:sched");
  assert.equal(signed.method, COMPOSE_AND_SCHEDULE_METHOD);
  assert.equal(signed.aud, "https://api.linkedone.fr/v1/compose-and-schedule");
  const body = JSON.parse(fetchImpl.calls[0].init.body);
  assert.equal(body.content, "Hello world");
  assert.deepEqual(body._envelope, { fake: "envelope" });
});

test("trailing slash in apiBase is normalized", async () => {
  const fetchImpl = mockFetch(200, { ok: true, postId: "p" });
  let signed = null;
  await scheduleViaLinkedone({ apiBase: "https://api.linkedone.fr/", content: "x", scheduledAt: FUTURE,
    signDelegate: async (a) => { signed = a; return {}; }, fetchImpl });
  assert.equal(signed.aud, "https://api.linkedone.fr/v1/compose-and-schedule");
});

test("rejects missing content / invalid date / too-soon", async () => {
  await assert.rejects(() => scheduleViaLinkedone({ apiBase: "x", content: "  ", scheduledAt: FUTURE, signDelegate: async()=>({}), fetchImpl: mockFetch(200,{}) }),
    (e) => e instanceof LinkedoneBrokerError && e.code === "missing_content");
  await assert.rejects(() => scheduleViaLinkedone({ apiBase: "x", content: "c", scheduledAt: "nope", signDelegate: async()=>({}), fetchImpl: mockFetch(200,{}) }),
    (e) => e instanceof LinkedoneBrokerError && e.code === "invalid_scheduled_at");
  await assert.rejects(() => scheduleViaLinkedone({ apiBase: "x", content: "c", scheduledAt: new Date(Date.now()+5000).toISOString(), signDelegate: async()=>({}), fetchImpl: mockFetch(200,{}) }),
    (e) => e instanceof LinkedoneBrokerError && e.code === "scheduled_at_too_soon");
});

test("maps a Linkedone error response", async () => {
  const fetchImpl = mockFetch(409, { ok: false, error: "post_already_scheduled", message: "already" });
  await assert.rejects(() => scheduleViaLinkedone({ apiBase: "https://api.linkedone.fr", content: "c", scheduledAt: FUTURE, signDelegate: async()=>({}), fetchImpl }),
    (e) => e instanceof LinkedoneBrokerError && e.code === "post_already_scheduled");
});

test("does NOT POST if signing throws", async () => {
  const fetchImpl = mockFetch(200, { ok: true });
  await assert.rejects(() => scheduleViaLinkedone({ apiBase: "https://api.linkedone.fr", content: "c", scheduledAt: FUTURE,
    signDelegate: async () => { throw new Error("sign failed"); }, fetchImpl }), (e) => e instanceof Error);
  assert.equal(fetchImpl.calls.length, 0);
});
