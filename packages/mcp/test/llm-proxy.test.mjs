// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * LLM pass-through proxy (PLAN-CONTAINER P0.1, SPEC-container-runtime §13.5):
 * the cage has NO egress, so the agent's model traffic must traverse the
 * gateway. P0 mode is a TRANSPARENT reverse proxy:
 *
 *   - requests under /llm/* are forwarded to the configured upstream
 *     (allowlist by construction: exactly one upstream base URL);
 *   - method, path, query, body and auth headers pass through untouched
 *     (I1/I2 — the agent is configured by base-URL redirection alone;
 *     subscription-credential mode §13.7.2 means the gateway must NOT
 *     tamper with authorization);
 *   - responses stream back chunk by chunk (SSE works);
 *   - the log line carries method/path/status/sizes/duration — NEVER bodies,
 *     NEVER credential values (I6);
 *   - upstream failure → 502; /llm without proxy configured → 404;
 *   - no MCP bearer on /llm: inside the cage, network position is the
 *     authenticator (the runtime cannot reach anything else anyway).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

const { createLlmProxy } = await import("../dist/llm-proxy.js");
const { startHttpGateway } = await import("../dist/http.js");

/* ------------------------- fake Anthropic upstream ------------------------ */

async function startUpstream() {
  const seen = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString("utf8");
    seen.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body,
    });

    const { pathname } = new URL(req.url ?? "/", "http://fake");
    if (pathname === "/v1/messages" && req.method === "POST") {
      res.writeHead(200, {
        "content-type": "application/json",
        "x-upstream": "fake-anthropic",
      });
      res.end(JSON.stringify({ id: "msg_1", echo: body ? JSON.parse(body) : null }));
      return;
    }
    if (pathname === "/v1/stream") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("event: chunk\ndata: one\n\n");
      setTimeout(() => {
        res.write("event: chunk\ndata: two\n\n");
        res.end();
      }, 30);
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("upstream-404");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    seen,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((r) => server.close(r)),
  };
}

function gwServerOptions() {
  // The LLM proxy needs no MCP server at all — but the gateway factory does.
  // A storage-free server is enough for these tests (no MCP calls are made).
  return {};
}

async function bootGateway(llm) {
  return startHttpGateway({
    host: "127.0.0.1",
    port: 0,
    token: "llm-proxy-test-token-000000000",
    serverOptions: gwServerOptions,
    log: () => {},
    ...(llm ? { extraRoutes: llm } : {}),
  });
}

/* -------------------------------------------------------------------------- */

test("POST body, path, query and auth headers pass through; response intact", async () => {
  const up = await startUpstream();
  const logs = [];
  const llm = createLlmProxy({
    upstream: up.url,
    prefix: "/llm",
    log: (e) => logs.push(e),
  });
  const gw = await bootGateway(llm);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/llm/v1/messages?beta=true`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": "sk-ant-SECRET",
        authorization: "Bearer oauth-SECRET",
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({ model: "claude", max_tokens: 8 }),
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-upstream"), "fake-anthropic");
    const json = await res.json();
    assert.equal(json.id, "msg_1");
    assert.deepEqual(json.echo, { model: "claude", max_tokens: 8 });

    assert.equal(up.seen.length, 1);
    const fwd = up.seen[0];
    assert.equal(fwd.method, "POST");
    assert.equal(fwd.url, "/v1/messages?beta=true", "prefix stripped, query kept");
    assert.equal(fwd.headers["x-api-key"], "sk-ant-SECRET");
    assert.equal(fwd.headers["authorization"], "Bearer oauth-SECRET");
    assert.equal(fwd.headers["anthropic-version"], "2023-06-01");
    assert.equal(fwd.body, JSON.stringify({ model: "claude", max_tokens: 8 }));
  } finally {
    await gw.close();
    await up.close();
  }
});

test("streaming responses arrive chunk by chunk (SSE)", async () => {
  const up = await startUpstream();
  const llm = createLlmProxy({ upstream: up.url, prefix: "/llm", log: () => {} });
  const gw = await bootGateway(llm);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/llm/v1/stream`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /event-stream/);
    const text = await res.text();
    assert.match(text, /data: one/);
    assert.match(text, /data: two/);
  } finally {
    await gw.close();
    await up.close();
  }
});

test("log lines carry metadata only — no bodies, no credentials", async () => {
  const up = await startUpstream();
  const logs = [];
  const llm = createLlmProxy({
    upstream: up.url,
    prefix: "/llm",
    log: (e) => logs.push(e),
  });
  const gw = await bootGateway(llm);
  try {
    await fetch(`http://127.0.0.1:${gw.port}/llm/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-SECRET" },
      body: JSON.stringify({ secret_prompt: "TOPSECRET" }),
    });
    assert.equal(logs.length, 1);
    const entry = logs[0];
    assert.equal(entry.method, "POST");
    assert.equal(entry.path, "/v1/messages");
    assert.equal(entry.status, 200);
    assert.equal(typeof entry.ms, "number");
    assert.ok(entry.reqBytes > 0);
    assert.ok(entry.resBytes > 0);
    const flat = JSON.stringify(entry);
    assert.doesNotMatch(flat, /TOPSECRET/, "no request body in logs");
    assert.doesNotMatch(flat, /SECRET/, "no credential value in logs");
  } finally {
    await gw.close();
    await up.close();
  }
});

test("upstream connection failure → 502, never a crash", async () => {
  const llm = createLlmProxy({
    upstream: "http://127.0.0.1:1", // nothing listens there
    prefix: "/llm",
    log: () => {},
  });
  const gw = await bootGateway(llm);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/llm/v1/messages`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(res.status, 502);
  } finally {
    await gw.close();
  }
});

test("upstream 404 passes through as 404 (transparent, not remapped)", async () => {
  const up = await startUpstream();
  const llm = createLlmProxy({ upstream: up.url, prefix: "/llm", log: () => {} });
  const gw = await bootGateway(llm);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/llm/does-not-exist`);
    assert.equal(res.status, 404);
    assert.equal(await res.text(), "upstream-404");
  } finally {
    await gw.close();
    await up.close();
  }
});

test("without a configured proxy, /llm stays 404 (nothing mounted)", async () => {
  const gw = await bootGateway(undefined);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/llm/v1/messages`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(res.status, 404);
  } finally {
    await gw.close();
  }
});

test("paths outside the prefix are not the proxy's business", async () => {
  const up = await startUpstream();
  const llm = createLlmProxy({ upstream: up.url, prefix: "/llm", log: () => {} });
  const gw = await bootGateway(llm);
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/other`);
    assert.equal(res.status, 404);
    assert.equal(up.seen.length, 0, "upstream untouched");
  } finally {
    await gw.close();
    await up.close();
  }
});
