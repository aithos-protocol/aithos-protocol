// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Egress allowlist proxy (dev subscription mode). The security property is
 * simple and load-bearing: the caged runtime can tunnel to the allowed domain
 * and to NOTHING else. Tests cover the pure decision + a real CONNECT tunnel.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";

import { isAllowed, createEgressProxy } from "../dev/egress-allowlist-proxy.mjs";

test("isAllowed: exact host + port only", () => {
  const allow = ["api.anthropic.com"];
  const ports = [443];
  assert.equal(isAllowed("api.anthropic.com", 443, allow, ports), true);
  assert.equal(isAllowed("example.com", 443, allow, ports), false, "other host denied");
  assert.equal(isAllowed("api.anthropic.com", 80, allow, ports), false, "other port denied");
  // No suffix / substring bypass.
  assert.equal(isAllowed("api.anthropic.com.evil.tld", 443, allow, ports), false);
  assert.equal(isAllowed("evil-api.anthropic.com", 443, allow, ports), false);
  assert.equal(isAllowed("xapi.anthropic.com", 443, allow, ports), false);
});

/**
 * Integration: point the allowlist at a fake upstream on an ephemeral port,
 * CONNECT through the proxy, and confirm the tunnel carries bytes. Then CONNECT
 * to a denied host and confirm a 403 with no tunnel.
 */
test("CONNECT to an allowed host tunnels; a denied host gets 403", async () => {
  // A fake "upstream" TCP server that echoes a banner.
  const upstream = net.createServer((sock) => {
    sock.write("UPSTREAM-OK");
    sock.on("data", () => {});
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const upstreamPort = upstream.address().port;

  const logs = [];
  const proxy = createEgressProxy({
    allow: ["127.0.0.1"],
    ports: [upstreamPort],
    onLog: (o) => logs.push(o),
  });
  await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
  const proxyPort = proxy.address().port;

  // --- allowed CONNECT: expect 200 then the upstream banner over the tunnel ---
  const banner = await new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1", () => {
      s.write(`CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`);
    });
    let buf = "";
    s.on("data", (d) => {
      buf += d.toString("latin1");
      if (buf.includes("UPSTREAM-OK")) {
        assert.match(buf, /^HTTP\/1\.1 200/, "tunnel established");
        s.destroy();
        resolve(buf);
      }
    });
    s.on("error", reject);
    setTimeout(() => reject(new Error("timeout waiting for tunnel")), 3000);
  });
  assert.match(banner, /UPSTREAM-OK/);

  // --- denied CONNECT: a host not on the allowlist → 403, no tunnel ----------
  const denied = await new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1", () => {
      s.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    });
    let buf = "";
    s.on("data", (d) => (buf += d.toString("latin1")));
    s.on("close", () => resolve(buf));
    s.on("error", reject);
    setTimeout(() => reject(new Error("timeout waiting for 403")), 3000);
  });
  assert.match(denied, /^HTTP\/1\.1 403/, "denied host rejected");

  assert.ok(logs.some((l) => l.event === "allow" && l.host === "127.0.0.1"));
  assert.ok(logs.some((l) => l.event === "deny" && l.host === "example.com"));

  await new Promise((r) => proxy.close(r));
  await new Promise((r) => upstream.close(r));
});

test("plain HTTP (non-CONNECT) is refused with 405", async () => {
  const proxy = createEgressProxy({ allow: ["api.anthropic.com"], ports: [443], onLog: () => {} });
  await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
  const port = proxy.address().port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(res.status, 405);
  } finally {
    await new Promise((r) => proxy.close(r));
  }
});
