#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Egress allowlist proxy — DEV ONLY (subscription mode, ÉTUDE-CAGE-ABONNEMENT
 * "B-egress").
 *
 * The sealed cage (§13.4 N1) has no egress: inference must traverse the gateway
 * /llm proxy. But Claude Code's subscription auth hits OAuth/admin endpoints
 * hard-coded to api.anthropic.com that ignore ANTHROPIC_BASE_URL (claude-code
 * issue #48011), so the subscription can't be used through the gateway.
 *
 * This forward proxy is the DEV compromise: it bridges the cage to EXACTLY ONE
 * domain (api.anthropic.com) and nothing else. The runtime stays on the `cage`
 * network (no direct egress) and reaches the world only through here, over
 * HTTPS_PROXY. Claude Code uses its OWN subscription auth (legitimate — it is
 * Claude Code making the calls, not us). Result:
 *
 *   - ACTIONS stay fully bounded: tools/connectors are reached only via the
 *     gateway MCP, gated by the mandate — this proxy adds no action capability;
 *   - the cage can reach the gateway (to act) + api.anthropic.com (to think),
 *     and NOTHING else — not example.com, not a connector API directly;
 *   - what is conceded (dev only): inference is not gateway-traced, and a
 *     revoked mandate still cuts actions but not "thinking". The sealed+traced
 *     ideal is B-MITM, later.
 *
 * CONNECT-only (all Anthropic traffic is HTTPS). Exact host match (no suffix
 * match — `api.anthropic.com.evil.tld` is rejected). Default port 443.
 */
import net from "node:net";
import http from "node:http";

/** Pure allow decision — exact host membership + port membership. */
export function isAllowed(host, port, allow, ports) {
  return allow.includes(host) && ports.includes(port);
}

const ALLOW = (process.env.EGRESS_ALLOWLIST ?? "api.anthropic.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const PORTS = (process.env.EGRESS_ALLOW_PORTS ?? "443")
  .split(",")
  .map((s) => Number(s.trim()))
  .filter((n) => Number.isInteger(n));
const PORT = Number(process.env.PORT ?? 8888);
const HOST = process.env.HOST ?? "0.0.0.0";

const log = (o) =>
  console.log(JSON.stringify({ kind: "aithos.egress.proxy", ...o }));

/** Build the proxy server (exported for tests; not started on import). */
export function createEgressProxy({ allow = ALLOW, ports = PORTS, onLog = log } = {}) {
  // Plain HTTP proxying is not needed (Anthropic is HTTPS); refuse it.
  const server = http.createServer((_req, res) => {
    res.writeHead(405, { "content-type": "text/plain" });
    res.end("this proxy supports HTTPS CONNECT only");
  });

  server.on("connect", (req, clientSocket, head) => {
    const [host, portStr] = String(req.url ?? "").split(":");
    const port = Number(portStr || 443);
    if (!isAllowed(host, port, allow, ports)) {
      onLog({ event: "deny", host, port });
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      clientSocket.destroy();
      return;
    }
    onLog({ event: "allow", host, port });
    const upstream = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on("error", () => clientSocket.destroy());
    clientSocket.on("error", () => upstream.destroy());
  });

  return server;
}

// Start only when run directly (not when imported by tests).
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const server = createEgressProxy();
  server.listen(PORT, HOST, () =>
    log({ event: "listening", host: HOST, port: PORT, allow: ALLOW, ports: PORTS }),
  );
  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
