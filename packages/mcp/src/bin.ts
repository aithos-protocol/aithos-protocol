#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos-mcp` — MCP server entry point (the NODE host).
 *
 * This file owns every node-only capability and injects it into the
 * isomorphic core (`createServer` in server.ts): the `FilesystemStorage`
 * backend reading `$AITHOS_HOME`, host file access for path-form mandates /
 * agent keyfiles, and the on-disk manifest-path diagnostic resource.
 *
 * Two transports are supported:
 *
 *   stdio  (default)   Speak MCP over this process's stdin/stdout. Intended
 *                      for local agents spawned by IDEs, shells, and CLI
 *                      tools (`claude mcp add ...`, Claude Desktop, etc.).
 *
 *   http               Speak MCP over HTTP using the Streamable HTTP transport
 *                      (single `POST /mcp` + SSE fallback). Stateful session
 *                      mode by default. Requires `AITHOS_MCP_TOKEN` to be set
 *                      in the environment; clients must send
 *                      `Authorization: Bearer <token>`.
 *
 * Usage:
 *   aithos-mcp                                          # stdio
 *   aithos-mcp --transport stdio
 *   aithos-mcp --transport http --port 8787 [--host 127.0.0.1]
 */
import { Command } from "commander";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  AITHOS_HOME,
  FilesystemStorage,
  ethosManifestPath,
  renderZoneMarkdown,
} from "@aithos/protocol-core";

import { createServer, type CreateServerOptions, type HostIo } from "./server.js";
import { parseMandatePack, hexToBytes, type MandatePack } from "./pack.js";
import {
  federate,
  parseRegistry,
  type McpRegistry,
  type FederationHandle,
} from "./gateway.js";

const nodeIo: HostIo = {
  readTextFile: (p) => readFile(p, "utf8"),
  resolvePath: (p) => path.resolve(p),
};

/** The node host's createServer options: filesystem storage + host io. */
function nodeServerOptions(autoCommit?: boolean, pack?: MandatePack): CreateServerOptions {
  return {
    storage: new FilesystemStorage(),
    home: AITHOS_HOME,
    manifestPath: ethosManifestPath,
    io: nodeIo,
    renderZone: renderZoneMarkdown,
    ...(autoCommit || pack?.options?.auto_commit ? { autoCommit: true } : {}),
    // P4.4 — mandate pack (§6.2.1): scope-filtered exposure + the pack's
    // delegate key as the default write authority.
    ...(pack
      ? {
          mandate: { scopes: pack.mandate.scopes, document: pack.mandate },
          delegate: {
            mandateId: pack.mandate.id,
            keySeed: hexToBytes(pack.agent_key.seed_hex),
            keyMultibase: pack.agent_key.pubkey_multibase,
          },
          ...(pack.options?.expose_tools
            ? { exposeTools: pack.options.expose_tools }
            : {}),
        }
      : {}),
  };
}

async function loadPack(p?: string): Promise<MandatePack | undefined> {
  if (!p) return undefined;
  const text = await readFile(path.resolve(p), "utf8");
  return parseMandatePack(text);
}

async function loadRegistry(p?: string): Promise<McpRegistry | undefined> {
  if (!p) return undefined;
  const text = await readFile(path.resolve(p), "utf8");
  return parseRegistry(text);
}

/**
 * T7 — the mandate's validity window. Federated tools must not be exposed under
 * an expired / not-yet-valid mandate. (Full revocation = server-side status
 * lookup; deferred for the proto — cf. PLAN-PROTO-SELFWIRED.md.)
 */
function isMandateLive(pack: MandatePack, now = Date.now()): boolean {
  const nb = Date.parse(pack.mandate.not_before);
  const na = Date.parse(pack.mandate.not_after);
  if (Number.isNaN(nb) || Number.isNaN(na)) return false;
  return now >= nb && now <= na;
}

interface CliOpts {
  transport: "stdio" | "http";
  port?: string;
  host?: string;
  stateless?: boolean;
  autoCommit?: boolean;
  mandatePack?: string;
  mcpRegistry?: string;
  auditLog?: string;
}

const program = new Command();
program
  .name("aithos-mcp")
  .description("MCP server for the Aithos protocol (ethos + mandates).")
  .option(
    "--transport <kind>",
    "Transport: stdio | http",
    (v) => {
      if (v !== "stdio" && v !== "http") {
        throw new Error(`invalid --transport ${v} (want stdio | http)`);
      }
      return v;
    },
    "stdio",
  )
  .option("--port <n>", "HTTP port (http transport only)", "8787")
  .option("--host <h>", "HTTP host (http transport only)", "127.0.0.1")
  .option("--stateless", "HTTP stateless mode (no session id)", false)
  .option(
    "--auto-commit",
    "Persist every write immediately (pre-0.10 behaviour). Default is " +
      "TRANSACTIONAL: writes stage in the session until ethos_commit.",
    false,
  )
  .option(
    "--mandate-pack <path>",
    "Boot under a mandate pack (spec §6.2.1): scope-filtered tools, the " +
      "pack's delegate key signs writes, validity/revocation re-checked " +
      "before anything persists.",
  )
  .option(
    "--mcp-registry <path>",
    "Federate downstream MCP servers declared in this registry (self-wired " +
      "gateway). A server is exposed only if the mandate carries scope " +
      "mcp.<id>. Requires --mandate-pack.",
  )
  .option(
    "--audit-log <path>",
    "Append a JSONL audit line per federated tool call (default: " +
      "./aithos-audit.jsonl).",
  )
  .action(async (opts: CliOpts) => {
    const pack = await loadPack(opts.mandatePack);
    const registry = await loadRegistry(opts.mcpRegistry);
    if (registry && !pack) {
      throw new Error("--mcp-registry requires --mandate-pack (scopes drive exposure)");
    }
    if (opts.transport === "stdio") {
      await runStdio(opts.autoCommit === true, pack, registry, opts.auditLog);
    } else {
      if (registry) {
        // Federation is wired for the stdio host (the proto's target). HTTP
        // federation is per-session and deferred — fail loud rather than
        // silently ignoring the registry.
        throw new Error("--mcp-registry is supported with --transport stdio only (proto)");
      }
      await runHttp(opts, pack);
    }
  });

async function runStdio(
  autoCommit: boolean,
  pack?: MandatePack,
  registry?: McpRegistry,
  auditLog?: string,
): Promise<void> {
  const server = createServer(nodeServerOptions(autoCommit, pack));

  // Self-wired gateway: federate downstream MCPs before connecting the
  // transport (tools must be registered up front). Only when a pack is present
  // and live; an expired/not-yet-valid mandate exposes NO federated tools.
  let federation: FederationHandle | undefined;
  if (registry && pack) {
    if (!isMandateLive(pack)) {
      console.error(
        "aithos-mcp gateway: mandate not live (window) — no federated tools exposed",
      );
    } else {
      federation = await federate({
        server: server as unknown as Parameters<typeof federate>[0]["server"],
        scopes: pack.mandate.scopes,
        mandateId: pack.mandate.id,
        registry,
        ...(auditLog ? { auditLogPath: auditLog } : {}),
      });
    }
  }

  const transport = new StdioServerTransport();
  // T6 — tear down downstream subprocesses when the session ends.
  if (federation) {
    transport.onclose = () => {
      void federation!.teardown();
    };
    const onSignal = () => {
      void federation!.teardown().finally(() => process.exit(0));
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
  }
  await server.connect(transport);
  // The stdio transport keeps stdin open for us; no further work needed.
}

async function runHttp(opts: CliOpts, pack?: MandatePack): Promise<void> {
  const port = Number(opts.port ?? "8787");
  const host = opts.host ?? "127.0.0.1";
  const token = process.env.AITHOS_MCP_TOKEN;
  if (!token) {
    throw new Error(
      "AITHOS_MCP_TOKEN must be set in the environment when using --transport http",
    );
  }

  // One MCP server instance + one transport *per session*. In stateful mode
  // we keep them in a map keyed by the session id the transport hands out.
  interface Session {
    transport: StreamableHTTPServerTransport;
    server: Awaited<ReturnType<typeof createServer>>;
  }
  const sessions = new Map<string, Session>();

  const authorize = (req: http.IncomingMessage): boolean => {
    const h = req.headers["authorization"];
    if (typeof h !== "string") return false;
    const [scheme, value] = h.split(" ", 2);
    return scheme?.toLowerCase() === "bearer" && value === token;
  };

  const httpServer = http.createServer(async (req, res) => {
    if (!req.url) {
      res.statusCode = 400;
      res.end();
      return;
    }
    // Only expose /mcp for JSON-RPC + SSE. /healthz for liveness.
    if (req.url === "/healthz") {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true, name: "aithos-mcp" }));
      return;
    }
    if (!req.url.startsWith("/mcp")) {
      res.statusCode = 404;
      res.end();
      return;
    }
    if (!authorize(req)) {
      res.statusCode = 401;
      res.setHeader("www-authenticate", 'Bearer realm="aithos-mcp"');
      res.end("unauthorized");
      return;
    }

    try {
      const sessionHeader = req.headers["mcp-session-id"];
      const sessionId =
        typeof sessionHeader === "string" ? sessionHeader : undefined;

      let session: Session | undefined = sessionId
        ? sessions.get(sessionId)
        : undefined;

      // First message on a new session — construct a fresh transport+server.
      if (!session) {
        if (opts.stateless) {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // stateless
          });
          // A per-request server cannot stage a transaction — force the
          // per-write auto-commit behaviour in stateless mode.
          const server = createServer(nodeServerOptions(true, pack));
          await server.connect(transport);
          session = { transport, server };
          // No entry stored; each request is independent.
        } else {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
          });
          const server = createServer(nodeServerOptions(opts.autoCommit === true, pack));
          transport.onclose = () => {
            const sid = transport.sessionId;
            if (sid) sessions.delete(sid);
          };
          await server.connect(transport);
          session = { transport, server };
          // Defer registration until the transport hands us the session id
          // (happens during the initialize handshake).
        }
      }

      // Pipe the request into the transport. For POST, the transport will
      // read the body itself; for GET (SSE) it only needs the request/response.
      await session.transport.handleRequest(req, res);

      // After the first handleRequest the transport assigns its session id;
      // register it so future requests find the same session.
      if (!opts.stateless && session.transport.sessionId) {
        sessions.set(session.transport.sessionId, session);
      }
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            error: (err as Error).message,
          }),
        );
      } else {
        try {
          res.end();
        } catch {
          /* noop */
        }
      }
    }
  });

  httpServer.listen(port, host, () => {
    // eslint-disable-next-line no-console
    console.log(`aithos-mcp: listening on http://${host}:${port}/mcp`);
  });

  const shutdown = () => {
    httpServer.close();
    for (const s of sessions.values()) {
      try {
        s.transport.close();
      } catch {
        /* noop */
      }
    }
  };
  process.on("SIGINT", () => {
    shutdown();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    shutdown();
    process.exit(0);
  });
}

program.parseAsync(process.argv).catch((e: unknown) => {
  // eslint-disable-next-line no-console
  console.error(`aithos-mcp: ${(e as Error).message}`);
  process.exit(1);
});
