// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Streamable-HTTP gateway factory — the node host's HTTP transport, extracted
 * from bin.ts into a testable unit (SPEC-container-runtime §13.6 G5: the
 * container gateway IS this transport, so its contract is pinned by tests).
 *
 * Responsibilities:
 *   - one MCP server + transport PER SESSION (stateful) or per request
 *     (stateless), built from the host-injected `serverOptions`;
 *   - constant-time bearer authentication on /mcp (S2, audit 2026-07-02);
 *   - NO HostIo ever reaches the per-session servers — that stays a host
 *     (bin.ts) decision, and the LFI guard tests pin it end to end (S1/S3);
 *   - /healthz liveness for container orchestration.
 *
 * Deliberately NOT here: transport-level tool logic (server.ts), downstream
 * federation mechanics (gateway.ts). The factory only wires them together.
 */
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID, timingSafeEqual } from "node:crypto";
import http from "node:http";

import { createServer, type CreateServerOptions } from "./server.js";

/* -------------------------------------------------------------------------- */
/* Bearer auth                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Build a constant-time bearer authorizer for the shared gateway token.
 *
 * timingSafeEqual requires equal-length buffers, so the comparison is gated on
 * length first — the length of a rejected guess is not itself sensitive.
 */
export function bearerAuthorizer(
  token: string,
): (req: Pick<http.IncomingMessage, "headers">) => boolean {
  const expected = Buffer.from(token, "utf8");
  return (req) => {
    const h = req.headers["authorization"];
    if (typeof h !== "string") return false;
    const [scheme, value] = h.split(" ", 2);
    if (scheme?.toLowerCase() !== "bearer" || typeof value !== "string") {
      return false;
    }
    const provided = Buffer.from(value, "utf8");
    return provided.length === expected.length && timingSafeEqual(provided, expected);
  };
}

/* -------------------------------------------------------------------------- */
/* Gateway factory                                                            */
/* -------------------------------------------------------------------------- */

export interface HttpGatewayOptions {
  /** Bind host. Default: 127.0.0.1. */
  readonly host?: string;
  /** Bind port. 0 picks an ephemeral port (tests). Default: 8787. */
  readonly port?: number;
  /** Shared bearer token — REQUIRED (fail closed: no token, no server). */
  readonly token: string;
  /** Stateless mode: a fresh server per request, no session map. */
  readonly stateless?: boolean;
  /**
   * Per-session MCP server options, injected by the host. Called once per
   * session (stateful) or per request (stateless). The host decides storage,
   * pack wiring and autoCommit; the factory NEVER adds a HostIo of its own
   * (S1 — the HTTP surface must not read host files named in tool args).
   */
  readonly serverOptions: (ctx: { stateless: boolean }) => CreateServerOptions;
  /**
   * Called after a session's server exists but before the transport is
   * connected — the hook where the container gateway federates downstream
   * tools for the session. Returns an optional async disposer invoked when
   * the session closes.
   */
  readonly onSessionServer?: (
    server: ReturnType<typeof createServer>,
    ctx: { sessionKind: "stateful" | "stateless" },
  ) => Promise<(() => Promise<void>) | undefined>;
  /**
   * Optional extra HTTP routes mounted BEFORE auth (e.g. the LLM pass-through
   * proxy at /llm — authenticated by network position inside the cage, not by
   * the MCP bearer; see deploy/container/README). Return true when the route
   * handled the request.
   */
  readonly extraRoutes?: (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ) => Promise<boolean> | boolean;
  /** Diagnostics sink. Default: console.log. */
  readonly log?: (msg: string) => void;
}

export interface HttpGatewayHandle {
  /** The port actually bound (useful with port 0). */
  readonly port: number;
  readonly server: http.Server;
  /** Stop listening and tear down every live session. */
  close(): Promise<void>;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  server: ReturnType<typeof createServer>;
  dispose?: (() => Promise<void>) | undefined;
}

/** Start the HTTP gateway. Resolves once the listener is bound. */
export async function startHttpGateway(
  opts: HttpGatewayOptions,
): Promise<HttpGatewayHandle> {
  const host = opts.host ?? "127.0.0.1";
  const port = opts.port ?? 8787;
  const log = opts.log ?? ((m: string) => console.log(m));
  if (!opts.token) {
    throw new Error("startHttpGateway: a bearer token is required (fail closed)");
  }
  const authorize = bearerAuthorizer(opts.token);
  const sessions = new Map<string, Session>();

  const newSession = async (kind: "stateful" | "stateless"): Promise<Session> => {
    const transport = new StreamableHTTPServerTransport(
      kind === "stateless"
        ? { sessionIdGenerator: undefined }
        : { sessionIdGenerator: () => randomUUID() },
    );
    const server = createServer(opts.serverOptions({ stateless: kind === "stateless" }));
    const dispose = opts.onSessionServer
      ? await opts.onSessionServer(server, { sessionKind: kind })
      : undefined;
    const session: Session = { transport, server, dispose };
    if (kind === "stateful") {
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) sessions.delete(sid);
        if (dispose) void dispose();
      };
    }
    await server.connect(transport);
    return session;
  };

  const httpServer = http.createServer(async (req, res) => {
    if (!req.url) {
      res.statusCode = 400;
      res.end();
      return;
    }
    if (req.url === "/healthz") {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true, name: "aithos-mcp" }));
      return;
    }
    // Host-mounted routes (LLM proxy) get first refusal, before the MCP gate.
    if (opts.extraRoutes && (await opts.extraRoutes(req, res))) {
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

      if (!session) {
        session = await newSession(opts.stateless ? "stateless" : "stateful");
      }

      await session.transport.handleRequest(req, res);

      // The transport assigns its session id during the initialize handshake;
      // register it so future requests find the same session.
      if (!opts.stateless && session.transport.sessionId) {
        sessions.set(session.transport.sessionId, session);
      }
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: (err as Error).message }));
      } else {
        try {
          res.end();
        } catch {
          /* noop */
        }
      }
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });
  const bound = httpServer.address();
  const actualPort =
    typeof bound === "object" && bound !== null ? bound.port : port;
  log(`aithos-mcp: listening on http://${host}:${actualPort}/mcp`);

  return {
    port: actualPort,
    server: httpServer,
    async close() {
      const closing = new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
      });
      for (const s of sessions.values()) {
        try {
          s.transport.close();
        } catch {
          /* noop */
        }
        if (s.dispose) {
          try {
            await s.dispose();
          } catch {
            /* noop */
          }
        }
      }
      sessions.clear();
      await closing;
    },
  };
}
