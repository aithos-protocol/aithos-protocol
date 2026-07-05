// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Transparent LLM pass-through proxy (SPEC-container-runtime §13.5, PLAN P0.1).
 *
 * The cage has no egress, so the agent's model inference must traverse the
 * gateway (I1). P0 is a TRANSPARENT reverse proxy:
 *
 *   - exactly ONE upstream base URL — the allowlist is the configuration
 *     itself, there is no dynamic target resolution (no SSRF surface);
 *   - the agent is configured by base-URL redirection alone
 *     (ANTHROPIC_BASE_URL=$GATEWAY/llm — I2);
 *   - auth headers pass through UNTOUCHED: in subscription-credential mode
 *     (§13.7.2) the credential lives with the runtime's agent and the gateway
 *     must not see, store or rewrite it. Custody mode (inject the key at the
 *     gateway) is P2 (§13.5 I3);
 *   - request/response bodies stream both ways (SSE works);
 *   - accountability without content capture (I6): one log entry per call —
 *     method, path (query stripped), status, byte counts, duration. NEVER
 *     bodies, NEVER header values.
 *
 * No MCP bearer on this route: inside the cage, network position is the
 * authenticator — the runtime can reach nothing but the gateway anyway (N1).
 * Deployments exposing the gateway beyond the cage network MUST NOT mount
 * the proxy there.
 */
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

/** One audited (metadata-only) proxied call. */
export interface LlmProxyLogEntry {
  readonly ts: string;
  readonly method: string;
  /** Path relative to the upstream, query stripped. */
  readonly path: string;
  readonly status: number;
  readonly reqBytes: number;
  readonly resBytes: number;
  readonly ms: number;
  readonly upstreamHost: string;
}

export interface LlmProxyOptions {
  /** Upstream base URL (e.g. https://api.anthropic.com). REQUIRED. */
  readonly upstream: string;
  /** Route prefix the proxy answers under. Default: /llm */
  readonly prefix?: string;
  /** Metadata sink. Default: JSON line on stdout. */
  readonly log?: (entry: LlmProxyLogEntry) => void;
  /**
   * Per-call liveness guard (L1, SPEC-container-runtime §13.9): throw to
   * refuse the inference with 403. A revoked mandate stops the agent from
   * ACTING (tools) and from THINKING (this route) alike.
   */
  readonly liveness?: () => Promise<void>;
}

/** Hop-by-hop headers never forwarded in either direction (RFC 9110 §7.6.1). */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
]);

function forwardableHeaders(
  headers: http.IncomingHttpHeaders,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Build the proxy route. Returns a handler compatible with the HTTP gateway's
 * `extraRoutes` mount: it answers `true` when it owned the request.
 */
export function createLlmProxy(
  opts: LlmProxyOptions,
): (req: http.IncomingMessage, res: http.ServerResponse) => Promise<boolean> {
  const prefix = opts.prefix ?? "/llm";
  const upstream = new URL(opts.upstream);
  const transport = upstream.protocol === "https:" ? https : http;
  const log =
    opts.log ??
    ((entry: LlmProxyLogEntry) =>
      console.log(JSON.stringify({ kind: "aithos.llm.proxy", ...entry })));

  return (req, res) =>
    new Promise<boolean>((resolve) => {
      const url = req.url ?? "";
      if (url !== prefix && !url.startsWith(`${prefix}/`)) {
        resolve(false);
        return;
      }
      const suffix = url.slice(prefix.length) || "/";
      const gate = opts.liveness ? opts.liveness() : Promise.resolve();
      gate.then(
        () => run(),
        (err: Error) => {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `inference refused: ${err.message}` }));
          resolve(true);
        },
      );
      const run = () => {
      const target = new URL(suffix, upstream);
      const started = Date.now();
      let reqBytes = 0;
      let resBytes = 0;

      const emit = (status: number) => {
        try {
          log({
            ts: new Date(started).toISOString(),
            method: req.method ?? "GET",
            path: target.pathname,
            status,
            reqBytes,
            resBytes,
            ms: Date.now() - started,
            upstreamHost: upstream.host,
          });
        } catch {
          /* the log sink must never break the proxy */
        }
      };

      const forward = transport.request(
        target,
        {
          method: req.method,
          headers: forwardableHeaders(req.headers),
        },
        (upstreamRes) => {
          const status = upstreamRes.statusCode ?? 502;
          const headers: Record<string, string | string[]> = {};
          for (const [k, v] of Object.entries(upstreamRes.headers)) {
            if (v === undefined) continue;
            if (HOP_BY_HOP.has(k.toLowerCase())) continue;
            headers[k] = v;
          }
          res.writeHead(status, headers);
          upstreamRes.on("data", (chunk: Buffer) => {
            resBytes += chunk.length;
            res.write(chunk);
          });
          upstreamRes.on("end", () => {
            res.end();
            emit(status);
            resolve(true);
          });
          upstreamRes.on("error", () => {
            try {
              res.end();
            } catch {
              /* noop */
            }
            emit(status);
            resolve(true);
          });
        },
      );

      forward.on("error", (err: Error) => {
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `llm upstream unreachable: ${err.message}` }));
        } else {
          try {
            res.end();
          } catch {
            /* noop */
          }
        }
        emit(502);
        resolve(true);
      });

      req.on("data", (chunk: Buffer) => {
        reqBytes += chunk.length;
      });
      req.on("aborted", () => {
        forward.destroy();
      });
      req.pipe(forward);
      };
    });
}
