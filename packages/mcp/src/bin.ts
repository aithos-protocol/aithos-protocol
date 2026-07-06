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
 *                      `Authorization: Bearer <token>`. The transport itself
 *                      lives in http.ts (startHttpGateway) so its contract is
 *                      testable end to end.
 *
 * Usage:
 *   aithos-mcp                                          # stdio
 *   aithos-mcp --transport stdio
 *   aithos-mcp --transport http --port 8787 [--host 127.0.0.1]
 */
import { Command } from "commander";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
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
  sessionFederation,
  isMandateWindowLive,
  type McpRegistry,
  type FederationHandle,
} from "./gateway.js";
import { startHttpGateway, type HttpGatewayOptions } from "./http.js";
import { createLlmProxy } from "./llm-proxy.js";
import { federateActions, httpActionDispatch, wsActionDispatch } from "./action-federation.js";
import { parseActionSection, type ActionDefinition } from "./actions.js";
import { fileAuditSink } from "./gateway.js";

/** Default audience for the browser-agent "hand" (overridable per actions file). */
const DEFAULT_HAND_AUD = "urn:aithos:downstream:browser-agent";

interface ActionsFile {
  readonly aud?: string;
  readonly actions: readonly ActionDefinition[];
}

/**
 * Load an actions catalogue: `{ aud?, actions: [{ id, goal, params_schema }] }`.
 * (For the demo these are a file; the production source is signed Ethos
 * sections — parseActionSection reads that shape from a section body.)
 */
async function loadActions(p?: string): Promise<ActionsFile | undefined> {
  if (!p) return undefined;
  const raw = JSON.parse(await readFile(path.resolve(p), "utf8")) as {
    aud?: string;
    actions?: unknown[];
  };
  if (!Array.isArray(raw.actions)) {
    throw new Error("actions file: \"actions\" must be an array");
  }
  const actions = raw.actions.map((a) => {
    const o = a as { id?: string; goal?: string; body?: string; title?: string; params_schema?: unknown };
    // Accept either a ready ActionDefinition or a raw Ethos-section shape.
    if (typeof o.body === "string") {
      return parseActionSection({ id: o.id ?? "", title: o.title, body: o.body });
    }
    if (typeof o.id !== "string" || !o.id) throw new Error("actions file: an action is missing id");
    return {
      id: o.id,
      goal: typeof o.goal === "string" ? o.goal : o.id,
      params_schema: (o.params_schema as ActionDefinition["params_schema"]) ?? { type: "object", properties: {} },
    };
  });
  return { ...(raw.aud ? { aud: raw.aud } : {}), actions };
}

const nodeIo: HostIo = {
  readTextFile: (p) => readFile(p, "utf8"),
  resolvePath: (p) => path.resolve(p),
};

/**
 * The node host's createServer options: filesystem storage + (optional) host io.
 *
 * Security: `io` grants the server the ability to read arbitrary files named in
 * tool arguments (path-form `mandate` / `agent_key`, which contain `seed_hex`).
 * That is acceptable for the **stdio** transport, where the caller *is* the
 * local user who already owns the filesystem. It is NOT acceptable for the
 * **http** transport, where any bearer-authenticated (possibly remote) client
 * could pass `agent_key: "/…/identities/<victim>/self.sealed.json"` and have the
 * server read it back (LFI, CWE-22). HTTP callers therefore get NO `io`:
 * id-form mandates still resolve through the storage backend, and path-form
 * mandates / agent keyfiles fail closed with a clear "resolves by id only"
 * error (see auth.ts). Pass `io` only for stdio.
 */
function nodeServerOptions(
  autoCommit?: boolean,
  pack?: MandatePack,
  io?: HostIo,
): CreateServerOptions {
  return {
    storage: new FilesystemStorage(),
    home: AITHOS_HOME,
    manifestPath: ethosManifestPath,
    ...(io ? { io } : {}),
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

/**
 * Per-call liveness for a mandate pack (G1/L1): validity window + a FRESH
 * revocation lookup against the local store on every dispatch. Throws with
 * the precise reason; callers fail closed.
 */
function packLiveness(pack: MandatePack): () => Promise<void> {
  const storage = new FilesystemStorage();
  return async () => {
    if (!isMandateWindowLive(pack.mandate)) {
      throw new Error(
        `mandate ${pack.mandate.id} is outside its validity window`,
      );
    }
    const rev = await storage.findRevocation(pack.mandate.id);
    if (rev) {
      throw new Error(
        `mandate ${pack.mandate.id} was revoked at ${rev.revoked_at}` +
          (rev.reason ? ` (${rev.reason})` : ""),
      );
    }
  };
}

async function loadRegistry(p?: string): Promise<McpRegistry | undefined> {
  if (!p) return undefined;
  const text = await readFile(path.resolve(p), "utf8");
  return parseRegistry(text);
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
  llmProxy?: boolean;
  llmUpstream?: string;
  actions?: string;
  actionsDownstream?: string;
  actionsBearer?: string;
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
      "gateway). A tool is exposed only if the mandate carries its scope " +
      "(mcp.<id>, or the entry's per-tool tool_scopes). Requires " +
      "--mandate-pack. Works over stdio and stateful HTTP.",
  )
  .option(
    "--audit-log <path>",
    "Append a JSONL audit line per federated tool call (default: " +
      "./aithos-audit.jsonl).",
  )
  .option(
    "--llm-proxy",
    "Mount the transparent LLM pass-through proxy under /llm (http " +
      "transport only). The cage's agent points ANTHROPIC_BASE_URL at it; " +
      "metadata is logged, bodies and credentials never are.",
    false,
  )
  .option(
    "--llm-upstream <url>",
    "Upstream base URL for --llm-proxy. Env: AITHOS_LLM_UPSTREAM.",
  )
  .option(
    "--actions <path>",
    "Expose owner-authored actions (Mandated Intent Envelope) as MCP tools. " +
      "A tool per action the mandate grants (mcp.browser.<id>); on call the " +
      "gateway validates params against the signed schema, signs an envelope, " +
      "and dispatches it. Requires --mandate-pack and --actions-downstream.",
  )
  .option(
    "--actions-downstream <url>",
    "URL of the hand that executes actions. http(s):// -> POST <url>/run_action; " +
      "ws(s):// -> run_action over the WebSocket (the real browser-agent at /ws).",
  )
  .option(
    "--actions-bearer <token>",
    "Bearer presented to a ws(s):// actions downstream at the handshake. " +
      "Env: AITHOS_ACTIONS_BEARER.",
  )
  .action(async (opts: CliOpts) => {
    if (!opts.actionsBearer && process.env.AITHOS_ACTIONS_BEARER) {
      opts.actionsBearer = process.env.AITHOS_ACTIONS_BEARER;
    }
    const pack = await loadPack(opts.mandatePack);
    const registry = await loadRegistry(opts.mcpRegistry);
    const actions = await loadActions(opts.actions);
    if (registry && !pack) {
      throw new Error("--mcp-registry requires --mandate-pack (scopes drive exposure)");
    }
    if (actions && (!pack || !opts.actionsDownstream)) {
      throw new Error("--actions requires --mandate-pack and --actions-downstream");
    }
    if (actions && opts.transport !== "http") {
      throw new Error("--actions is supported with --transport http (stateful) only");
    }
    if (opts.transport === "stdio") {
      if (opts.llmProxy) {
        throw new Error("--llm-proxy requires --transport http");
      }
      await runStdio(opts.autoCommit === true, pack, registry, opts.auditLog);
    } else {
      if (registry && opts.stateless) {
        // Per-request servers cannot own a federation lifecycle (they would
        // spawn + tear down every downstream on every request). Fail loud.
        throw new Error(
          "--mcp-registry requires stateful HTTP sessions (drop --stateless)",
        );
      }
      await runHttp(opts, pack, registry, actions);
    }
  });

async function runStdio(
  autoCommit: boolean,
  pack?: MandatePack,
  registry?: McpRegistry,
  auditLog?: string,
): Promise<void> {
  // stdio: caller is the local user, so host file access (io) is safe.
  const server = createServer(nodeServerOptions(autoCommit, pack, nodeIo));

  // Self-wired gateway: federate downstream MCPs before connecting the
  // transport (tools must be registered up front). Only when a pack is present
  // and live; an expired/not-yet-valid mandate exposes NO federated tools.
  let federation: FederationHandle | undefined;
  if (registry && pack) {
    if (!isMandateWindowLive(pack.mandate)) {
      console.error(
        "aithos-mcp gateway: mandate not live (window) — no federated tools exposed",
      );
    } else {
      federation = await federate({
        server: server as unknown as Parameters<typeof federate>[0]["server"],
        scopes: pack.mandate.scopes,
        mandateId: pack.mandate.id,
        registry,
        liveness: packLiveness(pack),
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

async function runHttp(
  opts: CliOpts,
  pack?: MandatePack,
  registry?: McpRegistry,
  actions?: ActionsFile,
): Promise<void> {
  const token = process.env.AITHOS_MCP_TOKEN;
  if (!token) {
    throw new Error(
      "AITHOS_MCP_TOKEN must be set in the environment when using --transport http",
    );
  }

  // Compose the per-session hook: registry (MCP downstreams) + actions
  // (Mandated Intent Envelope). Both register tools before the transport
  // connects; only actions has no teardown (its dispatch is stateless).
  const regHook =
    registry && pack
      ? sessionFederation({
          pack,
          registry,
          liveness: packLiveness(pack),
          ...(opts.auditLog ? { auditLogPath: opts.auditLog } : {}),
        })
      : undefined;

  const onSessionServer =
    regHook || (actions && pack)
      ? async (server: ReturnType<typeof createServer>) => {
          const dispose = regHook
            ? await regHook(server as unknown as Parameters<NonNullable<typeof regHook>>[0])
            : undefined;
          if (actions && pack && opts.actionsDownstream && isMandateWindowLive(pack.mandate)) {
            federateActions({
              server: server as unknown as Parameters<typeof federateActions>[0]["server"],
              actions: actions.actions,
              scopes: pack.mandate.scopes,
              mandate: pack.mandate,
              ownerDid: pack.mandate.issuer,
              aud: actions.aud ?? DEFAULT_HAND_AUD,
              delegateKey: {
                seed: hexToBytes(pack.agent_key.seed_hex),
                pubkeyMultibase: pack.agent_key.pubkey_multibase,
              },
              dispatch: /^wss?:\/\//.test(opts.actionsDownstream)
                ? wsActionDispatch(opts.actionsDownstream, { bearer: opts.actionsBearer })
                : httpActionDispatch(opts.actionsDownstream),
              liveness: packLiveness(pack),
              ...(opts.auditLog ? { auditSink: fileAuditSink(opts.auditLog) } : {}),
            });
          }
          return dispose;
        }
      : undefined;

  const handle = await startHttpGateway({
    host: opts.host ?? "127.0.0.1",
    port: Number(opts.port ?? "8787"),
    token,
    stateless: opts.stateless === true,
    // A per-request (stateless) server cannot stage a transaction — force the
    // per-write auto-commit behaviour there. NEVER pass nodeIo here (S1).
    serverOptions: ({ stateless }) =>
      nodeServerOptions(stateless ? true : opts.autoCommit === true, pack),
    // Container gateway core (§13.6): every stateful session federates the
    // registry (MCP downstreams) AND the actions (Mandated Intent Envelope)
    // against the pack's scopes; out-of-scope tools/actions stay invisible.
    ...(onSessionServer
      ? { onSessionServer: onSessionServer as unknown as NonNullable<HttpGatewayOptions["onSessionServer"]> }
      : {}),
    // §13.5 I1/I2: the cage's inference traverses the gateway. Transparent
    // pass-through in P0 (subscription-credential mode §13.7.2); custody,
    // token budget and server-side tool filtering are P2.
    ...(opts.llmProxy
      ? {
          extraRoutes: createLlmProxy({
            upstream:
              opts.llmUpstream ??
              process.env.AITHOS_LLM_UPSTREAM ??
              "https://api.anthropic.com",
            prefix: "/llm",
            // L1 — a revoked mandate stops inference too. Without a pack the
            // route stays open (nothing to gate on): container deployments
            // MUST boot the gateway with --mandate-pack.
            ...(pack ? { liveness: packLiveness(pack) } : {}),
          }),
        }
      : {}),
  });

  const shutdown = () => {
    void handle.close();
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
