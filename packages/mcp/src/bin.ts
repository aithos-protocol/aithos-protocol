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
  .action(async (opts: CliOpts) => {
    const pack = await loadPack(opts.mandatePack);
    const registry = await loadRegistry(opts.mcpRegistry);
    if (registry && !pack) {
      throw new Error("--mcp-registry requires --mandate-pack (scopes drive exposure)");
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
      await runHttp(opts, pack, registry);
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
): Promise<void> {
  const token = process.env.AITHOS_MCP_TOKEN;
  if (!token) {
    throw new Error(
      "AITHOS_MCP_TOKEN must be set in the environment when using --transport http",
    );
  }

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
    // registry against the pack's scopes; out-of-scope tools stay invisible.
    ...(registry && pack
      ? {
          onSessionServer: sessionFederation({
            pack,
            registry,
            ...(opts.auditLog ? { auditLogPath: opts.auditLog } : {}),
          }) as unknown as NonNullable<HttpGatewayOptions["onSessionServer"]>,
        }
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
