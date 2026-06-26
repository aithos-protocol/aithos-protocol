// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Self-wired MCP gateway (proto, cf. PLAN-PROTO-SELFWIRED.md, Phase 1).
 *
 * The NODE host federates downstream MCP servers declared in an owner-defined
 * registry, behind the single Aithos MCP. For every registry server whose
 * per-server scope `mcp.<id>` is carried by the session mandate, the gateway:
 *
 *   1. connects an MCP client to it (stdio spawn — http later),
 *   2. lists its tools and re-exposes them NAMESPACED (`<id>__<tool>`) on the
 *      Aithos server, gated by the scope,
 *   3. routes each `tools/call` to the owning downstream client,
 *   4. appends a per-call audit line attributed to the mandate.
 *
 * Out of scope for the proto: OAuth/custody, credential vault, first-party
 * connectors, per-action scopes, HTTP transport, connection pooling. The
 * downstream server holds its OWN credential (e.g. a GitHub PAT in the registry
 * entry's env); the session pack only carries the `mcp.<id>` scope.
 *
 * NODE-ONLY: spawns subprocesses, reads/writes files. Never imported by the
 * isomorphic core (server.ts) — wired from bin.ts, like FilesystemStorage.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { appendFile } from "node:fs/promises";

/* -------------------------------------------------------------------------- */
/* T1 — registry format + parsing                                             */
/* -------------------------------------------------------------------------- */

/** A downstream MCP spawned as a local subprocess (self-wired / local host). */
export interface StdioRegistryServer {
  /** Stable id; drives the scope `mcp.<id>` and the `<id>__` tool namespace. */
  readonly id: string;
  readonly transport: "stdio";
  /** Executable to spawn (e.g. "npx"). */
  readonly command: string;
  /** Arguments (e.g. ["-y", "@modelcontextprotocol/server-github"]). */
  readonly args?: readonly string[];
  /** Extra env for the subprocess (e.g. the downstream's own credential). */
  readonly env?: Readonly<Record<string, string>>;
}

/** A downstream MCP reached over HTTP (the only kind that works hosted/Lambda). */
export interface HttpRegistryServer {
  readonly id: string;
  readonly transport: "http";
  /** Streamable-HTTP MCP endpoint, e.g. https://api.githubcopilot.com/mcp/ */
  readonly url: string;
  /** Static headers to send on every request. */
  readonly headers?: Readonly<Record<string, string>>;
  /** Name of an env var whose value is sent as `Authorization: Bearer <value>`. */
  readonly bearer_env?: string;
}

/** One downstream MCP server the owner makes available. */
export type RegistryServer = StdioRegistryServer | HttpRegistryServer;

export interface McpRegistry {
  readonly servers: readonly RegistryServer[];
}

/** Parse + structurally validate a registry file. Throws on anything malformed. */
export function parseRegistry(jsonText: string): McpRegistry {
  let raw: unknown;
  try {
    raw = JSON.parse(jsonText);
  } catch (e) {
    throw new Error(`mcp registry is not valid JSON: ${(e as Error).message}`);
  }
  const r = raw as Partial<McpRegistry>;
  if (!Array.isArray(r.servers)) {
    throw new Error('mcp registry: "servers" must be an array');
  }
  const seen = new Set<string>();
  const list = r.servers as unknown[];
  const isStrMap = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null;
  for (let i = 0; i < list.length; i++) {
    const where = `mcp registry: servers[${i}]`;
    const item = list[i];
    if (!isStrMap(item)) throw new Error(`${where} must be an object`);
    const o = item;
    if (typeof o["id"] !== "string" || !o["id"]) throw new Error(`${where}.id missing`);
    const id = o["id"];
    if (seen.has(id)) throw new Error(`${where}.id duplicated ("${id}")`);
    seen.add(id);

    if (o["transport"] === "stdio") {
      if (typeof o["command"] !== "string" || !o["command"]) {
        throw new Error(`${where}.command missing`);
      }
      const args = o["args"];
      if (args !== undefined && (!Array.isArray(args) || args.some((a) => typeof a !== "string"))) {
        throw new Error(`${where}.args must be a string array`);
      }
      if (o["env"] !== undefined) {
        if (!isStrMap(o["env"])) throw new Error(`${where}.env must be an object`);
        for (const [k, v] of Object.entries(o["env"])) {
          if (typeof v !== "string") throw new Error(`${where}.env.${k} must be a string`);
        }
      }
    } else if (o["transport"] === "http") {
      if (typeof o["url"] !== "string" || !/^https?:\/\//.test(o["url"])) {
        throw new Error(`${where}.url must be an http(s) URL`);
      }
      if (o["headers"] !== undefined) {
        if (!isStrMap(o["headers"])) throw new Error(`${where}.headers must be an object`);
        for (const [k, v] of Object.entries(o["headers"])) {
          if (typeof v !== "string") throw new Error(`${where}.headers.${k} must be a string`);
        }
      }
      if (o["bearer_env"] !== undefined && typeof o["bearer_env"] !== "string") {
        throw new Error(`${where}.bearer_env must be a string`);
      }
    } else {
      throw new Error(`${where}.transport must be "stdio" or "http"`);
    }
  }
  return r as McpRegistry;
}

/* -------------------------------------------------------------------------- */
/* JSON Schema -> Zod raw shape (downstream tools advertise JSON Schema; the   */
/* Aithos McpServer.registerTool wants Zod and re-emits JSON Schema. Lossy by  */
/* design — the downstream server re-validates; we only need the model to see  */
/* a reasonable shape.)                                                        */
/* -------------------------------------------------------------------------- */

type JsonSchema = Record<string, unknown>;

function jsonSchemaToZod(node: unknown): z.ZodTypeAny {
  if (!node || typeof node !== "object") return z.any();
  const s = node as JsonSchema;

  if (Array.isArray(s["enum"]) && s["enum"].length > 0) {
    const vals = s["enum"].filter((v) => typeof v === "string") as string[];
    if (vals.length === s["enum"].length && vals.length > 0) {
      return vals.length === 1
        ? z.literal(vals[0]!)
        : z.enum(vals as [string, ...string[]]);
    }
    return z.any();
  }

  const t = s["type"];
  const type = Array.isArray(t) ? t.find((x) => x !== "null") : t;
  let out: z.ZodTypeAny;
  switch (type) {
    case "string":
      out = z.string();
      break;
    case "number":
      out = z.number();
      break;
    case "integer":
      out = z.number().int();
      break;
    case "boolean":
      out = z.boolean();
      break;
    case "array":
      out = z.array(jsonSchemaToZod(s["items"]));
      break;
    case "object":
      out = z.object(shapeFromObjectSchema(s)).passthrough();
      break;
    default:
      out = z.any();
  }
  if (typeof s["description"] === "string") out = out.describe(s["description"]);
  return out;
}

function shapeFromObjectSchema(s: JsonSchema): z.ZodRawShape {
  const props = (s["properties"] as Record<string, unknown> | undefined) ?? {};
  const required = new Set(
    (Array.isArray(s["required"]) ? s["required"] : []).filter(
      (x): x is string => typeof x === "string",
    ),
  );
  const shape: z.ZodRawShape = {};
  for (const [key, sub] of Object.entries(props)) {
    let field = jsonSchemaToZod(sub);
    if (!required.has(key)) field = field.optional();
    shape[key] = field;
  }
  return shape;
}

/** Top-level input schema -> raw shape for registerTool. */
export function inputSchemaToShape(inputSchema: unknown): z.ZodRawShape {
  if (inputSchema && typeof inputSchema === "object") {
    return shapeFromObjectSchema(inputSchema as JsonSchema);
  }
  return {};
}

/* -------------------------------------------------------------------------- */
/* Federation                                                                 */
/* -------------------------------------------------------------------------- */

/** The slice of a downstream MCP client the gateway consumes (real `Client`
 * satisfies it; fakes keep tests network-free). */
export interface DownstreamClient {
  listTools(): Promise<{
    tools: ReadonlyArray<{
      name: string;
      description?: string;
      inputSchema?: Record<string, unknown>;
    }>;
  }>;
  callTool(params: { name: string; arguments: Record<string, unknown> }): Promise<unknown>;
  close(): Promise<void>;
}

/** The slice of the Aithos McpServer the gateway needs (keeps wiring/tests easy). */
export interface RegisterableServer {
  registerTool(
    name: string,
    config: {
      title?: string;
      description?: string;
      inputSchema?: z.ZodRawShape;
    },
    cb: (
      args: Record<string, unknown>,
    ) => Promise<{
      content: Array<{ type: "text"; text: string }>;
      isError?: boolean;
    }>,
  ): unknown;
}

export interface FederateOptions {
  readonly server: RegisterableServer;
  /** The session mandate's scopes — drives `mcp.<id>` gating. */
  readonly scopes: readonly string[];
  /** Attribution for the audit log. */
  readonly mandateId: string;
  readonly registry: McpRegistry;
  /**
   * Where audit entries go. Default: a JSONL file (`auditLogPath`). Hosted hosts
   * (Lambda) pass `consoleAuditSink()` so entries land in CloudWatch instead of
   * an ephemeral file.
   */
  readonly auditSink?: AuditSink;
  /** Path for the default file sink (used only when `auditSink` is omitted). Default: ./aithos-audit.jsonl */
  readonly auditLogPath?: string;
  /** Diagnostics sink (default: stderr). */
  readonly log?: (msg: string) => void;
  /**
   * How to connect a downstream server. Default: spawn it over stdio. Injected
   * in tests to avoid spawning real subprocesses.
   */
  readonly connect?: (entry: RegistryServer) => Promise<DownstreamClient>;
}

export interface FederationHandle {
  /** Number of downstream servers actually connected + exposed. */
  readonly connected: number;
  /** Close every downstream client / kill subprocesses. */
  teardown(): Promise<void>;
}

const hasScope = (scopes: readonly string[], id: string): boolean =>
  scopes.includes(`mcp.${id}`);

/** Default connector: dispatch on the entry's transport. */
async function defaultConnect(entry: RegistryServer): Promise<DownstreamClient> {
  return entry.transport === "http" ? connectHttp(entry) : connectStdio(entry);
}

/** Spawn the downstream server over stdio (local host only — not Lambda). */
async function connectStdio(entry: StdioRegistryServer): Promise<DownstreamClient> {
  const client = new Client({ name: `aithos-gateway:${entry.id}`, version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: entry.command,
    args: [...(entry.args ?? [])],
    env: { ...getDefaultEnvironment(), ...(entry.env ?? {}) },
  });
  await client.connect(transport);
  return client as unknown as DownstreamClient;
}

/** Connect to a downstream MCP over Streamable HTTP (works hosted/Lambda). */
async function connectHttp(entry: HttpRegistryServer): Promise<DownstreamClient> {
  const headers: Record<string, string> = { ...(entry.headers ?? {}) };
  if (entry.bearer_env) {
    const v = process.env[entry.bearer_env];
    if (v) headers["Authorization"] = `Bearer ${v}`;
  }
  const client = new Client({ name: `aithos-gateway:${entry.id}`, version: "0.1.0" });
  const transport = new StreamableHTTPClientTransport(new URL(entry.url), {
    requestInit: { headers },
  });
  await client.connect(transport);
  return client as unknown as DownstreamClient;
}

/**
 * Connect to every authorized registry server and re-expose its tools on the
 * Aithos server. Returns a handle whose `teardown()` the host must call on
 * session close (T6). Connection failures DEGRADE GRACEFULLY: the offending
 * server is skipped with a warning, the session keeps running.
 */
export async function federate(opts: FederateOptions): Promise<FederationHandle> {
  const log = opts.log ?? ((m: string) => console.error(`aithos-mcp gateway: ${m}`));
  const sink = opts.auditSink ?? fileAuditSink(opts.auditLogPath ?? "./aithos-audit.jsonl");
  const connect = opts.connect ?? defaultConnect;
  const clients: DownstreamClient[] = [];
  let connected = 0;

  for (const entry of opts.registry.servers) {
    // T3 — scope gate (per server): never even connect to a server the mandate
    // does not grant. (Saves spawning a subprocess for nothing.)
    if (!hasScope(opts.scopes, entry.id)) {
      log(`skip "${entry.id}" (mandate lacks scope mcp.${entry.id})`);
      continue;
    }

    let client: DownstreamClient | undefined;
    try {
      client = await connect(entry);
      const listed = await client.listTools();
      for (const tool of listed.tools) {
        registerFederatedTool(opts, entry, client, tool, sink);
      }
      clients.push(client);
      connected += 1;
      log(`federated "${entry.id}" (${listed.tools.length} tools)`);
    } catch (e) {
      // Degrade: skip this server, keep the session alive (T2 acceptance).
      log(`could not federate "${entry.id}": ${(e as Error).message}`);
      if (client) {
        try {
          await client.close();
        } catch {
          /* noop */
        }
      }
    }
  }

  return {
    connected,
    async teardown() {
      await Promise.all(
        clients.map((c) =>
          c.close().catch(() => {
            /* best-effort */
          }),
        ),
      );
    },
  };
}

function registerFederatedTool(
  opts: FederateOptions,
  entry: RegistryServer,
  client: DownstreamClient,
  tool: { name: string; description?: string; inputSchema?: Record<string, unknown> },
  sink: AuditSink,
): void {
  const exposedName = `${entry.id}__${tool.name}`;
  opts.server.registerTool(
    exposedName,
    {
      ...(tool.description
        ? { description: `[${entry.id}] ${tool.description}` }
        : { description: `[${entry.id}] ${tool.name}` }),
      inputSchema: inputSchemaToShape(tool.inputSchema),
    },
    async (args: Record<string, unknown>) => {
      // T3 — defense in depth: re-check the scope at dispatch, even though the
      // tool would not have been registered without it.
      if (!hasScope(opts.scopes, entry.id)) {
        await emit(sink, opts.mandateId, entry.id, tool.name, args, "denied");
        return {
          content: [
            { type: "text" as const, text: `denied: mandate lacks scope mcp.${entry.id}` },
          ],
          isError: true,
        };
      }
      // T4 — route to the owning downstream client + map the result.
      const r = await callDownstream(client, tool.name, args ?? {});
      await emit(
        sink,
        opts.mandateId,
        entry.id,
        tool.name,
        args,
        r.isError ? "error" : "ok",
        r.isError ? r.payload : undefined,
      );
      return {
        content: [{ type: "text" as const, text: r.payload }],
        isError: r.isError,
      };
    },
  );
}

/** Project a downstream CallToolResult onto {payload, isError} (cf. SDK callMcpTool). */
async function callDownstream(
  client: DownstreamClient,
  name: string,
  input: Record<string, unknown>,
): Promise<{ payload: string; isError: boolean }> {
  try {
    const res = (await client.callTool({ name, arguments: input })) as {
      content?: ReadonlyArray<{ type?: string; text?: string }>;
      isError?: boolean;
    };
    const text = (res.content ?? [])
      .filter((c) => c.type === "text" && typeof c.text === "string")
      .map((c) => c.text as string)
      .join("\n");
    return {
      payload: text.length > 0 ? text : JSON.stringify({ ok: res.isError !== true }),
      isError: res.isError === true,
    };
  } catch (e) {
    return { payload: JSON.stringify({ error: (e as Error).message }), isError: true };
  }
}

/* -------------------------------------------------------------------------- */
/* T5 — audit log (JSONL)                                                     */
/* -------------------------------------------------------------------------- */

/** One audited federated call. */
export interface AuditEntry {
  readonly ts: string;
  readonly mandateId: string;
  readonly server: string;
  readonly tool: string;
  readonly paramsSummary: string;
  readonly status: "ok" | "error" | "denied";
  readonly error?: string;
}

/** Where audit entries go. Must never throw (it's called in the tool path). */
export type AuditSink = (entry: AuditEntry) => void | Promise<void>;

/** Append entries as JSONL to a file (local / self-wired host). */
export function fileAuditSink(path: string): AuditSink {
  return async (entry) => {
    try {
      await appendFile(path, JSON.stringify(entry) + "\n", "utf8");
    } catch (e) {
      console.error(`aithos-mcp gateway: audit write failed: ${(e as Error).message}`);
    }
  };
}

/** Emit entries as structured JSON on stdout (hosted / Lambda → CloudWatch). */
export function consoleAuditSink(): AuditSink {
  return (entry) => {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ kind: "aithos.gateway.audit", ...entry }));
  };
}

function summarizeParams(args: Record<string, unknown>): string {
  try {
    const s = JSON.stringify(args);
    return s.length > 200 ? `${s.slice(0, 197)}...` : s;
  } catch {
    return "<unserializable>";
  }
}

async function emit(
  sink: AuditSink,
  mandateId: string,
  server: string,
  tool: string,
  args: Record<string, unknown>,
  status: "ok" | "error" | "denied",
  error?: string,
): Promise<void> {
  try {
    await sink({
      ts: new Date().toISOString(),
      mandateId,
      server,
      tool,
      paramsSummary: summarizeParams(args ?? {}),
      status,
      ...(error ? { error } : {}),
    });
  } catch (e) {
    // Audit must never crash a tool call.
    console.error(`aithos-mcp gateway: audit sink failed: ${(e as Error).message}`);
  }
}
