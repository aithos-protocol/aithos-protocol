// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Aithos MCP server — isomorphic core.
 *
 * Wraps the protocol-core primitives (identity / ethos / mandate) as MCP tools
 * and resources so LLM agents speaking the Model Context Protocol can:
 *
 *   - introspect an identity (read sphere public keys, DID)
 *   - list sections across zones
 *   - read the current body of one or several sections (decrypting locally)
 *   - verify the full ethos (gamma anchor, signatures, manifest link)
 *   - add / update / delete sections (under a write mandate + agent key),
 *     each mutation emitting a signed gamma entry (spec §10)
 *
 * Tool names, schemas, and normative descriptions come from the canonical
 * catalogue in `@aithos/agent-tools` (decision D1). Legacy pre-0.9 `aithos_*`
 * names are accepted at `tools/call` (never listed) for one minor version.
 *
 * ISOMORPHISM. This module imports no node builtins and no filesystem
 * backend; every host capability is injected:
 *
 *   - `storage`      — an {@link AithosStorage} (REQUIRED). The node CLI
 *                      passes `FilesystemStorage` (see bin.ts); the SDK
 *                      passes its in-process EthosClient adapter; a platform
 *                      passes a §11-envelope remote storage.
 *   - `io`           — optional host file access, used only by the
 *                      path-form `mandate` / `agent_key` arguments.
 *   - `home`         — optional label for the backing store (diagnostics).
 *   - `manifestPath` — optional resolver enabling the filesystem-only
 *                      `manifest-path` diagnostic resource.
 *
 * MANDATE EXPOSURE (P0.3). When `mandate` is provided, `tools/list` exposes
 * only the tools allowed by its scopes (`toolsForScopes`); per-call zone
 * enforcement in the handlers is unchanged (defense in depth — a forged call
 * to a hidden or out-of-scope tool never writes).
 *
 * The server is intentionally stateless: each tool call re-reads from the
 * backend. That's slightly slower than caching, but it matches the on-disk
 * semantics (gamma entries may have been written between calls) and keeps
 * tamper detection honest.
 */
import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Granular, node-free protocol-core entry points only — the root barrel
// pulls FilesystemStorage (node:fs/os/crypto) and would break browser hosts.
import { SPHERE_FRAGMENTS, rootDid } from "@aithos/protocol-core/did";
import { verifyMandate } from "@aithos/protocol-core/mandate";
import type {
  AithosStorage,
  ApplyEditsResult,
  DidDocument,
  EthosEdit,
  Identity,
  Mandate,
  Manifest,
  Section,
  Sphere,
  ZoneDoc,
} from "@aithos/protocol-core";
import {
  getToolSpec,
  resolveLegacyToolCall,
  toolsForScopes,
  type AgentToolSpec,
} from "@aithos/agent-tools";

import { resolveWriteAuth, type HostIo, type ResolvedWriteAuth } from "./auth.js";

export type { HostIo } from "./auth.js";

// ---------- helpers --------------------------------------------------------

async function resolveHandle(
  storage: AithosStorage,
  handle?: string,
): Promise<string> {
  if (handle) return handle;
  const def = await storage.defaultHandle();
  if (!def) {
    throw new Error(
      "no handle provided and no default identity configured (run `aithos init`)",
    );
  }
  return def;
}

function ok(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text:
          typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
}

function sectionSummary(
  zone: Sphere,
  s: Section,
): {
  zone: Sphere;
  id: string;
  title: string;
  gamma_ref: string;
  tags: string[];
} {
  return {
    zone,
    id: s.id,
    title: s.title,
    gamma_ref: s.gamma_ref,
    tags: s.tags ?? [],
  };
}

/** Isomorphic bytes → base64 (Buffer on node, btoa elsewhere). */
function bytesToBase64(bytes: Uint8Array): string {
  const B = (
    globalThis as {
      Buffer?: { from(b: Uint8Array): { toString(enc: "base64"): string } };
    }
  ).Buffer;
  if (B) return B.from(bytes).toString("base64");
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return (globalThis as unknown as { btoa(s: string): string }).btoa(bin);
}

/**
 * Load the subject identity for a write if the backend has it available
 * locally. If the caller supplied a delegate (mandate + agentKey), a missing
 * local identity is not fatal — the storage backend will accept delegate-only
 * writes (this is the remote-storage shape).
 */
async function loadWriteIdentity(
  storage: AithosStorage,
  handle: string,
  auth: ResolvedWriteAuth | null,
): Promise<Identity | undefined> {
  const selfSigning =
    (storage as { selfSigningWrites?: boolean }).selfSigningWrites === true;
  let identity: Identity | undefined;
  try {
    identity = await storage.loadIdentity(handle);
  } catch (e) {
    if (!auth && !selfSigning) throw e;
    return undefined;
  }
  if (identity === undefined && !auth && !selfSigning) {
    throw new Error(
      `storage returned no subject identity for '${handle}' and does not ` +
        "declare `selfSigningWrites` — cannot sign this write (provide a " +
        "mandate + agent_key, or a self-signing storage)",
    );
  }
  return identity;
}

/**
 * Best-effort load of the subject identity for a READ. Returns `undefined` for
 * a tracked install or when the sphere keys aren't on disk — the per-section
 * reads degrade gracefully to the host view (public + clear indexes; encrypted
 * bodies and the self index stay hidden).
 */
async function loadReadIdentity(
  storage: AithosStorage,
  handle: string,
  tracked: boolean,
): Promise<Identity | undefined> {
  if (tracked) return undefined;
  try {
    return await storage.loadIdentity(handle);
  } catch {
    return undefined;
  }
}

/**
 * Storage capability marker (P1 note, formalized in 0.13): a storage that
 * signs writes with its own session keys (the SDK's `SdkStorage`) declares
 * `selfSigningWrites: true` and may resolve `loadIdentity()` to `undefined`.
 * Without the marker, an undefined subject identity on a non-delegated
 * write REFUSES honestly instead of proceeding silently.
 */
export type SelfSigningStorage = AithosStorage & {
  readonly selfSigningWrites?: boolean;
};

// ---------- server registration -------------------------------------------

export interface CreateServerOptions {
  /** Override the server name that appears in `initialize` results. */
  name?: string;
  /** Override the server version that appears in `initialize` results. */
  version?: string;
  /**
   * Storage backend for every identity / ethos / mandate read and write.
   * REQUIRED — the isomorphic core ships no default. The node CLI passes
   * `new FilesystemStorage()` (bin.ts); browsers pass their own adapter.
   */
  storage?: AithosStorage;
  /**
   * Optional label of the backing store, surfaced by `identity_list`
   * (the node CLI passes `AITHOS_HOME`).
   */
  home?: string;
  /**
   * Optional host file access. Enables the path-form `mandate` /
   * `agent_key` tool arguments (reading mandate JSONs and agent keyfiles
   * from the host filesystem). Without it, mandates resolve by id through
   * the storage backend only.
   */
  io?: HostIo;
  /**
   * Optional resolver from handle to the on-disk manifest path. When
   * provided, the `aithos://ethos/{handle}/manifest-path` diagnostic
   * resource is registered (filesystem hosts only).
   */
  manifestPath?: (handle: string) => string;
  /**
   * Mandate-scoped exposure (P0.3). When set, `tools/list` only registers
   * the tools its scopes allow (see `toolsForScopes` in @aithos/agent-tools).
   * Per-call zone enforcement in handlers is unchanged (defense in depth).
   *
   * P4: pass the full signed mandate as `document` to power
   * `mandate_describe` / `ethos_preflight_write` and the pre-write liveness
   * re-check (validity window + revocation). Scope filtering keeps working
   * with scopes alone.
   */
  mandate?: { readonly scopes: readonly string[]; readonly document?: Mandate };
  /**
   * Default write authority (P4.4 — mandate pack §6.2.1): when a write call
   * carries no `mandate` / `agent_key` arguments, sign with THIS delegate
   * key under the session mandate instead of requiring a local subject
   * identity. The CLI's `--mandate-pack` wires it; library hosts may too.
   */
  delegate?: {
    readonly mandateId: string;
    readonly keySeed: Uint8Array;
    readonly keyMultibase: string;
  };
  /** Optional extra restriction: only expose these canonical tool names. */
  exposeTools?: readonly string[];
  /**
   * Accept legacy pre-0.9 `aithos_*` tool names at `tools/call` (never
   * listed), logging a deprecation warning. Default true. Removal in 1.0.
   */
  legacyAliases?: boolean;
  /**
   * Per-write auto-commit (pre-0.10 behaviour): every write persists its own
   * edition immediately and `ethos_commit` / `ethos_discard` are not served.
   *
   * DEFAULT IS TRANSACTIONAL (D3): writes STAGE in the session and persist
   * as ONE edition at `ethos_commit`; a session that ends without commit is
   * discarded. Transactional mode requires the storage backend to implement
   * the optional `applyEdits` capability — when it does not, the server
   * falls back to auto-commit with a stderr notice. Stateless HTTP hosts
   * should pass `autoCommit: true` (a per-request server cannot stage).
   */
  autoCommit?: boolean;
  /**
   * Optional zone-markdown renderer for the `aithos://ethos/{handle}/{zone}`
   * resource (node hosts pass protocol-core's `renderZoneMarkdown`, which
   * lives in a node-bound module). Without it, decrypted zone re-rendering
   * degrades to the raw-bytes / explanatory fallbacks.
   */
  renderZone?: (
    zone: Sphere,
    doc: ZoneDoc,
    meta: {
      subjectDid: string;
      subjectHandle: string;
      editionVersion: string;
      createdAt: string;
    },
  ) => string;
}

export function createServer(opts: CreateServerOptions = {}): McpServer {
  const storage = opts.storage;
  if (!storage) {
    throw new Error(
      "createServer: opts.storage is required — pass `new FilesystemStorage()` " +
        "(node) or another AithosStorage implementation. The `aithos-mcp` CLI " +
        "does this for you.",
    );
  }
  const io = opts.io;

  const server = new McpServer(
    {
      name: opts.name ?? "aithos-mcp",
      version: opts.version ?? "0.9.0",
    },
    {
      // We expose tools + resources, not prompts.
      capabilities: { tools: {}, resources: {} },
    },
  );

  // ---- exposure set (P0.3) -------------------------------------------------
  const exposed = new Set(
    toolsForScopes(opts.mandate?.scopes, {
      ...(opts.exposeTools ? { tools: opts.exposeTools } : {}),
    }).map((t) => t.name),
  );

  /** Catalogue spec lookup that throws on drift (T10 guards this too). */
  const spec = (name: string): AgentToolSpec => {
    const s = getToolSpec(name);
    if (!s) {
      throw new Error(`tool '${name}' is not in the @aithos/agent-tools catalogue`);
    }
    return s;
  };

  /**
   * Register a catalogue tool when exposed. Title + normative description
   * come from the catalogue (single source of truth); the zod shape is the
   * runtime validation twin of the catalogue JSON Schema (T10 asserts the
   * structural match on the wire).
   */
  /** Every tool ACTUALLY served by this instance — `mandate_describe`
   *  reports exactly this set, so what it announces is what dispatch does
   *  (T15 holds by construction, not by parallel bookkeeping). */
  const registeredTools = new Set<string>();

  const register = (
    name: string,
    shape: z.ZodRawShape,
    handler: (args: Record<string, unknown>) => Promise<{ content: { type: "text"; text: string }[] }>,
  ): void => {
    if (!exposed.has(name)) return;
    const s = spec(name);
    registeredTools.add(name);
    server.registerTool(
      name,
      { title: s.title, description: s.description, inputSchema: shape },
      handler as never,
    );
  };

  // ------------------------------------------------------------------ identity

  register("identity_list", {}, async () => {
    const handles = await storage.listHandles();
    const out = await Promise.all(
      handles.map(async (h) => {
        try {
          const meta = await storage.loadIdentityMetadata(h);
          return {
            handle: meta.handle,
            did: meta.did,
            tracked: meta.tracked,
            spheres: meta.sphereDids,
          };
        } catch (e) {
          return { handle: h, error: (e as Error).message };
        }
      }),
    );
    return ok({ aithos_home: opts.home ?? null, identities: out });
  });

  register(
    "identity_describe",
    { handle: z.string().optional() },
    async ({ handle }) => {
      const h = await resolveHandle(storage, handle as string | undefined);
      const meta = await storage.loadIdentityMetadata(h);
      return ok({
        handle: meta.handle,
        displayName: meta.displayName,
        did: meta.did,
        tracked: meta.tracked,
        spheres: meta.sphereDids,
        sphereKeys: meta.sphereKeys,
      });
    },
  );

  // ------------------------------------------------------------------ ethos

  register(
    "ethos_list_sections",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS).optional(),
    },
    async (args) => {
      const { handle, zone } = args as { handle?: string; zone?: Sphere };
      const h = await resolveHandle(storage, handle);
      const tracked = await storage.isTrackedIdentity(h);
      // The section INDEX is cheap: id + title + gamma_ref, no body decryption.
      // For the encrypted self index, titles appear only with the owner key.
      const identity = await loadReadIdentity(storage, h, tracked);
      const zones: Sphere[] = zone ? [zone] : [...SPHERE_FRAGMENTS];
      const sections: Array<{
        zone: Sphere;
        id: string;
        title: string | null;
        title_hidden: boolean;
        gamma_ref: string;
        tags: string[];
        approx_size_bytes: number | null;
        est_tokens: number | null;
      }> = [];
      const skipped: Array<{ zone: Sphere; reason: string }> = [];
      for (const zn of zones) {
        try {
          const idx = await storage.readSectionIndex(
            h,
            zn,
            identity ? { identity } : undefined,
          );
          for (const r of idx) {
            sections.push({
              zone: zn,
              id: r.section_id,
              title: r.title ?? null,
              title_hidden: r.title_hidden,
              gamma_ref: r.gamma_ref,
              tags: [...(r.tags ?? [])],
              // V1 read-planning hints (absent when the backend can't stat).
              approx_size_bytes: r.approx_size_bytes ?? null,
              est_tokens:
                r.approx_size_bytes !== undefined
                  ? Math.ceil(r.approx_size_bytes / 4)
                  : null,
            });
          }
        } catch (e) {
          skipped.push({ zone: zn, reason: (e as Error).message });
        }
      }
      return ok({ handle: h, tracked, sections, skipped });
    },
  );

  register(
    "ethos_read_section",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
      section_id: z.string(),
    },
    async (args) => {
      const { handle, zone, section_id } = args as {
        handle?: string;
        zone: Sphere;
        section_id: string;
      };
      const h = await resolveHandle(storage, handle);
      const tracked = await storage.isTrackedIdentity(h);
      const identity = await loadReadIdentity(storage, h, tracked);
      // v0.3: fetch ONLY this section's blob (no whole-zone decryption).
      const [res] = await storage.readSections(h, [section_id], {
        zone,
        ...(identity ? { identity } : {}),
      });
      if (!res || !res.accessible || !res.section) {
        throw new Error(
          res?.reason ??
            `section ${section_id} not found in zone ${zone}` +
              (tracked && zone !== "public"
                ? ` (identity is tracked-only — no sphere key for ${zone})`
                : ""),
        );
      }
      return ok({
        zone: res.zone,
        id: res.section.id,
        title: res.section.title,
        tags: res.section.tags ?? [],
        gamma_ref: res.section.gamma_ref,
        body: res.section.body,
      });
    },
  );

  register(
    "ethos_read_sections",
    {
      handle: z.string().optional(),
      section_ids: z.array(z.string()).min(1),
      zone: z.enum(SPHERE_FRAGMENTS).optional(),
    },
    async (args) => {
      const { handle, section_ids, zone } = args as {
        handle?: string;
        section_ids: string[];
        zone?: Sphere;
      };
      const h = await resolveHandle(storage, handle);
      const tracked = await storage.isTrackedIdentity(h);
      const identity = await loadReadIdentity(storage, h, tracked);
      const results = await storage.readSections(h, section_ids, {
        ...(zone ? { zone } : {}),
        ...(identity ? { identity } : {}),
      });
      return ok({
        handle: h,
        tracked,
        sections: results.map((r) =>
          r.accessible && r.section
            ? {
                zone: r.zone,
                id: r.section.id,
                accessible: true as const,
                title: r.section.title,
                tags: r.section.tags ?? [],
                gamma_ref: r.section.gamma_ref,
                body: r.section.body,
              }
            : {
                zone: r.zone,
                id: r.section_id,
                accessible: false as const,
                reason: r.reason ?? "inaccessible",
              },
        ),
      });
    },
  );

  // ------------------------------------------------ contextualization (P3)
  //
  // V1/V2/V4/V5 — the primitives that make reading an ethos CHEAP for an
  // agent: plan with the size-hinted index, find with keyword search, ground
  // with a budgeted context pack, and re-sync with a content-address diff.
  // All scope-bounded: a mandate session only ever touches the zones its
  // read scopes grant (T12/T14).

  /** Zones this SESSION may read: all three, or the mandate's read scopes. */
  const readableZones = (): Sphere[] => {
    const scopes = opts.mandate?.scopes;
    if (!scopes) return [...SPHERE_FRAGMENTS];
    return SPHERE_FRAGMENTS.filter((z) => scopes.includes(`ethos.read.${z}`));
  };

  /** Intersect a caller-supplied zone list with the session's readable set. */
  const boundZones = (requested?: Sphere[]): Sphere[] => {
    const readable = readableZones();
    if (!requested || requested.length === 0) return readable;
    return requested.filter((z) => readable.includes(z));
  };

  const estTokens = (chars: number): number => Math.ceil(chars / 4);

  /** Plain keyword tokenizer — lowercase, unicode letters/digits, len ≥ 2. */
  const tokenize = (q: string): string[] => {
    const out: string[] = [];
    for (const w of q.toLowerCase().split(/[^\p{L}\p{N}]+/u)) {
      if (w.length >= 2 && !out.includes(w)) out.push(w);
    }
    return out;
  };

  /** Cap on how many section BODIES one search/pack call may decrypt. */
  const MAX_CONTEXT_READS = 50;

  interface ScoredSection {
    zone: Sphere;
    id: string;
    title: string;
    tags: readonly string[];
    body: string;
    score: number;
  }

  /**
   * Search v1 (D2 — "no NLP"): index first (titles/tags), then the bodies of
   * readable sections in the bounded zones, capped at MAX_CONTEXT_READS.
   * Scoring per query term: title hit ×3, tag hit ×2, body occurrences ×1
   * (each term's body contribution capped at 5).
   */
  const searchSections = async (
    handle: string,
    query: string,
    zones: Sphere[],
  ): Promise<ScoredSection[]> => {
    const terms = tokenize(query);
    if (terms.length === 0) return [];
    const tracked = await storage.isTrackedIdentity(handle);
    const identity = await loadReadIdentity(storage, handle, tracked);

    // Collect candidate ids per zone from the cheap index.
    const candidates: Array<{ zone: Sphere; id: string }> = [];
    for (const zone of zones) {
      try {
        const idx = await storage.readSectionIndex(
          handle,
          zone,
          identity ? { identity } : undefined,
        );
        for (const r of idx) candidates.push({ zone, id: r.section_id });
      } catch {
        /* unreadable zone for this session — skip silently (bounded view) */
      }
    }

    const out: ScoredSection[] = [];
    let reads = 0;
    for (const { zone, id } of candidates) {
      if (reads >= MAX_CONTEXT_READS) break;
      reads++;
      const [res] = await storage.readSections(handle, [id], {
        zone,
        ...(identity ? { identity } : {}),
      });
      if (!res || !res.accessible || !res.section) continue;
      const sec = res.section;
      const title = sec.title.toLowerCase();
      const tags = (sec.tags ?? []).map((t) => t.toLowerCase());
      const body = sec.body.toLowerCase();
      let score = 0;
      for (const term of terms) {
        if (title.includes(term)) score += 3;
        if (tags.some((t) => t.includes(term))) score += 2;
        let hits = 0;
        let i = body.indexOf(term);
        while (i !== -1 && hits < 5) {
          hits++;
          i = body.indexOf(term, i + term.length);
        }
        score += hits;
      }
      if (score > 0) {
        out.push({
          zone,
          id,
          title: sec.title,
          tags: sec.tags ?? [],
          body: sec.body,
          score,
        });
      }
    }
    out.sort((a, b) => b.score - a.score);
    return out;
  };

  /** ~160-char snippet centred on the first term occurrence. */
  const snippetOf = (body: string, query: string): string => {
    const terms = tokenize(query);
    const lower = body.toLowerCase();
    let at = -1;
    for (const t of terms) {
      const i = lower.indexOf(t);
      if (i !== -1 && (at === -1 || i < at)) at = i;
    }
    const start = Math.max(0, (at === -1 ? 0 : at) - 60);
    const cut = body.slice(start, start + 160).replace(/\s+/g, " ").trim();
    return (start > 0 ? "…" : "") + cut + (start + 160 < body.length ? "…" : "");
  };

  // ------------------------------------------------ incarnation (P6 — V10/V11/V16)

  /** Spec §12.3.4 default presentation guidance, `{handle}` substituted. */
  const defaultGuidance = (handle: string) => ({
    "aithos-guidance": "0.1.0",
    voice: {
      person: "first",
      languages: ["en"],
      tone: ["neutral", "factual"],
      formality: "neutral",
      verbosity: "short",
    },
    rendering: { pinned_sections: [], transition_style: "natural" },
    disclosure: {
      ai_disclosure: "always",
      disclosure_text:
        `You are speaking with an agent narrating from ${handle}'s Aithos ` +
        `ethos, not with ${handle} directly.`,
      scope_limits: [
        "private feelings, intentions, or decisions not stated in the ethos",
        "speculation about events not described in the ethos",
        "commitments or promises on behalf of the subject",
      ],
    },
    refusal_template:
      `That is outside what ${handle} has recorded in their ethos, so I ` +
      `cannot answer on their behalf.`,
  });

  interface VoiceProfileView {
    source: "authored" | "default";
    section_id: string | null;
    /** Authored section body verbatim, or the default as pretty JSON. */
    text: string;
    /** Parsed guidance object when `text` is JSON (§12.3.2); else null. */
    guidance: Record<string, unknown> | null;
  }

  /**
   * V10 — the subject's voice. An authored PUBLIC section tagged `voice`
   * (`guidance` as fallback tag) wins and its body is served verbatim;
   * otherwise the spec §12.3.4 default with `{handle}` substituted.
   * Public-only by design — §12.3.5: guidance is never private.
   */
  const voiceProfile = async (handle: string): Promise<VoiceProfileView> => {
    try {
      const idx = await storage.readSectionIndex(handle, "public");
      const byTag = (tag: string) =>
        idx.find((r) => (r.tags ?? []).some((t) => t.toLowerCase() === tag));
      const hit = byTag("voice") ?? byTag("guidance");
      if (hit) {
        const [res] = await storage.readSections(handle, [hit.section_id], {
          zone: "public",
        });
        if (res?.accessible && res.section) {
          let parsed: Record<string, unknown> | null = null;
          try {
            const j = JSON.parse(res.section.body) as unknown;
            if (j && typeof j === "object" && !Array.isArray(j)) {
              parsed = j as Record<string, unknown>;
            }
          } catch {
            /* prose guidance — served as text */
          }
          return {
            source: "authored",
            section_id: hit.section_id,
            text: res.section.body,
            guidance: parsed,
          };
        }
      }
    } catch {
      /* no public index on this host — fall through to the default */
    }
    const dg = defaultGuidance(handle);
    return {
      source: "default",
      section_id: null,
      text: JSON.stringify(dg, null, 2),
      guidance: dg as unknown as Record<string, unknown>,
    };
  };

  /** Best-effort subject card (handle + did + display name when local). */
  const subjectCard = async (
    h: string,
  ): Promise<{ handle: string; did?: string; display_name?: string }> => {
    try {
      const meta = await storage.loadIdentityMetadata(h);
      return {
        handle: h,
        did: meta.did,
        ...(meta.displayName ? { display_name: meta.displayName } : {}),
      };
    } catch {
      return { handle: h };
    }
  };

  register(
    "ethos_search",
    {
      handle: z.string().optional(),
      query: z.string().min(1),
      zones: z.array(z.enum(SPHERE_FRAGMENTS)).optional(),
      limit: z.number().int().min(1).max(25).optional(),
    },
    async (args) => {
      const { handle, query, zones, limit } = args as {
        handle?: string;
        query: string;
        zones?: Sphere[];
        limit?: number;
      };
      const h = await resolveHandle(storage, handle);
      const bounded = boundZones(zones);
      const scored = await searchSections(h, query, bounded);
      const top = scored.slice(0, limit ?? 8);
      return ok({
        handle: h,
        query,
        zones_searched: bounded,
        matches: top.map((m) => ({
          zone: m.zone,
          id: m.id,
          title: m.title,
          tags: [...m.tags],
          score: m.score,
          est_tokens: estTokens(m.body.length),
          snippet: snippetOf(m.body, query),
        })),
      });
    },
  );

  /** V4 assembly — shared by `ethos_context_pack` and `agent_briefing` (P6). */
  const buildContextPack = async (
    h: string,
    task: string,
    budget: number,
    zones?: Sphere[],
  ) => {
      const bounded = boundZones(zones);
      const tracked = await storage.isTrackedIdentity(h);
      const identity = await loadReadIdentity(storage, h, tracked);

      // 1) pinned/guidance sections from the index (cheap), bodies on demand.
      const anchors: Array<{ zone: Sphere; id: string; reason: "guidance" | "pinned" }> = [];
      for (const zone of bounded) {
        try {
          const idx = await storage.readSectionIndex(
            h,
            zone,
            identity ? { identity } : undefined,
          );
          for (const r of idx) {
            const tags = (r.tags ?? []).map((t) => t.toLowerCase());
            if (tags.includes("guidance")) anchors.push({ zone, id: r.section_id, reason: "guidance" });
            else if (tags.includes("pinned")) anchors.push({ zone, id: r.section_id, reason: "pinned" });
          }
        } catch {
          /* unreadable zone — bounded view */
        }
      }
      anchors.sort((a, b) => (a.reason === b.reason ? 0 : a.reason === "guidance" ? -1 : 1));

      // 2) task matches (reuses the search scorer; generous pre-limit).
      const matches = (await searchSections(h, task, bounded)).slice(0, 12);

      // 3) assemble under the budget: guidance → pinned → matches, dedup.
      const seen = new Set<string>();
      const sections: Array<{
        zone: Sphere;
        id: string;
        title: string;
        reason: string;
        truncated: boolean;
        est_tokens: number;
        body: string;
      }> = [];
      let used = 0;

      const push = async (
        zone: Sphere,
        id: string,
        reason: string,
        preloaded?: { title: string; body: string },
      ): Promise<boolean> => {
        const key = `${zone}/${id}`;
        if (seen.has(key)) return true;
        let sec = preloaded;
        if (!sec) {
          const [res] = await storage.readSections(h, [id], {
            zone,
            ...(identity ? { identity } : {}),
          });
          if (!res || !res.accessible || !res.section) return true; // skip silently
          sec = { title: res.section.title, body: res.section.body };
        }
        const remaining = budget - used;
        if (remaining <= 0) return false;
        const cost = estTokens(sec.body.length);
        let body = sec.body;
        let truncated = false;
        let charge = cost;
        if (cost > remaining) {
          body = sec.body.slice(0, remaining * 4);
          truncated = true;
          charge = remaining;
        }
        seen.add(key);
        sections.push({
          zone,
          id,
          title: sec.title,
          reason,
          truncated,
          est_tokens: charge,
          body,
        });
        used += charge;
        return !truncated;
      };

      let room = true;
      for (const a of anchors) {
        if (!room) break;
        room = await push(a.zone, a.id, a.reason);
      }
      for (const m of matches) {
        if (!room) break;
        room = await push(m.zone, m.id, "match", { title: m.title, body: m.body });
      }

      return {
        handle: h,
        task,
        zones_considered: bounded,
        budget_tokens: budget,
        used_tokens_est: used,
        sections,
      };
  };

  register(
    "ethos_context_pack",
    {
      handle: z.string().optional(),
      task: z.string().min(1),
      budget_tokens: z.number().int().min(100).max(20000).optional(),
      zones: z.array(z.enum(SPHERE_FRAGMENTS)).optional(),
    },
    async (args) => {
      const { handle, task, budget_tokens, zones } = args as {
        handle?: string;
        task: string;
        budget_tokens?: number;
        zones?: Sphere[];
      };
      const h = await resolveHandle(storage, handle);
      return ok(await buildContextPack(h, task, budget_tokens ?? 1500, zones));
    },
  );

  register(
    "ethos_introduce",
    {
      handle: z.string().optional(),
      audience: z.string().optional(),
      focus: z.string().optional(),
    },
    async (args) => {
      const { handle, audience, focus } = args as {
        handle?: string;
        audience?: string;
        focus?: string;
      };
      const h = await resolveHandle(storage, handle);
      // V16 — narration to a third party NEVER serves circle/self (spec
      // §4/§12). Exposure already requires ethos.read.public; defense in
      // depth for a forced call on a session that lacks it:
      if (opts.mandate && !opts.mandate.scopes.includes("ethos.read.public")) {
        throw new Error(
          "ethos_introduce requires scope ethos.read.public — third-party " +
            "narration is public-only, whatever the mandate (spec §4)",
        );
      }

      const vp = await voiceProfile(h);
      const guidance = vp.guidance ?? defaultGuidance(h);
      const subject = await subjectCard(h);

      // PUBLIC index only — the zone is hardcoded, never mandate-derived.
      let index: Awaited<ReturnType<AithosStorage["readSectionIndex"]>> = [];
      try {
        index = await storage.readSectionIndex(h, "public");
      } catch {
        /* no readable public index — introduction degrades to guidance only */
      }
      const taggedIds = (tag: string): string[] =>
        index
          .filter((r) => (r.tags ?? []).some((t) => t.toLowerCase() === tag))
          .map((r) => r.section_id);

      const readPublic = async (ids: string[]) => {
        if (ids.length === 0) {
          return [] as { id: string; title: string; body: string }[];
        }
        const res = await storage.readSections(h, ids, { zone: "public" });
        return res
          .filter((r) => r.accessible && r.section)
          .map((r) => ({
            id: r.section!.id,
            title: r.section!.title,
            body: r.section!.body,
          }));
      };

      // Headline: first public section tagged `intro` (§12.4.1 transposed).
      const [headline] = await readPublic(taggedIds("intro").slice(0, 1));

      // Pinned: authored guidance order wins; the `pinned` tag is the fallback.
      const rendering = (
        guidance as {
          rendering?: { pinned_sections?: string[]; topic_hints?: string[] };
        }
      ).rendering;
      const pinnedIds = rendering?.pinned_sections?.length
        ? rendering.pinned_sections.filter((id) =>
            index.some((r) => r.section_id === id),
          )
        : taggedIds("pinned");
      const pinned = await readPublic(pinnedIds.slice(0, 8));

      const matches = focus
        ? (await searchSections(h, focus, ["public"])).slice(0, 5).map((m) => ({
            id: m.id,
            title: m.title,
            score: m.score,
            body: m.body,
          }))
        : null;

      const refusal =
        (guidance as { refusal_template?: string }).refusal_template ??
        defaultGuidance(h).refusal_template;

      return ok({
        subject,
        audience: audience ?? null,
        presentation_guidance: vp.guidance ?? vp.text,
        guidance_source: vp.source,
        headline: headline ?? null,
        pinned,
        topics: rendering?.topic_hints ?? [],
        ...(focus !== undefined ? { focus, matches } : {}),
        refusal_template: refusal,
        zones_served: ["public"],
      });
    },
  );

  register(
    "agent_briefing",
    {
      handle: z.string().optional(),
      task: z.string().min(1),
      budget_tokens: z.number().int().min(100).max(20000).optional(),
      zones: z.array(z.enum(SPHERE_FRAGMENTS)).optional(),
    },
    async (args) => {
      const { handle, task, budget_tokens, zones } = args as {
        handle?: string;
        task: string;
        budget_tokens?: number;
        zones?: Sphere[];
      };
      const h = await resolveHandle(storage, handle);
      // V11 — one call to incarnate: powers + voice + grounded context,
      // composed from the SAME helpers the three source tools use.
      const subject = await subjectCard(h);
      const [mandateView, vp, pack] = await Promise.all([
        describeSession(),
        voiceProfile(h),
        buildContextPack(h, task, budget_tokens ?? 1500, zones),
      ]);
      return ok({
        subject,
        task,
        mandate: mandateView,
        voice_profile: {
          source: vp.source,
          section_id: vp.section_id,
          guidance: vp.guidance ?? vp.text,
        },
        context_pack: pack,
      });
    },
  );

  // diff_since needs edition history — served only when the backend keeps it
  // (filesystem `history/`; the platform PDS lands with P5). Same conditional
  // pattern as the transactional trio: capability present ⇒ tool served.
  if (typeof storage.readManifestAt === "function") {
    register(
      "ethos_diff_since",
      {
        handle: z.string().optional(),
        height: z.number().int().min(1),
      },
      async (args) => {
        const { handle, height } = args as { handle?: string; height: number };
        const h = await resolveHandle(storage, handle);
        const prev = await storage.readManifestAt!(h, height);
        if (!prev) {
          throw new Error(
            `ethos_diff_since: no edition at height ${height} (unknown or ` +
              `pruned from history)`,
          );
        }
        const cur = await storage.readManifest(h);
        type DescLite = { section_id: string; blob_sha?: string; gamma_ref: string; title?: string };
        type ZonesLite = Partial<Record<Sphere, { sections?: DescLite[] }>>;
        const zonesOf = (m: unknown): ZonesLite =>
          ((m as { zones?: ZonesLite }).zones ?? {}) as ZonesLite;
        const addr = (d: DescLite): string => d.blob_sha ?? d.gamma_ref;

        const out: Record<string, { added: object[]; modified: object[]; deleted: string[] }> = {};
        for (const zone of readableZones()) {
          const prevRows = zonesOf(prev)[zone]?.sections ?? [];
          const curRows = zonesOf(cur)[zone]?.sections ?? [];
          const prevMap = new Map(prevRows.map((d) => [d.section_id, d]));
          const curMap = new Map(curRows.map((d) => [d.section_id, d]));
          const added: object[] = [];
          const modified: object[] = [];
          const deleted: string[] = [];
          for (const [id, d] of curMap) {
            const was = prevMap.get(id);
            if (!was) added.push({ id, ...(d.title ? { title: d.title } : {}) });
            else if (addr(was) !== addr(d)) modified.push({ id, ...(d.title ? { title: d.title } : {}) });
          }
          for (const id of prevMap.keys()) {
            if (!curMap.has(id)) deleted.push(id);
          }
          if (added.length || modified.length || deleted.length) {
            out[zone] = { added, modified, deleted };
          }
        }
        const curH = (cur as unknown as { edition: { height: number } }).edition.height;
        return ok({
          handle: h,
          from_height: height,
          to_height: curH,
          changed: out,
          unchanged: Object.keys(out).length === 0,
        });
      },
    );
  }

  register(
    "ethos_verify",
    {
      handle: z.string().optional(),
      decrypt: z.boolean().optional(),
    },
    async (args) => {
      const { handle, decrypt } = args as { handle?: string; decrypt?: boolean };
      const h = await resolveHandle(storage, handle);
      const didDoc = await storage.loadDidDocument(h);
      // Tracked identities have no sealed seeds: we transparently downgrade to
      // a public-only verification rather than throwing. The result object
      // already notes which zones were skipped.
      const tracked = await storage.isTrackedIdentity(h);
      const identity =
        decrypt === false || tracked ? null : await storage.loadIdentity(h);
      const result = await storage.verifyEthos(h, identity, didDoc);
      return ok({ tracked, ...result });
    },
  );

  /**
   * Shared guard for every write tool: resolve the (optional) delegate auth
   * and enforce the per-zone write scope (defense in depth — exposure
   * filtering above is the coarse gate; this is the per-call gate, applied
   * at STAGE time in transactional mode and re-checked structurally by the
   * storage layer at commit).
   */
  /**
   * Liveness guard (P4, T6): a mandated authority must be inside its
   * validity window and unrevoked EVERY time it matters — at stage time and
   * again at commit (authority can be revoked between the two). Throws with
   * the precise reason; never writes.
   */
  const assertMandateLive = async (m: Mandate): Promise<void> => {
    const now = Date.now();
    const nbf = Date.parse(m.not_before);
    const naf = Date.parse(m.not_after);
    if (Number.isFinite(nbf) && now < nbf) {
      throw new Error(
        `mandate ${m.id} is not yet valid (not_before ${m.not_before})`,
      );
    }
    if (Number.isFinite(naf) && now > naf) {
      throw new Error(`mandate ${m.id} expired at ${m.not_after}`);
    }
    const rev = await storage.findRevocation(m.id);
    if (rev) {
      throw new Error(
        `mandate ${m.id} was revoked at ${rev.revoked_at}` +
          (rev.reason ? ` (${rev.reason})` : ""),
      );
    }
  };

  /** The session's default delegate auth (mandate pack), if configured. */
  const packAuth = (): ResolvedWriteAuth | null => {
    const doc = opts.mandate?.document;
    const del = opts.delegate;
    if (!doc || !del) return null;
    return {
      mandate: doc,
      mandatePath: "mandate-pack",
      agentKey: {
        seed_hex: "",
        pubkey_multibase: del.keyMultibase,
      },
      agentKeyPath: "mandate-pack",
      delegate: {
        mandateId: del.mandateId,
        keySeed: del.keySeed,
        keyMultibase: del.keyMultibase,
      },
    };
  };

  const resolveWriteFor = async (
    zone: Sphere,
    args: { mandate?: string; agent_key?: string },
  ): Promise<ResolvedWriteAuth | null> => {
    let auth = await resolveWriteAuth(
      storage,
      { mandate: args.mandate, agentKey: args.agent_key },
      io,
    );
    // P4.4 — no per-call auth args: fall back to the session's mandate-pack
    // delegate (the "agent chez le client" shape).
    if (!auth) auth = packAuth();
    if (auth) {
      const writeScope = `ethos.write.${zone}`;
      if (!auth.mandate.scopes.includes(writeScope)) {
        throw new Error(
          `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
        );
      }
      await assertMandateLive(auth.mandate);
    } else if (opts.mandate?.document) {
      // Session-level mandate WITHOUT a host delegate key (the SDK in-process
      // shape: the storage signs with its own session keys). Exposure already
      // gates the tool by scope — liveness must still hold here (T6).
      await assertMandateLive(opts.mandate.document);
    }
    return auth;
  };

  // ---------------------------------------------------------- transactions
  //
  // D3 — transactional editing. Writes STAGE in this server instance (one
  // instance == one MCP session on every transport this package ships) and
  // `ethos_commit` flushes the batch through the storage backend's
  // `applyEdits` capability: ONE edition, one manifest re-sign, one gamma
  // anchor advance. `ethos_discard` (or simply ending the session) drops the
  // batch — zero writes. Hosts opt back into the pre-0.10 behaviour with
  // `autoCommit: true`; storages without `applyEdits` force that fallback.

  const transactional =
    opts.autoCommit !== true && typeof storage.applyEdits === "function";
  if (opts.autoCommit !== true && !transactional) {
    console.error(
      "aithos-mcp: storage backend has no applyEdits capability — " +
        "falling back to per-write auto-commit",
    );
  }

  interface StagedWrite {
    edit: EthosEdit;
    /** Pre-composed summary for the commit acknowledgement. */
    summary: { op: string; zone: Sphere; section_id: string };
  }
  interface TxState {
    handle: string;
    /** `owner`, or `mandate:<id>` — one authority per transaction. */
    authKey: string;
    auth: ResolvedWriteAuth | null;
    writes: StagedWrite[];
  }
  let tx: TxState | null = null;

  /** Isomorphic 24-hex section id (matches the storage layer's shape). */
  const mintSectionId = (): string => {
    const bytes = new Uint8Array(12);
    (globalThis as unknown as { crypto: { getRandomValues(b: Uint8Array): Uint8Array } }).crypto.getRandomValues(bytes);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return `sec_${hex}`;
  };

  /** Enroll a write into the open transaction (single handle + authority). */
  const enroll = (
    handle: string,
    auth: ResolvedWriteAuth | null,
  ): TxState => {
    const authKey = auth ? `mandate:${auth.mandate.id}` : "owner";
    if (!tx) {
      tx = { handle, authKey, auth, writes: [] };
      return tx;
    }
    if (tx.handle !== handle) {
      throw new Error(
        `transaction already targets handle "${tx.handle}" — commit or ` +
          `discard before writing as "${handle}"`,
      );
    }
    if (tx.authKey !== authKey) {
      throw new Error(
        `transaction already carries authority ${tx.authKey} — a single ` +
          `commit cannot mix write authorities (got ${authKey})`,
      );
    }
    return tx;
  };

  /**
   * The section as THIS SESSION sees it: the latest staged upsert when the
   * batch touched it (unless deleted later), else the persisted section.
   * Returns null when unknown/deleted. Used for fail-fast existence checks,
   * append composition, and delete echoes.
   */
  const effectiveSection = async (
    handle: string,
    zone: Sphere,
    sectionId: string,
  ): Promise<{ title: string; body: string; tags?: readonly string[] } | null> => {
    if (tx && tx.handle === handle) {
      for (let i = tx.writes.length - 1; i >= 0; i--) {
        const e = tx.writes[i]!.edit;
        if (e.zone !== zone) continue;
        const id = e.op === "add" ? e.sectionId : e.sectionId;
        if (id !== sectionId) continue;
        if (e.op === "delete") return null;
        if (e.op === "add") {
          return { title: e.title, body: e.body, ...(e.tags ? { tags: e.tags } : {}) };
        }
        // modify — compose over what was below it.
        const baseIdx = tx.writes.slice(0, i);
        let base: { title: string; body: string; tags?: readonly string[] } | null = null;
        for (let j = baseIdx.length - 1; j >= 0; j--) {
          const b = baseIdx[j]!.edit;
          if (b.zone === zone && b.sectionId === sectionId) {
            if (b.op === "delete") { base = null; break; }
            if (b.op === "add") { base = { title: b.title, body: b.body, ...(b.tags ? { tags: b.tags } : {}) }; break; }
          }
        }
        if (!base) base = await persistedSection(handle, zone, sectionId);
        return {
          title: e.title !== undefined ? e.title : (base?.title ?? ""),
          body: e.body !== undefined ? e.body : (base?.body ?? ""),
          ...(e.clearTags
            ? {}
            : e.tags !== undefined
              ? { tags: e.tags }
              : base?.tags
                ? { tags: base.tags }
                : {}),
        };
      }
    }
    return persistedSection(handle, zone, sectionId);
  };

  const persistedSection = async (
    handle: string,
    zone: Sphere,
    sectionId: string,
  ): Promise<{ title: string; body: string; tags?: readonly string[] } | null> => {
    const tracked = await storage.isTrackedIdentity(handle);
    const identity = await loadReadIdentity(storage, handle, tracked);
    const [res] = await storage.readSections(handle, [sectionId], {
      zone,
      ...(identity ? { identity } : {}),
    });
    if (!res || !res.accessible || !res.section) return null;
    return {
      title: res.section.title,
      body: res.section.body,
      ...(res.section.tags ? { tags: res.section.tags } : {}),
    };
  };

  const stageAck = (t: TxState, w: StagedWrite) =>
    ok({
      staged: true,
      ...w.summary,
      pending: t.writes.length,
      note:
        "Nothing is persisted yet — `ethos_commit` seals the whole batch " +
        "as one edition; `ethos_discard` abandons it.",
    });

  // ------------------------------------------------------------------ writes

  register(
    "ethos_add_section",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
      title: z.string().min(1),
      body: z.string().min(1),
      tags: z.array(z.string()).optional(),
      mandate: z.string().optional(),
      agent_key: z.string().optional(),
    },
    async (args) => {
      const { handle, zone, title, body, tags } = args as {
        handle?: string;
        zone: Sphere;
        title: string;
        body: string;
        tags?: string[];
      };
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteFor(zone, args as never);
      if (transactional) {
        const t = enroll(h, auth);
        const sectionId = mintSectionId();
        const w: StagedWrite = {
          edit: { op: "add", zone, sectionId, title, body, ...(tags ? { tags } : {}) },
          summary: { op: "add", zone, section_id: sectionId },
        };
        t.writes.push(w);
        return stageAck(t, w);
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const { section, manifest, gammaEntry } = await storage.addSection(
        { handle: h, zone, title, body, tags },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        section: sectionSummary(zone, section as Section),
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
        gamma_entry_id: gammaEntry?.id ?? section.gamma_ref,
        gamma_head: manifest.gamma?.head ?? null,
        gamma_count: manifest.gamma?.count ?? 0,
      });
    },
  );

  register(
    "ethos_update_section",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
      section_id: z.string(),
      title: z.string().optional(),
      body: z.string().optional(),
      tags: z.array(z.string()).optional(),
      clear_tags: z.boolean().optional(),
      mandate: z.string().optional(),
      agent_key: z.string().optional(),
    },
    async (args) => {
      const { handle, zone, section_id, title, body, tags, clear_tags } =
        args as {
          handle?: string;
          zone: Sphere;
          section_id: string;
          title?: string;
          body?: string;
          tags?: string[];
          clear_tags?: boolean;
        };
      if (
        title === undefined &&
        body === undefined &&
        tags === undefined &&
        !clear_tags
      ) {
        throw new Error(
          "ethos_update_section: pass at least one of title, body, tags, clear_tags",
        );
      }
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteFor(zone, args as never);
      if (transactional) {
        const t = enroll(h, auth);
        const cur = await effectiveSection(h, zone, section_id);
        if (!cur) {
          throw new Error(
            `ethos_update_section: no section ${section_id} in zone ${zone} ` +
              `(persisted or staged)`,
          );
        }
        const w: StagedWrite = {
          edit: {
            op: "modify",
            zone,
            sectionId: section_id,
            ...(title !== undefined ? { title } : {}),
            ...(body !== undefined ? { body } : {}),
            ...(clear_tags ? { clearTags: true } : tags !== undefined ? { tags } : {}),
          },
          summary: { op: "modify", zone, section_id },
        };
        t.writes.push(w);
        return stageAck(t, w);
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const effectiveTags = clear_tags ? [] : tags;
      const { section, manifest, gammaEntry } = await storage.modifySection(
        {
          handle: h,
          zone,
          sectionId: section_id,
          title,
          body,
          tags: effectiveTags,
        },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        section: sectionSummary(zone, section as Section),
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
        gamma_entry_id: gammaEntry?.id ?? section.gamma_ref,
        gamma_head: manifest.gamma?.head ?? null,
        gamma_count: manifest.gamma?.count ?? 0,
      });
    },
  );

  register(
    "ethos_append_section",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
      section_id: z.string(),
      content: z.string().min(1),
      mandate: z.string().optional(),
      agent_key: z.string().optional(),
    },
    async (args) => {
      const { handle, zone, section_id, content } = args as {
        handle?: string;
        zone: Sphere;
        section_id: string;
        content: string;
      };
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteFor(zone, args as never);
      const cur = await effectiveSection(h, zone, section_id);
      if (!cur) {
        throw new Error(
          `ethos_append_section: no section ${section_id} in zone ${zone} ` +
            `(persisted${transactional ? " or staged" : ""})`,
        );
      }
      const nextBody = cur.body.length > 0 ? `${cur.body}\n${content}` : content;
      if (transactional) {
        const t = enroll(h, auth);
        const w: StagedWrite = {
          edit: { op: "modify", zone, sectionId: section_id, body: nextBody },
          summary: { op: "append", zone, section_id },
        };
        t.writes.push(w);
        return stageAck(t, w);
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const { section, manifest, gammaEntry } = await storage.modifySection(
        { handle: h, zone, sectionId: section_id, body: nextBody },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        section: sectionSummary(zone, section as Section),
        appended_chars: content.length,
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
        gamma_entry_id: gammaEntry?.id ?? section.gamma_ref,
      });
    },
  );

  register(
    "ethos_delete_section",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
      section_id: z.string(),
      reason: z.string().optional(),
      mandate: z.string().optional(),
      agent_key: z.string().optional(),
    },
    async (args) => {
      const { handle, zone, section_id, reason } = args as {
        handle?: string;
        zone: Sphere;
        section_id: string;
        reason?: string;
      };
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteFor(zone, args as never);
      if (transactional) {
        const t = enroll(h, auth);
        const cur = await effectiveSection(h, zone, section_id);
        if (!cur) {
          throw new Error(
            `ethos_delete_section: no section ${section_id} in zone ${zone} ` +
              `(persisted or staged)`,
          );
        }
        const w: StagedWrite = {
          edit: {
            op: "delete",
            zone,
            sectionId: section_id,
            ...(reason !== undefined ? { reason } : {}),
          },
          summary: { op: "delete", zone, section_id },
        };
        t.writes.push(w);
        return stageAck(t, w);
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const result = await storage.deleteSection(
        {
          handle: h,
          zone,
          sectionId: section_id,
          ...(reason !== undefined ? { reason } : {}),
        },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        zone,
        deleted_section_id: result.sectionId,
        deleted_title: result.deletedTitle ?? null,
        manifest_version: result.manifest.edition.version,
        manifest_height: result.manifest.edition.height,
        gamma_entry_id: result.gammaEntry?.id ?? null,
        gamma_head: result.manifest.gamma?.head ?? null,
        gamma_count: result.manifest.gamma?.count ?? 0,
      });
    },
  );

  // ------------------------------------------------------------ commit/discard
  //
  // Registered ONLY on transactional hosts: an auto-commit host has nothing
  // to commit and must not advertise the tools (T10 checks subset parity).

  if (transactional) {
    register(
      "ethos_commit",
      { message: z.string().optional() },
      async (args) => {
        const { message } = args as { message?: string };
        if (!tx || tx.writes.length === 0) {
          throw new Error(
            "ethos_commit: nothing is staged — stage writes first",
          );
        }
        const t = tx;
        // T6 — authority may have been revoked or expired since staging:
        // re-check NOW, before anything persists (per-call auth OR the
        // session-level mandate of a self-signing host).
        if (t.auth) await assertMandateLive(t.auth.mandate);
        else if (opts.mandate?.document) await assertMandateLive(opts.mandate.document);
        const identity = await loadWriteIdentity(storage, t.handle, t.auth);
        const result: ApplyEditsResult = await storage.applyEdits!(
          t.handle,
          t.writes.map((w) => w.edit),
          { identity, delegate: t.auth?.delegate },
        );
        // Success: the batch is sealed — clear the transaction.
        tx = null;
        return ok({
          committed: true,
          edits: result.results.length,
          ...(message !== undefined ? { message } : {}),
          manifest_version: result.manifest.edition.version,
          manifest_height: result.manifest.edition.height,
          gamma_head: result.manifest.gamma?.head ?? null,
          results: result.results.map((r) =>
            r.op === "delete"
              ? { op: r.op, zone: r.zone, section_id: r.sectionId }
              : {
                  op: r.op,
                  zone: r.zone,
                  section_id: r.section.id,
                  title: r.section.title,
                  gamma_ref: r.section.gamma_ref,
                },
          ),
        });
      },
    );

    register("ethos_discard", {}, async () => {
      const n = tx?.writes.length ?? 0;
      tx = null;
      return ok({
        discarded: n,
        note: n === 0 ? "nothing was staged" : "no edition was written",
      });
    });
  }

  // ------------------------------------------------------------------ mandates

  // ------------------------------------------------- living mandate (P4)

  /** Window + revocation status of a mandate, as data (never throws). */
  const mandateStatus = async (
    m: Mandate,
  ): Promise<{ valid: boolean; reasons: string[]; revoked: { revoked_at: string; reason?: string } | null }> => {
    const reasons: string[] = [];
    const now = Date.now();
    const nbf = Date.parse(m.not_before);
    const naf = Date.parse(m.not_after);
    if (Number.isFinite(nbf) && now < nbf) reasons.push(`not yet valid (not_before ${m.not_before})`);
    if (Number.isFinite(naf) && now > naf) reasons.push(`expired at ${m.not_after}`);
    let revoked: { revoked_at: string; reason?: string } | null = null;
    const rev = await storage.findRevocation(m.id);
    if (rev) {
      revoked = { revoked_at: rev.revoked_at, ...(rev.reason ? { reason: rev.reason } : {}) };
      reasons.push(`revoked at ${rev.revoked_at}`);
    }
    return { valid: reasons.length === 0, reasons, revoked };
  };

  const describeMandate = async (m: Mandate) => {
    const status = await mandateStatus(m);
    return {
      session: "delegate" as const,
      id: m.id,
      issuer: m.issuer,
      grantee: { id: m.grantee.id, pubkey: m.grantee.pubkey },
      actor_sphere: m.actor_sphere,
      scopes: [...m.scopes],
      ...(m.section_scope ? { section_scope: m.section_scope } : {}),
      not_before: m.not_before,
      not_after: m.not_after,
      issued_at: m.issued_at,
      status: {
        valid: status.valid,
        reasons: status.reasons,
        // Signature + issuer-binding verification is `mandate_verify`'s job
        // (needs the issuer DID document); this is the LIVE operational view.
        signature_checked: false,
      },
      revoked: status.revoked,
      tools: [...registeredTools].sort(),
    };
  };

  /** The no-argument `mandate_describe` view — also the `mandate` part of
   *  `agent_briefing` (P6). */
  const describeSession = async () => {
    const doc = opts.mandate?.document;
    if (doc) return describeMandate(doc);
    if (opts.mandate) {
      // Scope-filtered session without the full document (library host
      // that passed scopes only): report what is knowable.
      return {
        session: "delegate" as const,
        scopes: [...opts.mandate.scopes],
        tools: [...registeredTools].sort(),
        note:
          "session is mandate-scoped but the host did not provide the " +
          "mandate document — id/window/revocation unavailable here",
      };
    }
    return {
      session: "owner" as const,
      scopes: null,
      tools: [...registeredTools].sort(),
      note: "owner session — full authority over the subject's own ethos",
    };
  };

  register(
    "mandate_describe",
    { mandate: z.string().optional() },
    async (args) => {
      const { mandate } = args as { mandate?: string };
      if (mandate) {
        const m = await storage.loadMandate(mandate);
        return ok(await describeMandate(m));
      }
      return ok(await describeSession());
    },
  );

  register(
    "ethos_preflight_write",
    {
      handle: z.string().optional(),
      zone: z.enum(SPHERE_FRAGMENTS),
    },
    async (args) => {
      const { handle, zone } = args as { handle?: string; zone: Sphere };
      const h = await resolveHandle(storage, handle);
      // Owner session (no mandate): full authority.
      if (!opts.mandate) {
        return ok({ handle: h, zone, authorized: true, authority: "owner" });
      }
      const writeScope = `ethos.write.${zone}`;
      if (!opts.mandate.scopes.includes(writeScope)) {
        return ok({
          handle: h,
          zone,
          authorized: false,
          authority: "delegate",
          reason: `mandate does not include scope ${writeScope}`,
        });
      }
      const doc = opts.mandate.document;
      if (doc) {
        const status = await mandateStatus(doc);
        if (!status.valid) {
          return ok({
            handle: h,
            zone,
            authorized: false,
            authority: "delegate",
            reason: status.reasons.join("; "),
          });
        }
      }
      return ok({
        handle: h,
        zone,
        authorized: true,
        authority: "delegate",
        ...(doc
          ? { mandate_id: doc.id, rechecked_at_commit: true }
          : { note: "scope check only — host provided no mandate document" }),
      });
    },
  );

  register(
    "mandate_verify",
    {
      mandate: z.string(),
      at: z.string().optional(),
    },
    async (args) => {
      const { mandate, at } = args as { mandate: string; at?: string };
      let m: Mandate;
      if (mandate.includes("/") || mandate.endsWith(".json")) {
        if (!io) {
          throw new Error(
            "path-form mandates need host file access; this host resolves " +
              "mandates by id only (mandate_<ULID>)",
          );
        }
        const p = io.resolvePath ? io.resolvePath(mandate) : mandate;
        m = JSON.parse(await io.readTextFile(p)) as Mandate;
      } else {
        m = await storage.loadMandate(mandate);
      }
      // `issuer` is `did:aithos:<mb>` — find the matching local identity (owned
      // or tracked) to load its DID document. Verification only needs public
      // keys, so a tracked identity is perfectly fine as an issuer lookup.
      const subjectDid = m.issuer;
      let didDoc: DidDocument | undefined;
      for (const h of await storage.listHandles()) {
        try {
          const meta = await storage.loadIdentityMetadata(h);
          if (meta.did === subjectDid) {
            didDoc = meta.didDocument;
            break;
          }
        } catch {
          /* skip identities with corrupted did.json */
        }
      }
      if (!didDoc) {
        throw new Error(
          `no local DID document found for issuer ${subjectDid}; run \`aithos verify\` with --did-document to check externally-issued mandates`,
        );
      }
      const result = verifyMandate(m, didDoc, at ? new Date(at) : new Date());
      return ok({ mandateId: m.id, issuer: m.issuer, ...result });
    },
  );

  // ------------------------------------------------------------------ resources

  // `aithos://identities` — machine-readable index.
  server.registerResource(
    "aithos_identities",
    "aithos://identities",
    {
      title: "Local Aithos identities",
      mimeType: "application/json",
      description:
        "JSON index of every identity this host serves (handle, DID, tracked).",
    },
    async (uri) => {
      const handles = await storage.listHandles();
      const list = await Promise.all(
        handles.map(async (h) => {
          try {
            const meta = await storage.loadIdentityMetadata(h);
            return { handle: h, did: meta.did, tracked: meta.tracked };
          } catch (e) {
            return { handle: h, error: (e as Error).message };
          }
        }),
      );
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(list, null, 2),
          },
        ],
      };
    },
  );

  // Helper: enumerate ethos URIs for every local identity (used by the
  // `list` callback on every template). Cheap — just reads the directory.
  const listEthosResources = async () => {
    const out: Array<{ uri: string; name: string; mimeType?: string }> = [];
    for (const h of await storage.listHandles()) {
      out.push({
        uri: `aithos://ethos/${h}/manifest`,
        name: `ethos-manifest:${h}`,
        mimeType: "application/json",
      });
      out.push({
        uri: `aithos://ethos/${h}/voice`,
        name: `ethos-voice:${h}`,
        mimeType: "application/json",
      });
      for (const zn of SPHERE_FRAGMENTS) {
        out.push({
          uri: `aithos://ethos/${h}/${zn}`,
          name: `ethos-zone:${h}/${zn}`,
          mimeType: "text/markdown",
        });
      }
    }
    return out;
  };

  // `aithos://ethos/{handle}/manifest` — the signed manifest.
  server.registerResource(
    "aithos_ethos_manifest",
    new ResourceTemplate("aithos://ethos/{handle}/manifest", {
      list: async () => ({
        resources: (await listEthosResources()).filter((r) =>
          r.uri.endsWith("/manifest"),
        ),
      }),
    }),
    {
      title: "Ethos manifest",
      mimeType: "application/json",
      description:
        "Current signed manifest for the given identity (version, height, zones[].sha256_plaintext, …).",
    },
    async (uri, { handle }) => {
      const h = Array.isArray(handle) ? handle[0] : handle;
      if (!h) throw new Error(`malformed uri: ${uri.href}`);
      const m = await storage.readManifest(h);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(m, null, 2),
          },
        ],
      };
    },
  );

  // `aithos://ethos/{handle}/voice` — presentation guidance (V10, §12.3).
  // Registered BEFORE the {zone} template: both match `…/voice`, and
  // resolution follows registration order.
  server.registerResource(
    "aithos_ethos_voice",
    new ResourceTemplate("aithos://ethos/{handle}/voice", {
      list: async () => ({
        resources: (await listEthosResources()).filter((r) =>
          r.uri.endsWith("/voice"),
        ),
      }),
    }),
    {
      title: "Voice profile (presentation guidance)",
      mimeType: "application/json",
      description:
        "How to narrate this subject (§12.3): an authored public section " +
        "tagged `voice`/`guidance` served verbatim, or the spec §12.3.4 " +
        "default with {handle} substituted.",
    },
    async (uri, { handle }) => {
      const h = Array.isArray(handle) ? handle[0] : handle;
      if (!h) throw new Error(`malformed uri: ${uri.href}`);
      const vp = await voiceProfile(h);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: vp.guidance ? "application/json" : "text/markdown",
            text: vp.text,
          },
        ],
      };
    },
  );

  // `aithos://ethos/{handle}/{zone}` — markdown source of a zone (plaintext
  // for `public`, decrypted in memory for `circle`/`self` if the identity is
  // local; otherwise the raw ciphertext is returned as a fallback).
  server.registerResource(
    "aithos_ethos_zone",
    new ResourceTemplate("aithos://ethos/{handle}/{zone}", {
      list: async () => ({
        resources: (await listEthosResources()).filter(
          (r) =>
            !r.uri.endsWith("/manifest") &&
            !r.uri.endsWith("/manifest-path") &&
            !r.uri.endsWith("/voice"),
        ),
      }),
    }),
    {
      title: "Ethos zone (markdown)",
      mimeType: "text/markdown",
      description:
        "Markdown source of an ethos zone. Reading circle/self requires a " +
        "local identity; otherwise the encrypted on-disk form is returned.",
    },
    async (uri, vars) => {
      const handle = Array.isArray(vars.handle) ? vars.handle[0] : vars.handle;
      const rawZone = Array.isArray(vars.zone) ? vars.zone[0] : vars.zone;
      const zone = rawZone as Sphere | undefined;
      if (!handle || !zone || !SPHERE_FRAGMENTS.includes(zone)) {
        throw new Error(`malformed uri: ${uri.href}`);
      }
      if (zone === "public") {
        // v0.2: the public zone is a single markdown file. v0.3: there is no
        // single blob, so re-render the zone from its per-section docs.
        try {
          const bytes = await storage.readZoneBytes(handle, zone);
          return {
            contents: [
              { uri: uri.href, mimeType: "text/markdown", text: new TextDecoder("utf-8").decode(bytes) },
            ],
          };
        } catch {
          if (!opts.renderZone) {
            throw new Error(
              `zone "${zone}" of "${handle}" is per-section (v0.3); read ` +
                `sections by id (ethos_read_sections) — this host has no ` +
                `zone renderer`,
            );
          }
          const manifest = await storage.readManifest(handle);
          const doc = await storage.readZoneDoc(handle, zone, { manifest });
          const md = opts.renderZone(zone, doc, {
            subjectDid: manifest.subject_did,
            subjectHandle: handle,
            editionVersion: manifest.edition.version,
            createdAt: manifest.edition.created_at,
          });
          return { contents: [{ uri: uri.href, mimeType: "text/markdown", text: md }] };
        }
      }
      // For encrypted zones, decrypt with a local identity and re-render. Without
      // a key, fall back to the raw ciphertext (v0.2 sync agents); a v0.3
      // per-section ethos has no single zone blob, so report that instead.
      try {
        if (!opts.renderZone) throw new Error("no zone renderer on this host");
        const identity = await storage.loadIdentity(handle);
        const manifest = await storage.readManifest(handle);
        const doc = await storage.readZoneDoc(handle, zone, {
          identity,
          manifest,
        });
        // Re-render markdown using the host-injected canonical renderer.
        const md = opts.renderZone(zone, doc, {
          subjectDid: rootDid(identity),
          subjectHandle: handle,
          editionVersion: manifest.edition.version,
          createdAt: manifest.edition.created_at,
        });
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "text/markdown",
              text: md,
            },
          ],
        };
      } catch {
        try {
          const bytes = await storage.readZoneBytes(handle, zone);
          return {
            contents: [
              {
                uri: uri.href,
                mimeType: "application/octet-stream",
                blob: bytesToBase64(bytes),
              },
            ],
          };
        } catch {
          return {
            contents: [
              {
                uri: uri.href,
                mimeType: "text/plain",
                text:
                  `Zone "${zone}" of "${handle}" is encrypted and no sphere key is available. ` +
                  `For a v0.3 per-section ethos, read individual sections by id ` +
                  `(ethos_read_sections); there is no single zone blob.`,
              },
            ],
          };
        }
      }
    },
  );

  // `aithos://ethos/{handle}/manifest-path` — absolute on-disk path, useful
  // for UIs that want to open the file directly. Filesystem-only diagnostic;
  // registered when the host provides a `manifestPath` resolver (bin.ts does).
  const manifestPath = opts.manifestPath;
  if (manifestPath) {
    server.registerResource(
      "aithos_ethos_manifest_path",
      new ResourceTemplate("aithos://ethos/{handle}/manifest-path", {
        list: undefined,
      }),
      {
        title: "Ethos manifest file path",
        mimeType: "text/plain",
      },
      async (uri, { handle }) => {
        const h = Array.isArray(handle) ? handle[0] : handle;
        if (!h) throw new Error(`malformed uri: ${uri.href}`);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "text/plain",
              text: manifestPath(h),
            },
          ],
        };
      },
    );
  }

  // ------------------------------------------------------------ legacy aliases
  //
  // tools/list exposes ONLY canonical names; legacy `aithos_*` names keep
  // resolving at tools/call for one minor version (removal in 1.0). The MCP
  // SDK has no public "hidden tool" facility, so we wrap its tools/call
  // request handler. The private-map access below is pinned by the alias
  // regression test in test/h1-inmemory.test.mjs — an SDK upgrade that moves
  // these internals fails loudly there, never silently.
  if (opts.legacyAliases !== false) {
    const inner = (
      server as unknown as {
        server: {
          _requestHandlers?: Map<
            string,
            (req: unknown, extra: unknown) => Promise<unknown>
          >;
        };
      }
    ).server;
    const handlers = inner._requestHandlers;
    const original = handlers?.get("tools/call");
    if (!handlers || !original) {
      // SDK internals moved — canonical names keep working; aliases don't.
      console.error(
        "aithos-mcp: legacy alias bridge unavailable (MCP SDK internals " +
          "changed); pre-0.9 aithos_* tool names will not resolve",
      );
    } else {
      handlers.set("tools/call", async (req: unknown, extra: unknown) => {
        const r = req as {
          params?: { name?: string; arguments?: Record<string, unknown> };
        };
        const name = r.params?.name;
        if (typeof name === "string") {
          const resolved = resolveLegacyToolCall(name, r.params?.arguments);
          if (resolved.wasAlias) {
            console.error(
              `aithos-mcp: tool '${name}' is a deprecated alias of ` +
                `'${resolved.name}' — update your client (removal in 1.0)`,
            );
            req = {
              ...r,
              params: {
                ...r.params,
                name: resolved.name,
                arguments: resolved.args,
              },
            };
          }
        }
        return original(req, extra);
      });
    }
  }

  return server;
}

// Re-export the Manifest type for downstream consumers (tests, etc.).
export type { Manifest };
