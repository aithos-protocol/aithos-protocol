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
  DidDocument,
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
  try {
    return await storage.loadIdentity(handle);
  } catch (e) {
    if (!auth) throw e;
    return undefined;
  }
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
   */
  mandate?: { readonly scopes: readonly string[] };
  /** Optional extra restriction: only expose these canonical tool names. */
  exposeTools?: readonly string[];
  /**
   * Accept legacy pre-0.9 `aithos_*` tool names at `tools/call` (never
   * listed), logging a deprecation warning. Default true. Removal in 1.0.
   */
  legacyAliases?: boolean;
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
  const register = (
    name: string,
    shape: z.ZodRawShape,
    handler: (args: Record<string, unknown>) => Promise<{ content: { type: "text"; text: string }[] }>,
  ): void => {
    if (!exposed.has(name)) return;
    const s = spec(name);
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
   * Shared guard for the three write tools: resolve the (optional) delegate
   * auth and enforce the per-zone write scope (defense in depth — exposure
   * filtering above is the coarse gate; this is the per-call gate).
   */
  const resolveWriteFor = async (
    zone: Sphere,
    args: { mandate?: string; agent_key?: string },
  ): Promise<ResolvedWriteAuth | null> => {
    const auth = await resolveWriteAuth(
      storage,
      { mandate: args.mandate, agentKey: args.agent_key },
      io,
    );
    if (auth) {
      const writeScope = `ethos.write.${zone}`;
      if (!auth.mandate.scopes.includes(writeScope)) {
        throw new Error(
          `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
        );
      }
    }
    return auth;
  };

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
      const identity = await loadWriteIdentity(storage, h, auth);
      const { section, manifest, gammaEntry } = await storage.addSection(
        { handle: h, zone, title, body, tags },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        section: sectionSummary(zone, section as Section),
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
        // v0.3 writes have no signed gamma entry yet — fall back to the
        // section's gamma_ref as the provenance anchor.
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

  // ------------------------------------------------------------------ mandates

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

  // `aithos://ethos/{handle}/{zone}` — markdown source of a zone (plaintext
  // for `public`, decrypted in memory for `circle`/`self` if the identity is
  // local; otherwise the raw ciphertext is returned as a fallback).
  server.registerResource(
    "aithos_ethos_zone",
    new ResourceTemplate("aithos://ethos/{handle}/{zone}", {
      list: async () => ({
        resources: (await listEthosResources()).filter(
          (r) => !r.uri.endsWith("/manifest") && !r.uri.endsWith("/manifest-path"),
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
