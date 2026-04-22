/**
 * Aithos MCP server (v0.4.1 republish — content identical to 0.4.0, the
 * original tarball upload was interrupted and the registry slot became
 * unusable; no behavioural change).
 *
 * Wraps the protocol-core primitives (identity / ethos / mandate) as MCP tools
 * and resources so LLM agents speaking the Model Context Protocol can:
 *
 *   - introspect an identity (read sphere public keys, DID)
 *   - list sections across zones
 *   - read the current body of a section (decrypting circle/self locally)
 *   - verify the full ethos (gamma anchor, signatures, manifest link)
 *   - add sections and modify them (under a write mandate + agent key), each
 *     mutation emitting a signed gamma entry (spec §10)
 *
 * Every I/O call flows through an injected {@link AithosStorage}. The default
 * is {@link FilesystemStorage} which reads/writes the local `$AITHOS_HOME`.
 * Hosts that want to back the MCP with a remote API (e.g. the Aithos platform)
 * can pass their own `AithosStorage` implementation — typically one that
 * packages every write in a signed envelope (spec §11.2) and forwards it to
 * the remote.
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

import {
  AITHOS_HOME,
  ethosManifestPath,
  FilesystemStorage,
  SPHERE_FRAGMENTS,
  TrackedIdentityError,
  rootDid,
  verifyMandate,
  type AithosStorage,
  type DidDocument,
  type Identity,
  type Mandate,
  type Manifest,
  type Section,
  type Sphere,
  type ZoneDoc,
} from "@aithos/protocol-core";
import fs from "node:fs";
import path from "node:path";

import { resolveWriteAuth, type ResolvedWriteAuth } from "./auth.js";

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

/**
 * Best-effort zone loader: decrypts circle/self if the identity is owned,
 * errors with a tracked-identity message if only the public data is available.
 */
async function readZone(
  storage: AithosStorage,
  handle: string,
  zone: Sphere,
): Promise<ZoneDoc> {
  if (zone === "public") {
    try {
      return await storage.readZoneDoc(handle, zone);
    } catch (e) {
      throw new Error(
        `failed to load public zone for ${handle}: ${(e as Error).message}`,
      );
    }
  }
  // circle / self need a local Identity (subject secret) to decrypt.
  // `storage.loadIdentity` throws `TrackedIdentityError` if any sealed seed is
  // missing (filesystem backend) — we let it bubble up so the caller gets a
  // clear message.
  const identity = await storage.loadIdentity(handle);
  const manifest = await storage.readManifest(handle);
  return storage.readZoneDoc(handle, zone, { identity, manifest });
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

// ---------- server registration -------------------------------------------

export interface CreateServerOptions {
  /** Override the server name that appears in `initialize` results. */
  name?: string;
  /** Override the server version that appears in `initialize` results. */
  version?: string;
  /**
   * Storage backend for every identity / ethos / mandate read and write.
   * Defaults to {@link FilesystemStorage} which reads `$AITHOS_HOME`.
   */
  storage?: AithosStorage;
}

export function createServer(opts: CreateServerOptions = {}): McpServer {
  const server = new McpServer(
    {
      name: opts.name ?? "aithos-mcp",
      version: opts.version ?? "0.1.0",
    },
    {
      // We expose tools + resources, not prompts.
      capabilities: { tools: {}, resources: {} },
    },
  );

  const storage: AithosStorage = opts.storage ?? new FilesystemStorage();

  // ------------------------------------------------------------------ identity

  server.registerTool(
    "aithos_list_identities",
    {
      title: "List local Aithos identities",
      description:
        "Lists every identity in the local store (under $AITHOS_HOME), " +
        "returning handle, DID, and the sphere DID URLs.",
      inputSchema: {},
    },
    async () => {
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
      return ok({ aithos_home: AITHOS_HOME, identities: out });
    },
  );

  server.registerTool(
    "aithos_show_identity",
    {
      title: "Show identity metadata",
      description:
        "Returns the DID, display name, sphere DID URLs, and key fingerprints " +
        "for the named (or default) identity.",
      inputSchema: {
        handle: z
          .string()
          .optional()
          .describe("Identity handle; defaults to the configured default."),
      },
    },
    async ({ handle }) => {
      const h = await resolveHandle(storage, handle);
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

  server.registerTool(
    "aithos_ethos_list_sections",
    {
      title: "List ethos sections",
      description:
        "Lists every section in the ethos across public/circle/self (or a single " +
        "zone via `zone`). Circle and self require a local identity to decrypt.",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS).optional(),
      },
    },
    async ({ handle, zone }) => {
      const h = await resolveHandle(storage, handle);
      const tracked = await storage.isTrackedIdentity(h);
      const zones: Sphere[] = zone ? [zone] : [...SPHERE_FRAGMENTS];
      const sections: ReturnType<typeof sectionSummary>[] = [];
      const skipped: Array<{ zone: Sphere; reason: string }> = [];
      for (const z of zones) {
        // Fast path: tracked identity, encrypted zone — don't even try to
        // decrypt, surface a clean "skipped" record instead of a synthetic
        // error row shaped like a section.
        if (tracked && z !== "public") {
          skipped.push({
            zone: z,
            reason:
              "encrypted — no sphere key (identity is tracked-only)",
          });
          continue;
        }
        try {
          const doc = await readZone(storage, h, z);
          for (const s of doc.sections) sections.push(sectionSummary(z, s));
        } catch (e) {
          if (e instanceof TrackedIdentityError) {
            skipped.push({ zone: z, reason: e.message });
          } else {
            skipped.push({ zone: z, reason: (e as Error).message });
          }
        }
      }
      return ok({ handle: h, tracked, sections, skipped });
    },
  );

  server.registerTool(
    "aithos_ethos_show_section",
    {
      title: "Show a section's current content",
      description:
        "Returns the current body of a section, plus metadata and the " +
        "gamma_ref anchor. Mutation history lives in the gamma log — call " +
        "`aithos_ethos_gamma` (or `aithos gamma show --section`) to walk it.",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS),
        sectionId: z.string().describe("Section id (sec_<hex>)"),
      },
    },
    async ({ handle, zone, sectionId }) => {
      const h = await resolveHandle(storage, handle);
      // Short-circuit encrypted zones on a tracked identity with an explicit
      // message — the on-disk ciphertext cannot be read without the sphere key,
      // so there's no point trying and surfacing a generic decryption error.
      if ((await storage.isTrackedIdentity(h)) && zone !== "public") {
        throw new Error(
          `cannot read section in ${zone} zone of "${h}": identity is tracked-only ` +
            `(no sphere key on disk). Only the public zone is readable.`,
        );
      }
      const doc = await readZone(storage, h, zone);
      const section = doc.sections.find((s) => s.id === sectionId);
      if (!section) {
        throw new Error(`section ${sectionId} not found in zone ${zone}`);
      }
      return ok({
        zone,
        id: section.id,
        title: section.title,
        tags: section.tags ?? [],
        gamma_ref: section.gamma_ref,
        body: section.body,
      });
    },
  );

  server.registerTool(
    "aithos_ethos_verify",
    {
      title: "Verify ethos integrity",
      description:
        "Full integrity check: zone signatures, manifest signature, edition " +
        "history link, and the gamma anchor (manifest.gamma.head must match " +
        "the live log tail, and every section's gamma_ref must exist in the " +
        "log). The signed mutation history itself is walked by the companion " +
        "`aithos gamma verify` tool.",
      inputSchema: {
        handle: z.string().optional(),
        decrypt: z
          .boolean()
          .optional()
          .describe(
            "If false, skip decrypting circle/self and only verify public + manifest.",
          ),
      },
    },
    async ({ handle, decrypt }) => {
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

  server.registerTool(
    "aithos_ethos_add_section",
    {
      title: "Add a new section",
      description:
        "Creates a new section with an initial revision. Requires either a " +
        "local subject identity (writes under the sphere key) OR a write " +
        "mandate + agent keyfile (writes under the delegate key).",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS),
        title: z.string().min(1),
        body: z.string().min(1).describe("Initial revision body (markdown)"),
        tags: z.array(z.string()).optional(),
        mandate: z
          .string()
          .optional()
          .describe(
            "Mandate id (mandate_<ULID>) or absolute path to the JSON file.",
          ),
        agentKey: z
          .string()
          .optional()
          .describe(
            "Path to the delegate keyfile produced by `aithos delegate-key`.",
          ),
      },
    },
    async ({ handle, zone, title, body, tags, mandate, agentKey }) => {
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteAuth(storage, { mandate, agentKey });
      if (auth) {
        const writeScope = `ethos.write.${zone}`;
        if (!auth.mandate.scopes.includes(writeScope)) {
          throw new Error(
            `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
          );
        }
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const { section, manifest, gammaEntry } = await storage.addSection(
        {
          handle: h,
          zone,
          title,
          body,
          tags,
        },
        { identity, delegate: auth?.delegate },
      );
      return ok({
        section: sectionSummary(zone, section as Section),
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
        gamma_entry_id: gammaEntry.id,
        gamma_head: manifest.gamma?.head ?? null,
        gamma_count: manifest.gamma?.count ?? 0,
      });
    },
  );

  server.registerTool(
    "aithos_ethos_modify_section",
    {
      title: "Modify an existing section in-place",
      description:
        "Applies a change to one or more of {title, body, tags} on an " +
        "existing section. Emits one signed `section.modify` entry in the " +
        "gamma log carrying the full new value of each changed field (spec " +
        "§10.6.1); the previous state remains in the log as the audit trail. " +
        "Auth semantics identical to `aithos_ethos_add_section`. Pass at " +
        "least one of { title, body, tags, clearTags }.",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS),
        sectionId: z.string(),
        title: z.string().optional(),
        body: z.string().optional(),
        tags: z.array(z.string()).optional(),
        clearTags: z.boolean().optional(),
        mandate: z.string().optional(),
        agentKey: z.string().optional(),
      },
    },
    async ({
      handle,
      zone,
      sectionId,
      title,
      body,
      tags,
      clearTags,
      mandate,
      agentKey,
    }) => {
      if (title === undefined && body === undefined && tags === undefined && !clearTags) {
        throw new Error(
          "aithos_ethos_modify_section: pass at least one of title, body, tags, clearTags",
        );
      }
      const h = await resolveHandle(storage, handle);
      const auth = await resolveWriteAuth(storage, { mandate, agentKey });
      if (auth) {
        const writeScope = `ethos.write.${zone}`;
        if (!auth.mandate.scopes.includes(writeScope)) {
          throw new Error(
            `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
          );
        }
      }
      const identity = await loadWriteIdentity(storage, h, auth);
      const effectiveTags = clearTags ? [] : tags;
      const { section, manifest, gammaEntry } = await storage.modifySection(
        {
          handle: h,
          zone,
          sectionId,
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
        gamma_entry_id: gammaEntry.id,
        gamma_head: manifest.gamma?.head ?? null,
        gamma_count: manifest.gamma?.count ?? 0,
      });
    },
  );

  // ------------------------------------------------------------------ mandates

  server.registerTool(
    "aithos_mandate_verify",
    {
      title: "Verify a mandate",
      description:
        "Checks a mandate's signature, expiry, revocation state, and subject " +
        "binding against the subject's DID document. Pass either a mandate id " +
        "(looked up in the local store) or a path to a mandate JSON.",
      inputSchema: {
        mandate: z.string(),
        at: z
          .string()
          .optional()
          .describe("RFC 3339 timestamp to evaluate validity at (default: now)"),
      },
    },
    async ({ mandate, at }) => {
      let m: Mandate;
      if (mandate.includes("/") || mandate.endsWith(".json")) {
        const p = path.resolve(mandate);
        m = JSON.parse(fs.readFileSync(p, "utf8")) as Mandate;
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
        "JSON index of every identity in $AITHOS_HOME (handle, DID, spheres).",
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
      for (const z of SPHERE_FRAGMENTS) {
        out.push({
          uri: `aithos://ethos/${h}/${z}`,
          name: `ethos-zone:${h}/${z}`,
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
        const bytes = await storage.readZoneBytes(handle, zone);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "text/markdown",
              text: new TextDecoder("utf-8").decode(bytes),
            },
          ],
        };
      }
      // For encrypted zones, try to decrypt with a local identity. If we don't
      // have one, return the ciphertext blob — useful for synchronisation
      // agents that never need plaintext.
      try {
        const identity = await storage.loadIdentity(handle);
        const manifest = await storage.readManifest(handle);
        const doc = await storage.readZoneDoc(handle, zone, {
          identity,
          manifest,
        });
        // Re-render markdown using the ethos module's canonical renderer.
        const { renderZoneMarkdown } = await import("@aithos/protocol-core");
        const md = renderZoneMarkdown(zone, doc, {
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
        const bytes = await storage.readZoneBytes(handle, zone);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/octet-stream",
              blob: Buffer.from(bytes).toString("base64"),
            },
          ],
        };
      }
    },
  );

  // `aithos://ethos/{handle}/manifest/path` — absolute on-disk path, useful
  // for UIs that want to open the file directly. Filesystem-only diagnostic;
  // only registered when the backend is a {@link FilesystemStorage}.
  if (storage instanceof FilesystemStorage) {
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
              text: ethosManifestPath(h),
            },
          ],
        };
      },
    );
  }

  return server;
}

// Re-export the Manifest type for downstream consumers (tests, etc.).
export type { Manifest };
