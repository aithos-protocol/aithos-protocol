/**
 * Aithos MCP server.
 *
 * Wraps the CLI's ethos + identity + mandate primitives as MCP tools and
 * resources so that LLM agents speaking the Model Context Protocol can:
 *
 *   - introspect an identity (read sphere public keys, DID)
 *   - list sections across zones
 *   - read the current body of a section (decrypting circle/self locally)
 *   - verify the full ethos (chains, signatures, manifest link)
 *   - append revisions (under a write mandate + agent key)
 *
 * The server is intentionally stateless: each tool call re-reads from disk.
 * That's slightly slower than caching, but it matches the on-disk semantics
 * (the CLI may have written new revisions between calls) and makes tamper
 * detection honest.
 */
import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import {
  loadConfig,
  listIdentities,
  AITHOS_HOME,
  identityDir,
  readJson,
} from "@aithos/cli/storage";
import {
  loadIdentity,
  loadIdentityMetadata,
  isTrackedIdentity,
  TrackedIdentityError,
  rootDid,
  sphereDidUrl,
  type DidDocument,
} from "@aithos/cli/identity";
import {
  ethosManifestPath,
  ethosZoneFile,
  readManifest,
  loadZoneDoc,
  verifyEthos,
  addSection,
  addRevision,
  type Section,
  type ZoneDoc,
  type Manifest,
} from "@aithos/cli/ethos";
import { SPHERE_FRAGMENTS, type Sphere } from "@aithos/cli/did";
import {
  verifyMandate,
  loadMandate,
  type Mandate,
} from "@aithos/cli/mandate";
import fs from "node:fs";
import path from "node:path";

import { resolveWriteAuth } from "./auth.js";

// ---------- helpers --------------------------------------------------------

function resolveHandle(handle?: string): string {
  if (handle) return handle;
  const cfg = loadConfig();
  if (!cfg.default_handle) {
    throw new Error(
      "no handle provided and no default identity configured (run `aithos init`)",
    );
  }
  return cfg.default_handle;
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
  revision: number;
  updated_at: string;
  tags: string[];
} {
  const latest = s.revisions[s.revisions.length - 1];
  return {
    zone,
    id: s.id,
    title: s.title,
    revision: s.revisions.length,
    updated_at: latest?.at ?? "",
    tags: s.tags ?? [],
  };
}

/**
 * Best-effort zone loader: decrypts circle/self if the identity is owned,
 * errors with a tracked-identity message if only the public data is available.
 */
function readZone(handle: string, zone: Sphere): ZoneDoc {
  if (zone === "public") {
    // No identity required to read the cleartext public zone.
    try {
      return loadZoneDoc(handle, zone);
    } catch (e) {
      // `loadZoneDoc` may still need the manifest; fall through with a helpful error
      throw new Error(
        `failed to load public zone for ${handle}: ${(e as Error).message}`,
      );
    }
  }
  // circle / self need a local Identity (subject secret) to decrypt.
  // loadIdentity throws TrackedIdentityError if any sealed seed is missing,
  // which we let bubble up — the caller gets a clear message.
  const identity = loadIdentity(handle);
  const manifest = readManifest(handle);
  return loadZoneDoc(handle, zone, identity, manifest);
}

// ---------- server registration -------------------------------------------

export interface CreateServerOptions {
  /** Override the server name that appears in `initialize` results. */
  name?: string;
  /** Override the server version that appears in `initialize` results. */
  version?: string;
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
      const handles = listIdentities();
      const out = handles.map((h) => {
        try {
          const meta = loadIdentityMetadata(h);
          return {
            handle: meta.handle,
            did: meta.did,
            tracked: meta.tracked,
            spheres: meta.sphereDids,
          };
        } catch (e) {
          return { handle: h, error: (e as Error).message };
        }
      });
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
      const h = resolveHandle(handle);
      const meta = loadIdentityMetadata(h);
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
      const h = resolveHandle(handle);
      const tracked = isTrackedIdentity(h);
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
          const doc = readZone(h, z);
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
        "Returns the latest revision body of a section, plus metadata. " +
        "Set `includeHistory` to get every revision.",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS),
        sectionId: z.string().describe("Section id (sec_<hex>)"),
        includeHistory: z.boolean().optional(),
      },
    },
    async ({ handle, zone, sectionId, includeHistory }) => {
      const h = resolveHandle(handle);
      // Short-circuit encrypted zones on a tracked identity with an explicit
      // message — the on-disk ciphertext cannot be read without the sphere key,
      // so there's no point trying and surfacing a generic decryption error.
      if (isTrackedIdentity(h) && zone !== "public") {
        throw new Error(
          `cannot read section in ${zone} zone of "${h}": identity is tracked-only ` +
            `(no sphere key on disk). Only the public zone is readable.`,
        );
      }
      const doc = readZone(h, zone);
      const section = doc.sections.find((s) => s.id === sectionId);
      if (!section) {
        throw new Error(`section ${sectionId} not found in zone ${zone}`);
      }
      const latest = section.revisions[section.revisions.length - 1];
      const payload: Record<string, unknown> = {
        zone,
        id: section.id,
        title: section.title,
        tags: section.tags ?? [],
        updated_at: latest?.at,
        body: latest?.body,
      };
      if (includeHistory) {
        payload.revisions = section.revisions.map((r) => ({
          at: r.at,
          body: r.body,
          hash: r.hash,
          prev_hash: r.prev_hash,
          signer_key: r.signature?.key,
        }));
      }
      return ok(payload);
    },
  );

  server.registerTool(
    "aithos_ethos_verify",
    {
      title: "Verify ethos integrity",
      description:
        "Full integrity check: section hash chains, per-revision signatures, " +
        "zone signatures, manifest signature, and edition history link.",
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
      const h = resolveHandle(handle);
      const didDoc = readJson<DidDocument>(
        path.join(identityDir(h), "did.json"),
      );
      // Tracked identities have no sealed seeds: we transparently downgrade to
      // a public-only verification rather than throwing. The result object
      // already notes which zones were skipped.
      const tracked = isTrackedIdentity(h);
      const identity =
        decrypt === false || tracked ? null : loadIdentity(h);
      const result = verifyEthos(h, identity, didDoc);
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
      const h = resolveHandle(handle);
      const identity = loadIdentity(h);
      const auth = resolveWriteAuth({ mandate, agentKey });
      if (auth) {
        const writeScope = `ethos.write.${zone}`;
        if (!auth.mandate.scopes.includes(writeScope)) {
          throw new Error(
            `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
          );
        }
      }
      const { section, manifest } = addSection({
        handle: h,
        zone,
        identity,
        title,
        body,
        tags,
        delegate: auth?.delegate,
      });
      return ok({
        section: sectionSummary(zone, section),
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
      });
    },
  );

  server.registerTool(
    "aithos_ethos_add_revision",
    {
      title: "Append a revision to an existing section",
      description:
        "Appends a new revision body to a section (append-only, hash-chained). " +
        "Auth semantics identical to `aithos_ethos_add_section`.",
      inputSchema: {
        handle: z.string().optional(),
        zone: z.enum(SPHERE_FRAGMENTS),
        sectionId: z.string(),
        body: z.string().min(1),
        mandate: z.string().optional(),
        agentKey: z.string().optional(),
      },
    },
    async ({ handle, zone, sectionId, body, mandate, agentKey }) => {
      const h = resolveHandle(handle);
      const identity = loadIdentity(h);
      const auth = resolveWriteAuth({ mandate, agentKey });
      if (auth) {
        const writeScope = `ethos.write.${zone}`;
        if (!auth.mandate.scopes.includes(writeScope)) {
          throw new Error(
            `Mandate ${auth.mandate.id} does not include scope ${writeScope}`,
          );
        }
      }
      const { revision, manifest } = addRevision({
        handle: h,
        zone,
        identity,
        sectionId,
        body,
        delegate: auth?.delegate,
      });
      return ok({
        zone,
        sectionId,
        revision: {
          at: revision.at,
          hash: revision.hash,
          prev_hash: revision.prev_hash,
          signer_key: revision.signature?.key,
        },
        manifest_version: manifest.edition.version,
        manifest_height: manifest.edition.height,
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
        m = loadMandate(mandate);
      }
      // `issuer` is `did:aithos:<mb>` — find the matching local identity (owned
      // or tracked) to load its DID document. Verification only needs public
      // keys, so a tracked identity is perfectly fine as an issuer lookup.
      const subjectDid = m.issuer;
      let didDoc: DidDocument | undefined;
      for (const h of listIdentities()) {
        try {
          const meta = loadIdentityMetadata(h);
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
      const handles = listIdentities();
      const list = handles.map((h) => {
        try {
          const meta = loadIdentityMetadata(h);
          return { handle: h, did: meta.did, tracked: meta.tracked };
        } catch (e) {
          return { handle: h, error: (e as Error).message };
        }
      });
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
  const listEthosResources = () => {
    const out: Array<{ uri: string; name: string; mimeType?: string }> = [];
    for (const h of listIdentities()) {
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
        resources: listEthosResources().filter((r) =>
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
      const m = readManifest(h);
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
        resources: listEthosResources().filter(
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
        const p = ethosZoneFile(handle, zone);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "text/markdown",
              text: fs.readFileSync(p, "utf8"),
            },
          ],
        };
      }
      // For encrypted zones, try to decrypt with a local identity. If we don't
      // have one, return the ciphertext blob — useful for synchronisation
      // agents that never need plaintext.
      try {
        const identity = loadIdentity(handle);
        const manifest = readManifest(handle);
        const doc = loadZoneDoc(handle, zone, identity, manifest);
        // Re-render markdown using the ethos module's canonical renderer.
        const { renderZoneMarkdown } = await import("@aithos/cli/ethos");
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
        const p = ethosZoneFile(handle, zone);
        const bytes = fs.readFileSync(p);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/octet-stream",
              blob: bytes.toString("base64"),
            },
          ],
        };
      }
    },
  );

  // `aithos://ethos/{handle}/manifest/path` — absolute on-disk path, useful for
  // UIs that want to open the file directly. Cheap, diagnostic-only.
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

  return server;
}

// Re-export the Manifest type for downstream consumers (tests, etc.).
export type { Manifest };
