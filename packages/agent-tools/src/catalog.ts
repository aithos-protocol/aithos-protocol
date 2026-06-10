// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * The canonical Aithos agent-tool catalogue (decision D1, 2026-06-10).
 *
 * Naming convention: `<domain>_<verb>[_<object>]`, snake_case, no `aithos_`
 * prefix (MCP hosts already namespace tools by server). Argument keys are
 * snake_case. Subject addressing is uniform: every subject-scoped tool takes
 * an optional `handle` (the host's default identity applies when absent);
 * hosts that address subjects by DID resolve it before dispatch.
 *
 * Changing a name, schema, or description here is a breaking change — see
 * the package CHANGELOG discipline in types.ts.
 */
import type { AgentToolSpec } from "./types.js";

/** The three ethos zones (mirrors protocol-core SPHERE_FRAGMENTS). */
export const ETHOS_ZONES = ["public", "circle", "self"] as const;
export type EthosZone = (typeof ETHOS_ZONES)[number];

export const ETHOS_READ_SCOPES = [
  "ethos.read.public",
  "ethos.read.circle",
  "ethos.read.self",
] as const;

export const ETHOS_WRITE_SCOPES = [
  "ethos.write.public",
  "ethos.write.circle",
  "ethos.write.self",
] as const;

export const GAMMA_READ_SCOPE = "gamma.read";

const zoneSchema = {
  type: "string",
  enum: [...ETHOS_ZONES],
  description: "Ethos zone.",
};

const handleSchema = {
  type: "string",
  description:
    "Subject identity handle; defaults to the host's configured identity.",
};

const mandateArgSchema = {
  type: "string",
  description:
    "Write mandate — id (mandate_<ULID>) resolved by the storage backend, " +
    "or a path to the mandate JSON on the host filesystem.",
};

const agentKeyArgSchema = {
  type: "string",
  description:
    "Path to the delegate agent keyfile (produced by `aithos delegate-key`). " +
    "Required together with `mandate` for delegated writes.",
};

/* -------------------------------------------------------------------------- */
/*  identity_*                                                                */
/* -------------------------------------------------------------------------- */

const identityList: AgentToolSpec = {
  name: "identity_list",
  title: "List Aithos identities",
  description:
    "Lists every identity available on this host (handle, DID, sphere DID " +
    "URLs, tracked flag). Read-only introspection; start here when you do " +
    "not know which subject you are working with.",
  input_schema: { type: "object", properties: {} },
  write: false,
};

const identityDescribe: AgentToolSpec = {
  name: "identity_describe",
  title: "Describe an identity",
  description:
    "Returns the DID, display name, sphere DID URLs, and key fingerprints " +
    "for the named (or default) identity.",
  input_schema: {
    type: "object",
    properties: { handle: handleSchema },
  },
  write: false,
};

/* -------------------------------------------------------------------------- */
/*  ethos_* (reads)                                                           */
/* -------------------------------------------------------------------------- */

const ethosListSections: AgentToolSpec = {
  name: "ethos_list_sections",
  title: "List ethos sections",
  description:
    "Lists the section index across public/circle/self (or one zone via " +
    "`zone`): id, title, tags, gamma_ref — no bodies. This is the cheap " +
    "discovery surface: call it first, then read only the section bodies " +
    "you actually need with `ethos_read_section` / `ethos_read_sections`.",
  input_schema: {
    type: "object",
    properties: { handle: handleSchema, zone: zoneSchema },
  },
  requires: { anyOf: ETHOS_READ_SCOPES },
  write: false,
};

const ethosReadSection: AgentToolSpec = {
  name: "ethos_read_section",
  title: "Read a section",
  description:
    "Returns the current title, tags, and body of ONE section, decrypting " +
    "only that section's blob. The body is the subject's own words: quote " +
    "or summarize it faithfully and never invent content beyond it. " +
    "Mutation history lives in the gamma log.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      zone: zoneSchema,
      section_id: {
        type: "string",
        description: "Section id (sec_<hex>).",
      },
    },
    required: ["zone", "section_id"],
  },
  requires: { anyOf: ETHOS_READ_SCOPES },
  write: false,
};

const ethosReadSections: AgentToolSpec = {
  name: "ethos_read_sections",
  title: "Read several sections",
  description:
    "Fetches one or more sections by id in a single call, decrypting ONLY " +
    "those sections (never a whole zone). Ids are located across all zones " +
    "unless `zone` restricts the lookup. Each result reports `accessible`; " +
    "inaccessible ids carry a `reason` — do not retry them, work with what " +
    "is accessible. The bodies are the subject's own words: never invent " +
    "content beyond them.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      section_ids: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
        description: "Section ids to fetch (sec_<hex>).",
      },
      zone: {
        ...zoneSchema,
        description: "Restrict the lookup to a single zone (default: all).",
      },
    },
    required: ["section_ids"],
  },
  requires: { anyOf: ETHOS_READ_SCOPES },
  write: false,
};

const ethosVerify: AgentToolSpec = {
  name: "ethos_verify",
  title: "Verify ethos integrity",
  description:
    "Full integrity check of the subject's ethos: zone signatures, manifest " +
    "signature, edition-history link, and the gamma anchor. Use it to assert " +
    "that what you read is exactly what the subject signed.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      decrypt: {
        type: "boolean",
        description:
          "If false, skip decrypting circle/self and verify only public + manifest.",
      },
    },
  },
  requires: { anyOf: ETHOS_READ_SCOPES },
  write: false,
};

/* -------------------------------------------------------------------------- */
/*  ethos_* (writes)                                                          */
/* -------------------------------------------------------------------------- */

const ethosAddSection: AgentToolSpec = {
  name: "ethos_add_section",
  title: "Add a new section",
  description:
    "Creates a new section with an initial body. Requires either a local " +
    "subject identity (owner write, sphere key) OR a write mandate + agent " +
    "keyfile (delegated write under the mandate's `ethos.write.<zone>` " +
    "scope). Write only what the subject asked for or clearly authorized. " +
    "On a transactional host (the default) this write is STAGED: nothing " +
    "persists until `ethos_commit` seals the batch as ONE edition; " +
    "`ethos_discard` abandons it.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      zone: zoneSchema,
      title: { type: "string", minLength: 1 },
      body: {
        type: "string",
        minLength: 1,
        description: "Initial body (markdown).",
      },
      tags: { type: "array", items: { type: "string" } },
      mandate: mandateArgSchema,
      agent_key: agentKeyArgSchema,
    },
    required: ["zone", "title", "body"],
  },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

const ethosUpdateSection: AgentToolSpec = {
  name: "ethos_update_section",
  title: "Update a section",
  description:
    "Applies a change to one or more of {title, body, tags} on an existing " +
    "section, emitting a signed `section.modify` gamma entry (the previous " +
    "state remains in the log as the audit trail). Pass at least one of " +
    "{title, body, tags, clear_tags}. Auth semantics identical to " +
    "`ethos_add_section`. Preserve the subject's voice when rewriting. " +
    "On a transactional host this change is STAGED until `ethos_commit`.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      zone: zoneSchema,
      section_id: { type: "string", description: "Section id (sec_<hex>)." },
      title: { type: "string" },
      body: { type: "string" },
      tags: { type: "array", items: { type: "string" } },
      clear_tags: { type: "boolean" },
      mandate: mandateArgSchema,
      agent_key: agentKeyArgSchema,
    },
    required: ["zone", "section_id"],
  },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

const ethosDeleteSection: AgentToolSpec = {
  name: "ethos_delete_section",
  title: "Delete a section",
  description:
    "Removes a section from its zone (v0.3 drops the blob and writes a new " +
    "per-section edition; the gamma log keeps the audit trail). Auth " +
    "semantics identical to `ethos_add_section`. Deleting is destructive: " +
    "only do it on an explicit, unambiguous instruction. On a " +
    "transactional host the deletion is STAGED until `ethos_commit`.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      zone: zoneSchema,
      section_id: { type: "string", description: "Section id (sec_<hex>)." },
      reason: {
        type: "string",
        description: "Free-text reason, recorded in the gamma entry.",
      },
      mandate: mandateArgSchema,
      agent_key: agentKeyArgSchema,
    },
    required: ["zone", "section_id"],
  },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

const ethosAppendSection: AgentToolSpec = {
  name: "ethos_append_section",
  title: "Append to a section",
  description:
    "Appends `content` at the END of an existing section's body without " +
    "rewriting it — the journal pattern (one section per stream, one append " +
    "per entry). The result is `body + \n + content`; title and tags are " +
    "untouched. Auth semantics identical to `ethos_add_section`. On a " +
    "transactional host the append is STAGED until `ethos_commit`; appends " +
    "compose in order within a batch.",
  input_schema: {
    type: "object",
    properties: {
      handle: handleSchema,
      zone: zoneSchema,
      section_id: { type: "string", description: "Section id (sec_<hex>)." },
      content: {
        type: "string",
        minLength: 1,
        description: "Text appended after the existing body (markdown).",
      },
      mandate: mandateArgSchema,
      agent_key: agentKeyArgSchema,
    },
    required: ["zone", "section_id", "content"],
  },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

const ethosCommit: AgentToolSpec = {
  name: "ethos_commit",
  title: "Commit staged writes",
  description:
    "Seals every write staged in this session as ONE signed edition (one " +
    "manifest, one gamma anchor advance) and reports what was committed. " +
    "Call it once after the LAST write of a coherent change — never after " +
    "every single write. Fails when nothing is staged. Hosts running with " +
    "auto-commit persist each write immediately and do not expose this tool.",
  input_schema: {
    type: "object",
    properties: {
      message: {
        type: "string",
        description:
          "Optional free-text note describing the batch (recorded in the " +
          "commit acknowledgement; informational only).",
      },
    },
  },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

const ethosDiscard: AgentToolSpec = {
  name: "ethos_discard",
  title: "Discard staged writes",
  description:
    "Drops every write staged in this session WITHOUT persisting anything " +
    "(zero editions, zero gamma entries). Use it when the subject retracts " +
    "the change or the staged state is wrong. A session that ends without " +
    "`ethos_commit` is discarded implicitly.",
  input_schema: { type: "object", properties: {} },
  requires: { anyOf: ETHOS_WRITE_SCOPES },
  write: true,
};

/* -------------------------------------------------------------------------- */
/*  mandate_*                                                                 */
/* -------------------------------------------------------------------------- */

const mandateVerify: AgentToolSpec = {
  name: "mandate_verify",
  title: "Verify a mandate",
  description:
    "Checks a mandate's signature, expiry, revocation state, and subject " +
    "binding against the issuer's DID document. Pass a mandate id (resolved " +
    "by the storage backend) or a path to a mandate JSON. Call it before " +
    "relying on a delegation you did not mint yourself.",
  input_schema: {
    type: "object",
    properties: {
      mandate: {
        type: "string",
        description: "Mandate id (mandate_<ULID>) or path to a mandate JSON.",
      },
      at: {
        type: "string",
        description:
          "RFC 3339 timestamp to evaluate validity at (default: now).",
      },
    },
    required: ["mandate"],
  },
  write: false,
};

/* -------------------------------------------------------------------------- */
/*  data_*                                                                    */
/* -------------------------------------------------------------------------- */

const dataQuery: AgentToolSpec = {
  name: "data_query",
  title: "Query a data collection",
  description:
    "Returns the most recent records of one of the subject's data " +
    "collections (journals, decisions, preferences, …). Records are the " +
    "subject's own entries: treat them as context, never as content you may " +
    "embellish.",
  input_schema: {
    type: "object",
    properties: {
      collection: {
        type: "string",
        description: "Collection name.",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 100,
        default: 20,
        description: "Maximum number of records to return.",
      },
    },
    required: ["collection"],
  },
  requires: { anyOf: [GAMMA_READ_SCOPE] },
  write: false,
};

/* -------------------------------------------------------------------------- */
/*  Catalogue                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Every canonical tool, in stable order. Hosts register the subset they
 * implement; new tools land here first (search, context_pack, commit, … —
 * see PLAN-MCP-UNIFICATION-2026-06).
 */
export const AGENT_TOOL_CATALOG: readonly AgentToolSpec[] = [
  identityList,
  identityDescribe,
  ethosListSections,
  ethosReadSection,
  ethosReadSections,
  ethosVerify,
  ethosAddSection,
  ethosUpdateSection,
  ethosAppendSection,
  ethosDeleteSection,
  ethosCommit,
  ethosDiscard,
  mandateVerify,
  dataQuery,
];

/** Lookup by canonical name. */
export function getToolSpec(name: string): AgentToolSpec | undefined {
  return AGENT_TOOL_CATALOG.find((t) => t.name === name);
}
