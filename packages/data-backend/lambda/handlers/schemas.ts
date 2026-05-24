// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for schema-management primitives (A2b, spec/data §3.7.4) :
 *
 *   - aithos.data.register_schema  (owner-only, signed envelope)
 *   - aithos.data.get_schema       (anonymous read, spec §5.5.1)
 *
 * These let a subject publish their own vendor-namespace
 * (`aithos.x.<vendor>.<name>.v<N>`) JSON Schema documents to their PDS,
 * which is then used at record-write time to enforce
 * `additionalProperties: false` and per-field type validation.
 *
 * Without A2b a buggy or malicious client could store arbitrary fields
 * in the indexable metadata of a vendor record, bypassing the strict
 * validation that core schemas enjoy. With A2b the owner can opt into
 * server-side enforcement for their vendor schemas at any time.
 *
 * Core schemas (`aithos.<name>.v<N>`) cannot be registered via this
 * endpoint — they go through the protocol PR review per spec §3.7.2.
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalize } from "@aithos/protocol-core/canonical";
import { RpcError } from "../jsonrpc.js";
import { requireSubjectMatch, type Caller } from "../auth/authenticate.js";
import { validateRequired } from "./collections.js";
import type { AithosSchema } from "../schemas/registry.js";
import { getSchema, listSchemas } from "../schemas/registry.js";
import {
  countOwnerSchemas,
  getOwnerSchema,
  putOwnerSchema,
  SchemaImmutableError,
} from "../schemas/store.js";

/* -------------------------------------------------------------------------- */
/*  Constants                                                                 */
/* -------------------------------------------------------------------------- */

/** Per-spec limit (§3.7.4) — keeps DDB Item size bounded. */
const MAX_SCHEMA_DOC_BYTES = 10 * 1024;

/** Per-owner schema cap. */
const MAX_SCHEMAS_PER_OWNER = 50;

/**
 * Vendor schema identifier shape :
 *   `aithos.x.<vendor>.<name>.v<N>`
 * with vendor and name as lowercase alphanumeric + `_`/`-`, version as
 * a positive integer. Mirrors the spec §3.3 regex restricted to the
 * vendor namespace (core `aithos.<bareword>` is NOT accepted here).
 *
 * Exported for unit tests — callers should treat as an implementation
 * detail and use `register_schema`'s -32071 response as the authority.
 */
export const VENDOR_SCHEMA_ID =
  /^aithos\.x\.[a-z][a-z0-9_-]{0,30}\.[a-z][a-z0-9_-]{0,62}\.v[1-9][0-9]*$/;

/** Semver, restrictive enough to keep parsing trivial. */
export const SEMVER =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$/;

/* -------------------------------------------------------------------------- */
/*  register_schema                                                           */
/* -------------------------------------------------------------------------- */

interface RegisterSchemaParams {
  subject_did?: string;
  schema_doc?: unknown;
}

export async function registerSchemaHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as RegisterSchemaParams;
  validateRequired(p, ["subject_did", "schema_doc"]);
  requireSubjectMatch(caller, p.subject_did!);

  // Owner-only — delegates cannot reconfigure the schema set even with
  // an admin scope on a collection. Registering a schema affects the
  // shape of validation for every future write of that schema id,
  // including writes by other delegates, which is a power we keep
  // pinned to the sphere key.
  if (caller.mode === "delegate") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: register_schema is owner-only; delegates cannot publish schemas",
    );
  }

  const doc = parseSchemaDoc(p.schema_doc);
  const schemaId = doc["aithos:schema"];
  const version = doc["aithos:version"];

  // 1. Identifier well-formedness (spec §3.3, restricted to vendor ns).
  if (!VENDOR_SCHEMA_ID.test(schemaId)) {
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: schema identifier "${schemaId}" must match ` +
        `aithos.x.<vendor>.<name>.v<N> ` +
        `(lowercase, alphanumeric + _ -, vendor segment ≤ 30 chars, name segment ≤ 62, version ≥ 1)`,
    );
  }

  // 2. Core namespace is closed to self-registration — those go through
  //    the protocol's PR review.
  if (schemaId.startsWith("aithos.") && !schemaId.startsWith("aithos.x.")) {
    throw new RpcError(
      -32071,
      "AITHOS_DATA_SCHEMA_INVALID: core aithos.<name>.v<N> schemas cannot be self-registered; submit a PR per spec §3.7.2",
    );
  }
  if (getSchema(schemaId)) {
    // Defense in depth — should be unreachable given the regex above
    // refuses `aithos.<bareword>.v*`, but if a vendor id ever collided
    // with a bundled REGISTRY entry we'd rather refuse loudly than
    // silently shadow the core schema.
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: schema "${schemaId}" is a core schema bundled by the platform and cannot be re-registered`,
    );
  }

  // 3. Semver.
  if (!SEMVER.test(version)) {
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: aithos:version "${version}" is not a valid semver string`,
    );
  }

  // 4. Document structural validity (JSON Schema 2020-12 subset we
  //    actually enforce — same one validateMetadata expects).
  const structuralErr = validateSchemaDoc(doc);
  if (structuralErr) {
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: ${structuralErr}`,
    );
  }

  // 5. Size cap.
  const docBytes = jsonByteLength(doc);
  if (docBytes > MAX_SCHEMA_DOC_BYTES) {
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: schema document is ${docBytes} bytes, exceeds limit ${MAX_SCHEMA_DOC_BYTES}`,
    );
  }

  // 6. Per-owner quota — but only count if this is a NEW schema id
  //    (re-registering the same id is a no-op for the quota).
  const existing = await getOwnerSchema(p.subject_did!, schemaId);
  if (!existing) {
    const { count, totalBytes } = await countOwnerSchemas(p.subject_did!);
    if (count >= MAX_SCHEMAS_PER_OWNER) {
      throw new RpcError(
        -32071,
        `AITHOS_DATA_SCHEMA_INVALID: owner has reached the per-subject quota of ${MAX_SCHEMAS_PER_OWNER} schemas`,
      );
    }
    const projectedTotal = totalBytes + docBytes;
    const totalCap = MAX_SCHEMAS_PER_OWNER * MAX_SCHEMA_DOC_BYTES;
    if (projectedTotal > totalCap) {
      throw new RpcError(
        -32071,
        `AITHOS_DATA_SCHEMA_INVALID: owner schema footprint would reach ${projectedTotal} bytes, exceeds cap ${totalCap}`,
      );
    }
  }

  // 7. Compute canonical hash and persist (idempotent).
  const docHash = canonicalSha256(doc);
  let result: { stored: { doc_hash: string; created_at: string }; created: boolean };
  try {
    result = await putOwnerSchema({
      ownerDid: p.subject_did!,
      schemaId,
      schemaDoc: doc as AithosSchema,
      docHash,
    });
  } catch (err) {
    if (err instanceof SchemaImmutableError) {
      throw new RpcError(
        -32082,
        `AITHOS_DATA_SCHEMA_IMMUTABLE: ${err.message}`,
        err.data,
      );
    }
    throw err;
  }

  return {
    schema_id: schemaId,
    doc_hash: result.stored.doc_hash,
    created: result.created,
    created_at: result.stored.created_at,
  };
}

/* -------------------------------------------------------------------------- */
/*  get_schema                                                                */
/* -------------------------------------------------------------------------- */
//
// Anonymous read (spec §5.5.1). Schemas are public — the doc itself
// isn't sensitive (it's only the shape of validation, not data). We
// honor lookups against the bundled core REGISTRY without a subject_did
// and against an owner's vendor registry when subject_did is supplied.
//
// A delegate writing to a subject's collection uses this to discover
// the schema shape so the SDK can split records into indexable vs
// encrypted fields client-side, matching what the server expects.

interface GetSchemaParams {
  /** Owner DID, required for vendor (`aithos.x.*`) schemas. */
  subject_did?: string;
  /** The schema identifier itself. */
  schema?: string;
}

export async function getSchemaHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as GetSchemaParams;
  validateRequired(p, ["schema"]);

  const schemaId = p.schema!;

  // Core schemas — sync REGISTRY, no subject_did required.
  const core = getSchema(schemaId);
  if (core) {
    return { schema: core, source: "core" };
  }

  // Vendor schemas need a subject_did to know whose registry to query.
  if (!schemaId.startsWith("aithos.x.")) {
    throw new RpcError(
      -32070,
      `AITHOS_DATA_SCHEMA_UNKNOWN: schema "${schemaId}" is not in the core registry`,
    );
  }
  if (!p.subject_did) {
    throw new RpcError(
      -32602,
      `invalid params: vendor schema "${schemaId}" requires subject_did to know whose registry to query`,
    );
  }

  const stored = await getOwnerSchema(p.subject_did, schemaId);
  if (!stored) {
    throw new RpcError(
      -32070,
      `AITHOS_DATA_SCHEMA_UNKNOWN: vendor schema "${schemaId}" is not registered for ${p.subject_did}`,
    );
  }
  return {
    schema: stored.schema_doc,
    source: "owner",
    owner_did: p.subject_did,
    doc_hash: stored.doc_hash,
    created_at: stored.created_at,
  };
}

/* -------------------------------------------------------------------------- */
/*  list_schemas (covers core + a single owner's vendor registry)             */
/* -------------------------------------------------------------------------- */
//
// Convenience read so apps can ask the PDS "what core schemas are
// known here" without bundling the list in every client. Not strictly
// A2b but adjacent and trivial to ship together; the spec §5.5.2
// already declares the primitive.

interface ListSchemasParams {
  prefix?: string;
}

export async function listSchemasHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as ListSchemasParams;
  const prefix = p.prefix ?? "";
  const out = listSchemas()
    .filter((s) => s["aithos:schema"].startsWith(prefix))
    .map((s) => ({
      schema: s["aithos:schema"],
      version: s["aithos:version"],
      title: s.title,
    }));
  return { items: out, source: "core" };
}

/* -------------------------------------------------------------------------- */
/*  Internal — schema-doc parsing & structural validation                     */
/* -------------------------------------------------------------------------- */

/**
 * Parse the incoming `schema_doc` param and assert the shape we need
 * to validate records against it. Returns a typed view on success or
 * throws `-32071 AITHOS_DATA_SCHEMA_INVALID` with a precise reason.
 */
function parseSchemaDoc(raw: unknown): AithosSchemaIncoming {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new RpcError(
      -32071,
      "AITHOS_DATA_SCHEMA_INVALID: schema_doc must be a JSON object",
    );
  }
  const doc = raw as Record<string, unknown>;
  const id = doc["aithos:schema"];
  const version = doc["aithos:version"];
  const properties = doc["properties"];
  if (typeof id !== "string") {
    throw new RpcError(
      -32071,
      "AITHOS_DATA_SCHEMA_INVALID: schema_doc must declare a string aithos:schema field",
    );
  }
  if (typeof version !== "string") {
    throw new RpcError(
      -32071,
      "AITHOS_DATA_SCHEMA_INVALID: schema_doc must declare a string aithos:version field",
    );
  }
  if (doc["type"] !== "object") {
    throw new RpcError(
      -32071,
      `AITHOS_DATA_SCHEMA_INVALID: schema_doc.type must be "object"`,
    );
  }
  if (properties === undefined || typeof properties !== "object" || Array.isArray(properties)) {
    throw new RpcError(
      -32071,
      "AITHOS_DATA_SCHEMA_INVALID: schema_doc must declare a properties object",
    );
  }
  return doc as unknown as AithosSchemaIncoming;
}

// Plain narrowing — same shape as AithosSchema but `aithos:schema`
// and `aithos:version` are guaranteed strings by parseSchemaDoc.
type AithosSchemaIncoming = AithosSchema;

/**
 * Walk the schema doc and reject constructs the validator can't
 * enforce. Spec §3.5.2 requires schemas to validate against the
 * JSON Schema 2020-12 meta-schema; we accept a strict subset (the
 * fields used by validateMetadata) and reject anything else loudly so
 * publishers don't silently lose validation.
 *
 * Exported for unit tests.
 */
export function validateSchemaDoc(doc: AithosSchema): string | null {
  const ALLOWED_TOP = new Set([
    "aithos:schema",
    "aithos:version",
    "$id",
    "$schema",
    "title",
    "description",
    "type",
    "required",
    "additionalProperties",
    "properties",
    "$defs",
  ]);
  const KNOWN_FIELD_KEYS = new Set([
    "type",
    "format",
    "pattern",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "uniqueItems",
    "enum",
    "items",
    "default",
    "description",
    "title",
    "aithos:indexable",
    "aithos:encrypted",
    "aithos:auto",
    "aithos:derived_from",
    "aithos:pii",
    "aithos:ref",
  ]);
  for (const key of Object.keys(doc)) {
    if (!ALLOWED_TOP.has(key)) {
      return `unsupported top-level key "${key}" — allowed: ${[...ALLOWED_TOP].join(", ")}`;
    }
  }
  if (
    doc.additionalProperties !== undefined &&
    doc.additionalProperties !== false &&
    doc.additionalProperties !== true
  ) {
    return "additionalProperties must be a boolean";
  }
  if (doc.required !== undefined) {
    if (!Array.isArray(doc.required)) return "required must be an array of strings";
    for (const r of doc.required) {
      if (typeof r !== "string") return "required[] entries must be strings";
    }
  }
  for (const [field, sub] of Object.entries(doc.properties)) {
    if (sub === null || typeof sub !== "object" || Array.isArray(sub)) {
      return `properties.${field} must be an object`;
    }
    const f = sub as Record<string, unknown>;
    for (const k of Object.keys(f)) {
      if (!KNOWN_FIELD_KEYS.has(k)) {
        return `properties.${field}.${k} is not a supported keyword`;
      }
    }
    if (f["aithos:indexable"] === true && f["aithos:encrypted"] === true) {
      return `properties.${field} cannot be both indexable and encrypted (spec §3.2.4)`;
    }
    if (f["aithos:auto"] !== undefined) {
      const v = f["aithos:auto"];
      if (v !== "on_insert" && v !== "on_modify") {
        return `properties.${field}.aithos:auto must be "on_insert" or "on_modify"`;
      }
    }
    const t = f["type"];
    if (t !== undefined && typeof t !== "string") {
      return `properties.${field}.type must be a string`;
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/*  Hash helpers                                                              */
/* -------------------------------------------------------------------------- */

export function canonicalSha256(value: unknown): string {
  const bytes = new TextEncoder().encode(canonicalize(value));
  const digest = sha256(bytes);
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

function jsonByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}
