// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Schema registry — bundled at build time so Lambda doesn't fetch
 * schema documents at runtime.
 *
 * Each schema is keyed by its `aithos:schema` identifier
 * (e.g. `aithos.contacts.v1`). The registry exposes:
 *
 *   - `getSchema(id)` — fetch a registered schema or null.
 *   - `validateRecord(schemaId, metadata, allowAuto)` — validate a
 *     record's `metadata` (clear) portion against the schema's
 *     indexable fields. The encrypted payload is opaque to the
 *     platform and not validated server-side.
 *
 * The validator is a small hand-rolled subset of JSON Schema 2020-12
 * sufficient for the v0.1 core schemas. We avoid ajv to keep the
 * Lambda bundle small and to keep control over the Aithos-specific
 * `aithos:*` annotations.
 */

import { contactsV1Schema } from "./aithos.contacts.v1.js";

/* -------------------------------------------------------------------------- */
/*  Registry                                                                  */
/* -------------------------------------------------------------------------- */

export interface AithosSchema {
  readonly "aithos:schema": string;
  readonly "aithos:version": string;
  readonly title: string;
  readonly type: "object";
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly properties: Record<string, AithosFieldSchema>;
  readonly $defs?: Record<string, unknown>;
}

export interface AithosFieldSchema {
  readonly type?: string;
  readonly format?: string;
  readonly pattern?: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly uniqueItems?: boolean;
  readonly enum?: readonly string[];
  readonly items?: AithosFieldSchema;
  readonly default?: unknown;
  readonly "aithos:indexable"?: boolean;
  readonly "aithos:encrypted"?: boolean;
  readonly "aithos:auto"?: "on_insert" | "on_modify";
  readonly "aithos:derived_from"?: string;
  readonly "aithos:pii"?: boolean;
}

const REGISTRY: Record<string, AithosSchema> = {
  [contactsV1Schema["aithos:schema"]]: contactsV1Schema,
};

/**
 * Synchronous lookup limited to the bundled core REGISTRY. Used by
 * call sites that explicitly want core-only behavior (e.g. namespace
 * gating in create_collection). For the general write-path lookup that
 * falls back to per-owner registered vendor schemas, use
 * {@link resolveSchema} (async, DDB-backed).
 */
export function getSchema(id: string): AithosSchema | null {
  return REGISTRY[id] ?? null;
}

export function listSchemas(): readonly AithosSchema[] {
  return Object.values(REGISTRY);
}

/**
 * Two-tier schema resolution (spec §3.4.3) :
 *   1. Bundled core REGISTRY — `aithos.<name>.v<N>`.
 *   2. Owner-published vendor registry (DDB, A2b) — `aithos.x.<vendor>.<name>.v<N>`,
 *      scoped to the calling owner so a vendor's schema is visible only
 *      under the subjects that have explicitly registered it.
 *
 * Returns null when neither lookup hits — callers MUST decide whether
 * that's fatal (core namespace → reject) or permissive (vendor
 * namespace pre-A2b registration → accept at face value, see
 * records.ts for the A2a fallback rationale).
 *
 * Async because the second tier is a DDB Get. The first tier is sync
 * so a `aithos.contacts.v1` lookup never hits DDB.
 */
export async function resolveSchema(
  id: string,
  ownerDid?: string,
): Promise<AithosSchema | null> {
  const core = REGISTRY[id];
  if (core) return core;
  if (ownerDid && id.startsWith("aithos.x.")) {
    // Lazy import — the store pulls in the DDB client, which we don't
    // want to bundle into call sites that only need the sync core
    // REGISTRY (e.g. unit tests of validateMetadata).
    const { getOwnerSchema } = await import("./store.js");
    const stored = await getOwnerSchema(ownerDid, id);
    return stored?.schema_doc ?? null;
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/*  Validation                                                                */
/* -------------------------------------------------------------------------- */

export interface ValidationError {
  readonly field: string;
  readonly reason: string;
}

export interface ValidationResult {
  readonly ok: boolean;
  readonly errors: readonly ValidationError[];
  /**
   * The cleaned metadata object — with auto-fields stripped and
   * default values applied. Use this rather than the original input.
   */
  readonly metadata: Record<string, unknown>;
}

export interface ValidateOptions {
  /**
   * Operation context. Drives `aithos:auto` enforcement:
   *   - "insert": auto-on-insert fields are server-set, rejected if
   *     client-supplied.
   *   - "update": same, plus auto-on-modify enforcement.
   */
  readonly op: "insert" | "update";
  /**
   * If true, client-supplied values for auto-fields are silently
   * overridden rather than rejected. Defaults to true (more
   * forgiving — the spec leaves this implementation-specific).
   */
  readonly silentlyOverrideAuto?: boolean;
}

/**
 * Validate the metadata clear portion of a record against its schema.
 *
 * Only validates fields declared `aithos:indexable` (or marked
 * `aithos:auto`). Fields declared `aithos:encrypted` are not in the
 * metadata object — they live in the payload ciphertext and are
 * opaque to the platform.
 *
 * For core schemas the lookup is sync (REGISTRY). For owner-published
 * vendor schemas the caller should resolve via {@link resolveSchema}
 * and pass the schema document via {@link validateMetadataAgainst} to
 * avoid a second DDB read.
 */
export function validateMetadata(
  schemaId: string,
  metadata: Record<string, unknown>,
  options: ValidateOptions,
): ValidationResult {
  const schema = getSchema(schemaId);
  if (!schema) {
    return {
      ok: false,
      errors: [{ field: "*", reason: `unknown schema "${schemaId}"` }],
      metadata,
    };
  }
  return validateMetadataAgainst(schema, metadata, options);
}

/**
 * Same as {@link validateMetadata} but accepts an already-resolved
 * schema document. Useful when the caller already paid the cost of
 * resolution (e.g. a DDB Get for a vendor schema) and doesn't want to
 * pay again.
 */
export function validateMetadataAgainst(
  schema: AithosSchema,
  metadata: Record<string, unknown>,
  options: ValidateOptions,
): ValidationResult {
  const errors: ValidationError[] = [];
  const cleaned: Record<string, unknown> = {};
  const silentOverride = options.silentlyOverrideAuto ?? true;

  // 1. Unknown fields
  if (schema.additionalProperties === false) {
    for (const k of Object.keys(metadata)) {
      const propSchema = schema.properties[k];
      if (!propSchema) {
        errors.push({ field: k, reason: "unknown field (not in schema)" });
        continue;
      }
      if (propSchema["aithos:encrypted"] === true) {
        errors.push({
          field: k,
          reason: "field is encrypted in schema; should be in payload, not metadata",
        });
      }
    }
  }

  // 2. Per-field validation
  for (const [field, fieldSchema] of Object.entries(schema.properties)) {
    const isAuto = fieldSchema["aithos:auto"] !== undefined;
    const supplied = metadata[field];

    if (fieldSchema["aithos:encrypted"] === true) {
      // Skip — encrypted fields aren't in metadata
      continue;
    }

    if (isAuto && supplied !== undefined) {
      if (silentOverride) {
        // Silently drop client value — server will compute
        continue;
      } else {
        errors.push({
          field,
          reason: `field is ${fieldSchema["aithos:auto"]}, client MUST NOT supply`,
        });
        continue;
      }
    }

    if (supplied === undefined) {
      const required = schema.required?.includes(field) ?? false;
      if (required && !isAuto) {
        errors.push({ field, reason: "required field missing" });
      }
      // Apply default if present
      if (fieldSchema.default !== undefined) {
        cleaned[field] = fieldSchema.default;
      }
      continue;
    }

    const err = validateValue(field, supplied, fieldSchema);
    if (err) {
      errors.push(err);
    } else {
      cleaned[field] = supplied;
    }
  }

  return { ok: errors.length === 0, errors, metadata: cleaned };
}

function validateValue(
  field: string,
  value: unknown,
  schema: AithosFieldSchema,
): ValidationError | null {
  const t = schema.type;
  if (t === "string") {
    if (typeof value !== "string") {
      return { field, reason: `expected string, got ${typeof value}` };
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      return { field, reason: `shorter than minLength=${schema.minLength}` };
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      return { field, reason: `longer than maxLength=${schema.maxLength}` };
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      return { field, reason: `does not match pattern ${schema.pattern}` };
    }
    if (schema.enum && !schema.enum.includes(value)) {
      return { field, reason: `not in enum [${schema.enum.join(", ")}]` };
    }
    if (schema.format === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      return { field, reason: "not a valid email" };
    }
    if (schema.format === "date-time" && Number.isNaN(Date.parse(value))) {
      return { field, reason: "not a valid RFC 3339 date-time" };
    }
    return null;
  }
  if (t === "number" || t === "integer") {
    if (typeof value !== "number") {
      return { field, reason: `expected number, got ${typeof value}` };
    }
    if (t === "integer" && !Number.isInteger(value)) {
      return { field, reason: "expected integer" };
    }
    return null;
  }
  if (t === "boolean") {
    if (typeof value !== "boolean") {
      return { field, reason: `expected boolean, got ${typeof value}` };
    }
    return null;
  }
  if (t === "array") {
    if (!Array.isArray(value)) {
      return { field, reason: `expected array, got ${typeof value}` };
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      return { field, reason: `fewer than minItems=${schema.minItems}` };
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return { field, reason: `more than maxItems=${schema.maxItems}` };
    }
    if (schema.uniqueItems) {
      const seen = new Set<unknown>();
      for (const v of value) {
        const key = typeof v === "object" ? JSON.stringify(v) : String(v);
        if (seen.has(key)) {
          return { field, reason: "array items not unique" };
        }
        seen.add(key);
      }
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        const itemErr = validateValue(`${field}[${i}]`, value[i], schema.items);
        if (itemErr) return itemErr;
      }
    }
    return null;
  }
  if (t === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { field, reason: `expected object, got ${value === null ? "null" : typeof value}` };
    }
    return null;
  }
  // Unknown / unspecified type — pass through
  return null;
}

/* -------------------------------------------------------------------------- */
/*  Auto-field helpers                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Return the list of fields that should be server-set at insert time.
 */
export function autoOnInsertFields(schemaId: string): string[] {
  const schema = getSchema(schemaId);
  if (!schema) return [];
  return Object.entries(schema.properties)
    .filter(([, f]) => f["aithos:auto"] === "on_insert")
    .map(([k]) => k);
}

/**
 * Return the list of fields that should be server-set on any modification.
 */
export function autoOnModifyFields(schemaId: string): string[] {
  const schema = getSchema(schemaId);
  if (!schema) return [];
  return Object.entries(schema.properties)
    .filter(([, f]) => f["aithos:auto"] === "on_modify")
    .map(([k]) => k);
}
