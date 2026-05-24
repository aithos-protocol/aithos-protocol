// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for collection-level primitives:
 *   - aithos.data.create_collection
 *   - aithos.data.get_collection
 *   - aithos.data.list_collections
 *
 * Each handler receives a `Caller` already authenticated by the router
 * (envelope signature verified, nonce committed, mandate validated if
 * present). The handler enforces scope and subject ownership.
 *
 * Spec ref: spec/data/05-api-primitives.md §5.3.x, §5.4.1.
 */

import {
  PutCommand,
  GetCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import {
  ddb,
  TABLE_NAME,
  pkForSubject,
  skForCollection,
} from "../ddb.js";
import { RpcError } from "../jsonrpc.js";
import {
  requireScope,
  requireSubjectMatch,
  type Caller,
} from "../auth/authenticate.js";
import { getSchema } from "../schemas/registry.js";
import { appendGammaEntry } from "../gamma/store.js";
import { hashJson } from "../gamma/hash-util.js";

/* -------------------------------------------------------------------------- */
/*  create_collection                                                         */
/* -------------------------------------------------------------------------- */

interface CreateCollectionParams {
  subject_did?: string;
  collection_name?: string;
  schema?: string;
  cmk_envelope?: unknown;
  forward_secrecy?: "best_effort" | "strict";
}

export async function createCollectionHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as CreateCollectionParams;
  validateRequired(p, ["subject_did", "collection_name", "schema", "cmk_envelope"]);
  requireSubjectMatch(caller, p.subject_did!);

  // create_collection is owner-only in v0.1 — delegate cannot create a
  // collection on behalf of the subject (the CMK is generated client-side
  // by the subject and the wrap is for their sphere key).
  if (caller.mode === "delegate") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: create_collection is owner-only in v0.1; delegates cannot create collections",
    );
  }

  // Schema namespace validation per RFC §3.3 :
  //
  //   - `aithos.<name>.v<N>` (one segment before <name>) → core schemas
  //     maintained by the Aithos protocol authority. MUST be present in
  //     the bundled server-side REGISTRY (cf. schemas/registry.ts).
  //
  //   - `aithos.x.<vendor>.<name>.v<N>` → vendor namespace (per spec
  //     §3.3). Accepted at face value for now : the SDK client is the
  //     authoritative validator. The server-side `validateMetadata` path
  //     in records.ts/update handlers is conditionally skipped when the
  //     schema isn't in REGISTRY (`if (getSchema(...))`), so vendor
  //     records pass through without metadata enforcement. This is
  //     temporary — A2b (see PLAN-A2b-schema-self-registration.md) will
  //     introduce a per-owner schema registry table, letting vendors
  //     publish their own schemas and have them validated server-side.
  //
  //   - Any other prefix (e.g. did:web:vendor.com:posts.v1, or a custom
  //     scheme an organization wants to use internally) → accepted at
  //     face value, same rationale as vendor namespace.
  //
  // The split below isolates the strict "core must be registered" gate
  // to the actual core namespace.
  const isCoreAithos =
    p.schema!.startsWith("aithos.") && !p.schema!.startsWith("aithos.x.");
  if (isCoreAithos && !getSchema(p.schema!)) {
    throw new RpcError(
      -32070,
      `AITHOS_DATA_SCHEMA_UNKNOWN: schema "${p.schema}" is not registered on this platform`,
    );
  }

  const collectionUrn = `urn:aithos:collection:${p.subject_did}:${p.collection_name}`;
  const now = new Date().toISOString();

  const item = {
    pk: pkForSubject(p.subject_did!),
    sk: skForCollection(p.collection_name!),
    type: "collection",
    aithos_data: "0.1.0",
    urn: collectionUrn,
    subject_did: p.subject_did,
    name: p.collection_name,
    schema: p.schema,
    created_at: now,
    modified_at: now,
    record_count: 0,
    forward_secrecy: p.forward_secrecy ?? "best_effort",
    cmk_envelope: p.cmk_envelope,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
        ConditionExpression: "attribute_not_exists(pk)",
      }),
    );
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      throw new RpcError(
        -32073,
        `AITHOS_DATA_COLLECTION_EXISTS: collection "${p.collection_name}" already exists for this subject`,
      );
    }
    throw err;
  }

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: p.subject_did!,
    op: "data.collection.created",
    payload: {
      collection_urn: collectionUrn,
      collection_name: p.collection_name,
      schema: p.schema,
      forward_secrecy: item.forward_secrecy,
      cmk_envelope_hash: hashJson(p.cmk_envelope),
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });
  void gamma;

  return {
    urn: collectionUrn,
    subject_did: p.subject_did,
    name: p.collection_name,
    schema: p.schema,
    created_at: now,
    modified_at: now,
    record_count: 0,
    forward_secrecy: item.forward_secrecy,
    cmk_envelope: p.cmk_envelope,
  };
}

/* -------------------------------------------------------------------------- */
/*  get_collection                                                            */
/* -------------------------------------------------------------------------- */

interface GetCollectionParams {
  subject_did?: string;
  collection_name?: string;
}

export async function getCollectionHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as GetCollectionParams;
  validateRequired(p, ["subject_did", "collection_name"]);
  requireSubjectMatch(caller, p.subject_did!);
  requireScope(caller, p.collection_name!, "read");

  const r = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: pkForSubject(p.subject_did!),
        sk: skForCollection(p.collection_name!),
      },
    }),
  );

  if (!r.Item) {
    throw new RpcError(
      -32020,
      `AITHOS_NOT_FOUND: collection "${p.collection_name}" not found for subject ${p.subject_did}`,
    );
  }

  return projectCollection(r.Item);
}

/* -------------------------------------------------------------------------- */
/*  list_collections                                                          */
/* -------------------------------------------------------------------------- */

interface ListCollectionsParams {
  subject_did?: string;
  limit?: number;
  cursor?: string;
}

export async function listCollectionsHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as ListCollectionsParams;
  validateRequired(p, ["subject_did"]);
  requireSubjectMatch(caller, p.subject_did!);
  // list_collections is owner-only — a delegate sees only the collection
  // they have a wrap on, via get_collection.
  if (caller.mode === "delegate") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: list_collections is owner-only in v0.1; delegates may only call get_collection on the specific collection they hold a wrap for",
    );
  }

  const limit = clampLimit(p.limit, 20, 100);
  const exclusiveStartKey = p.cursor ? decodeCursor(p.cursor) : undefined;

  const r = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      FilterExpression: "#type = :ctype",
      ExpressionAttributeNames: { "#type": "type" },
      ExpressionAttributeValues: {
        ":pk": pkForSubject(p.subject_did!),
        ":prefix": "col#",
        ":ctype": "collection",
      },
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey,
    }),
  );

  const items = (r.Items ?? []).map(projectCollectionBrief);

  return {
    items,
    next_cursor: r.LastEvaluatedKey ? encodeCursor(r.LastEvaluatedKey) : undefined,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helpers (also used by records.ts)                                          */
/* -------------------------------------------------------------------------- */

function projectCollection(item: Record<string, unknown>): unknown {
  return {
    urn: item.urn,
    subject_did: item.subject_did,
    name: item.name,
    schema: item.schema,
    created_at: item.created_at,
    modified_at: item.modified_at,
    record_count: item.record_count ?? 0,
    forward_secrecy: item.forward_secrecy,
    cmk_envelope: item.cmk_envelope,
  };
}

function projectCollectionBrief(item: Record<string, unknown>): unknown {
  return {
    name: item.name,
    urn: item.urn,
    schema: item.schema,
    record_count: item.record_count ?? 0,
    created_at: item.created_at,
    modified_at: item.modified_at,
  };
}

export function validateRequired<T extends object>(
  params: T,
  required: (keyof T)[],
): void {
  for (const k of required) {
    if (params[k] === undefined || params[k] === null || params[k] === "") {
      throw new RpcError(-32602, `invalid params: missing or empty "${String(k)}"`);
    }
  }
}

export function clampLimit(
  v: number | undefined,
  defaultValue: number,
  max: number,
): number {
  if (v === undefined) return defaultValue;
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
    throw new RpcError(-32602, "invalid params: limit must be a positive integer");
  }
  return Math.min(v, max);
}

export function encodeCursor(key: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(key), "utf8").toString("base64url");
}

export function decodeCursor(s: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(s, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new RpcError(-32602, "invalid params: cursor is malformed");
  }
}
