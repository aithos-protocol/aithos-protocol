// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for collection-level primitives:
 *   - aithos.data.create_collection
 *   - aithos.data.get_collection
 *   - aithos.data.list_collections
 *
 * Spec ref: spec/data/05-api-primitives.md §5.3.x, §5.4.1.
 *
 * v0.1 dev note: no envelope / mandate verification yet. Each handler
 * accepts the caller-supplied subject_did at face value. Wire the real
 * auth in Sub-jalon 3.2.
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

/* -------------------------------------------------------------------------- */
/*  create_collection                                                         */
/* -------------------------------------------------------------------------- */

export interface CreateCollectionParams {
  subject_did?: string;
  collection_name?: string;
  schema?: string;
  cmk_envelope?: unknown;
  forward_secrecy?: "best_effort" | "strict";
}

export async function createCollectionHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as CreateCollectionParams;
  validateRequired(p, ["subject_did", "collection_name", "schema", "cmk_envelope"]);

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

export interface GetCollectionParams {
  subject_did?: string;
  collection_name?: string;
}

export async function getCollectionHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as GetCollectionParams;
  validateRequired(p, ["subject_did", "collection_name"]);

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

export interface ListCollectionsParams {
  subject_did?: string;
  limit?: number;
  cursor?: string;
}

export async function listCollectionsHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as ListCollectionsParams;
  validateRequired(p, ["subject_did"]);

  const limit = clampLimit(p.limit, 20, 100);
  const exclusiveStartKey = p.cursor ? decodeCursor(p.cursor) : undefined;

  const r = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      // Collection items have sk = "col#<name>" — records have sk =
      // "col#<name>#rec#<id>". To list only collections, we need a
      // FilterExpression because "begins_with" matches both.
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
/*  Helpers                                                                   */
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
