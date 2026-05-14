// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for record-level primitives:
 *   - aithos.data.insert_record
 *   - aithos.data.get_record
 *   - aithos.data.list_records
 *
 * Spec ref: spec/data/05-api-primitives.md §5.3.4, §5.3.5, §5.4.2.
 */

import { ulid } from "ulid";
import {
  PutCommand,
  GetCommand,
  QueryCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import {
  ddb,
  TABLE_NAME,
  pkForSubject,
  skForCollection,
  skForRecord,
  gsi1pkForCollection,
  gsi1skForRecord,
} from "../ddb.js";
import { RpcError } from "../jsonrpc.js";
import {
  clampLimit,
  decodeCursor,
  encodeCursor,
  validateRequired,
} from "./collections.js";

/* -------------------------------------------------------------------------- */
/*  insert_record                                                             */
/* -------------------------------------------------------------------------- */

export interface InsertRecordParams {
  collection_urn?: string;
  record_id?: string;
  metadata?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export async function insertRecordHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as InsertRecordParams;
  validateRequired(p, ["collection_urn", "metadata", "payload"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);

  // Confirm the collection exists
  const colKey = {
    pk: pkForSubject(subjectDid),
    sk: skForCollection(collectionName),
  };
  const col = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: colKey }));
  if (!col.Item) {
    throw new RpcError(
      -32020,
      `AITHOS_NOT_FOUND: collection ${p.collection_urn} does not exist`,
    );
  }

  const now = new Date().toISOString();
  const recordId = p.record_id ?? `record_${ulid()}`;
  const metadata = {
    ...p.metadata!,
    created_at: now,
    modified_at: now,
  };

  const item = {
    pk: pkForSubject(subjectDid),
    sk: skForRecord(collectionName, recordId),
    gsi1pk: gsi1pkForCollection(subjectDid, collectionName),
    gsi1sk: gsi1skForRecord(now, recordId),
    type: "record",
    aithos_data: "0.1.0",
    record_id: recordId,
    collection_urn: p.collection_urn,
    schema: col.Item.schema,
    metadata,
    payload: p.payload,
    deleted: false,
    created_at: now,
    modified_at: now,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
        ConditionExpression: "attribute_not_exists(sk)",
      }),
    );
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      throw new RpcError(
        -32073,
        `AITHOS_DATA_RECORD_EXISTS: record_id "${recordId}" already exists`,
      );
    }
    throw err;
  }

  // Bump the collection's record_count + modified_at (best-effort; not
  // transactionally consistent with the put above — acceptable for the
  // POC, will become a TransactWriteItems call in 3.2)
  await ddb
    .send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: colKey,
        UpdateExpression: "ADD record_count :one SET modified_at = :now",
        ExpressionAttributeValues: { ":one": 1, ":now": now },
      }),
    )
    .catch(() => {
      /* swallow — bookkeeping only */
    });

  return {
    record_id: recordId,
    gamma_ref: `gamma_pending_${now}`, // placeholder — gamma wiring in Sub-jalon 3.2
  };
}

/* -------------------------------------------------------------------------- */
/*  get_record                                                                */
/* -------------------------------------------------------------------------- */

export interface GetRecordParams {
  collection_urn?: string;
  record_id?: string;
}

export async function getRecordHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as GetRecordParams;
  validateRequired(p, ["collection_urn", "record_id"]);
  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);

  const r = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: pkForSubject(subjectDid),
        sk: skForRecord(collectionName, p.record_id!),
      },
    }),
  );

  if (!r.Item || r.Item.deleted) {
    throw new RpcError(
      -32020,
      `AITHOS_NOT_FOUND: record ${p.record_id} not found in ${p.collection_urn}`,
    );
  }

  return projectRecord(r.Item);
}

/* -------------------------------------------------------------------------- */
/*  list_records                                                              */
/* -------------------------------------------------------------------------- */

export interface ListRecordsParams {
  collection_urn?: string;
  order?: "newest" | "oldest";
  limit?: number;
  cursor?: string;
  include_deleted?: boolean;
}

export async function listRecordsHandler(
  params: Record<string, unknown>,
): Promise<unknown> {
  const p = params as ListRecordsParams;
  validateRequired(p, ["collection_urn"]);
  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);

  const limit = clampLimit(p.limit, 20, 100);
  const order = p.order ?? "newest";
  const exclusiveStartKey = p.cursor ? decodeCursor(p.cursor) : undefined;

  // Use GSI1 — partitioned by (subject, collection), sorted by mtime.
  const exprAttrValues: Record<string, unknown> = {
    ":pk": gsi1pkForCollection(subjectDid, collectionName),
  };
  if (!p.include_deleted) exprAttrValues[":f"] = false;

  const r = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: "gsi1_by_collection_mtime",
      KeyConditionExpression: "gsi1pk = :pk",
      ExpressionAttributeValues: exprAttrValues,
      ScanIndexForward: order === "oldest",
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey,
      ...(p.include_deleted ? {} : { FilterExpression: "deleted = :f" }),
    }),
  );

  return {
    items: (r.Items ?? []).map(projectRecord),
    next_cursor: r.LastEvaluatedKey ? encodeCursor(r.LastEvaluatedKey) : undefined,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function projectRecord(item: Record<string, unknown>): unknown {
  return {
    aithos_data: item.aithos_data,
    urn: `${item.collection_urn}:${item.record_id}`,
    collection_urn: item.collection_urn,
    record_id: item.record_id,
    schema: item.schema,
    metadata: item.metadata,
    payload: item.payload,
    deleted: item.deleted ?? false,
    created_at: item.created_at,
    modified_at: item.modified_at,
    gamma_ref: `gamma_pending_${item.modified_at}`,
  };
}

/**
 * Parse a collection URN of the form
 *   urn:aithos:collection:<subject_did>:<collection_name>
 *
 * Note: subject_did itself contains colons ("did:aithos:z6…"), so we
 * cannot just split on ":". We anchor on the fixed prefix and the
 * known position of the final segment.
 */
export function parseCollectionUrn(urn: string): {
  subjectDid: string;
  collectionName: string;
} {
  const prefix = "urn:aithos:collection:";
  if (!urn.startsWith(prefix)) {
    throw new RpcError(-32602, `invalid collection_urn: missing prefix "${prefix}"`);
  }
  const rest = urn.slice(prefix.length);
  // Find the last colon — that separates collection_name from the DID
  const lastColon = rest.lastIndexOf(":");
  if (lastColon < 0) {
    throw new RpcError(-32602, `invalid collection_urn: no separator between DID and collection name`);
  }
  const subjectDid = rest.slice(0, lastColon);
  const collectionName = rest.slice(lastColon + 1);
  if (!subjectDid || !collectionName) {
    throw new RpcError(-32602, `invalid collection_urn: empty subject_did or collection_name`);
  }
  return { subjectDid, collectionName };
}
