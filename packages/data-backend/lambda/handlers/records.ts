// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for record-level primitives:
 *   - aithos.data.insert_record
 *   - aithos.data.get_record
 *   - aithos.data.list_records
 *   - aithos.data.update_record   (NEW in Sub-jalon 3.2a)
 *   - aithos.data.delete_record   (NEW in Sub-jalon 3.2a)
 *
 * Each handler receives an authenticated `Caller`. Scope is enforced
 * via requireScope() at the entry of every handler.
 *
 * Spec ref: spec/data/05-api-primitives.md §5.3.4–5.3.5, §5.4.2–5.4.4.
 */

import { ulid } from "ulid";
import {
  PutCommand,
  GetCommand,
  QueryCommand,
  UpdateCommand,
  DeleteCommand,
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
  requireScope,
  requireSubjectMatch,
  type Caller,
} from "../auth/authenticate.js";
import {
  clampLimit,
  decodeCursor,
  encodeCursor,
  validateRequired,
} from "./collections.js";
import { getSchema, validateMetadata } from "../schemas/registry.js";
import { appendGammaEntry } from "../gamma/store.js";
import { hashJson } from "../gamma/hash-util.js";

/* -------------------------------------------------------------------------- */
/*  insert_record                                                             */
/* -------------------------------------------------------------------------- */

interface InsertRecordParams {
  collection_urn?: string;
  record_id?: string;
  metadata?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export async function insertRecordHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as InsertRecordParams;
  validateRequired(p, ["collection_urn", "metadata", "payload"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  requireScope(caller, collectionName, "write");

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

  const schemaId = col.Item.schema as string;
  const now = new Date().toISOString();
  const recordId = p.record_id ?? `record_${ulid()}`;

  // Validate the metadata clear against the registered schema.
  // Encrypted payload remains opaque and is not validated server-side.
  if (getSchema(schemaId)) {
    const result = validateMetadata(schemaId, p.metadata!, { op: "insert" });
    if (!result.ok) {
      throw new RpcError(
        -32072,
        `AITHOS_DATA_RECORD_INVALID: ${result.errors.map((e) => `${e.field}: ${e.reason}`).join("; ")}`,
        { errors: result.errors },
      );
    }
    p.metadata = result.metadata;
  }

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
    authored_by: caller.mode === "delegate" ? caller.mandateId : undefined,
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

  // Bookkeeping — bump record_count and modified_at on the collection.
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
      /* best-effort */
    });

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.record.created",
    payload: {
      collection_urn: p.collection_urn,
      record_id: recordId,
      schema: col.Item.schema,
      metadata_hash: hashJson(metadata),
      payload_hash: hashJson(p.payload),
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
    ...(caller.mandateId ? { authorizedBy: caller.mandateId } : {}),
  });

  return {
    record_id: recordId,
    gamma_ref: gamma.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  get_record                                                                */
/* -------------------------------------------------------------------------- */

interface GetRecordParams {
  collection_urn?: string;
  record_id?: string;
}

export async function getRecordHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as GetRecordParams;
  validateRequired(p, ["collection_urn", "record_id"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  requireScope(caller, collectionName, "read");

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

interface ListRecordsParams {
  collection_urn?: string;
  order?: "newest" | "oldest";
  limit?: number;
  cursor?: string;
  include_deleted?: boolean;
  filter?: RecordFilter;
}

interface RecordFilter {
  equals?: { field: string; value: string | number | boolean };
  contains?: { field: string; value: string };
  tags_any?: string[];
  tags_all?: string[];
  range?: { field: string; gte?: string; lte?: string };
}

export async function listRecordsHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as ListRecordsParams;
  validateRequired(p, ["collection_urn"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  requireScope(caller, collectionName, "read");

  const limit = clampLimit(p.limit, 20, 100);
  const order = p.order ?? "newest";
  const exclusiveStartKey = p.cursor ? decodeCursor(p.cursor) : undefined;

  // Build FilterExpression from caller-supplied filter and include_deleted.
  const filterClauses: string[] = [];
  const exprAttrValues: Record<string, unknown> = {
    ":pk": gsi1pkForCollection(subjectDid, collectionName),
  };
  const exprAttrNames: Record<string, string> = {};

  if (!p.include_deleted) {
    filterClauses.push("deleted = :f_deleted");
    exprAttrValues[":f_deleted"] = false;
  }

  const flt = p.filter;
  if (flt?.equals) {
    exprAttrNames["#f_eq_k"] = "metadata";
    exprAttrNames["#f_eq_v"] = flt.equals.field;
    exprAttrValues[":f_eq"] = flt.equals.value;
    filterClauses.push("#f_eq_k.#f_eq_v = :f_eq");
  }
  if (flt?.contains) {
    exprAttrNames["#f_ct_k"] = "metadata";
    exprAttrNames["#f_ct_v"] = flt.contains.field;
    exprAttrValues[":f_ct"] = flt.contains.value;
    filterClauses.push("contains(#f_ct_k.#f_ct_v, :f_ct)");
  }
  if (flt?.tags_any && flt.tags_any.length > 0) {
    exprAttrNames["#f_ta_k"] = "metadata";
    exprAttrNames["#f_ta_v"] = "tags";
    const orParts: string[] = [];
    flt.tags_any.forEach((t, i) => {
      const ph = `:f_ta_${i}`;
      exprAttrValues[ph] = t;
      orParts.push(`contains(#f_ta_k.#f_ta_v, ${ph})`);
    });
    filterClauses.push(`(${orParts.join(" OR ")})`);
  }
  if (flt?.tags_all && flt.tags_all.length > 0) {
    exprAttrNames["#f_taa_k"] = "metadata";
    exprAttrNames["#f_taa_v"] = "tags";
    flt.tags_all.forEach((t, i) => {
      const ph = `:f_taa_${i}`;
      exprAttrValues[ph] = t;
      filterClauses.push(`contains(#f_taa_k.#f_taa_v, ${ph})`);
    });
  }
  if (flt?.range) {
    exprAttrNames["#f_rg_k"] = "metadata";
    exprAttrNames["#f_rg_v"] = flt.range.field;
    if (flt.range.gte) {
      exprAttrValues[":f_rg_gte"] = flt.range.gte;
      filterClauses.push("#f_rg_k.#f_rg_v >= :f_rg_gte");
    }
    if (flt.range.lte) {
      exprAttrValues[":f_rg_lte"] = flt.range.lte;
      filterClauses.push("#f_rg_k.#f_rg_v <= :f_rg_lte");
    }
  }

  const r = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: "gsi1_by_collection_mtime",
      KeyConditionExpression: "gsi1pk = :pk",
      ExpressionAttributeValues: exprAttrValues,
      ...(Object.keys(exprAttrNames).length > 0
        ? { ExpressionAttributeNames: exprAttrNames }
        : {}),
      ScanIndexForward: order === "oldest",
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey,
      ...(filterClauses.length > 0
        ? { FilterExpression: filterClauses.join(" AND ") }
        : {}),
    }),
  );

  return {
    items: (r.Items ?? []).map(projectRecord),
    next_cursor: r.LastEvaluatedKey ? encodeCursor(r.LastEvaluatedKey) : undefined,
  };
}

/* -------------------------------------------------------------------------- */
/*  update_record  (Sub-jalon 3.2a NEW)                                       */
/* -------------------------------------------------------------------------- */

interface UpdateRecordParams {
  collection_urn?: string;
  record_id?: string;
  metadata?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  expected_modified_at?: string;
}

export async function updateRecordHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as UpdateRecordParams;
  validateRequired(p, ["collection_urn", "record_id", "metadata", "payload"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  requireScope(caller, collectionName, "write");

  // Fetch current to preserve created_at and detect concurrent modification
  const recordKey = {
    pk: pkForSubject(subjectDid),
    sk: skForRecord(collectionName, p.record_id!),
  };
  const r = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: recordKey }));
  if (!r.Item || r.Item.deleted) {
    throw new RpcError(
      -32020,
      `AITHOS_NOT_FOUND: record ${p.record_id} not found in ${p.collection_urn}`,
    );
  }
  if (
    p.expected_modified_at &&
    p.expected_modified_at !== r.Item.modified_at
  ) {
    throw new RpcError(
      -32077,
      `AITHOS_DATA_CONCURRENT_MODIFICATION: record was modified since expected_modified_at`,
      { actual: r.Item.modified_at, expected: p.expected_modified_at },
    );
  }

  // Validate metadata against the collection's schema.
  const schemaId = r.Item.schema as string;
  if (getSchema(schemaId)) {
    const result = validateMetadata(schemaId, p.metadata!, { op: "update" });
    if (!result.ok) {
      throw new RpcError(
        -32072,
        `AITHOS_DATA_RECORD_INVALID: ${result.errors.map((e) => `${e.field}: ${e.reason}`).join("; ")}`,
        { errors: result.errors },
      );
    }
    p.metadata = result.metadata;
  }

  const now = new Date().toISOString();
  const newMetadata = {
    ...p.metadata!,
    created_at: r.Item.created_at,
    modified_at: now,
  };

  const newItem = {
    ...r.Item,
    gsi1sk: gsi1skForRecord(now, p.record_id!),
    metadata: newMetadata,
    payload: p.payload,
    modified_at: now,
    authored_by: caller.mode === "delegate" ? caller.mandateId : r.Item.authored_by,
  };

  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: newItem,
      ConditionExpression:
        p.expected_modified_at
          ? "modified_at = :expected"
          : "attribute_exists(sk)",
      ExpressionAttributeValues: p.expected_modified_at
        ? { ":expected": p.expected_modified_at }
        : undefined,
    }),
  );

  // Bookkeeping — bump collection modified_at
  await ddb
    .send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk: pkForSubject(subjectDid), sk: skForCollection(collectionName) },
        UpdateExpression: "SET modified_at = :now",
        ExpressionAttributeValues: { ":now": now },
      }),
    )
    .catch(() => {
      /* best-effort */
    });

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.record.modified",
    payload: {
      collection_urn: p.collection_urn,
      record_id: p.record_id,
      prev_metadata_hash: hashJson(r.Item.metadata ?? {}),
      prev_payload_hash: hashJson(r.Item.payload ?? {}),
      metadata_hash: hashJson(newMetadata),
      payload_hash: hashJson(p.payload),
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
    ...(caller.mandateId ? { authorizedBy: caller.mandateId } : {}),
  });

  return {
    record_id: p.record_id,
    modified_at: now,
    gamma_ref: gamma.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  delete_record  (Sub-jalon 3.2a NEW)                                       */
/* -------------------------------------------------------------------------- */

interface DeleteRecordParams {
  collection_urn?: string;
  record_id?: string;
  /** When true, hard-delete (no soft-delete row). Default false. */
  hard_delete?: boolean;
}

export async function deleteRecordHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as DeleteRecordParams;
  validateRequired(p, ["collection_urn", "record_id"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  requireScope(caller, collectionName, "write");

  const recordKey = {
    pk: pkForSubject(subjectDid),
    sk: skForRecord(collectionName, p.record_id!),
  };

  // Fetch first to make sure it exists (so we return 404 vs silently no-op)
  const r = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: recordKey }));
  if (!r.Item || r.Item.deleted) {
    throw new RpcError(
      -32020,
      `AITHOS_NOT_FOUND: record ${p.record_id} not found in ${p.collection_urn}`,
    );
  }

  const now = new Date().toISOString();

  if (p.hard_delete) {
    // Hard delete — admin operation; locked behind owner-only.
    if (caller.mode === "delegate") {
      throw new RpcError(
        -32042,
        "AITHOS_INSUFFICIENT_SCOPE: hard_delete is owner-only in v0.1",
      );
    }
    await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: recordKey }));
  } else {
    // Soft delete — clear payload, set deleted: true, preserve metadata
    // for audit and for the eventual gamma chain check.
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: recordKey,
        UpdateExpression: "SET deleted = :t, payload = :empty, modified_at = :now",
        ExpressionAttributeValues: {
          ":t": true,
          ":empty": {},
          ":now": now,
        },
      }),
    );
  }

  // Bookkeeping — decrement record_count
  await ddb
    .send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk: pkForSubject(subjectDid), sk: skForCollection(collectionName) },
        UpdateExpression: "ADD record_count :neg1 SET modified_at = :now",
        ExpressionAttributeValues: { ":neg1": -1, ":now": now },
      }),
    )
    .catch(() => {
      /* best-effort */
    });

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.record.deleted",
    payload: {
      collection_urn: p.collection_urn,
      record_id: p.record_id,
      prev_metadata_hash: hashJson(r.Item.metadata ?? {}),
      prev_payload_hash: hashJson(r.Item.payload ?? {}),
      hard_delete: p.hard_delete === true,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
    ...(caller.mandateId ? { authorizedBy: caller.mandateId } : {}),
  });

  return {
    record_id: p.record_id,
    deleted_at: now,
    hard_delete: p.hard_delete === true,
    gamma_ref: gamma.id,
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
    authored_by: item.authored_by,
    gamma_ref: `gamma_pending_${item.modified_at}`,
  };
}

export function parseCollectionUrn(urn: string): {
  subjectDid: string;
  collectionName: string;
} {
  const prefix = "urn:aithos:collection:";
  if (!urn.startsWith(prefix)) {
    throw new RpcError(-32602, `invalid collection_urn: missing prefix "${prefix}"`);
  }
  const rest = urn.slice(prefix.length);
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
