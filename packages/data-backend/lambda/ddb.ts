// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * DynamoDB client + key helpers for the single-table design.
 *
 * Key scheme (PK, SK):
 *   ("subj#<did>", "col#<name>")                 → collection metadata
 *   ("subj#<did>", "col#<name>#rec#<record_id>") → record document
 *
 * GSI1 (gsi1pk, gsi1sk):
 *   ("subj#<did>#col#<name>", "rec#<modified_at>#<record_id>")
 *     → enables list_records by collection, sorted by modified_at desc
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

const region = process.env.AWS_REGION ?? "eu-west-3";
const tableName = process.env.DATA_TABLE_NAME ?? "aithos-data-pds-dev";
const schemasTableName =
  process.env.SCHEMAS_TABLE_NAME ?? "aithos-data-pds-schemas-dev";

const baseClient = new DynamoDBClient({ region });

export const ddb = DynamoDBDocumentClient.from(baseClient, {
  marshallOptions: {
    removeUndefinedValues: true,
    convertClassInstanceToMap: false,
  },
});

export const TABLE_NAME = tableName;
export const SCHEMAS_TABLE_NAME = schemasTableName;

/* -------------------------------------------------------------------------- */
/*  Key helpers                                                               */
/* -------------------------------------------------------------------------- */

export function pkForSubject(subjectDid: string): string {
  return `subj#${subjectDid}`;
}

export function skForCollection(collectionName: string): string {
  return `col#${collectionName}`;
}

export function skForRecord(collectionName: string, recordId: string): string {
  return `col#${collectionName}#rec#${recordId}`;
}

export function gsi1pkForCollection(
  subjectDid: string,
  collectionName: string,
): string {
  return `subj#${subjectDid}#col#${collectionName}`;
}

export function gsi1skForRecord(modifiedAt: string, recordId: string): string {
  // ISO 8601 sorts lexicographically. Prefix with "rec#" so collection
  // metadata (sk="col#…", no gsi1sk) is excluded from queries on this index.
  return `rec#${modifiedAt}#${recordId}`;
}

/* -------------------------------------------------------------------------- */
/*  Schemas table key helpers (A2b — per-owner vendor schema registry)        */
/* -------------------------------------------------------------------------- */

/**
 * Partition key for the schemas table — one partition per owner DID so
 * the per-owner quota check (count + size sum) is a single Query.
 */
export function pkForSchemasOwner(ownerDid: string): string {
  return `owner#${ownerDid}`;
}

/**
 * Sort key — the schema identifier itself (e.g. `aithos.x.linkedone.post.v1`).
 * Each (owner_did, schema_id) pair is unique.
 */
export function skForSchema(schemaId: string): string {
  return schemaId;
}
