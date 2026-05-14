// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Revocations table — mandate revocation lookup.
 *
 * Spec ref: §4.6 (mandate revocations) and the envelope verifier's
 * `findRevocation` context hook in `@aithos/protocol-core/envelope`.
 *
 * Schema: { mandate_id (PK), revoked_at, reason, issuer, revocation_doc }.
 *
 * Two integrations:
 *   - `findRevocation(mandate_id)` — called by `authenticate()` for
 *     every mandate-bearing envelope. Lookup hit → -32041
 *     AITHOS_MANDATE_REVOKED.
 *   - `recordRevocation(rev)` — called by `revoke_app` handler.
 *     Idempotent: writing the same mandate_id twice is a no-op.
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";

const region = process.env.AWS_REGION ?? "eu-west-3";
const tableName =
  process.env.REVOCATIONS_TABLE_NAME ?? "aithos-data-pds-revocations-dev";

const baseClient = new DynamoDBClient({ region });
const ddb = DynamoDBDocumentClient.from(baseClient);

export interface StoredRevocation {
  mandate_id: string;
  issuer: string;
  revoked_at: string;
  reason?: string;
  /** Full signed revocation document if supplied by the issuer. */
  revocation_doc?: unknown;
}

/**
 * Lookup a revocation for the given mandate id.
 *
 * Returns `null` when the mandate is NOT revoked. The exact shape returned
 * to the envelope verifier matches `Revocation` from @aithos/protocol-core
 * — we project only the fields the verifier reads.
 */
export async function findRevocation(
  mandateId: string,
): Promise<{ revoked_at: string; reason?: string } | null> {
  const r = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: { mandate_id: mandateId },
    }),
  );
  if (!r.Item) return null;
  return {
    revoked_at: r.Item.revoked_at as string,
    ...(r.Item.reason ? { reason: r.Item.reason as string } : {}),
  };
}

export async function recordRevocation(rev: StoredRevocation): Promise<void> {
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: rev,
    }),
  );
}
