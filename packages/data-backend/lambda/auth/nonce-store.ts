// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * DDB-backed replay-protection cache, per spec §11.5 / §11.10.
 *
 * Atomic conditional insert via PutItem with `attribute_not_exists(pk)`.
 * Native DDB TTL on the `expires_at_epoch` attribute (seconds since
 * epoch) reclaims storage automatically — DDB asynchronously purges
 * within ~48h of expiry. The freshness window (≤300s envelope TTL +
 * 30s grace, per §11.5.2) means the rejection logic in PutItem
 * triggers well before purge becomes relevant.
 *
 * Failures of the underlying DDB call propagate as exceptions, which
 * verifyEnvelope translates into a -32603 "fail closed" outcome.
 */

import { DynamoDBClient, ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";
import type { EnvelopeReplayCache } from "@aithos/protocol-core/envelope";

const region = process.env.AWS_REGION ?? "eu-west-3";
const nonceTableName =
  process.env.NONCE_TABLE_NAME ?? "aithos-data-pds-nonces-dev";

const baseClient = new DynamoDBClient({ region });
const ddb = DynamoDBDocumentClient.from(baseClient);

export class DdbReplayCache implements EnvelopeReplayCache {
  async putIfAbsent(key: string, expiresAtSeconds: number): Promise<boolean> {
    try {
      await ddb.send(
        new PutCommand({
          TableName: nonceTableName,
          Item: {
            pk: key,
            expires_at_epoch: expiresAtSeconds,
            seen_at: new Date().toISOString(),
          },
          ConditionExpression: "attribute_not_exists(pk)",
        }),
      );
      return true; // committed — first time we see this nonce
    } catch (err) {
      if (err instanceof ConditionalCheckFailedException) {
        return false; // nonce already in the cache — replay
      }
      throw err; // genuine failure — let it propagate to fail-closed
    }
  }
}

export const replayCache = new DdbReplayCache();
