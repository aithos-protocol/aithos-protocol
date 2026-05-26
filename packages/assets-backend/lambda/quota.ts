// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Per-subject byte-quota tracking.
 *
 * Default: 5 GB per subject (spec/assets/10-open-questions.md §10.13).
 * Configurable per deployment via `PER_SUBJECT_QUOTA_BYTES` env var.
 *
 * The current accounting strategy is denormalized:
 *   - Each subject has a "meta" item in the assets table at
 *     (pk="subj#<did>", sk="meta#quota") holding `used_bytes`.
 *   - On every `complete_upload` we increment `used_bytes` via
 *     ATOMIC `ADD` with a `ConditionExpression` enforcing
 *     `used_bytes + size <= limit`. Single-round-trip enforcement.
 *   - On `delete_asset` / `assets.tombstoned`, we decrement.
 *
 * The meta item is auto-created on first upload.
 */

import { UpdateCommand, GetCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import {
  ddb,
  ASSETS_TABLE_NAME,
  PER_SUBJECT_QUOTA_BYTES,
} from "./deps.js";
import { pkForSubject } from "./ddb.js";
import { quotaExceeded } from "./errors.js";

const QUOTA_META_SK = "meta#quota";

/* -------------------------------------------------------------------------- */
/*  Read                                                                      */
/* -------------------------------------------------------------------------- */

export interface QuotaState {
  readonly used_bytes: number;
  readonly limit_bytes: number;
}

export async function getQuota(subjectDid: string): Promise<QuotaState> {
  const r = await ddb.send(
    new GetCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: { pk: pkForSubject(subjectDid), sk: QUOTA_META_SK },
    }),
  );
  const item = r.Item as { used_bytes?: number } | undefined;
  return {
    used_bytes: item?.used_bytes ?? 0,
    limit_bytes: PER_SUBJECT_QUOTA_BYTES,
  };
}

/* -------------------------------------------------------------------------- */
/*  Atomic reserve (on complete_upload)                                        */
/* -------------------------------------------------------------------------- */

/**
 * Atomically increment the subject's `used_bytes` by `delta`, refusing
 * the operation if the result would exceed the quota.
 *
 * On success returns the new `used_bytes`. On overrun throws
 * `AITHOS_ASSETS_QUOTA_EXCEEDED`.
 */
export async function reserveQuota(
  subjectDid: string,
  delta: number,
): Promise<number> {
  if (delta <= 0) {
    // Nothing to reserve. Return current usage.
    return (await getQuota(subjectDid)).used_bytes;
  }

  const limit = PER_SUBJECT_QUOTA_BYTES;

  try {
    const r = await ddb.send(
      new UpdateCommand({
        TableName: ASSETS_TABLE_NAME,
        Key: { pk: pkForSubject(subjectDid), sk: QUOTA_META_SK },
        UpdateExpression: "ADD used_bytes :d SET limit_bytes = :l",
        ConditionExpression:
          "attribute_not_exists(used_bytes) OR used_bytes + :d <= :l",
        ExpressionAttributeValues: {
          ":d": delta,
          ":l": limit,
        },
        ReturnValues: "ALL_NEW",
      }),
    );
    const newUsed = (r.Attributes as { used_bytes?: number } | undefined)
      ?.used_bytes;
    return newUsed ?? delta;
  } catch (e) {
    if (e instanceof ConditionalCheckFailedException) {
      const current = await getQuota(subjectDid);
      throw quotaExceeded(current.used_bytes + delta, limit);
    }
    throw e;
  }
}

/* -------------------------------------------------------------------------- */
/*  Atomic release (on delete_asset)                                           */
/* -------------------------------------------------------------------------- */

/**
 * Atomically decrement the subject's `used_bytes` by `delta`. Safe to
 * call even when `used_bytes` doesn't exist yet (no-op then). The
 * counter is floored at 0.
 */
export async function releaseQuota(
  subjectDid: string,
  delta: number,
): Promise<void> {
  if (delta <= 0) return;

  try {
    await ddb.send(
      new UpdateCommand({
        TableName: ASSETS_TABLE_NAME,
        Key: { pk: pkForSubject(subjectDid), sk: QUOTA_META_SK },
        UpdateExpression: "ADD used_bytes :d",
        ConditionExpression:
          "attribute_exists(used_bytes) AND used_bytes >= :delta",
        ExpressionAttributeValues: {
          ":d": -delta,
          ":delta": delta,
        },
      }),
    );
  } catch (e) {
    if (e instanceof ConditionalCheckFailedException) {
      // Counter doesn't exist yet, or would go negative. Force to 0
      // explicitly to keep the meta item consistent.
      await ddb.send(
        new UpdateCommand({
          TableName: ASSETS_TABLE_NAME,
          Key: { pk: pkForSubject(subjectDid), sk: QUOTA_META_SK },
          UpdateExpression:
            "SET used_bytes = if_not_exists(used_bytes, :zero)",
          ExpressionAttributeValues: { ":zero": 0 },
        }),
      );
      // Don't throw — release is best-effort and resilient to drift.
      return;
    }
    throw e;
  }
}
