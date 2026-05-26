// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Gamma log store for the assets sub-protocol — append-only,
 * hash-chained audit trail.
 *
 * Spec ref: `spec/assets/08-audit.md`.
 *
 * Each entry carries a `prev_hash` linking it to the chronologically
 * previous entry of the same subject, and a `hash` over its own
 * canonicalized content. Tampering with any past entry breaks the
 * chain detectably at verify time.
 *
 * v0.1 dev note: per-entry cryptographic signatures (subject sphere
 * key) are NOT enforced server-side in this iteration. Authorship is
 * attested by the envelope signature that produced the entry — the
 * entry's `authored_by_envelope_nonce` field links to the envelope's
 * replay-cache record. The spec calls for proper signatures; this is a
 * v0.2 addition consistent with how data-backend handles the same.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ulid } from "ulid";
import {
  PutCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import { canonicalize } from "@aithos/protocol-core/canonical";

import { ddb, GAMMA_TABLE_NAME } from "../deps.js";

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export type GammaOp =
  | "assets.upload_initiated"
  | "assets.created"
  | "assets.upload_aborted"
  | "assets.referenced"
  | "assets.unreferenced"
  | "assets.orphaned"
  | "assets.authorize_grantee"
  | "assets.revoke_grantee"
  | "assets.amk_rotated"
  | "assets.rotate_owner_wrap"
  | "assets.tombstoned"
  | "assets.purged"
  | "assets.imported"
  | "assets.exported";

export interface GammaEntry {
  readonly id: string;
  readonly at: string;
  readonly subject: string;
  readonly op: GammaOp;
  readonly payload: Record<string, unknown>;
  readonly prev_hash: string;
  readonly hash: string;
  readonly authored_by_envelope_nonce: string;
  readonly authored_by_pubkey: string;
  readonly authorized_by?: string;
}

export interface AppendArgs {
  readonly subject: string;
  readonly op: GammaOp;
  readonly payload: Record<string, unknown>;
  readonly authoredByEnvelopeNonce: string;
  readonly authoredByPubkey: string;
  readonly authorizedBy?: string;
}

const GENESIS_PREV_HASH = "sha256:" + "0".repeat(64);

/* -------------------------------------------------------------------------- */
/*  Append                                                                    */
/* -------------------------------------------------------------------------- */

export async function appendGammaEntry(
  args: AppendArgs,
): Promise<GammaEntry> {
  const head = await getHead(args.subject);
  const prevHash = head?.hash ?? GENESIS_PREV_HASH;

  const entryId = `gamma_${ulid()}`;
  const at = new Date().toISOString();

  const unsigned = {
    id: entryId,
    at,
    subject: args.subject,
    op: args.op,
    payload: args.payload,
    prev_hash: prevHash,
    authored_by_envelope_nonce: args.authoredByEnvelopeNonce,
    authored_by_pubkey: args.authoredByPubkey,
    ...(args.authorizedBy ? { authorized_by: args.authorizedBy } : {}),
  };
  const hash = computeEntryHash(unsigned);
  const entry: GammaEntry = { ...unsigned, hash };

  try {
    await ddb.send(
      new PutCommand({
        TableName: GAMMA_TABLE_NAME,
        Item: {
          subject_did: args.subject,
          entry_id: entryId,
          ...entry,
        },
        ConditionExpression: "attribute_not_exists(entry_id)",
      }),
    );
  } catch (err) {
    if (err instanceof ConditionalCheckFailedException) {
      console.warn("ULID collision on gamma append, retrying", { entryId });
      return appendGammaEntry(args);
    }
    throw err;
  }

  return entry;
}

/* -------------------------------------------------------------------------- */
/*  Head lookup                                                               */
/* -------------------------------------------------------------------------- */

export async function getHead(subject: string): Promise<GammaEntry | null> {
  const r = await ddb.send(
    new QueryCommand({
      TableName: GAMMA_TABLE_NAME,
      KeyConditionExpression: "subject_did = :s",
      ExpressionAttributeValues: { ":s": subject },
      ScanIndexForward: false,
      Limit: 1,
    }),
  );
  if (!r.Items || r.Items.length === 0) return null;
  return r.Items[0] as GammaEntry;
}

/* -------------------------------------------------------------------------- */
/*  Chain walk + verify                                                       */
/* -------------------------------------------------------------------------- */

export async function listEntries(
  subject: string,
  limit = 100,
  opPrefix?: string,
): Promise<GammaEntry[]> {
  const r = await ddb.send(
    new QueryCommand({
      TableName: GAMMA_TABLE_NAME,
      KeyConditionExpression: "subject_did = :s",
      ExpressionAttributeValues: { ":s": subject },
      ScanIndexForward: true,
      Limit: limit,
    }),
  );
  const items = (r.Items ?? []) as GammaEntry[];
  if (opPrefix) {
    return items.filter((e) => e.op.startsWith(opPrefix));
  }
  return items;
}

/* -------------------------------------------------------------------------- */
/*  Hash computation                                                          */
/* -------------------------------------------------------------------------- */

function computeEntryHash(unsigned: Omit<GammaEntry, "hash">): string {
  const canonical = canonicalize(unsigned);
  const bytes = new TextEncoder().encode(canonical);
  const digest = sha256(bytes);
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}
