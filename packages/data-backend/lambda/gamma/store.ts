// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Gamma log store — append-only, hash-chained audit trail.
 *
 * Spec ref: `spec/data/08-audit.md`.
 *
 * Each entry carries a `prev_hash` linking it to the chronologically
 * previous entry of the same subject, and a `hash` over its own
 * canonicalized content. Tampering with any past entry breaks the
 * chain detectably at verify time.
 *
 * v0.1 dev note: per-entry cryptographic signatures (subject sphere
 * key or delegate key + mandate id) are NOT enforced server-side in
 * this iteration. Authorship is attested by the envelope signature
 * that produced the entry — the entry's `authored_by_envelope_nonce`
 * field links to the envelope's replay-cache record. Future
 * Sub-jalon adds per-entry signatures as the spec mandates.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ulid } from "ulid";
import {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient, ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

import { canonicalize } from "@aithos/protocol-core/canonical";

const region = process.env.AWS_REGION ?? "eu-west-3";
const tableName = process.env.GAMMA_TABLE_NAME ?? "aithos-data-pds-gamma-dev";

const baseClient = new DynamoDBClient({ region });
const ddb = DynamoDBDocumentClient.from(baseClient);

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export type GammaOp =
  | "data.collection.created"
  | "data.collection.tombstoned"
  | "data.collection.authorize_grantee"
  | "data.collection.revoke_grantee"
  | "data.collection.rotate_cmk"
  | "data.record.created"
  | "data.record.modified"
  | "data.record.deleted";

export interface GammaEntry {
  /** Server-generated ULID — lexicographically sortable by time. */
  readonly id: string;
  /** RFC 3339 timestamp. */
  readonly at: string;
  /** Subject DID this entry belongs to. */
  readonly subject: string;
  /** Operation type. */
  readonly op: GammaOp;
  /** Operation-specific payload (typically commits to record/collection content via hashes). */
  readonly payload: Record<string, unknown>;
  /** SHA-256 of the previous entry's `hash`, or "sha256:<64 zeroes>" for the first entry. */
  readonly prev_hash: string;
  /** SHA-256 of canonicalized form of this entry without the `hash` field. */
  readonly hash: string;
  /** Envelope nonce that authored this entry. v0.1 dev — replaces a real Ed25519 signature. */
  readonly authored_by_envelope_nonce: string;
  /** Caller's signer pubkey (sphere or delegate). */
  readonly authored_by_pubkey: string;
  /** Mandate id if the entry was authored under a mandate. */
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

/**
 * Append a new entry to the subject's chain. Returns the entry that
 * was committed (including its hash).
 *
 * Steps:
 *   1. Look up the current head (latest entry by subject, descending).
 *   2. Compute prev_hash from head.hash (or genesis if no head).
 *   3. Build the unsigned entry, compute its hash.
 *   4. PutItem with condition attribute_not_exists(entry_id) for safety.
 *   5. Return the entry.
 *
 * Concurrency note: two appends on the same subject in flight may
 * both read the same head and produce two entries with the same
 * prev_hash. The second commit's ULID is later than the first (ULIDs
 * include millisecond timestamps), so subsequent verification of the
 * chain will detect a fork. In v0.1 dev we accept this race for
 * simplicity. Future Sub-jalon introduces a TransactWriteItems-based
 * append-with-compare-and-swap on a "head pointer" attribute.
 */
export async function appendGammaEntry(args: AppendArgs): Promise<GammaEntry> {
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
        TableName: tableName,
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
      // ULID collision (effectively impossible). Retry with a fresh one.
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
      TableName: tableName,
      KeyConditionExpression: "subject_did = :s",
      ExpressionAttributeValues: { ":s": subject },
      ScanIndexForward: false, // newest first
      Limit: 1,
    }),
  );
  if (!r.Items || r.Items.length === 0) return null;
  return r.Items[0] as GammaEntry;
}

/* -------------------------------------------------------------------------- */
/*  Chain walk + verify                                                       */
/* -------------------------------------------------------------------------- */

/**
 * List entries for a subject in chronological order.
 *
 * Used by e2e tests and admin tools to verify chain integrity.
 */
export async function listEntries(subject: string, limit = 100): Promise<GammaEntry[]> {
  const r = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: "subject_did = :s",
      ExpressionAttributeValues: { ":s": subject },
      ScanIndexForward: true,
      Limit: limit,
    }),
  );
  return (r.Items ?? []) as GammaEntry[];
}

/**
 * Walk the chain, verifying:
 *   - Each entry's `hash` matches its canonical form.
 *   - Each entry's `prev_hash` matches the previous entry's `hash`.
 *
 * Returns { ok: true } if intact, or { ok: false, errors } with a
 * description of where the chain breaks.
 */
export interface VerifyChainResult {
  readonly ok: boolean;
  readonly entryCount: number;
  readonly errors: readonly string[];
}

export async function verifyChain(subject: string): Promise<VerifyChainResult> {
  const entries = await listEntries(subject, 1000);
  const errors: string[] = [];
  let expectedPrev = GENESIS_PREV_HASH;

  for (const e of entries) {
    if (e.prev_hash !== expectedPrev) {
      errors.push(
        `entry ${e.id}: prev_hash mismatch — got ${e.prev_hash}, expected ${expectedPrev}`,
      );
    }
    const recomputed = computeEntryHash({
      id: e.id,
      at: e.at,
      subject: e.subject,
      op: e.op,
      payload: e.payload,
      prev_hash: e.prev_hash,
      authored_by_envelope_nonce: e.authored_by_envelope_nonce,
      authored_by_pubkey: e.authored_by_pubkey,
      ...(e.authorized_by ? { authorized_by: e.authorized_by } : {}),
    });
    if (recomputed !== e.hash) {
      errors.push(
        `entry ${e.id}: hash mismatch — stored ${e.hash}, recomputed ${recomputed}`,
      );
    }
    expectedPrev = e.hash;
  }

  return { ok: errors.length === 0, entryCount: entries.length, errors };
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
