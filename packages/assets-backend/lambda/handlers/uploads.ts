// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Upload-lifecycle handlers:
 *   - aithos.assets.init_upload
 *   - aithos.assets.complete_upload
 *   - aithos.assets.abort_upload
 *
 * Spec ref: spec/assets/05-api-primitives.md §5.4.1–5.4.3.
 */

import { ulid } from "ulid";
import {
  PutCommand,
  GetCommand,
  DeleteCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  ddb,
  ASSETS_TABLE_NAME,
  UPLOADS_TABLE_NAME,
  PER_ASSET_CAP_BYTES,
  PRESIGNED_URL_TTL_SECONDS,
  isMediaTypeAllowed,
  PROTOCOL_VERSION,
} from "../deps.js";
import {
  pkForSubject,
  skForAsset,
  gsi1pkForSubject,
  gsi1skForSha,
  urnForAsset,
  s3KeyForAsset,
} from "../ddb.js";
import {
  presignPut,
  headObject,
  deleteObject,
  publicAssetUrl,
} from "../s3-presign.js";
import {
  hashMismatch,
  invalidParams,
  mediaTypeRejected,
  sizeCapExceeded,
  sizeMismatch,
  uploadNotFound,
} from "../errors.js";
import { reserveQuota } from "../quota.js";
import { appendGammaEntry } from "../gamma/store.js";
import type { Caller } from "../auth/envelope.js";

/* -------------------------------------------------------------------------- */
/*  init_upload                                                                */
/* -------------------------------------------------------------------------- */

interface InitUploadParams {
  subject_did: string;
  media_type: string;
  size_bytes: number;
  sha256_of_plaintext: string;
  attached_context?: {
    kind: "ethos" | "data";
    zone?: "public" | "circle" | "self";
    section_id?: string;
    collection_urn?: string;
    record_id?: string;
  };
  regime?: "auto" | "public" | "private";
  forward_secrecy?: "best_effort" | "strict";
  amk_envelope?: unknown;
  encryption_nonce?: string;
}

export async function initUploadHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<InitUploadParams>;

  // Param validation
  if (typeof p.subject_did !== "string" || !p.subject_did) {
    throw invalidParams("subject_did is required");
  }
  if (p.subject_did !== caller.subjectDid) {
    throw invalidParams("subject_did must match envelope iss (owner-only v0.1)");
  }
  if (typeof p.media_type !== "string" || !p.media_type) {
    throw invalidParams("media_type is required");
  }
  if (typeof p.size_bytes !== "number" || p.size_bytes < 0) {
    throw invalidParams("size_bytes must be a non-negative integer");
  }
  if (typeof p.sha256_of_plaintext !== "string" || !/^[0-9a-f]{64}$/i.test(p.sha256_of_plaintext)) {
    throw invalidParams("sha256_of_plaintext must be 64 hex chars");
  }
  if (!isMediaTypeAllowed(p.media_type)) {
    throw mediaTypeRejected(p.media_type);
  }
  if (p.size_bytes > PER_ASSET_CAP_BYTES) {
    throw sizeCapExceeded(p.size_bytes, PER_ASSET_CAP_BYTES);
  }

  const regime = resolveRegime(p);
  const encrypted = regime === "private";

  // Dedup probe — `(subject_did, sha256)` GSI lookup
  const existing = await dedupProbe(p.subject_did, p.sha256_of_plaintext);
  if (existing) {
    return {
      result: "dedup_hit",
      urn: urnForAsset(p.subject_did, existing.asset_id),
      asset_id: existing.asset_id,
      asset: existing,
    };
  }

  // Allocate fresh asset_id + upload session
  const assetId = `asset_${ulid()}`;
  const uploadSession = `upl_${ulid()}`;
  const urn = urnForAsset(p.subject_did, assetId);
  const s3Key = s3KeyForAsset(p.subject_did, assetId);

  // Compute the on-disk content length:
  //  - public: same as plaintext
  //  - private: nonce(24) + ciphertext + tag(16) = size_bytes + 40
  const contentLength = encrypted ? p.size_bytes + 24 + 16 : p.size_bytes;

  const presigned = await presignPut({
    key: s3Key,
    contentType: encrypted ? "application/octet-stream" : p.media_type,
    contentLength,
    ttlSeconds: PRESIGNED_URL_TTL_SECONDS,
  });

  // Persist the pending-upload record with TTL.
  const ttlSeconds = Math.floor(Date.now() / 1000) + PRESIGNED_URL_TTL_SECONDS + 60;
  await ddb.send(
    new PutCommand({
      TableName: UPLOADS_TABLE_NAME,
      Item: {
        upload_session: uploadSession,
        subject_did: p.subject_did,
        asset_id: assetId,
        s3_key: s3Key,
        media_type: p.media_type,
        size_bytes: p.size_bytes,
        content_length_on_disk: contentLength,
        sha256_of_plaintext: p.sha256_of_plaintext.toLowerCase(),
        encrypted,
        regime,
        forward_secrecy: p.forward_secrecy ?? "best_effort",
        amk_envelope: encrypted ? p.amk_envelope ?? null : null,
        encryption_nonce: encrypted ? p.encryption_nonce ?? null : null,
        attached_context: p.attached_context ?? null,
        authored_by_envelope_nonce: caller.envelopeNonce,
        authored_by_pubkey: caller.signerPubkeyMultibase,
        created_at: new Date().toISOString(),
        expires_at_epoch: ttlSeconds,
      },
    }),
  );

  // Emit gamma: assets.upload_initiated
  await appendGammaEntry({
    subject: p.subject_did,
    op: "assets.upload_initiated",
    payload: {
      urn,
      media_type: p.media_type,
      size_bytes: p.size_bytes,
      sha256_of_plaintext: p.sha256_of_plaintext.toLowerCase(),
      attached_context: p.attached_context ?? null,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  return {
    result: "upload",
    urn,
    asset_id: assetId,
    upload_session: uploadSession,
    upload_url: presigned.url,
    upload_url_expires_at: presigned.expiresAt,
    upload_constraints: {
      max_bytes: PER_ASSET_CAP_BYTES,
      expected_sha256: p.sha256_of_plaintext.toLowerCase(),
      expected_size_bytes: p.size_bytes,
      content_length_on_disk: contentLength,
    },
  };
}

/* -------------------------------------------------------------------------- */
/*  complete_upload                                                            */
/* -------------------------------------------------------------------------- */

interface CompleteUploadParams {
  upload_session: string;
  observed_sha256_of_plaintext?: string;
  /**
   * Optional final AMK envelope sent by the SDK on `complete_upload`.
   *
   * Rationale: at `init_upload` time the client doesn't yet know the
   * server-allocated URN, and the AMK wraps are AAD-bound to the URN.
   * So the client sends a placeholder envelope at init (empty `wraps`,
   * empty `nonce`) and the real envelope here once the URN is known.
   *
   * The handler prefers this field over `pending.amk_envelope` whenever
   * a non-empty `wraps[]` is supplied. Public uploads (encrypted=false)
   * ignore the field entirely; nothing is ever stored.
   *
   * Shape validation is intentionally light at this layer — full
   * envelope schema is enforced server-side by the SDK contract and
   * client-side by the `decryptAssetBytes` AAD check at read time.
   */
  amk_envelope?: unknown;
}

export async function completeUploadHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<CompleteUploadParams>;
  if (typeof p.upload_session !== "string" || !p.upload_session) {
    throw invalidParams("upload_session is required");
  }

  // Load pending upload
  const r = await ddb.send(
    new GetCommand({
      TableName: UPLOADS_TABLE_NAME,
      Key: { upload_session: p.upload_session },
    }),
  );
  const pending = r.Item as PendingUpload | undefined;
  if (!pending) {
    throw uploadNotFound(p.upload_session);
  }
  if (pending.subject_did !== caller.subjectDid) {
    // The complete_upload caller MUST be the same identity as init.
    throw uploadNotFound(p.upload_session);
  }

  // Verify the bytes are actually in S3.
  const head = await headObject(pending.s3_key);
  if (!head) {
    throw uploadNotFound(p.upload_session);
  }
  if (head.contentLength !== pending.content_length_on_disk) {
    throw sizeMismatch(pending.content_length_on_disk, head.contentLength);
  }

  // Optional client-side double-check on the plaintext SHA-256.
  // We cannot recompute it server-side because (a) private assets are
  // encrypted, (b) public assets are arbitrary bytes the client knows
  // the hash of from upload-init declaration.
  if (
    typeof p.observed_sha256_of_plaintext === "string" &&
    p.observed_sha256_of_plaintext.toLowerCase() !== pending.sha256_of_plaintext
  ) {
    throw hashMismatch(
      pending.sha256_of_plaintext,
      p.observed_sha256_of_plaintext,
    );
  }

  // Reserve quota (atomic). Throws AITHOS_ASSETS_QUOTA_EXCEEDED on overrun.
  await reserveQuota(pending.subject_did, pending.size_bytes);

  // Materialize the asset metadata document.
  const urn = urnForAsset(pending.subject_did, pending.asset_id);
  const now = new Date().toISOString();

  // Pick the AMK envelope to persist. The SDK sends a placeholder at
  // init_upload (empty `wraps[]`, empty `nonce`) because the AMK wraps
  // are AAD-bound to the URN, which isn't known until the server
  // allocates the asset_id. On complete_upload the SDK sends the real
  // envelope. We prefer the complete-time envelope whenever it carries
  // a non-empty `wraps[]`; otherwise we keep what was sent at init.
  const finalEnvelope = pending.encrypted
    ? pickEnvelope(p.amk_envelope, pending.amk_envelope)
    : undefined;

  const assetItem = {
    pk: pkForSubject(pending.subject_did),
    sk: skForAsset(pending.asset_id),
    // Sparse GSI1 — only populated for ACTIVE assets to enable dedup.
    gsi1pk: gsi1pkForSubject(pending.subject_did),
    gsi1sk: gsi1skForSha(pending.sha256_of_plaintext),
    "aithos-assets": PROTOCOL_VERSION,
    urn,
    subject_did: pending.subject_did,
    asset_id: pending.asset_id,
    media_type: pending.media_type,
    size_bytes: pending.size_bytes,
    sha256_of_plaintext: pending.sha256_of_plaintext,
    encrypted: pending.encrypted,
    amk_envelope: finalEnvelope,
    storage: {
      backend: "s3" as const,
      key: pending.s3_key,
    },
    attached_context: pending.attached_context ?? undefined,
    forward_secrecy: pending.forward_secrecy,
    referenced_by: [],
    state: "ACTIVE",
    created_at: now,
    modified_at: now,
  };

  // Emit gamma: assets.created (includes gamma_ref → set onto the metadata).
  const gammaEntry = await appendGammaEntry({
    subject: pending.subject_did,
    op: "assets.created",
    payload: {
      urn,
      media_type: pending.media_type,
      size_bytes: pending.size_bytes,
      sha256_of_plaintext: pending.sha256_of_plaintext,
      encrypted: pending.encrypted,
      recipients_count: Array.isArray(
        (finalEnvelope as { wraps?: unknown[] } | undefined)?.wraps,
      )
        ? (finalEnvelope as { wraps: unknown[] }).wraps.length
        : 0,
      attached_context: pending.attached_context ?? null,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  // Final asset item with gamma_ref
  const finalItem = { ...assetItem, gamma_ref: gammaEntry.id };
  await ddb.send(
    new PutCommand({
      TableName: ASSETS_TABLE_NAME,
      Item: finalItem,
      // ConditionExpression: keep idempotency on re-call
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }),
  );

  // Clean up the pending-upload session
  await ddb.send(
    new DeleteCommand({
      TableName: UPLOADS_TABLE_NAME,
      Key: { upload_session: p.upload_session },
    }),
  );

  // Compose the public URL for convenience (only used for public regime).
  const publicUrl =
    pending.regime === "public"
      ? publicAssetUrl(pending.subject_did, pending.asset_id)
      : undefined;

  return {
    urn,
    asset: { ...stripDdbKeys(finalItem), public_url: publicUrl },
  };
}

/* -------------------------------------------------------------------------- */
/*  abort_upload                                                               */
/* -------------------------------------------------------------------------- */

interface AbortUploadParams {
  upload_session: string;
}

export async function abortUploadHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<AbortUploadParams>;
  if (typeof p.upload_session !== "string" || !p.upload_session) {
    throw invalidParams("upload_session is required");
  }

  const r = await ddb.send(
    new GetCommand({
      TableName: UPLOADS_TABLE_NAME,
      Key: { upload_session: p.upload_session },
    }),
  );
  const pending = r.Item as PendingUpload | undefined;
  if (!pending) {
    // Idempotent abort — already gone is success.
    return { aborted: false };
  }
  if (pending.subject_did !== caller.subjectDid) {
    return { aborted: false };
  }

  // Best-effort delete of any partial S3 object.
  try {
    await deleteObject(pending.s3_key);
  } catch (e) {
    // Object may not exist (client never PUT). Swallow.
    console.warn("abort_upload: S3 deleteObject failed", { e });
  }

  await ddb.send(
    new DeleteCommand({
      TableName: UPLOADS_TABLE_NAME,
      Key: { upload_session: p.upload_session },
    }),
  );

  await appendGammaEntry({
    subject: pending.subject_did,
    op: "assets.upload_aborted",
    payload: {
      urn: urnForAsset(pending.subject_did, pending.asset_id),
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  return { aborted: true };
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

interface PendingUpload {
  upload_session: string;
  subject_did: string;
  asset_id: string;
  s3_key: string;
  media_type: string;
  size_bytes: number;
  content_length_on_disk: number;
  sha256_of_plaintext: string;
  encrypted: boolean;
  regime: "public" | "private";
  forward_secrecy: "best_effort" | "strict";
  amk_envelope: unknown;
  encryption_nonce: string | null;
  attached_context: unknown;
  authored_by_envelope_nonce: string;
  authored_by_pubkey: string;
  created_at: string;
  expires_at_epoch: number;
}

/**
 * Resolve the upload regime (public/private) from the inputs.
 *
 * Rules:
 *   - regime=auto + attached_context.kind="ethos" + zone="public" → public
 *   - regime=auto + anything else → private
 *   - regime=public → public
 *   - regime=private → private (an explicit AMK envelope MUST be present)
 */
function resolveRegime(
  p: Partial<InitUploadParams>,
): "public" | "private" {
  if (p.regime === "public") return "public";
  if (p.regime === "private") return "private";
  // auto
  if (
    p.attached_context?.kind === "ethos" &&
    p.attached_context.zone === "public"
  ) {
    return "public";
  }
  return "private";
}

async function dedupProbe(
  subjectDid: string,
  sha256Hex: string,
): Promise<{ asset_id: string; urn: string } | null> {
  const r = await ddb.send(
    new QueryCommand({
      TableName: ASSETS_TABLE_NAME,
      IndexName: "gsi1_by_subject_sha",
      KeyConditionExpression: "gsi1pk = :pk AND gsi1sk = :sk",
      ExpressionAttributeValues: {
        ":pk": gsi1pkForSubject(subjectDid),
        ":sk": gsi1skForSha(sha256Hex),
      },
      Limit: 1,
    }),
  );
  if (!r.Items || r.Items.length === 0) return null;
  const item = r.Items[0] as { asset_id?: string; urn?: string };
  if (!item.asset_id || !item.urn) return null;
  return { asset_id: item.asset_id, urn: item.urn };
}

function stripDdbKeys(item: Record<string, unknown>): Record<string, unknown> {
  const { pk, sk, gsi1pk, gsi1sk, gsi2pk, gsi2sk, ...rest } = item;
  void pk;
  void sk;
  void gsi1pk;
  void gsi1sk;
  void gsi2pk;
  void gsi2sk;
  return rest;
}

/**
 * Pick the AMK envelope to persist on `complete_upload`.
 *
 * Returns the complete-time envelope when it carries a non-empty
 * `wraps[]` array (the SDK only ships a real envelope on complete —
 * init carries a placeholder), otherwise falls back to the
 * init-time envelope, otherwise undefined.
 *
 * Validation is intentionally minimal: we check shape (object with
 * `wraps` array) only. Deep schema validation belongs to the SDK
 * contract; bytes-level integrity is enforced by AEAD/AAD at read.
 *
 * Exported for unit testing — the handler is the only production
 * caller.
 */
export function pickEnvelope(
  fromComplete: unknown,
  fromInit: unknown,
): unknown {
  const completeHasWraps = hasNonEmptyWraps(fromComplete);
  if (completeHasWraps) return fromComplete;
  if (fromInit !== null && fromInit !== undefined) return fromInit;
  return undefined;
}

function hasNonEmptyWraps(env: unknown): boolean {
  if (!env || typeof env !== "object") return false;
  const wraps = (env as { wraps?: unknown }).wraps;
  return Array.isArray(wraps) && wraps.length > 0;
}
