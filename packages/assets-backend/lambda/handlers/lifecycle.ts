// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Lifecycle handlers:
 *   - aithos.assets.delete_asset (force ACTIVE/ORPHANED → TOMBSTONED)
 *   - aithos.assets.rotate_owner_wrap (re-wrap AMK for new sphere key)
 *
 * Spec ref: spec/assets/05-api-primitives.md §5.4.6, §5.4.10.
 *
 * AMK rotation (`aithos.assets.rotate_amk`), authorize/revoke grantee,
 * and bulk-rotate-owner-wrap are spec'd but NOT IMPLEMENTED in v0.1.
 * They live in this module as stubs returning -32050 NotImplemented.
 */

import {
  DeleteCommand,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

import { ddb, ASSETS_TABLE_NAME } from "../deps.js";
import {
  pkForSubject,
  skForAsset,
  parseAssetUrn,
  urnForAsset,
} from "../ddb.js";
import { deleteObject } from "../s3-presign.js";
import { RpcError } from "../jsonrpc.js";
import {
  invalidParams,
  notFound,
  stillReferenced,
} from "../errors.js";
import { releaseQuota } from "../quota.js";
import { appendGammaEntry } from "../gamma/store.js";
import type { Caller } from "../auth/envelope.js";

/* -------------------------------------------------------------------------- */
/*  delete_asset                                                               */
/* -------------------------------------------------------------------------- */

interface DeleteAssetParams {
  urn: string;
}

export async function deleteAssetHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<DeleteAssetParams>;
  if (typeof p.urn !== "string" || !p.urn) throw invalidParams("urn is required");
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");
  if (parsed.subjectDid !== caller.subjectDid) throw notFound();

  const r = await ddb.send(
    new GetCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: {
        pk: pkForSubject(parsed.subjectDid),
        sk: skForAsset(parsed.assetId),
      },
    }),
  );
  const item = r.Item as
    | {
        referenced_by?: unknown[];
        size_bytes?: number;
        storage?: { key: string };
        state?: string;
      }
    | undefined;
  if (!item) throw notFound();

  if ((item.referenced_by?.length ?? 0) > 0) {
    throw stillReferenced(item.referenced_by!.length);
  }

  // Delete S3 object (best-effort).
  if (item.storage?.key) {
    try {
      await deleteObject(item.storage.key);
    } catch (e) {
      console.warn("delete_asset: S3 deleteObject failed", { e });
    }
  }

  // Release quota.
  await releaseQuota(parsed.subjectDid, item.size_bytes ?? 0);

  // Transition to TOMBSTONED — keep the metadata document with
  // state=TOMBSTONED + tombstoned_at, drop GSI keys (the sparse dedup
  // index should not return tombstoned items).
  const nowIso = new Date().toISOString();
  const gammaEntry = await appendGammaEntry({
    subject: parsed.subjectDid,
    op: "assets.tombstoned",
    payload: { urn: p.urn, reason: "explicit_delete" },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  await ddb.send(
    new UpdateCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: {
        pk: pkForSubject(parsed.subjectDid),
        sk: skForAsset(parsed.assetId),
      },
      UpdateExpression:
        "REMOVE gsi1pk, gsi1sk SET #state = :state, tombstoned_at = :now, modified_at = :now, gamma_ref = :gr",
      ExpressionAttributeNames: { "#state": "state" },
      ExpressionAttributeValues: {
        ":state": "TOMBSTONED",
        ":now": nowIso,
        ":gr": gammaEntry.id,
      },
    }),
  );

  return {
    urn: p.urn,
    tombstoned_at: nowIso,
    gamma_ref: gammaEntry.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  rotate_owner_wrap                                                          */
/* -------------------------------------------------------------------------- */

interface RotateOwnerWrapParams {
  urn: string;
  new_wrap: {
    recipient: string;
    alg: "x25519-hkdf-sha256-aead";
    ephemeral_public: string;
    wrap_nonce: string;
    wrapped_key: string;
  };
  old_wrap_recipient: string;
}

export async function rotateOwnerWrapHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<RotateOwnerWrapParams>;
  if (typeof p.urn !== "string" || !p.urn) throw invalidParams("urn is required");
  if (typeof p.old_wrap_recipient !== "string") {
    throw invalidParams("old_wrap_recipient is required");
  }
  if (!p.new_wrap || typeof p.new_wrap !== "object") {
    throw invalidParams("new_wrap is required");
  }
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");
  if (parsed.subjectDid !== caller.subjectDid) throw notFound();

  const r = await ddb.send(
    new GetCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: {
        pk: pkForSubject(parsed.subjectDid),
        sk: skForAsset(parsed.assetId),
      },
    }),
  );
  const item = r.Item as
    | {
        amk_envelope?: { wraps?: Array<{ recipient: string }> };
        encrypted?: boolean;
        state?: string;
      }
    | undefined;
  if (!item) throw notFound();
  if (!item.encrypted) {
    throw invalidParams("rotate_owner_wrap is for encrypted assets only");
  }
  if (item.state === "TOMBSTONED" || item.state === "GONE") throw notFound();

  const wraps = item.amk_envelope?.wraps ?? [];
  const filtered = wraps.filter((w) => w.recipient !== p.old_wrap_recipient);
  // Replace any existing wrap addressed to the new recipient too (idempotent)
  const newWraps = [
    ...filtered.filter((w) => w.recipient !== p.new_wrap!.recipient),
    p.new_wrap,
  ];

  const nowIso = new Date().toISOString();
  const gammaEntry = await appendGammaEntry({
    subject: parsed.subjectDid,
    op: "assets.rotate_owner_wrap",
    payload: {
      urn: p.urn,
      old_owner_recipient: p.old_wrap_recipient,
      new_owner_recipient: p.new_wrap.recipient,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  await ddb.send(
    new UpdateCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: {
        pk: pkForSubject(parsed.subjectDid),
        sk: skForAsset(parsed.assetId),
      },
      UpdateExpression:
        "SET amk_envelope.wraps = :wraps, modified_at = :now, gamma_ref = :gr",
      ExpressionAttributeValues: {
        ":wraps": newWraps,
        ":now": nowIso,
        ":gr": gammaEntry.id,
      },
    }),
  );

  return {
    urn: p.urn,
    gamma_ref: gammaEntry.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  Stubs for v0.2-bound primitives                                            */
/* -------------------------------------------------------------------------- */

const NOT_IMPLEMENTED = -32050;

export async function authorizeGranteeHandler(): Promise<unknown> {
  throw new RpcError(
    NOT_IMPLEMENTED,
    "aithos.assets.authorize_grantee — mandate-grantee auth lands in v0.2",
  );
}
export async function revokeGranteeHandler(): Promise<unknown> {
  throw new RpcError(
    NOT_IMPLEMENTED,
    "aithos.assets.revoke_grantee — mandate-grantee auth lands in v0.2",
  );
}
export async function rotateAmkHandler(): Promise<unknown> {
  throw new RpcError(
    NOT_IMPLEMENTED,
    "aithos.assets.rotate_amk — AMK rotation lands in v0.2",
  );
}
