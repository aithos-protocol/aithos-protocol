// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handlers for authorization-level primitives:
 *   - aithos.data.authorize_app      (§5.4.5)
 *   - aithos.data.revoke_app         (§5.4.6)
 *   - aithos.data.rotate_cmk         (§5.4.7)
 *
 * These primitives manipulate the CMK envelope on a collection. The
 * cryptographic work (wrap, unwrap, re-wrap) happens entirely
 * client-side per the protocol's "platform never sees the CMK in
 * clear" invariant; the handlers here only validate and persist.
 *
 * Owner-only in v0.1: only the subject who created the collection
 * may add/remove recipients or rotate the CMK. Sub-delegation
 * (`data.<col>.admin` scope) is deferred to a future version.
 */

import {
  GetCommand,
  UpdateCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";

import { verifyMandate, type Mandate } from "@aithos/protocol-core/mandate";

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
  requireSubjectMatch,
  type Caller,
} from "../auth/authenticate.js";
import { resolveIssuerDoc } from "../auth/did-resolver.js";
import { recordRevocation } from "../auth/revocations.js";
import { parseCollectionUrn } from "./records.js";
import { validateRequired } from "./collections.js";
import { appendGammaEntry } from "../gamma/store.js";
import { hashJson } from "../gamma/hash-util.js";

/* -------------------------------------------------------------------------- */
/*  authorize_app                                                             */
/* -------------------------------------------------------------------------- */

interface AuthorizeAppParams {
  collection_urn?: string;
  /** The full signed mandate document granting access to the new grantee. */
  mandate?: Mandate;
  /** The CMK wrap addressed to the new grantee's X25519 key. */
  wrap?: {
    recipient: string;
    alg: string;
    ephemeral_public: string;
    wrap_nonce: string;
    wrapped_key: string;
  };
}

export async function authorizeAppHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as AuthorizeAppParams;
  validateRequired(p, ["collection_urn", "mandate", "wrap"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  if (caller.mode !== "owner") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: authorize_app is owner-only in v0.1; sub-delegation via data.<col>.admin is deferred",
    );
  }

  const mandate = p.mandate!;

  // 1. Mandate issuer must match the calling subject.
  if (mandate.issuer !== subjectDid) {
    throw new RpcError(
      -32040,
      `AITHOS_MANDATE_INVALID: mandate.issuer (${mandate.issuer}) does not match caller subject (${subjectDid})`,
    );
  }

  // 2. Mandate signature + window + structure.
  // Use the enriched resolver from caller (HOTFIX-A2a-RESOLVER) so that
  // mandates signed by a non-root sphere (e.g. #circle for custodial
  // did:aithos users) verify correctly when the caller passed
  // `_subject_sphere_pubkeys` in params.
  const issuerDoc = await caller.resolveIssuerDoc(subjectDid);
  if (!issuerDoc) {
    throw new RpcError(
      -32011,
      `cannot resolve DID document for subject ${subjectDid}`,
    );
  }
  const check = verifyMandate(mandate, issuerDoc, new Date());
  if (!check.ok) {
    throw new RpcError(
      -32040,
      `AITHOS_MANDATE_INVALID: ${check.errors.join("; ")}`,
      { errors: check.errors },
    );
  }

  // 3. Mandate must carry at least one data.<col>.<action> scope for
  //    this collection — otherwise the wrap serves no purpose.
  const matchesCol = mandate.scopes.some((s) => {
    const parts = s.split(".");
    if (parts[0] !== "data") return false;
    return parts[1] === collectionName || parts[1] === "*";
  });
  if (!matchesCol) {
    throw new RpcError(
      -32042,
      `AITHOS_INSUFFICIENT_SCOPE: mandate does not carry any data.${collectionName}.* scope`,
      { scopes: mandate.scopes },
    );
  }

  // 4. Wrap recipient must match the mandate's grantee key.
  if (!mandate.grantee.pubkey) {
    throw new RpcError(
      -32040,
      "AITHOS_MANDATE_INVALID: mandate.grantee.pubkey is required for data mandates that include read scope",
    );
  }
  // The wrap.recipient is a DID URL like `did:key:z6Mk...#kex` or
  // a multibase string. We accept either form and only require that
  // the substring containing the mandate's grantee pubkey is present.
  if (!p.wrap!.recipient.includes(mandate.grantee.pubkey)) {
    throw new RpcError(
      -32079,
      `AITHOS_DATA_WRAP_RECIPIENT_MISMATCH: wrap.recipient does not contain mandate.grantee.pubkey`,
      { wrapRecipient: p.wrap!.recipient, granteePubkey: mandate.grantee.pubkey },
    );
  }

  // 5. Fetch the collection — must exist and not already have this recipient.
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
  const existingEnvelope = col.Item.cmk_envelope as {
    alg: string;
    wraps: Array<{ recipient: string }>;
  };
  const wraps = existingEnvelope.wraps ?? [];
  if (wraps.some((w) => w.recipient === p.wrap!.recipient)) {
    throw new RpcError(
      -32073,
      `AITHOS_DATA_RECIPIENT_DUPLICATE: recipient ${p.wrap!.recipient} already authorized on this collection`,
    );
  }

  // 6. Append the wrap. Stored as an indexable mandate registry entry too.
  const now = new Date().toISOString();
  const newWraps = [...wraps, p.wrap!];

  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: colKey,
      UpdateExpression:
        "SET cmk_envelope = :env, modified_at = :now, mandate_index.#mid = :midItem",
      ExpressionAttributeNames: { "#mid": mandate.id },
      ExpressionAttributeValues: {
        ":env": { alg: existingEnvelope.alg, wraps: newWraps },
        ":now": now,
        ":midItem": {
          mandate_id: mandate.id,
          grantee_pubkey: mandate.grantee.pubkey,
          scopes: mandate.scopes,
          not_before: mandate.not_before,
          not_after: mandate.not_after,
          authorized_at: now,
        },
      },
    }),
  ).catch(async (err) => {
    // The mandate_index attribute may not exist yet on the collection
    // item if this is the first authorize_app. Fall back to creating
    // it with a fresh map.
    if ((err as { name?: string }).name === "ValidationException") {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: colKey,
          UpdateExpression:
            "SET cmk_envelope = :env, modified_at = :now, mandate_index = :mi",
          ExpressionAttributeValues: {
            ":env": { alg: existingEnvelope.alg, wraps: newWraps },
            ":now": now,
            ":mi": {
              [mandate.id]: {
                mandate_id: mandate.id,
                grantee_pubkey: mandate.grantee.pubkey,
                scopes: mandate.scopes,
                not_before: mandate.not_before,
                not_after: mandate.not_after,
                authorized_at: now,
              },
            },
          },
        }),
      );
    } else {
      throw err;
    }
  });

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.collection.authorize_grantee",
    payload: {
      collection_urn: p.collection_urn,
      mandate_id: mandate.id,
      grantee_did_url: p.wrap!.recipient,
      grantee_pubkey: mandate.grantee.pubkey,
      scopes: mandate.scopes,
      not_before: mandate.not_before,
      not_after: mandate.not_after,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  return {
    wrap_index: newWraps.length - 1,
    mandate_id: mandate.id,
    authorized_at: now,
    gamma_ref: gamma.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  revoke_app                                                                */
/* -------------------------------------------------------------------------- */

interface RevokeAppParams {
  collection_urn?: string;
  mandate_id?: string;
  /** Optional signed revocation document. */
  revocation?: { revoked_at?: string; reason?: string; signature?: unknown };
  /** When true, rotate CMK + accept re-wrapped DEKs. Default false. */
  rotate_cmk?: boolean;
  /** When rotate_cmk:true, the new CMK envelope. */
  new_cmk_envelope?: { alg: string; wraps: Array<unknown> };
  /** When rotate_cmk:true, the per-record re-wrapped DEKs. */
  re_wrapped_deks?: Array<{
    record_id: string;
    dek_wrapped_for_cmk: string;
  }>;
}

export async function revokeAppHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as RevokeAppParams;
  validateRequired(p, ["collection_urn", "mandate_id"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  if (caller.mode !== "owner") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: revoke_app is owner-only in v0.1",
    );
  }

  // Fetch the collection — must exist and have a mandate entry to revoke.
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
  const mandateIndex = (col.Item.mandate_index ?? {}) as Record<string, {
    grantee_pubkey: string;
  }>;
  const mandateEntry = mandateIndex[p.mandate_id!];

  // An append-only mandate (`data.<col>.append`) is never run through
  // authorize_app — it carries no CMK wrap (the depositor seals each DEK to
  // the owner's pubkey instead). So a missing mandate_index entry is NOT an
  // error here: we still publish the revocation so the PDS rejects future
  // envelopes signed under that mandate. Only when an entry exists do we have
  // a wrap to strip. Revoking is owner-only + subject-matched (checked above),
  // so recording a revocation for an owner-named mandate id is safe.
  const existingEnvelope = col.Item.cmk_envelope as {
    alg: string;
    wraps: Array<{ recipient: string }>;
  };
  const filteredWraps = mandateEntry
    ? (existingEnvelope.wraps ?? []).filter(
        (w) => !w.recipient.includes(mandateEntry.grantee_pubkey),
      )
    : (existingEnvelope.wraps ?? []);

  const now = new Date().toISOString();

  // 2. Optional CMK rotation
  let newEnvelope: { alg: string; wraps: Array<unknown> };
  if (p.rotate_cmk) {
    if (!p.new_cmk_envelope) {
      throw new RpcError(
        -32602,
        "invalid params: new_cmk_envelope is required when rotate_cmk: true",
      );
    }
    newEnvelope = p.new_cmk_envelope;
    // Apply per-record re-wrapped DEKs if provided
    if (p.re_wrapped_deks && p.re_wrapped_deks.length > 0) {
      for (const r of p.re_wrapped_deks) {
        const recKey = {
          pk: pkForSubject(subjectDid),
          sk: skForRecord(collectionName, r.record_id),
        };
        await ddb.send(
          new UpdateCommand({
            TableName: TABLE_NAME,
            Key: recKey,
            UpdateExpression:
              "SET payload.dek_wrapped_for_cmk = :w, modified_at = :now, gsi1sk = :gsi",
            ExpressionAttributeValues: {
              ":w": r.dek_wrapped_for_cmk,
              ":now": now,
              ":gsi": gsi1skForRecord(now, r.record_id),
            },
          }),
        );
      }
    }
  } else {
    newEnvelope = { alg: existingEnvelope.alg, wraps: filteredWraps };
  }

  // 3. Persist collection update + remove mandate from index
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: colKey,
      UpdateExpression:
        "SET cmk_envelope = :env, modified_at = :now REMOVE mandate_index.#mid",
      ExpressionAttributeNames: { "#mid": p.mandate_id! },
      ExpressionAttributeValues: {
        ":env": newEnvelope,
        ":now": now,
      },
    }),
  );

  // 4. Record the revocation so future envelope verifications reject this mandate
  await recordRevocation({
    mandate_id: p.mandate_id!,
    issuer: subjectDid,
    revoked_at: p.revocation?.revoked_at ?? now,
    ...(p.revocation?.reason ? { reason: p.revocation.reason } : {}),
    ...(p.revocation ? { revocation_doc: p.revocation } : {}),
  });

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.collection.revoke_grantee",
    payload: {
      collection_urn: p.collection_urn,
      mandate_id: p.mandate_id,
      revoked_at: now,
      rotated_cmk: p.rotate_cmk === true,
      ...(p.revocation?.reason ? { reason: p.revocation.reason } : {}),
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  return {
    mandate_id: p.mandate_id,
    revoked_at: now,
    rotated_cmk: p.rotate_cmk === true,
    gamma_ref: gamma.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  rotate_cmk                                                                */
/* -------------------------------------------------------------------------- */

interface RotateCMKParams {
  collection_urn?: string;
  new_cmk_envelope?: { alg: string; wraps: Array<unknown> };
  re_wrapped_deks?: Array<{
    record_id: string;
    dek_wrapped_for_cmk: string;
  }>;
}

export async function rotateCmkHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as RotateCMKParams;
  validateRequired(p, ["collection_urn", "new_cmk_envelope"]);

  const { subjectDid, collectionName } = parseCollectionUrn(p.collection_urn!);
  requireSubjectMatch(caller, subjectDid);
  if (caller.mode !== "owner") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: rotate_cmk is owner-only in v0.1",
    );
  }

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

  // Apply re-wrapped DEKs
  if (p.re_wrapped_deks && p.re_wrapped_deks.length > 0) {
    for (const r of p.re_wrapped_deks) {
      const recKey = {
        pk: pkForSubject(subjectDid),
        sk: skForRecord(collectionName, r.record_id),
      };
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: recKey,
          UpdateExpression:
            "SET payload.dek_wrapped_for_cmk = :w, modified_at = :now",
          ExpressionAttributeValues: {
            ":w": r.dek_wrapped_for_cmk,
            ":now": now,
          },
        }),
      );
    }
  }

  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: colKey,
      UpdateExpression: "SET cmk_envelope = :env, modified_at = :now",
      ExpressionAttributeValues: {
        ":env": p.new_cmk_envelope,
        ":now": now,
      },
    }),
  );

  // Gamma audit entry
  const gamma = await appendGammaEntry({
    subject: subjectDid,
    op: "data.collection.rotate_cmk",
    payload: {
      collection_urn: p.collection_urn,
      reason: "manual",
      new_cmk_envelope_hash: hashJson(p.new_cmk_envelope),
      records_rewrapped: p.re_wrapped_deks?.length ?? 0,
    },
    authoredByEnvelopeNonce: caller.envelopeNonce,
    authoredByPubkey: caller.signerPubkeyMultibase,
  });

  return {
    rotated_at: now,
    records_rewrapped: p.re_wrapped_deks?.length ?? 0,
    gamma_ref: gamma.id,
  };
}

// Re-export PutCommand so the unused-import marker is satisfied even
// though we don't use it directly here. Keeps the import surface
// consistent across handlers/.
void PutCommand;
