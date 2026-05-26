// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Reference-lifecycle handlers:
 *   - aithos.assets.ref_asset
 *   - aithos.assets.unref_asset
 *
 * Spec ref: spec/assets/05-api-primitives.md §5.4.4, §5.4.5.
 *
 * Both operations are idempotent on the (kind, sub-id) tuple.
 * The handler also moves the asset to ORPHANED / back to ACTIVE based
 * on the resulting reference count.
 */

import { GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

import { ddb, ASSETS_TABLE_NAME } from "../deps.js";
import {
  pkForSubject,
  skForAsset,
  parseAssetUrn,
} from "../ddb.js";
import { invalidParams, notFound } from "../errors.js";
import { appendGammaEntry } from "../gamma/store.js";
import type { Caller } from "../auth/envelope.js";

/* -------------------------------------------------------------------------- */
/*  ref_asset                                                                  */
/* -------------------------------------------------------------------------- */

interface RefAssetParams {
  urn: string;
  reference: AssetReferenceInput;
}

type AssetReferenceInput =
  | {
      kind: "ethos.section";
      ethos_edition_urn: string;
      zone: "public" | "circle" | "self";
      section_id: string;
      since_height: number;
    }
  | {
      kind: "data.record";
      data_record_urn: string;
      field: string;
    };

export async function refAssetHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<RefAssetParams>;
  if (typeof p.urn !== "string" || !p.urn) throw invalidParams("urn is required");
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");
  if (!p.reference || typeof p.reference !== "object") {
    throw invalidParams("reference is required");
  }
  // v0.1 owner-only
  if (parsed.subjectDid !== caller.subjectDid) throw notFound();

  validateReference(p.reference);

  // Load to compute idempotency + current ref count
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
        referenced_by?: AssetReferenceInput[];
        state?: string;
        last_referenced_at?: string;
      }
    | undefined;
  if (!item) throw notFound();

  const existing = item.referenced_by ?? [];
  const isDup = existing.some((e) => sameReference(e, p.reference!));

  // Build the new state
  const nowIso = new Date().toISOString();
  let nextRefs: AssetReferenceInput[];
  let stateNext = item.state ?? "ACTIVE";
  if (isDup) {
    // Idempotent: don't grow the array but still bump modified_at
    nextRefs = existing;
  } else {
    nextRefs = [
      ...existing,
      withSince(p.reference, nowIso) as AssetReferenceInput,
    ];
    stateNext = "ACTIVE"; // a new reference always activates the asset
  }

  const gammaEntry = await appendGammaEntry({
    subject: parsed.subjectDid,
    op: "assets.referenced",
    payload: {
      urn: p.urn,
      reference: p.reference,
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
        "SET referenced_by = :rb, modified_at = :now, last_referenced_at = :now, #state = :state, gamma_ref = :gr",
      ExpressionAttributeNames: { "#state": "state" },
      ExpressionAttributeValues: {
        ":rb": nextRefs,
        ":now": nowIso,
        ":state": stateNext,
        ":gr": gammaEntry.id,
      },
    }),
  );

  return {
    urn: p.urn,
    reference_count: nextRefs.length,
    gamma_ref: gammaEntry.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  unref_asset                                                                */
/* -------------------------------------------------------------------------- */

export async function unrefAssetHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<RefAssetParams>;
  if (typeof p.urn !== "string" || !p.urn) throw invalidParams("urn is required");
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");
  if (!p.reference || typeof p.reference !== "object") {
    throw invalidParams("reference is required");
  }
  if (parsed.subjectDid !== caller.subjectDid) throw notFound();

  validateReference(p.reference);

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
        referenced_by?: AssetReferenceInput[];
        state?: string;
      }
    | undefined;
  if (!item) throw notFound();

  const existing = item.referenced_by ?? [];
  const nextRefs = existing.filter(
    (e) => !sameReference(e, p.reference!),
  );

  const nowIso = new Date().toISOString();
  const stateNext = nextRefs.length === 0 ? "ORPHANED" : "ACTIVE";

  const gammaEntry = await appendGammaEntry({
    subject: parsed.subjectDid,
    op: "assets.unreferenced",
    payload: {
      urn: p.urn,
      reference: p.reference,
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
        "SET referenced_by = :rb, modified_at = :now, #state = :state, gamma_ref = :gr",
      ExpressionAttributeNames: { "#state": "state" },
      ExpressionAttributeValues: {
        ":rb": nextRefs,
        ":now": nowIso,
        ":state": stateNext,
        ":gr": gammaEntry.id,
      },
    }),
  );

  // Emit assets.orphaned if we just dropped to 0
  if (nextRefs.length === 0 && (item.state ?? "ACTIVE") !== "ORPHANED") {
    await appendGammaEntry({
      subject: parsed.subjectDid,
      op: "assets.orphaned",
      payload: { urn: p.urn },
      authoredByEnvelopeNonce: caller.envelopeNonce,
      authoredByPubkey: caller.signerPubkeyMultibase,
    });
  }

  return {
    urn: p.urn,
    reference_count: nextRefs.length,
    gamma_ref: gammaEntry.id,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function validateReference(ref: AssetReferenceInput): void {
  if (ref.kind === "ethos.section") {
    if (typeof ref.ethos_edition_urn !== "string") {
      throw invalidParams("reference.ethos_edition_urn required");
    }
    if (
      ref.zone !== "public" &&
      ref.zone !== "circle" &&
      ref.zone !== "self"
    ) {
      throw invalidParams("reference.zone must be public/circle/self");
    }
    if (typeof ref.section_id !== "string") {
      throw invalidParams("reference.section_id required");
    }
    if (typeof ref.since_height !== "number") {
      throw invalidParams("reference.since_height required");
    }
  } else if (ref.kind === "data.record") {
    if (typeof ref.data_record_urn !== "string") {
      throw invalidParams("reference.data_record_urn required");
    }
    if (typeof ref.field !== "string") {
      throw invalidParams("reference.field required");
    }
  } else {
    throw invalidParams("reference.kind must be ethos.section or data.record");
  }
}

function sameReference(
  a: AssetReferenceInput,
  b: AssetReferenceInput,
): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "ethos.section" && b.kind === "ethos.section") {
    return (
      a.ethos_edition_urn === b.ethos_edition_urn &&
      a.zone === b.zone &&
      a.section_id === b.section_id
    );
  }
  if (a.kind === "data.record" && b.kind === "data.record") {
    return (
      a.data_record_urn === b.data_record_urn && a.field === b.field
    );
  }
  return false;
}

function withSince(
  ref: AssetReferenceInput,
  nowIso: string,
): AssetReferenceInput & { since?: string } {
  if (ref.kind === "data.record") {
    return { ...ref, since: nowIso };
  }
  return ref;
}
