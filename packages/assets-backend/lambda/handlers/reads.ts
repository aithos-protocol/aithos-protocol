// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Read-side handlers:
 *   - aithos.assets.get_asset
 *   - aithos.assets.head_asset
 *   - aithos.assets.list_assets
 *   - aithos.assets.list_references
 *   - aithos.assets.verify
 *   - aithos.assets.get_public_asset (anonymous)
 *   - aithos.assets.head_public_asset (anonymous)
 *
 * Spec ref: spec/assets/05-api-primitives.md §5.3.
 */

import {
  GetCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";

import { ddb, ASSETS_TABLE_NAME } from "../deps.js";
import {
  pkForSubject,
  skForAsset,
  parseAssetUrn,
  s3KeyForAsset,
} from "../ddb.js";
import {
  presignGet,
  headObject,
  publicAssetUrl,
} from "../s3-presign.js";
import {
  invalidParams,
  notFound,
  notPublic,
  tombstoned,
} from "../errors.js";
import type { Caller } from "../auth/envelope.js";

/* -------------------------------------------------------------------------- */
/*  get_asset                                                                  */
/* -------------------------------------------------------------------------- */

interface GetAssetParams {
  urn: string;
  url_ttl_seconds?: number;
}

export async function getAssetHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<GetAssetParams>;
  if (typeof p.urn !== "string" || !p.urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");

  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();

  // v0.1 — owner-only: enforce caller is the subject.
  if (item.subject_did !== caller.subjectDid) {
    throw notFound(); // intentionally indistinguishable from non-existence
  }

  if (item.state === "TOMBSTONED" || item.state === "GONE") {
    throw tombstoned();
  }

  // Construct the fetch URL — CloudFront for public, presigned S3 for private.
  let fetch_url: string;
  let fetch_url_expires_at: string | undefined;
  let fetch_url_kind: "s3_presigned" | "cloudfront_stable";

  if (item.encrypted) {
    const presigned = await presignGet({
      key: item.storage.key,
      ttlSeconds: p.url_ttl_seconds,
    });
    fetch_url = presigned.url;
    fetch_url_expires_at = presigned.expiresAt;
    fetch_url_kind = "s3_presigned";
  } else {
    fetch_url = publicAssetUrl(item.subject_did, item.asset_id);
    fetch_url_kind = "cloudfront_stable";
  }

  return {
    asset: stripDdbKeys(item),
    fetch_url,
    ...(fetch_url_expires_at ? { fetch_url_expires_at } : {}),
    fetch_url_kind,
  };
}

/* -------------------------------------------------------------------------- */
/*  head_asset                                                                 */
/* -------------------------------------------------------------------------- */

export async function headAssetHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<GetAssetParams>;
  if (typeof p.urn !== "string" || !p.urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");
  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();
  if (item.subject_did !== caller.subjectDid) throw notFound();
  return { asset: stripDdbKeys(item) };
}

/* -------------------------------------------------------------------------- */
/*  list_assets                                                                */
/* -------------------------------------------------------------------------- */

interface ListAssetsParams {
  subject_did: string;
  limit?: number;
  cursor?: string;
  order?: "newest" | "oldest";
  filter?: {
    media_type_prefix?: string;
    size_bytes?: { gte?: number; lte?: number };
    created_after?: string;
    created_before?: string;
    attached_to?: unknown;
    tags_any?: readonly string[];
  };
  include_orphaned?: boolean;
  include_tombstoned?: boolean;
}

export async function listAssetsHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<ListAssetsParams>;
  if (typeof p.subject_did !== "string" || !p.subject_did) {
    throw invalidParams("subject_did is required");
  }
  // owner-only v0.1
  if (p.subject_did !== caller.subjectDid) {
    throw notFound();
  }

  const limit = Math.min(Math.max(p.limit ?? 20, 1), 100);
  const order = p.order ?? "newest";

  const queryInput: {
    TableName: string;
    KeyConditionExpression: string;
    ExpressionAttributeValues: Record<string, unknown>;
    Limit: number;
    ScanIndexForward: boolean;
    ExclusiveStartKey?: Record<string, unknown>;
  } = {
    TableName: ASSETS_TABLE_NAME,
    KeyConditionExpression: "pk = :pk AND begins_with(sk, :sk_prefix)",
    ExpressionAttributeValues: {
      ":pk": pkForSubject(p.subject_did),
      ":sk_prefix": "asset#",
    },
    Limit: limit,
    ScanIndexForward: order === "oldest",
  };
  if (p.cursor) {
    try {
      queryInput.ExclusiveStartKey = JSON.parse(
        Buffer.from(p.cursor, "base64url").toString("utf8"),
      );
    } catch {
      throw invalidParams("invalid cursor");
    }
  }

  const r = await ddb.send(new QueryCommand(queryInput));
  let items = (r.Items ?? []) as AssetItem[];

  // Filter client-side (Dynamo can't filter on all the spec fields cheaply).
  items = items.filter((it) => matchesFilter(it, p));

  const nextCursor = r.LastEvaluatedKey
    ? Buffer.from(JSON.stringify(r.LastEvaluatedKey)).toString("base64url")
    : undefined;

  return {
    items: items.map((it) => ({
      urn: it.urn,
      asset_id: it.asset_id,
      media_type: it.media_type,
      size_bytes: it.size_bytes,
      sha256_of_plaintext: it.sha256_of_plaintext,
      encrypted: it.encrypted,
      created_at: it.created_at,
      modified_at: it.modified_at,
      reference_count: it.referenced_by?.length ?? 0,
      state: it.state ?? "ACTIVE",
    })),
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  };
}

/* -------------------------------------------------------------------------- */
/*  list_references                                                            */
/* -------------------------------------------------------------------------- */

interface ListReferencesParams {
  urn: string;
}

export async function listReferencesHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<ListReferencesParams>;
  if (typeof p.urn !== "string" || !p.urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");

  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();
  if (item.subject_did !== caller.subjectDid) throw notFound();

  return {
    items: item.referenced_by ?? [],
  };
}

/* -------------------------------------------------------------------------- */
/*  verify                                                                     */
/* -------------------------------------------------------------------------- */

interface VerifyParams {
  urn: string;
}

export async function verifyHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as Partial<VerifyParams>;
  if (typeof p.urn !== "string" || !p.urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(p.urn);
  if (!parsed) throw invalidParams("malformed asset URN");

  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();
  if (item.subject_did !== caller.subjectDid) throw notFound();

  const head = await headObject(item.storage.key);
  if (!head) {
    return {
      urn: item.urn,
      storage_present: false,
      ok: false,
      notes: "S3 object missing",
      metadata_sha256_of_plaintext: item.sha256_of_plaintext,
    };
  }

  return {
    urn: item.urn,
    storage_present: true,
    storage_size_bytes: head.contentLength,
    storage_sha256: "", // server cannot compute without download — left empty in v0.1
    metadata_sha256_of_plaintext: item.sha256_of_plaintext,
    ok: head.contentLength > 0,
    notes:
      head.contentLength > 0
        ? "object present; plaintext SHA verification is client-side"
        : "object exists but is empty",
  };
}

/* -------------------------------------------------------------------------- */
/*  Anonymous: get_public_asset / head_public_asset                            */
/* -------------------------------------------------------------------------- */

/**
 * Anonymous variants. Called with an empty Caller (router bypasses
 * envelope verification for these paths). The handler is here as a
 * sibling for code locality.
 */
export async function getPublicAssetHandler(
  rawParams: Record<string, unknown>,
): Promise<unknown> {
  const urn = rawParams.urn;
  if (typeof urn !== "string" || !urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(urn);
  if (!parsed) throw invalidParams("malformed asset URN");

  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();
  if (item.encrypted) throw notPublic();
  if (item.state === "TOMBSTONED" || item.state === "GONE") {
    throw tombstoned();
  }

  return {
    urn: item.urn,
    media_type: item.media_type,
    size_bytes: item.size_bytes,
    sha256_of_plaintext: item.sha256_of_plaintext,
    fetch_url: publicAssetUrl(item.subject_did, item.asset_id),
  };
}

export async function headPublicAssetHandler(
  rawParams: Record<string, unknown>,
): Promise<unknown> {
  const urn = rawParams.urn;
  if (typeof urn !== "string" || !urn) {
    throw invalidParams("urn is required");
  }
  const parsed = parseAssetUrn(urn);
  if (!parsed) throw invalidParams("malformed asset URN");

  const item = await fetchAssetItem(parsed.subjectDid, parsed.assetId);
  if (!item) throw notFound();
  if (item.encrypted) throw notPublic();

  return {
    urn: item.urn,
    media_type: item.media_type,
    size_bytes: item.size_bytes,
    sha256_of_plaintext: item.sha256_of_plaintext,
  };
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

interface AssetItem {
  pk: string;
  sk: string;
  urn: string;
  subject_did: string;
  asset_id: string;
  media_type: string;
  size_bytes: number;
  sha256_of_plaintext: string;
  encrypted: boolean;
  amk_envelope?: unknown;
  storage: { backend: "s3"; key: string };
  attached_context?: unknown;
  forward_secrecy: "best_effort" | "strict";
  referenced_by: unknown[];
  state?: "ACTIVE" | "ORPHANED" | "TOMBSTONED" | "GONE";
  created_at: string;
  modified_at: string;
  last_referenced_at?: string;
  gamma_ref: string;
}

async function fetchAssetItem(
  subjectDid: string,
  assetId: string,
): Promise<AssetItem | null> {
  const r = await ddb.send(
    new GetCommand({
      TableName: ASSETS_TABLE_NAME,
      Key: { pk: pkForSubject(subjectDid), sk: skForAsset(assetId) },
    }),
  );
  return (r.Item as AssetItem) ?? null;
}

function matchesFilter(
  item: AssetItem,
  params: Partial<ListAssetsParams>,
): boolean {
  // Default: exclude orphaned/tombstoned unless explicitly asked
  const state = item.state ?? "ACTIVE";
  if (state === "ORPHANED" && !params.include_orphaned) return false;
  if (state === "TOMBSTONED" && !params.include_tombstoned) return false;
  if (state === "GONE") return false;

  const f = params.filter;
  if (!f) return true;

  if (f.media_type_prefix && !item.media_type.startsWith(f.media_type_prefix)) {
    return false;
  }
  if (f.size_bytes?.gte !== undefined && item.size_bytes < f.size_bytes.gte) {
    return false;
  }
  if (f.size_bytes?.lte !== undefined && item.size_bytes > f.size_bytes.lte) {
    return false;
  }
  if (f.created_after && item.created_at <= f.created_after) return false;
  if (f.created_before && item.created_at >= f.created_before) return false;

  return true;
}

function stripDdbKeys(item: AssetItem): Record<string, unknown> {
  const { pk, sk, ...rest } = item as AssetItem & {
    gsi1pk?: string;
    gsi1sk?: string;
    gsi2pk?: string;
    gsi2sk?: string;
  };
  void pk;
  void sk;
  return rest;
}
