// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * DynamoDB key helpers for the assets PDS single-table design.
 *
 * Table `aithos-assets-pds-dev`:
 *
 *   ("subj#<did>", "asset#<asset_id>")          → asset metadata document
 *   GSI1 ("subj#<did>", "sha256#<hex>")          → dedup probe entry
 *     (sparse, only present for ACTIVE assets)
 *   GSI2 ("purge#<shard>", "lra#<iso>#<asset_id>") → purge scheduler shard
 *     (reserved for v0.2 — populated but not queried in v0.1)
 *
 * Table `aithos-assets-pds-uploads-dev`:
 *
 *   ("upload_session_id")                        → pending upload metadata
 *
 * Table `aithos-assets-pds-nonces-dev`:
 *
 *   ("<iss>#<nonce>")                            → replay-cache entry, TTL
 *
 * Table `aithos-assets-pds-gamma-dev`:
 *
 *   ("subject_did", "entry_id")                  → gamma log entry
 */

/* -------------------------------------------------------------------------- */
/*  Assets table keys                                                         */
/* -------------------------------------------------------------------------- */

export function pkForSubject(subjectDid: string): string {
  return `subj#${subjectDid}`;
}

export function skForAsset(assetId: string): string {
  return `asset#${assetId}`;
}

export function gsi1pkForSubject(subjectDid: string): string {
  // Same partition as the primary table — single-tenant query (a subject's dedup index).
  return `subj#${subjectDid}`;
}

export function gsi1skForSha(sha256Hex: string): string {
  return `sha256#${sha256Hex.toLowerCase()}`;
}

/* -------------------------------------------------------------------------- */
/*  Purge GSI (reserved for v0.2)                                             */
/* -------------------------------------------------------------------------- */

/** Number of purge shards. Spreads the GSI2 partition write load. */
const PURGE_SHARD_COUNT = 8;

export function gsi2pkForPurge(assetId: string): string {
  // Deterministic shard from asset_id (last hex char of ULID).
  const lastChar = assetId.charCodeAt(assetId.length - 1);
  const shard = lastChar % PURGE_SHARD_COUNT;
  return `purge#${shard}`;
}

export function gsi2skForLastReferencedAt(
  lastReferencedAtIso: string,
  assetId: string,
): string {
  return `lra#${lastReferencedAtIso}#${assetId}`;
}

/* -------------------------------------------------------------------------- */
/*  Asset URN composition                                                      */
/* -------------------------------------------------------------------------- */

export function urnForAsset(subjectDid: string, assetId: string): string {
  return `urn:aithos:asset:${subjectDid}:${assetId}`;
}

/**
 * Parse an asset URN into `(subject_did, asset_id)` components.
 * Returns null on malformed URN. Lenient: subject_did may contain
 * colons (it's a DID like did:aithos:z6Mkr…), so we split on the LAST
 * colon to recover asset_id.
 */
export function parseAssetUrn(
  urn: string,
): { subjectDid: string; assetId: string } | null {
  const PREFIX = "urn:aithos:asset:";
  if (!urn.startsWith(PREFIX)) return null;
  const rest = urn.substring(PREFIX.length);
  const lastColon = rest.lastIndexOf(":");
  if (lastColon < 0) return null;
  return {
    subjectDid: rest.substring(0, lastColon),
    assetId: rest.substring(lastColon + 1),
  };
}

/* -------------------------------------------------------------------------- */
/*  S3 object key                                                              */
/* -------------------------------------------------------------------------- */

/**
 * S3 key for an asset's bytes:
 *   `<subject_did>/<asset_id>/raw.bin`
 */
export function s3KeyForAsset(subjectDid: string, assetId: string): string {
  return `${subjectDid}/${assetId}/raw.bin`;
}
