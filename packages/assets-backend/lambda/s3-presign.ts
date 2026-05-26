// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * S3 presigned URL helpers.
 *
 * - Presigned PUT URLs for upload (init_upload flow).
 * - Presigned GET URLs for private asset fetch (get_asset flow).
 *
 * Spec ref: `spec/assets/05-api-primitives.md` §5.1, §5.4.1, §5.3.1.
 */

import {
  GetObjectCommand,
  PutObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import {
  s3,
  ASSETS_BUCKET_NAME,
  PRESIGNED_URL_TTL_SECONDS,
} from "./deps.js";

/* -------------------------------------------------------------------------- */
/*  Presigned PUT (upload)                                                    */
/* -------------------------------------------------------------------------- */

export interface PresignPutInput {
  /** Object key in S3 (e.g. "<did>/<asset_id>/raw.bin"). */
  readonly key: string;
  /** Declared content type to bind into the signed request. */
  readonly contentType: string;
  /** Maximum allowed Content-Length, enforced server-side by S3. */
  readonly contentLength: number;
  /** TTL in seconds. Defaults to PRESIGNED_URL_TTL_SECONDS. */
  readonly ttlSeconds?: number;
}

export interface PresignPutOutput {
  readonly url: string;
  readonly expiresAt: string; // ISO 8601
}

/**
 * Generate a presigned PUT URL that the client uses to upload the
 * asset bytes directly to S3. The Content-Type and Content-Length are
 * baked into the signature, so the client cannot alter them.
 */
export async function presignPut(
  input: PresignPutInput,
): Promise<PresignPutOutput> {
  const ttl = input.ttlSeconds ?? PRESIGNED_URL_TTL_SECONDS;
  const command = new PutObjectCommand({
    Bucket: ASSETS_BUCKET_NAME,
    Key: input.key,
    ContentType: input.contentType,
    ContentLength: input.contentLength,
  });
  const url = await getSignedUrl(s3, command, {
    expiresIn: ttl,
    // Sign the headers, not just the URL — prevents the client from
    // changing Content-Type / Content-Length after the fact.
    signableHeaders: new Set(["content-type", "content-length"]),
  });
  return {
    url,
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
  };
}

/* -------------------------------------------------------------------------- */
/*  Presigned GET (private asset fetch)                                       */
/* -------------------------------------------------------------------------- */

export interface PresignGetInput {
  readonly key: string;
  readonly ttlSeconds?: number;
  /**
   * Optional. When set, the response will carry this Content-Disposition
   * (typically "attachment; filename=…" for asset downloads).
   */
  readonly contentDisposition?: string;
}

export interface PresignGetOutput {
  readonly url: string;
  readonly expiresAt: string;
}

/**
 * Generate a short-lived presigned GET URL for an authorized fetch of
 * a private asset's ciphertext.
 */
export async function presignGet(
  input: PresignGetInput,
): Promise<PresignGetOutput> {
  const ttl = input.ttlSeconds ?? PRESIGNED_URL_TTL_SECONDS;
  const command = new GetObjectCommand({
    Bucket: ASSETS_BUCKET_NAME,
    Key: input.key,
    ...(input.contentDisposition
      ? { ResponseContentDisposition: input.contentDisposition }
      : {}),
  });
  const url = await getSignedUrl(s3, command, { expiresIn: ttl });
  return {
    url,
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
  };
}

/* -------------------------------------------------------------------------- */
/*  Server-side object operations                                             */
/* -------------------------------------------------------------------------- */

export interface HeadResult {
  /** Size in bytes of the object on disk. */
  readonly contentLength: number;
  readonly contentType?: string;
  readonly etag?: string;
  readonly lastModified?: string;
}

/**
 * Fetch S3 object metadata. Returns null if the object does not exist.
 * Used by complete_upload to verify the client actually uploaded the
 * declared bytes before committing the asset metadata to DynamoDB.
 */
export async function headObject(key: string): Promise<HeadResult | null> {
  try {
    const r = await s3.send<{
      ContentLength?: number;
      ContentType?: string;
      ETag?: string;
      LastModified?: Date;
    }>(new HeadObjectCommand({ Bucket: ASSETS_BUCKET_NAME, Key: key }));
    return {
      contentLength: r.ContentLength ?? 0,
      contentType: r.ContentType,
      etag: r.ETag,
      lastModified: r.LastModified?.toISOString(),
    };
  } catch (e) {
    const err = e as { name?: string; $metadata?: { httpStatusCode?: number } };
    if (
      err.name === "NotFound" ||
      err.$metadata?.httpStatusCode === 404
    ) {
      return null;
    }
    throw e;
  }
}

/**
 * Delete an asset's S3 object. Used by delete_asset and by AMK
 * rotation paths.
 */
export async function deleteObject(key: string): Promise<void> {
  await s3.send(
    new DeleteObjectCommand({ Bucket: ASSETS_BUCKET_NAME, Key: key }),
  );
}

/**
 * Compose the stable CloudFront URL for a public asset. The CDN
 * distribution domain is supplied via env (set by the CDK stack).
 *
 * For v0.1 we use the raw distribution domain (`d1234.cloudfront.net`);
 * a future revision MAY map to a custom domain (`assets.aithos.be`).
 */
export function publicAssetUrl(subjectDid: string, assetId: string): string {
  const domain = process.env.PUBLIC_ASSETS_CDN_DOMAIN;
  if (!domain) {
    // Fallback for local-mock / test environments without CDN configured.
    return `https://cdn.example/${subjectDid}/${assetId}/raw.bin`;
  }
  return `https://${domain}/${subjectDid}/${assetId}/raw.bin`;
}
