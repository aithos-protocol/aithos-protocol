// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AWS client singletons + environment configuration.
 *
 * Why singletons:
 *   Lambda warm starts reuse the same Node process; constructing DDB
 *   and S3 clients once at module load amortizes connection setup
 *   across many invocations.
 */

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { S3Client } from "@aws-sdk/client-s3";

const region = process.env.AWS_REGION ?? "eu-west-3";

const baseDdbClient = new DynamoDBClient({ region });

export const ddb = DynamoDBDocumentClient.from(baseDdbClient, {
  marshallOptions: {
    removeUndefinedValues: true,
    convertClassInstanceToMap: false,
  },
});

export const s3 = new S3Client({ region });

/* -------------------------------------------------------------------------- */
/*  Environment configuration                                                 */
/* -------------------------------------------------------------------------- */

export const ASSETS_TABLE_NAME =
  process.env.ASSETS_TABLE_NAME ?? "aithos-assets-pds-dev";
export const NONCE_TABLE_NAME =
  process.env.NONCE_TABLE_NAME ?? "aithos-assets-pds-nonces-dev";
export const GAMMA_TABLE_NAME =
  process.env.GAMMA_TABLE_NAME ?? "aithos-assets-pds-gamma-dev";
export const UPLOADS_TABLE_NAME =
  process.env.UPLOADS_TABLE_NAME ?? "aithos-assets-pds-uploads-dev";
export const ASSETS_BUCKET_NAME =
  process.env.ASSETS_BUCKET_NAME ?? "aithos-assets-pds-dev";

export const PER_SUBJECT_QUOTA_BYTES = parseEnvInt(
  "PER_SUBJECT_QUOTA_BYTES",
  5 * 1024 * 1024 * 1024,
);
export const PER_ASSET_CAP_BYTES = parseEnvInt(
  "PER_ASSET_CAP_BYTES",
  100 * 1024 * 1024,
);
export const PRESIGNED_URL_TTL_SECONDS = parseEnvInt(
  "PRESIGNED_URL_TTL_SECONDS",
  900,
);

export const PROTOCOL_VERSION =
  process.env.AITHOS_ASSETS_PROTOCOL_VERSION ?? "0.1.0";

/* -------------------------------------------------------------------------- */
/*  Re-export media-type helper (lives in its own module for testability)     */
/* -------------------------------------------------------------------------- */

export { isMediaTypeAllowed } from "./media-types.js";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function parseEnvInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return n;
}
