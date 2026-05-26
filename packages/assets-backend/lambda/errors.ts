// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Centralized JSON-RPC error codes for the assets PDS.
 *
 * Spec ref: `spec/assets/05-api-primitives.md` §5.5.
 */

import { RpcError } from "./jsonrpc.js";

/* -------------------------------------------------------------------------- */
/*  Standard JSON-RPC codes (reused from data-backend)                        */
/* -------------------------------------------------------------------------- */

export const RPC_PARSE_ERROR = -32700;
export const RPC_INVALID_REQUEST = -32600;
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL_ERROR = -32603;

/* -------------------------------------------------------------------------- */
/*  Aithos-shared error codes (envelope / auth)                               */
/* -------------------------------------------------------------------------- */

export const AITHOS_BAD_ENVELOPE = -32010;
export const AITHOS_ENVELOPE_EXPIRED = -32011;
export const AITHOS_BAD_SIGNATURE = -32012;
export const AITHOS_REPLAY_DETECTED = -32013;
export const AITHOS_NOT_FOUND = -32020;
export const AITHOS_INSUFFICIENT_SCOPE = -32021;

/* -------------------------------------------------------------------------- */
/*  Assets-specific error codes (spec §5.5)                                   */
/* -------------------------------------------------------------------------- */

export const AITHOS_ASSETS_HASH_MISMATCH = -32030;
export const AITHOS_ASSETS_SIZE_MISMATCH = -32031;
export const AITHOS_ASSETS_UPLOAD_NOT_FOUND = -32032;
export const AITHOS_ASSETS_STILL_REFERENCED = -32033;
export const AITHOS_ASSETS_TOMBSTONED = -32034;
export const AITHOS_ASSETS_NOT_PUBLIC = -32035;
export const AITHOS_ASSETS_MEDIA_TYPE_REJECTED = -32036;
export const AITHOS_ASSETS_SIZE_CAP_EXCEEDED = -32037;
export const AITHOS_ASSETS_QUOTA_EXCEEDED = -32038;

/* -------------------------------------------------------------------------- */
/*  Ergonomic constructors                                                    */
/* -------------------------------------------------------------------------- */

export function notFound(message = "asset not found"): RpcError {
  return new RpcError(AITHOS_NOT_FOUND, message);
}

export function invalidParams(message: string, data?: unknown): RpcError {
  return new RpcError(RPC_INVALID_PARAMS, message, data);
}

export function uploadNotFound(uploadSession: string): RpcError {
  return new RpcError(
    AITHOS_ASSETS_UPLOAD_NOT_FOUND,
    `upload session "${uploadSession}" not found or expired`,
  );
}

export function hashMismatch(
  expected: string,
  observed: string,
): RpcError {
  return new RpcError(
    AITHOS_ASSETS_HASH_MISMATCH,
    `plaintext SHA-256 mismatch: expected ${expected}, observed ${observed}`,
    { expected, observed },
  );
}

export function sizeMismatch(
  expected: number,
  observed: number,
): RpcError {
  return new RpcError(
    AITHOS_ASSETS_SIZE_MISMATCH,
    `byte size mismatch: expected ${expected}, observed ${observed}`,
    { expected, observed },
  );
}

export function quotaExceeded(used: number, limit: number): RpcError {
  return new RpcError(
    AITHOS_ASSETS_QUOTA_EXCEEDED,
    `subject quota exceeded: ${used} / ${limit} bytes used`,
    { used_bytes: used, limit_bytes: limit },
  );
}

export function sizeCapExceeded(declared: number, cap: number): RpcError {
  return new RpcError(
    AITHOS_ASSETS_SIZE_CAP_EXCEEDED,
    `declared size ${declared} exceeds per-asset cap ${cap}`,
    { declared_bytes: declared, cap_bytes: cap },
  );
}

export function mediaTypeRejected(mediaType: string): RpcError {
  return new RpcError(
    AITHOS_ASSETS_MEDIA_TYPE_REJECTED,
    `media type "${mediaType}" is not in the platform allow-list`,
    { media_type: mediaType },
  );
}

export function stillReferenced(refCount: number): RpcError {
  return new RpcError(
    AITHOS_ASSETS_STILL_REFERENCED,
    `asset is still referenced by ${refCount} context(s); unref all references before delete`,
    { reference_count: refCount },
  );
}

export function tombstoned(): RpcError {
  return new RpcError(
    AITHOS_ASSETS_TOMBSTONED,
    "asset has been tombstoned; bytes are gone",
  );
}

export function notPublic(): RpcError {
  return new RpcError(
    AITHOS_ASSETS_NOT_PUBLIC,
    "anonymous endpoint called on a private asset",
  );
}
