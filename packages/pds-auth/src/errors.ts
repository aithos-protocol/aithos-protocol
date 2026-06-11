// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * JSON-RPC error carrying a numeric code. Shared by both PDS backends (each
 * jsonrpc module re-exports it) so a single class identity flows through the
 * resolver, the sphere lock and the router's `instanceof RpcError` status map.
 */
export class RpcError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.code = code;
    this.data = data;
  }
}
