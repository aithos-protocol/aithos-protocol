// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/** JSON-RPC 2.0 response helpers. */

export interface JsonRpcSuccess {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result: unknown;
}

export interface JsonRpcFailure {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly error: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export function jsonRpcResult(
  id: string | number | null,
  result: unknown,
): JsonRpcSuccess {
  return { jsonrpc: "2.0", id, result };
}

export function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcFailure {
  return {
    jsonrpc: "2.0",
    id,
    error: data !== undefined ? { code, message, data } : { code, message },
  };
}

/** Thrown by handlers to signal a JSON-RPC error to the router. */
export class RpcError extends Error {
  readonly code: number;
  readonly data?: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.code = code;
    this.data = data;
  }
}
