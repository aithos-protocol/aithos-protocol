// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Lambda router for the Aithos data sub-protocol PDS.
 *
 * Receives JSON-RPC 2.0 requests at /mcp/primitives/{read,write} and
 * dispatches over the method name. Each handler module exports a
 * function matching `Handler` below.
 *
 * Authentication note (v0.1 dev):
 *   This iteration does NOT verify envelope signatures or mandates. The
 *   handler trusts the caller. Sub-jalon 3.2 wires the real verification
 *   path via @aithos/protocol-core's envelope module.
 */

import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
} from "aws-lambda";

import {
  createCollectionHandler,
  getCollectionHandler,
  listCollectionsHandler,
} from "./handlers/collections.js";
import {
  insertRecordHandler,
  getRecordHandler,
  listRecordsHandler,
} from "./handlers/records.js";
import { jsonRpcError, jsonRpcResult } from "./jsonrpc.js";

const PROTOCOL_VERSION = process.env.AITHOS_DATA_PROTOCOL_VERSION ?? "0.1.0";

interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

const HANDLERS: Record<string, (params: Record<string, unknown>) => Promise<unknown>> = {
  // Read primitives
  "aithos.data.get_collection": getCollectionHandler,
  "aithos.data.list_collections": listCollectionsHandler,
  "aithos.data.get_record": getRecordHandler,
  "aithos.data.list_records": listRecordsHandler,

  // Write primitives
  "aithos.data.create_collection": createCollectionHandler,
  "aithos.data.insert_record": insertRecordHandler,
};

/**
 * Lambda entry point.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  // Healthcheck endpoint
  if (event.requestContext.http.path === "/healthz") {
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ok: true,
        protocol: "aithos.data",
        version: PROTOCOL_VERSION,
      }),
    };
  }

  // Parse body
  if (!event.body) {
    return httpResponse(400, jsonRpcError(null, -32700, "missing request body"));
  }
  let body: JsonRpcRequest;
  try {
    body = JSON.parse(event.body) as JsonRpcRequest;
  } catch {
    return httpResponse(400, jsonRpcError(null, -32700, "parse error: invalid JSON"));
  }

  // Validate JSON-RPC envelope
  if (body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return httpResponse(
      400,
      jsonRpcError(body.id ?? null, -32600, "invalid request: jsonrpc must be '2.0' and method a string"),
    );
  }

  // Dispatch
  const fn = HANDLERS[body.method];
  if (!fn) {
    return httpResponse(
      404,
      jsonRpcError(body.id ?? null, -32601, `method not found: ${body.method}`),
    );
  }

  try {
    const result = await fn(body.params ?? {});
    return httpResponse(200, jsonRpcResult(body.id ?? null, result));
  } catch (err) {
    const e = err as { code?: number; message?: string; data?: unknown };
    const code = typeof e.code === "number" ? e.code : -32000;
    const message = e.message ?? "internal error";
    const data = e.data;
    console.error("handler error", { method: body.method, code, message, data });
    return httpResponse(
      // Map JSON-RPC error code class to HTTP status
      code >= -32099 && code <= -32000 ? 400 : 500,
      jsonRpcError(body.id ?? null, code, message, data),
    );
  }
};

function httpResponse(statusCode: number, body: unknown): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}
