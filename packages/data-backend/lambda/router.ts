// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Lambda router for the Aithos data sub-protocol PDS.
 *
 * Pipeline per request:
 *   1. Parse JSON-RPC envelope.
 *   2. Dispatch on `method` to find the handler.
 *   3. Run `authenticate()` (envelope + mandate verification +
 *      replay-cache atomic insert). FAIL CLOSED on any error.
 *   4. Call the handler with the verified `Caller` object.
 *
 * Authentication is mandatory for every method exposed here in
 * Sub-jalon 3.2a. There is no anonymous read path yet — the spec's
 * §10.5 anonymous endpoints (resolve_handle, search, etc.) are not
 * part of the data PDS surface, they live on the Ethos platform.
 */

import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
} from "aws-lambda";

import { authenticate, type Caller } from "./auth/authenticate.js";
import {
  createCollectionHandler,
  getCollectionHandler,
  listCollectionsHandler,
} from "./handlers/collections.js";
import {
  insertRecordHandler,
  getRecordHandler,
  listRecordsHandler,
  updateRecordHandler,
  deleteRecordHandler,
} from "./handlers/records.js";
import { jsonRpcError, jsonRpcResult, RpcError } from "./jsonrpc.js";

const PROTOCOL_VERSION = process.env.AITHOS_DATA_PROTOCOL_VERSION ?? "0.1.0";

interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

type Handler = (caller: Caller) => Promise<unknown>;

const HANDLERS: Record<string, Handler> = {
  // Read primitives
  "aithos.data.get_collection": getCollectionHandler,
  "aithos.data.list_collections": listCollectionsHandler,
  "aithos.data.get_record": getRecordHandler,
  "aithos.data.list_records": listRecordsHandler,

  // Write primitives
  "aithos.data.create_collection": createCollectionHandler,
  "aithos.data.insert_record": insertRecordHandler,
  "aithos.data.update_record": updateRecordHandler,
  "aithos.data.delete_record": deleteRecordHandler,
};

/**
 * Lambda entry point.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  const path = event.requestContext.http.path;

  // Healthcheck endpoint (anonymous, no envelope required)
  if (path === "/healthz") {
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ok: true,
        protocol: "aithos.data",
        version: PROTOCOL_VERSION,
        authentication: "envelope+mandate required on /mcp/primitives/*",
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

  // Build the expected audience URL from the request context. Spec §11.4 step 2
  // requires `envelope.aud` to match this exactly (modulo normalization).
  const expectedAud = buildExpectedAud(event);

  // Authentication: throws RpcError on any failure.
  let caller: Caller;
  try {
    caller = await authenticate({
      method: body.method,
      rawParams: body.params ?? {},
      expectedAud,
    });
  } catch (err) {
    return errorResponse(body.id ?? null, err);
  }

  // Dispatch to handler with the verified caller
  try {
    const result = await fn(caller);
    return httpResponse(200, jsonRpcResult(body.id ?? null, result));
  } catch (err) {
    return errorResponse(body.id ?? null, err);
  }
};

function httpResponse(statusCode: number, body: unknown): APIGatewayProxyResultV2 {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

function errorResponse(
  id: string | number | null,
  err: unknown,
): APIGatewayProxyResultV2 {
  const e = err as { code?: number; message?: string; data?: unknown };
  const code = typeof e.code === "number" ? e.code : -32000;
  const message = e.message ?? "internal error";
  const data = e.data;

  // Map JSON-RPC error code → HTTP status
  let status = 500;
  if (err instanceof RpcError) {
    if (code === -32010 || code === -32011 || code === -32012 || code === -32013) {
      status = 401; // authentication failure
    } else if (
      code === -32040 ||
      code === -32041 ||
      code === -32042
    ) {
      status = 403; // mandate / scope failure
    } else if (code === -32020) {
      status = 404; // not found
    } else if (code >= -32099 && code <= -32000) {
      status = 400; // other client error
    } else if (code === -32601) {
      status = 404;
    } else if (code === -32602) {
      status = 400;
    } else if (code === -32603) {
      status = 500;
    }
  }

  if (status >= 500) {
    console.error("handler error", { code, message, data, error: err });
  } else {
    console.warn("client error", { code, message });
  }

  return httpResponse(status, jsonRpcError(id, code, message, data));
}

/**
 * Reconstruct the URL that the client should have set as `envelope.aud`.
 * Spec §11.2 pins `aud` to the absolute endpoint URL (scheme + host +
 * pathname, no query, no fragment).
 *
 * API Gateway gives us the path verbatim in `requestContext.http.path`.
 * The host comes from the `domainName` field, which excludes the port
 * and stage prefix on HTTP API. Scheme is always HTTPS.
 */
function buildExpectedAud(event: APIGatewayProxyEventV2): string {
  const host = event.requestContext.domainName;
  const path = event.requestContext.http.path;
  return `https://${host}${path}`;
}
