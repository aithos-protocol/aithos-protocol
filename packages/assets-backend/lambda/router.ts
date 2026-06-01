// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Lambda router for the Aithos assets sub-protocol PDS.
 *
 * Pipeline per request:
 *   1. Parse JSON-RPC envelope.
 *   2. Identify the method; anonymous methods skip auth, others go
 *      through `authenticate()`.
 *   3. Call the handler with the verified `Caller` (or raw params for
 *      anonymous calls).
 *
 * Owner-only authentication in v0.1. Mandate-based delegate auth lands
 * in v0.2 (chapter 04 of the assets spec).
 */

import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2,
} from "aws-lambda";

import { authenticate, type Caller } from "./auth/envelope.js";
import {
  initUploadHandler,
  completeUploadHandler,
  abortUploadHandler,
} from "./handlers/uploads.js";
import {
  getAssetHandler,
  headAssetHandler,
  listAssetsHandler,
  listReferencesHandler,
  verifyHandler,
  getPublicAssetHandler,
  headPublicAssetHandler,
} from "./handlers/reads.js";
import {
  refAssetHandler,
  unrefAssetHandler,
} from "./handlers/references.js";
import {
  deleteAssetHandler,
  rotateOwnerWrapHandler,
  authorizeGranteeHandler,
  revokeGranteeHandler,
  rotateAmkHandler,
} from "./handlers/lifecycle.js";
import { jsonRpcError, jsonRpcResult, RpcError } from "./jsonrpc.js";
import { PROTOCOL_VERSION } from "./deps.js";

/**
 * Public-facing host the assets PDS is reachable on through CloudFront
 * (e.g. "assets.aithos.be"). Host only — no scheme, no path.
 *
 * Behind CloudFront the origin request policy strips the viewer Host
 * (`all_viewer_except_host`), so `event.requestContext.domainName` is the raw
 * execute-api host, NOT the vanity domain a modern SDK signs into its `aud`.
 * When set we accept BOTH endpoints (dual-aud) during the edge migration.
 * Leave unset to keep the legacy single-aud behavior.
 */
const ASSETS_PUBLIC_HOST = process.env.ASSETS_PUBLIC_HOST;

interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

type AuthedHandler = (caller: Caller) => Promise<unknown>;
type AnonHandler = (params: Record<string, unknown>) => Promise<unknown>;

/** Methods requiring envelope authentication (owner-only in v0.1). */
const AUTHED_HANDLERS: Record<string, AuthedHandler> = {
  // Upload lifecycle
  "aithos.assets.init_upload": initUploadHandler,
  "aithos.assets.complete_upload": completeUploadHandler,
  "aithos.assets.abort_upload": abortUploadHandler,

  // Read primitives
  "aithos.assets.get_asset": getAssetHandler,
  "aithos.assets.head_asset": headAssetHandler,
  "aithos.assets.list_assets": listAssetsHandler,
  "aithos.assets.list_references": listReferencesHandler,
  "aithos.assets.verify": verifyHandler,

  // Reference primitives
  "aithos.assets.ref_asset": refAssetHandler,
  "aithos.assets.unref_asset": unrefAssetHandler,

  // Lifecycle primitives
  "aithos.assets.delete_asset": deleteAssetHandler,
  "aithos.assets.rotate_owner_wrap": rotateOwnerWrapHandler,

  // Stubs for v0.2-bound primitives — return -32050 to signal
  // not-implemented while keeping the wire surface stable.
  "aithos.assets.authorize_grantee": authorizeGranteeHandler,
  "aithos.assets.revoke_grantee": revokeGranteeHandler,
  "aithos.assets.rotate_amk": rotateAmkHandler,
};

/** Anonymous methods — public reads. */
const ANON_HANDLERS: Record<string, AnonHandler> = {
  "aithos.assets.get_public_asset": getPublicAssetHandler,
  "aithos.assets.head_public_asset": headPublicAssetHandler,
};

/**
 * Lambda entry point.
 */
export const handler = async (
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> => {
  const path = event.requestContext?.http?.path ?? "";
  const method = event.requestContext?.http?.method ?? "";

  // Healthcheck endpoint (anonymous, no envelope required)
  if (method === "GET" && path === "/healthz") {
    return httpResponse(200, {
      ok: true,
      protocol: "aithos.assets",
      version: PROTOCOL_VERSION,
      authentication: "envelope required on /mcp/primitives/write and on private reads",
    });
  }

  // Parse body
  if (!event.body) {
    return httpResponse(
      400,
      jsonRpcError(null, -32700, "missing request body"),
    );
  }
  let body: JsonRpcRequest;
  try {
    body = JSON.parse(event.body) as JsonRpcRequest;
  } catch {
    return httpResponse(
      400,
      jsonRpcError(null, -32700, "parse error: invalid JSON"),
    );
  }
  if (body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return httpResponse(
      400,
      jsonRpcError(
        body.id ?? null,
        -32600,
        "invalid request: jsonrpc must be '2.0' and method a string",
      ),
    );
  }

  // Dispatch — try anonymous first, then authed
  const anonFn = ANON_HANDLERS[body.method];
  if (anonFn) {
    try {
      const result = await anonFn(body.params ?? {});
      return httpResponse(200, jsonRpcResult(body.id ?? null, result));
    } catch (err) {
      return errorResponse(body.id ?? null, err);
    }
  }

  const authedFn = AUTHED_HANDLERS[body.method];
  if (!authedFn) {
    return httpResponse(
      404,
      jsonRpcError(
        body.id ?? null,
        -32601,
        `method not found: ${body.method}`,
      ),
    );
  }

  const expectedAud = buildExpectedAud(event);

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

  try {
    const result = await authedFn(caller);
    return httpResponse(200, jsonRpcResult(body.id ?? null, result));
  } catch (err) {
    return errorResponse(body.id ?? null, err);
  }
};

function httpResponse(
  statusCode: number,
  body: unknown,
): APIGatewayProxyResultV2 {
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

  let status = 500;
  if (err instanceof RpcError) {
    if (
      code === -32010 ||
      code === -32011 ||
      code === -32012 ||
      code === -32013
    ) {
      status = 401;
    } else if (code === -32021) {
      status = 403;
    } else if (code === -32020) {
      status = 404;
    } else if (code === -32601) {
      status = 404;
    } else if (
      code === -32034 ||
      code === -32035
    ) {
      status = 410; // Gone (tombstoned) / 410 also for not-public misuse
    } else if (code >= -32099 && code <= -32000) {
      status = 400;
    } else if (code === -32602) {
      status = 400;
    }
  }

  if (status >= 500) {
    console.error("handler error", { code, message, data, error: err });
  } else {
    console.warn("client error", { code, message });
  }

  return httpResponse(status, jsonRpcError(id, code, message, data));
}

function buildExpectedAud(event: APIGatewayProxyEventV2): string | string[] {
  const host = event.requestContext.domainName;
  const path = event.requestContext.http.path;
  const originAud = `https://${host}${path}`;
  // Dual-aud during the assets PDS edge migration (strangler EXPAND step):
  // also accept the public vanity endpoint a modern SDK signs once pointed at
  // CloudFront (assets.aithos.be). The origin host stays accepted so legacy
  // clients hitting the raw execute-api URL keep working. Drop the vanity
  // branch once the metric shows all clients target the vanity domain.
  if (ASSETS_PUBLIC_HOST && ASSETS_PUBLIC_HOST !== host) {
    return [`https://${ASSETS_PUBLIC_HOST}${path}`, originAud];
  }
  return originAud;
}
