// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * E2E test helper — a thin JSON-RPC client + envelope signer for
 * test scripts that hit the deployed assets PDS over HTTPS.
 *
 * Not for production use. Production code goes through the
 * @aithos/sdk's sdk.assets namespace.
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import { ulid } from "ulid";

import { canonicalize } from "@aithos/protocol-core/canonical";
import { ed25519PublicKeyToMultibase } from "@aithos/protocol-core/did";

export interface TestIdentity {
  /** did:key:z…  */
  readonly did: string;
  readonly publicKey: Uint8Array;
  readonly seed: Uint8Array;
}

export interface CallOptions {
  readonly path: "/mcp/primitives/read" | "/mcp/primitives/write";
  readonly method: string;
  readonly params: Record<string, unknown>;
  readonly identity: TestIdentity;
}

/** Read the base URL from env, panicking helpfully if missing. */
export function pdsUrl(): string {
  const u = process.env.AITHOS_ASSETS_PDS_URL;
  if (!u) {
    throw new Error(
      "AITHOS_ASSETS_PDS_URL is not set — point it at the deployed stack's apiEndpoint output",
    );
  }
  return u.replace(/\/$/, "");
}

/** Construct a test identity from a 32-byte seed. */
export async function identityFromSeed(seed: Uint8Array): Promise<TestIdentity> {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const publicKey = await ed.getPublicKeyAsync(seed);
  const multibase = ed25519PublicKeyToMultibase(publicKey);
  return {
    did: `did:key:${multibase}`,
    publicKey,
    seed,
  };
}

/** Read the test identity from the env-provided seed (hex). */
export async function testIdentity(): Promise<TestIdentity> {
  const hex = process.env.AITHOS_ASSETS_TEST_SEED_HEX;
  if (!hex || hex.length !== 64) {
    throw new Error("AITHOS_ASSETS_TEST_SEED_HEX must be a 64-char hex string");
  }
  const seed = hexToBytes(hex);
  return identityFromSeed(seed);
}

/**
 * Sign a JSON-RPC envelope and POST it to the PDS. Returns the
 * `result` field on success, throws an Error carrying the JSON-RPC
 * error payload on failure.
 */
export async function call(opts: CallOptions): Promise<unknown> {
  const url = pdsUrl() + opts.path;
  const envelope = await signEnvelope({
    aud: url,
    method: opts.method,
    params: opts.params,
    identity: opts.identity,
  });
  const body = {
    jsonrpc: "2.0" as const,
    id: ulid(),
    method: opts.method,
    params: { ...opts.params, _envelope: envelope },
  };
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json: { result?: unknown; error?: { code: number; message: string } };
  try {
    json = JSON.parse(text) as typeof json;
  } catch {
    throw new Error(`non-JSON response (status=${r.status}): ${text.slice(0, 500)}`);
  }
  if (json.error) {
    const err = new Error(json.error.message) as Error & { code?: number };
    err.code = json.error.code;
    throw err;
  }
  return json.result;
}

/** Anonymous JSON-RPC call, no envelope. */
export async function anonCall(
  path: "/mcp/primitives/read",
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const url = pdsUrl() + path;
  const body = {
    jsonrpc: "2.0" as const,
    id: ulid(),
    method,
    params,
  };
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await r.json()) as {
    result?: unknown;
    error?: { code: number; message: string };
  };
  if (json.error) {
    const err = new Error(json.error.message) as Error & { code?: number };
    err.code = json.error.code;
    throw err;
  }
  return json.result;
}

/* -------------------------------------------------------------------------- */
/*  Envelope signing                                                          */
/* -------------------------------------------------------------------------- */

async function signEnvelope(input: {
  aud: string;
  method: string;
  params: Record<string, unknown>;
  identity: TestIdentity;
}): Promise<Record<string, unknown>> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 60;
  const nonce = ulid();
  const paramsCanonical = canonicalize(input.params);
  const paramsHash =
    "sha256-" +
    bytesToHex(sha256(new TextEncoder().encode(paramsCanonical)));
  const verificationMethod = `${input.identity.did}#${
    input.identity.did.split(":").pop()
  }`;

  const unsigned = {
    "aithos-envelope": "0.1.0" as const,
    iss: input.identity.did,
    aud: input.aud,
    method: input.method,
    iat: now,
    exp,
    nonce,
    params_hash: paramsHash,
    proof: {
      type: "Ed25519Signature2020" as const,
      verificationMethod,
      created: new Date(now * 1000).toISOString(),
      proofValue: "",
    },
  };
  const canonicalForSign = canonicalize(unsigned);
  const sig = await ed.signAsync(
    new TextEncoder().encode(canonicalForSign),
    input.identity.seed,
  );
  return {
    ...unsigned,
    proof: { ...unsigned.proof, proofValue: base64url(sig) },
  };
}

/* -------------------------------------------------------------------------- */
/*  Utilities                                                                 */
/* -------------------------------------------------------------------------- */

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex;
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
