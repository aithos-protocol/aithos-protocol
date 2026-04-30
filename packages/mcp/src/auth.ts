// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Resolver helpers for write-mandate auth.
 *
 * The MCP server never *creates* mandates — those are minted by `aithos grant`
 * on the subject's machine. At call time we just need to:
 *
 *   1. Locate the mandate JSON (by id via the storage backend, or at a
 *      filesystem path).
 *   2. Locate an agent keyfile whose public key matches `mandate.grantee.pubkey`.
 *   3. Return both to the caller in a shape the ethos module already accepts.
 *
 * If neither is provided, writes fall back to the subject's own sphere key —
 * which only works when the MCP server is running on the subject's machine
 * (typical for local stdio use).
 *
 * The id-form mandate lookup goes through the injected {@link AithosStorage}
 * so remote backends can resolve mandates against their own store. Path-form
 * (absolute/relative `.json`) is always the MCP server's own filesystem.
 */
import fs from "node:fs";
import path from "node:path";
import { Buffer } from "node:buffer";
import {
  mandatesDir,
  type AithosStorage,
  type Mandate,
} from "@aithos/protocol-core";

export interface AgentKeyFile {
  aithos?: string;
  id?: string;
  seed_hex: string;
  pubkey_multibase: string;
}

export interface ResolvedWriteAuth {
  mandate: Mandate;
  mandatePath: string;
  agentKey: AgentKeyFile;
  agentKeyPath: string;
  /** Ready-to-use shape expected by ethos.addSection / modifySection. */
  delegate: {
    mandateId: string;
    keySeed: Uint8Array;
    keyMultibase: string;
  };
}

/**
 * Resolve a mandate by id or path. Id form goes through the storage backend
 * so remote MCP deployments can resolve against the server's mandate store.
 */
export async function resolveMandate(
  storage: AithosStorage,
  idOrPath: string,
): Promise<{ mandate: Mandate; mandatePath: string }> {
  // Path form (absolute or relative with extension / slash).
  if (idOrPath.includes("/") || idOrPath.endsWith(".json")) {
    const p = path.resolve(idOrPath);
    const raw = fs.readFileSync(p, "utf8");
    return { mandate: JSON.parse(raw) as Mandate, mandatePath: p };
  }
  // Id form — ask the backend.
  const mandate = await storage.loadMandate(idOrPath);
  // `mandatePath` is diagnostic metadata (where the mandate "would" live
  // on the local filesystem); remote backends may not have a real file there.
  const mandatePath = path.join(mandatesDir(), `${idOrPath}.json`);
  return { mandate, mandatePath };
}

/**
 * Load an agent keyfile from disk (JSON: { seed_hex, id?, pubkey_multibase? }).
 */
export function loadAgentKey(pathOrEnv: string): {
  key: AgentKeyFile;
  path: string;
} {
  const p = path.resolve(pathOrEnv);
  const raw = fs.readFileSync(p, "utf8");
  const parsed = JSON.parse(raw) as AgentKeyFile;
  if (!parsed.seed_hex) {
    throw new Error(`agent keyfile ${p} is missing seed_hex`);
  }
  return { key: parsed, path: p };
}

/**
 * Join a mandate + agent-key pair, validating surface-level consistency.
 */
export async function resolveWriteAuth(
  storage: AithosStorage,
  args: { mandate?: string; agentKey?: string },
): Promise<ResolvedWriteAuth | null> {
  if (!args.mandate && !args.agentKey) return null;
  if (!args.mandate || !args.agentKey) {
    throw new Error(
      "write mandate and agent-key must be provided together (both or neither)",
    );
  }
  const { mandate, mandatePath } = await resolveMandate(storage, args.mandate);
  const { key, path: agentKeyPath } = loadAgentKey(args.agentKey);
  if (
    mandate.grantee.pubkey &&
    key.pubkey_multibase &&
    mandate.grantee.pubkey !== key.pubkey_multibase
  ) {
    throw new Error(
      `agent keyfile pubkey does not match mandate.grantee.pubkey`,
    );
  }
  return {
    mandate,
    mandatePath,
    agentKey: key,
    agentKeyPath,
    delegate: {
      mandateId: mandate.id,
      keySeed: Uint8Array.from(Buffer.from(key.seed_hex, "hex")),
      keyMultibase: key.pubkey_multibase,
    },
  };
}
