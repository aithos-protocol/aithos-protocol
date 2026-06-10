// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Resolver helpers for write-mandate auth — isomorphic.
 *
 * The MCP server never *creates* mandates — those are minted by `aithos grant`
 * on the subject's machine. At call time we just need to:
 *
 *   1. Locate the mandate JSON (by id via the storage backend, or at a
 *      filesystem path via the injected {@link HostIo}).
 *   2. Locate an agent keyfile whose public key matches `mandate.grantee.pubkey`.
 *   3. Return both to the caller in a shape the ethos module already accepts.
 *
 * If neither is provided, writes fall back to the subject's own sphere key —
 * which only works when the MCP server is running on the subject's machine
 * (typical for local stdio use).
 *
 * ISOMORPHISM. This module imports no node builtins. Path-form lookups
 * (mandate JSONs, agent keyfiles) require the host to inject a {@link HostIo};
 * hosts without one (browsers) resolve mandates by id through the storage
 * backend only, and delegated writes carry their key material differently
 * (the SDK host signs with its own session keys).
 */
import type { AithosStorage, Mandate } from "@aithos/protocol-core";

/** Minimal host file access, injected by filesystem hosts (bin.ts). */
export interface HostIo {
  /** Read a UTF-8 text file at `path`. */
  readTextFile(path: string): Promise<string>;
  /** Optional path normalizer (node hosts pass `path.resolve`). */
  resolvePath?(p: string): string;
}

export interface AgentKeyFile {
  aithos?: string;
  id?: string;
  seed_hex: string;
  pubkey_multibase: string;
}

export interface ResolvedWriteAuth {
  mandate: Mandate;
  /** Where the mandate came from (path, or `mandate:<id>` for id form). */
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

/** hex → bytes without Buffer (isomorphic). */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 1 ? "0" + hex : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("invalid hex in agent keyfile seed_hex");
    }
    out[i] = byte;
  }
  return out;
}

function looksLikePath(idOrPath: string): boolean {
  return idOrPath.includes("/") || idOrPath.endsWith(".json");
}

/**
 * Resolve a mandate by id or path. Id form goes through the storage backend
 * so remote MCP deployments can resolve against the server's mandate store;
 * path form needs the host's {@link HostIo}.
 */
export async function resolveMandate(
  storage: AithosStorage,
  idOrPath: string,
  io?: HostIo,
): Promise<{ mandate: Mandate; mandatePath: string }> {
  if (looksLikePath(idOrPath)) {
    if (!io) {
      throw new Error(
        "path-form mandates need host file access; this host resolves " +
          "mandates by id only (mandate_<ULID>)",
      );
    }
    const p = io.resolvePath ? io.resolvePath(idOrPath) : idOrPath;
    const raw = await io.readTextFile(p);
    return { mandate: JSON.parse(raw) as Mandate, mandatePath: p };
  }
  // Id form — ask the backend. `mandatePath` is diagnostic metadata only.
  const mandate = await storage.loadMandate(idOrPath);
  return { mandate, mandatePath: `mandate:${idOrPath}` };
}

/**
 * Load an agent keyfile (JSON: { seed_hex, id?, pubkey_multibase? }) from the
 * host filesystem via {@link HostIo}.
 */
export async function loadAgentKey(
  pathOrEnv: string,
  io?: HostIo,
): Promise<{ key: AgentKeyFile; path: string }> {
  if (!io) {
    throw new Error(
      "agent keyfiles need host file access; this host cannot read " +
        "delegate keys from a path",
    );
  }
  const p = io.resolvePath ? io.resolvePath(pathOrEnv) : pathOrEnv;
  const raw = await io.readTextFile(p);
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
  io?: HostIo,
): Promise<ResolvedWriteAuth | null> {
  if (!args.mandate && !args.agentKey) return null;
  if (!args.mandate || !args.agentKey) {
    throw new Error(
      "write mandate and agent-key must be provided together (both or neither)",
    );
  }
  const { mandate, mandatePath } = await resolveMandate(
    storage,
    args.mandate,
    io,
  );
  const { key, path: agentKeyPath } = await loadAgentKey(args.agentKey, io);
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
      keySeed: hexToBytes(key.seed_hex),
      keyMultibase: key.pubkey_multibase,
    },
  };
}
