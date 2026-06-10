// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mandate pack (P4.4 — realizes spec §6.2.1 "agent chez le client").
 *
 * ONE file the subject hands to a delegated agent host: the signed mandate,
 * the delegate keypair, and host options. A Claude Desktop / Cursor config
 * then needs a single flag:
 *
 *   { "command": "aithos-mcp", "args": ["--mandate-pack", "~/packs/agent.json"] }
 *
 * The server boots mandate-scoped (`tools/list` filtered by the scopes),
 * writes sign with the delegate key by default (no per-call `mandate` /
 * `agent_key` args needed), and the mandate's liveness (window + revocation)
 * is re-checked before anything persists.
 *
 * ISOMORPHIC: parsing only — reading the file is the host's job (bin.ts).
 */
import type { Mandate } from "@aithos/protocol-core";

export interface MandatePack {
  readonly "aithos-mandate-pack": "1";
  /** The signed mandate (§4). */
  readonly mandate: Mandate;
  /** The delegate keypair matching `mandate.grantee.pubkey`. */
  readonly agent_key: {
    readonly seed_hex: string;
    readonly pubkey_multibase: string;
  };
  /** Optional host options. */
  readonly options?: {
    /** Per-write editions (pre-0.10 behaviour). Default: transactional. */
    readonly auto_commit?: boolean;
    /** Restrict exposure to these canonical tool names. */
    readonly expose_tools?: readonly string[];
  };
}

/** hex → bytes without Buffer (isomorphic). */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 1 ? "0" + hex : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex in agent_key.seed_hex");
    out[i] = byte;
  }
  return out;
}

/**
 * Parse + structurally validate a mandate pack. Throws with a precise
 * message on anything malformed — a half-loaded pack must never boot a
 * server with weaker constraints than intended.
 */
export function parseMandatePack(jsonText: string): MandatePack {
  let raw: unknown;
  try {
    raw = JSON.parse(jsonText);
  } catch (e) {
    throw new Error(`mandate pack is not valid JSON: ${(e as Error).message}`);
  }
  const p = raw as Partial<MandatePack>;
  if (p["aithos-mandate-pack"] !== "1") {
    throw new Error('mandate pack: missing or unsupported "aithos-mandate-pack" (want "1")');
  }
  const m = p.mandate as Mandate | undefined;
  if (!m || typeof m !== "object") throw new Error("mandate pack: missing mandate");
  if (typeof m.id !== "string" || !m.id) throw new Error("mandate pack: mandate.id missing");
  if (!Array.isArray(m.scopes) || m.scopes.some((s) => typeof s !== "string")) {
    throw new Error("mandate pack: mandate.scopes must be a string array");
  }
  if (typeof m.not_after !== "string" || typeof m.not_before !== "string") {
    throw new Error("mandate pack: mandate validity window missing");
  }
  if (!m.grantee || typeof m.grantee.pubkey !== "string") {
    throw new Error("mandate pack: mandate.grantee.pubkey missing");
  }
  const k = p.agent_key;
  if (!k || typeof k.seed_hex !== "string" || !k.seed_hex) {
    throw new Error("mandate pack: agent_key.seed_hex missing");
  }
  if (typeof k.pubkey_multibase !== "string" || !k.pubkey_multibase) {
    throw new Error("mandate pack: agent_key.pubkey_multibase missing");
  }
  if (m.grantee.pubkey !== k.pubkey_multibase) {
    throw new Error(
      "mandate pack: agent_key.pubkey_multibase does not match mandate.grantee.pubkey",
    );
  }
  hexToBytes(k.seed_hex); // validates
  const o = p.options;
  if (o !== undefined) {
    if (typeof o !== "object" || o === null) throw new Error("mandate pack: options must be an object");
    if (o.auto_commit !== undefined && typeof o.auto_commit !== "boolean") {
      throw new Error("mandate pack: options.auto_commit must be a boolean");
    }
    if (
      o.expose_tools !== undefined &&
      (!Array.isArray(o.expose_tools) || o.expose_tools.some((t) => typeof t !== "string"))
    ) {
      throw new Error("mandate pack: options.expose_tools must be a string array");
    }
  }
  return p as MandatePack;
}
