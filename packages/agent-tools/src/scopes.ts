// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Scope → tool exposure rules (decision: tools/list is filtered by the
 * mandate's scopes; per-call zone enforcement stays at dispatch time).
 */
import { AGENT_TOOL_CATALOG } from "./catalog.js";
import type { AgentToolSpec } from "./types.js";

/**
 * Returns true when `spec` is exposed to a caller bearing `scopes`.
 *
 * - `scopes === undefined` — owner session (no mandate): everything.
 * - otherwise — the spec's `requires.anyOf` must intersect the scopes.
 */
export function scopeAllowsTool(
  spec: AgentToolSpec,
  scopes: readonly string[] | undefined,
): boolean {
  if (scopes === undefined) return true;
  if (!spec.requires) return true;
  return spec.requires.anyOf.some((s) => scopes.includes(s));
}

/**
 * The catalogue subset a caller bearing `scopes` may see, in catalogue order.
 *
 * @param scopes   The mandate's scopes; `undefined` = owner (full catalogue).
 * @param opts.tools     Restrict to these canonical names (unknown ignored).
 * @param opts.readOnly  Drop every write tool.
 */
export function toolsForScopes(
  scopes: readonly string[] | undefined,
  opts?: { tools?: readonly string[]; readOnly?: boolean },
): readonly AgentToolSpec[] {
  let out = AGENT_TOOL_CATALOG.filter((t) => scopeAllowsTool(t, scopes));
  if (opts?.readOnly) out = out.filter((t) => !t.write);
  if (opts?.tools && opts.tools.length > 0) {
    const wanted = new Set(opts.tools);
    out = out.filter((t) => wanted.has(t.name));
  }
  return out;
}

/** True when `name` is a write tool of the canonical catalogue. */
export function isWriteTool(name: string): boolean {
  return AGENT_TOOL_CATALOG.some((t) => t.name === name && t.write);
}
