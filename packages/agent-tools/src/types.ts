// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Shared types for the canonical Aithos agent-tool catalogue.
 *
 * This package is the single source of truth for tool NAMES, normative
 * DESCRIPTIONS, input JSON SCHEMAS, and SCOPE rules across every Aithos tool
 * host:
 *
 *   - `@aithos/mcp`            — the standalone MCP server (stdio / HTTP)
 *   - `aithos-sdk`             — the in-app agent loop (browser, in-process)
 *   - the platform compute proxy registry (server-side converse loop)
 *
 * It carries **zero runtime dependencies** and is isomorphic by construction
 * (no node builtins, no DOM). Hosts register the subset of the catalogue they
 * implement; the parity test (T10) asserts every host's registered tools are
 * a subset of — and structurally identical to — the canonical specs.
 */

/**
 * A (deliberately loose) JSON Schema object. We do not model the full JSON
 * Schema grammar — specs in this catalogue use a small, conservative subset:
 * `type`, `properties`, `required`, `items`, `enum`, `minimum`, `maximum`,
 * `minItems`, `minLength`, `description`, `default`.
 */
export type JsonSchema = Record<string, unknown>;

/**
 * Scope gating rule for a tool.
 *
 * - `undefined` (absent)  — the tool is always exposed (safe introspection).
 * - `{ anyOf: [...] }`    — exposed when the caller's mandate carries at
 *                           least ONE of the listed scopes. An owner session
 *                           (no mandate) always sees the full catalogue.
 *
 * Exposure is the *coarse* gate used to build `tools/list`. Hosts MUST keep
 * their fine-grained, per-call enforcement at dispatch time (e.g. a write to
 * zone `circle` still requires `ethos.write.circle` even when the tool was
 * exposed because the mandate carries `ethos.write.public`). Defense in
 * depth: a forged call to a non-exposed or out-of-scope tool never writes.
 */
export interface ScopeRule {
  readonly anyOf: readonly string[];
}

/**
 * One canonical tool specification.
 *
 * `description` is normative: it is shipped verbatim to the calling model and
 * is part of the contract (behavioral instructions such as "never invent
 * content beyond the returned sections" live here). Renaming a tool, changing
 * its schema, or editing its description is a breaking change to this package
 * and MUST be reflected in the CHANGELOG (spec §10.10 discipline).
 */
export interface AgentToolSpec {
  /** Canonical snake_case name, `<domain>_<verb>[_<object>]`. */
  readonly name: string;
  /** Human title (UI surfaces; not sent to models by every host). */
  readonly title: string;
  /** Normative description, shipped verbatim to the calling model. */
  readonly description: string;
  /** JSON Schema for the tool arguments (always `type: "object"`). */
  readonly input_schema: JsonSchema;
  /** Scope exposure rule. Absent = always exposed. */
  readonly requires?: ScopeRule;
  /** True when the tool mutates subject state (used by readOnly filters). */
  readonly write: boolean;
}

/**
 * Outcome shape every Aithos dispatcher returns for a tool call. Dispatchers
 * never throw for domain refusals — refusals travel back to the model as an
 * `is_error` tool result so the loop can recover gracefully.
 */
export interface DispatchOutcome {
  /** JSON-encoded payload (or plain-text error message). */
  readonly payload: string;
  readonly isError: boolean;
}

/** A legacy (pre-0.9) tool name alias and its argument-rename map. */
export interface LegacyAlias {
  /** The canonical tool the alias resolves to. */
  readonly canonical: string;
  /**
   * Shallow argument renames to apply (legacy key → canonical key). Keys not
   * present in the map pass through unchanged.
   */
  readonly renameArgs?: Readonly<Record<string, string>>;
}
