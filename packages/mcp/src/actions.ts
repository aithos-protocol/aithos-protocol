// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mandated Intent Envelope — gateway side (SPEC-mandated-intent-envelope 0.1.0).
 *
 * An "action" is owner-authored, signed content anchored in the Ethos (a
 * section): `{ id, goal, params_schema }`. The gateway exposes each action the
 * mandate scopes allow as an MCP tool; when the caged agent calls it, the
 * gateway:
 *
 *   1. checks the mandate covers `mcp.browser.<id>` (scope filter),
 *   2. VALIDATES the agent parameters against the SIGNED params_schema — the
 *      security crux: the agent's freedom is bounded by signed limits,
 *   3. signs a Mandated Intent Envelope via `signEnvelopeWithMandate`
 *      (method = action id, params = validated params, mandate, delegate key)
 *      as the attributable audit record — the gamma anchor (who did what, under
 *      which mandate), and the verifiable form for a downstream that wants it,
 *   4. dispatches the validated action to the downstream ("the hand").
 *
 * The hand is a DUMB effector: it trusts the cage boundary + the authenticated
 * channel (bearer) and executes — it holds no Aithos key and re-verifies
 * nothing. The enforcement that matters lives here, at the gateway: mandate
 * liveness, scope, and above all the parameter validation against the signed
 * schema. Independent re-verification by the hand is OPTIONAL (only for a
 * downstream that does not trust the gateway).
 *
 * The agent supplies only (id, params). It never supplies the recipe, holds no
 * key, and cannot forge intent — everything authoritative is Ethos-anchored and
 * gateway-validated. This module is the PURE core (parse / validate / scope /
 * sign); wiring to a downstream (WS `run_action`) + gamma lives with the host.
 *
 * ISOMORPHIC: no node builtins. Signing material is injected by the host.
 */
import { signEnvelopeWithMandate } from "@aithos/protocol-core";
import type { Mandate, SignedEnvelope } from "@aithos/protocol-core";

/* -------------------------------------------------------------------------- */
/* Action model                                                               */
/* -------------------------------------------------------------------------- */

/** JSON Schema (the v0 subset this module validates — see `validateParams`). */
export type JsonSchema = {
  readonly type?: string;
  readonly enum?: readonly unknown[];
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly items?: JsonSchema;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly pattern?: string;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly description?: string;
};

/** An owner-authored action, resolved from a signed Ethos section. */
export interface ActionDefinition {
  /** Stable id — drives the scope `mcp.browser.<id>` and the tool name. */
  readonly id: string;
  /** Human description (becomes the MCP tool title/description). */
  readonly goal: string;
  /** JSON Schema for the agent-supplied parameters (the declared slots). */
  readonly params_schema: JsonSchema;
}

/**
 * The scope that grants an action — `mcp.browser.<id>`, aligned with the
 * downstream (browser-agent) scope vocabulary (`mcp.<service>.<verb>`). Like
 * other `mcp.*` connector scopes it rides on the self/circle spheres; it is
 * NOT a public-sphere scope (public is limited to ethos.*.public /
 * ethos.read.all / gamma.read / compute.invoke / data.*).
 */
export function actionScope(id: string): string {
  return `mcp.browser.${id}`;
}

/** Namespaced MCP tool name for an action (avoids collision with core tools). */
export function actionToolName(id: string): string {
  return `browser_action__${id}`;
}

/** Recover the action id from a tool name (inverse of {@link actionToolName}). */
export function actionIdFromToolName(name: string): string | null {
  const prefix = "browser_action__";
  return name.startsWith(prefix) ? name.slice(prefix.length) : null;
}

/**
 * Parse an action from an Ethos section. The section body is JSON:
 * `{ "goal": string, "params_schema": <JSON Schema> }`. Throws on anything
 * malformed — a half-parsed action must never become a tool.
 */
export function parseActionSection(section: {
  id: string;
  title?: string;
  body: string;
  tags?: readonly string[];
}): ActionDefinition {
  if (!section.id) throw new Error("action section: missing id");
  let raw: unknown;
  try {
    raw = JSON.parse(section.body);
  } catch (e) {
    throw new Error(`action section ${section.id}: body is not valid JSON: ${(e as Error).message}`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`action section ${section.id}: body must be a JSON object`);
  }
  const o = raw as Record<string, unknown>;
  const goal =
    typeof o["goal"] === "string" && o["goal"]
      ? (o["goal"] as string)
      : section.title && section.title.length > 0
        ? section.title
        : section.id;
  const schema = o["params_schema"];
  if (schema !== undefined && (typeof schema !== "object" || schema === null)) {
    throw new Error(`action section ${section.id}: params_schema must be an object`);
  }
  return {
    id: section.id,
    goal,
    params_schema: (schema as JsonSchema | undefined) ?? { type: "object", properties: {} },
  };
}

/** Keep only the actions whose scope the mandate carries (deny by default). */
export function actionsInScope(
  actions: readonly ActionDefinition[],
  scopes: readonly string[],
): ActionDefinition[] {
  const set = new Set(scopes);
  return actions.filter((a) => set.has(actionScope(a.id)));
}

/* -------------------------------------------------------------------------- */
/* Parameter validation (the security crux) — a strict v0 JSON-Schema subset  */
/* -------------------------------------------------------------------------- */

export type ValidationResult = { ok: true } | { ok: false; error: string };

/**
 * Validate agent-supplied `value` against a signed `schema`. Strict by design:
 * unknown properties are REJECTED (additionalProperties defaults to false), and
 * every declared constraint is enforced. A malicious agent cannot smuggle a
 * value the owner's signed schema does not permit.
 *
 * Supported (v0): type (string/number/integer/boolean/object/array), enum,
 * required, properties, additionalProperties, items, min/maxLength, pattern,
 * minimum/maximum, min/maxItems. Anything else is treated conservatively.
 */
export function validateParams(schema: JsonSchema, value: unknown): ValidationResult {
  return check(schema, value, "params");
}

function check(schema: JsonSchema, value: unknown, path: string): ValidationResult {
  // enum takes precedence — exact membership.
  if (schema.enum) {
    const okEnum = schema.enum.some((e) => deepEqual(e, value));
    if (!okEnum) return fail(path, `must be one of ${JSON.stringify(schema.enum)}`);
  }

  const type = schema.type ?? inferDefaultType(schema);
  switch (type) {
    case "string": {
      if (typeof value !== "string") return fail(path, "must be a string");
      if (schema.minLength !== undefined && value.length < schema.minLength)
        return fail(path, `must be at least ${schema.minLength} chars`);
      if (schema.maxLength !== undefined && value.length > schema.maxLength)
        return fail(path, `must be at most ${schema.maxLength} chars`);
      if (schema.pattern !== undefined) {
        let re: RegExp;
        try {
          re = new RegExp(schema.pattern);
        } catch {
          return fail(path, "schema has an invalid pattern");
        }
        if (!re.test(value)) return fail(path, `must match ${schema.pattern}`);
      }
      return { ok: true };
    }
    case "integer":
    case "number": {
      if (typeof value !== "number" || Number.isNaN(value))
        return fail(path, "must be a number");
      if (type === "integer" && !Number.isInteger(value))
        return fail(path, "must be an integer");
      if (schema.minimum !== undefined && value < schema.minimum)
        return fail(path, `must be ≥ ${schema.minimum}`);
      if (schema.maximum !== undefined && value > schema.maximum)
        return fail(path, `must be ≤ ${schema.maximum}`);
      return { ok: true };
    }
    case "boolean":
      if (typeof value !== "boolean") return fail(path, "must be a boolean");
      return { ok: true };
    case "array": {
      if (!Array.isArray(value)) return fail(path, "must be an array");
      if (schema.minItems !== undefined && value.length < schema.minItems)
        return fail(path, `must have at least ${schema.minItems} items`);
      if (schema.maxItems !== undefined && value.length > schema.maxItems)
        return fail(path, `must have at most ${schema.maxItems} items`);
      if (schema.items) {
        for (let i = 0; i < value.length; i++) {
          const r = check(schema.items, value[i], `${path}[${i}]`);
          if (!r.ok) return r;
        }
      }
      return { ok: true };
    }
    case "object":
    default: {
      if (typeof value !== "object" || value === null || Array.isArray(value))
        return fail(path, "must be an object");
      const obj = value as Record<string, unknown>;
      const props = schema.properties ?? {};
      const required = schema.required ?? [];
      for (const key of required) {
        if (!(key in obj)) return fail(`${path}.${key}`, "is required");
      }
      // Deny by default: reject any property the schema does not declare.
      const additional = schema.additionalProperties === true;
      for (const key of Object.keys(obj)) {
        if (!(key in props)) {
          if (!additional) return fail(`${path}.${key}`, "is not an allowed parameter");
          continue;
        }
        const r = check(props[key]!, obj[key], `${path}.${key}`);
        if (!r.ok) return r;
      }
      return { ok: true };
    }
  }
}

function inferDefaultType(schema: JsonSchema): string {
  if (schema.properties || schema.required || schema.additionalProperties !== undefined)
    return "object";
  if (schema.items || schema.minItems !== undefined || schema.maxItems !== undefined)
    return "array";
  return "object";
}

function fail(path: string, msg: string): ValidationResult {
  return { ok: false, error: `${path} ${msg}` };
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a && b && typeof a === "object") {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return false;
}

/* -------------------------------------------------------------------------- */
/* Envelope signing (reuses §5 — no new crypto)                               */
/* -------------------------------------------------------------------------- */

export interface SignActionEnvelopeArgs {
  /** The owner (subject) DID — the envelope issuer. */
  readonly ownerDid: string;
  /** The downstream audience (the "hand" that will verify + execute). */
  readonly aud: string;
  /** The action being invoked. */
  readonly action: Pick<ActionDefinition, "id">;
  /** Agent parameters — MUST already be validated against the signed schema. */
  readonly params: unknown;
  /** The session mandate (carries the grantee delegate pubkey + scopes). */
  readonly mandate: Mandate;
  /** The delegate signing material (from the mandate pack). */
  readonly delegateKey: { readonly seed: Uint8Array; readonly pubkeyMultibase: string };
  /** Envelope TTL (default 120s — the envelope is near-real-time, §11.3). */
  readonly ttlSeconds?: number;
  readonly now?: Date;
  readonly nonce?: string;
}

/**
 * Produce a Mandated Intent Envelope for an action call: a §5 SignedEnvelope
 * whose `method` is the action id and whose `params` are the validated agent
 * parameters, signed by the delegate key the mandate names. The downstream
 * re-verifies it with `verifyEnvelope` (expectedMethod = action id).
 */
export function signActionEnvelope(args: SignActionEnvelopeArgs): SignedEnvelope {
  return signEnvelopeWithMandate({
    iss: args.ownerDid,
    aud: args.aud,
    method: args.action.id,
    params: args.params,
    delegateKey: args.delegateKey,
    mandate: args.mandate,
    ttlSeconds: args.ttlSeconds ?? 120,
    ...(args.now ? { now: args.now } : {}),
    ...(args.nonce ? { nonce: args.nonce } : {}),
  });
}
