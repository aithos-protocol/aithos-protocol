// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mandated Intent Envelope — gateway federation (A4). Registers owner-authored
 * actions (resolved from the Ethos) as MCP tools the caged agent can call, and
 * on each call performs the notary duties (SPEC-mandated-intent-envelope §4.2):
 *
 *   G1 liveness   — mandate live (window + fresh revocation), fail closed;
 *   G2 in scope   — only actions the mandate grants are exposed (deny default);
 *   G3 validate   — agent params checked against the SIGNED schema, reject on
 *                   any violation, BEFORE signing (the security crux);
 *   G4 sign       — signActionEnvelope (delegate key, method = action id): the
 *                   attributable audit anchor (gamma), NOT a hand precondition;
 *   G5 dispatch   — send the validated action to the downstream ("the hand")
 *                   over an authenticated channel + audit, keyed by the nonce.
 *
 * The hand is a DUMB effector: it trusts the cage boundary + the authenticated
 * channel (bearer) and re-verifies nothing. The enforcement that matters lives
 * here, at the gateway (G1–G3). The downstream transport is injected
 * (`dispatch`) so this stays testable and transport-agnostic: the real
 * browser-agent binding sends `run_action` over its WebSocket (see
 * `wsActionDispatch`); tests inject an in-process function.
 */
import type { Mandate, SignedEnvelope } from "@aithos/protocol-core";

import {
  actionScope,
  actionToolName,
  actionsInScope,
  validateParams,
  signActionEnvelope,
  type ActionDefinition,
} from "./actions.js";
import { inputSchemaToShape, type RegisterableServer, type AuditSink } from "./gateway.js";

/** What a downstream returns for a run_action (a RunReport / RunStopped). */
export interface RunReport {
  readonly ok: boolean;
  readonly type?: string;
  readonly result?: unknown;
  readonly error?: string;
  readonly [k: string]: unknown;
}

/**
 * Send the validated action to the downstream "hand" and get its report. The
 * signed `envelope` rides along for attribution (and for a downstream that
 * chooses to verify), but a dumb hand acts on `(action, params)` alone.
 */
export type ActionDispatch = (req: {
  readonly envelope: unknown;
  readonly action: { readonly id: string };
  readonly params: unknown;
}) => Promise<RunReport>;

export interface FederateActionsOptions {
  readonly server: RegisterableServer;
  /** Owner-authored actions resolved from the Ethos. */
  readonly actions: readonly ActionDefinition[];
  /** The session mandate's scopes — drives `mcp.browser.<id>` gating. */
  readonly scopes: readonly string[];
  /** The signed mandate (carries the grantee delegate pubkey). */
  readonly mandate: Mandate;
  /** The owner (subject) DID — the envelope issuer. */
  readonly ownerDid: string;
  /** The downstream audience identifier (signed into the envelope aud). */
  readonly aud: string;
  /** Delegate signing material (from the mandate pack). */
  readonly delegateKey: { readonly seed: Uint8Array; readonly pubkeyMultibase: string };
  /** Send the signed envelope to the downstream. */
  readonly dispatch: ActionDispatch;
  /** Per-call liveness (G1): throw to refuse (revoked / expired / unreachable). */
  readonly liveness?: () => Promise<void>;
  readonly auditSink?: AuditSink;
  readonly log?: (msg: string) => void;
}

export interface FederateActionsHandle {
  /** Number of actions exposed as tools. */
  readonly exposed: number;
}

/**
 * Register every in-scope action as an MCP tool that signs a Mandated Intent
 * Envelope and dispatches it. Returns a handle with how many were exposed.
 */
export function federateActions(opts: FederateActionsOptions): FederateActionsHandle {
  const log = opts.log ?? ((m: string) => console.error(`aithos-mcp actions: ${m}`));
  const audit = async (
    action: string,
    params: unknown,
    status: "ok" | "error" | "denied",
    error?: string,
    envelopeNonce?: string,
  ) => {
    if (!opts.auditSink) return;
    try {
      await opts.auditSink({
        ts: new Date().toISOString(),
        mandateId: opts.mandate.id,
        server: "browser-agent",
        tool: action,
        paramsSummary: summarize(params),
        status,
        ...(error ? { error } : {}),
        ...(envelopeNonce ? { envelopeNonce } : {}),
      });
    } catch (e) {
      log(`audit sink failed: ${(e as Error).message}`);
    }
  };

  const inScope = actionsInScope(opts.actions, opts.scopes);
  for (const action of inScope) {
    opts.server.registerTool(
      actionToolName(action.id),
      {
        description: `[browser-agent] ${action.goal}`,
        inputSchema: inputSchemaToShape(action.params_schema),
      },
      async (args: Record<string, unknown>) => {
        // G1 — fail-closed liveness on every call.
        if (opts.liveness) {
          try {
            await opts.liveness();
          } catch (e) {
            const reason = (e as Error).message;
            await audit(action.id, args, "denied", reason);
            return errorResult(`denied: ${reason}`);
          }
        }
        // G3 — validate the agent params against the SIGNED schema. Reject
        // before signing; the agent's freedom is bounded by signed limits.
        const v = validateParams(action.params_schema, args ?? {});
        if (!v.ok) {
          await audit(action.id, args, "denied", v.error);
          return errorResult(`invalid parameters: ${v.error}`);
        }
        // G4 — sign the Mandated Intent Envelope: the attributable audit
        // anchor (its nonce keys the gamma record), not a hand precondition.
        let envelope: SignedEnvelope;
        try {
          envelope = signActionEnvelope({
            ownerDid: opts.ownerDid,
            aud: opts.aud,
            action: { id: action.id },
            params: args ?? {},
            mandate: opts.mandate,
            delegateKey: opts.delegateKey,
          });
        } catch (e) {
          const reason = (e as Error).message;
          await audit(action.id, args, "error", reason);
          return errorResult(`could not sign action envelope: ${reason}`);
        }
        // G5 — dispatch the validated action to the hand + audit, keyed by the
        // envelope nonce so the effect is attributable to this exact envelope.
        try {
          const report = await opts.dispatch({ envelope, action: { id: action.id }, params: args ?? {} });
          await audit(
            action.id,
            args,
            report.ok ? "ok" : "error",
            report.ok ? undefined : report.error,
            envelope.nonce,
          );
          return {
            content: [{ type: "text" as const, text: JSON.stringify(report) }],
            isError: !report.ok,
          };
        } catch (e) {
          const reason = (e as Error).message;
          await audit(action.id, args, "error", reason, envelope.nonce);
          return errorResult(`downstream unreachable: ${reason}`);
        }
      },
    );
    log(`exposed action "${action.id}" (scope ${actionScope(action.id)})`);
  }

  return { exposed: inScope.length };
}

function errorResult(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true };
}

/**
 * Default `ActionDispatch`: POST `{ envelope, action, params }` to
 * `<baseUrl>/run_action` and return the downstream's report. The real
 * browser-agent binding will send the same message over its WebSocket; this
 * HTTP form matches the mock hand and any HTTP-fronted connector.
 */
export function httpActionDispatch(baseUrl: string): ActionDispatch {
  const url = `${baseUrl.replace(/\/$/, "")}/run_action`;
  return async (req) => {
    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      });
    } catch (e) {
      return { ok: false, type: "run_stopped", error: `downstream unreachable: ${(e as Error).message}` };
    }
    let report: unknown;
    try {
      report = await res.json();
    } catch {
      return { ok: false, type: "run_stopped", error: `downstream returned non-JSON (status ${res.status})` };
    }
    const r = report as RunReport;
    // Trust the report's own ok flag, but never let a 4xx/5xx masquerade as ok.
    return { ...r, ok: r.ok === true && res.ok };
  };
}

function summarize(args: unknown): string {
  try {
    const s = JSON.stringify(args ?? {});
    return s.length > 200 ? `${s.slice(0, 197)}...` : s;
  } catch {
    return "<unserializable>";
  }
}
