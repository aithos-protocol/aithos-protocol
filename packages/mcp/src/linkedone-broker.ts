// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Provisional Linkedone broker (cf. linkedone PLAN-AITHOS-BROKER-MVP).
//
// Pure orchestration for the `linkedone_schedule_post` tool: validate the
// inputs, sign a delegate-path envelope, and POST to the Linkedone backend's
// `/v1/compose-and-schedule` endpoint (which creates the draft + schedules it
// server-side under Linkedone's own enrolled delegate).
//
// All I/O is INJECTED (`signDelegate`, `fetchImpl`) so this module is
// unit-testable without a network or a live backend. The server wires the
// real delegate signer (protocol-core `signEnvelopeWithMandate`) and `fetch`.

/** Minimum lead time before a scheduled publication (EventBridge floor). */
export const MIN_SCHEDULE_LEAD_MS = 30_000;

export const COMPOSE_AND_SCHEDULE_PATH = "/v1/compose-and-schedule";
export const COMPOSE_AND_SCHEDULE_METHOD = "linkedone.compose_and_schedule";

export interface ScheduleViaLinkedoneArgs {
  /** Linkedone API base, e.g. `https://api.linkedone.fr` (no trailing slash). */
  readonly apiBase: string;
  /** Post body (markdown). */
  readonly content: string;
  /** Requested publication time (ISO 8601 or anything Date.parse accepts). */
  readonly scheduledAt: string;
  /** Signs a delegate-path envelope bound to (aud, method, params). */
  readonly signDelegate: (a: {
    readonly aud: string;
    readonly method: string;
    readonly params: unknown;
  }) => Promise<unknown>;
  /** Fetch implementation (injected for testability). */
  readonly fetchImpl: typeof fetch;
  /** Clock override (ms epoch) for deterministic tests. */
  readonly now?: () => number;
}

export interface ScheduleViaLinkedoneResult {
  readonly ok: true;
  readonly postId?: string;
  readonly scheduledAt: string;
  readonly scheduleArn?: string;
}

export class LinkedoneBrokerError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "LinkedoneBrokerError";
    this.code = code;
  }
}

export async function scheduleViaLinkedone(
  args: ScheduleViaLinkedoneArgs,
): Promise<ScheduleViaLinkedoneResult> {
  const { apiBase, content, scheduledAt, signDelegate, fetchImpl } = args;
  const now = args.now ? args.now() : Date.now();

  if (typeof content !== "string" || content.trim().length === 0) {
    throw new LinkedoneBrokerError("missing_content", "post content is required");
  }
  const t = Date.parse(scheduledAt);
  if (Number.isNaN(t)) {
    throw new LinkedoneBrokerError(
      "invalid_scheduled_at",
      "scheduled_at must be a valid ISO 8601 datetime",
    );
  }
  if (t <= now + MIN_SCHEDULE_LEAD_MS) {
    throw new LinkedoneBrokerError(
      "scheduled_at_too_soon",
      "scheduled_at must be at least 30 seconds in the future",
    );
  }
  const scheduledAtIso = new Date(t).toISOString();

  const base = apiBase.replace(/\/+$/, "");
  const aud = `${base}${COMPOSE_AND_SCHEDULE_PATH}`;
  const params = { content, scheduledAt: scheduledAtIso };
  const envelope = await signDelegate({
    aud,
    method: COMPOSE_AND_SCHEDULE_METHOD,
    params,
  });

  let res: Response;
  try {
    res = await fetchImpl(aud, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...params, _envelope: envelope }),
    });
  } catch (e) {
    throw new LinkedoneBrokerError(
      "linkedone_unreachable",
      `Linkedone API unreachable: ${(e as Error).message}`,
    );
  }

  let data: Record<string, unknown> = {};
  try {
    data = (await res.json()) as Record<string, unknown>;
  } catch {
    /* tolerate empty / non-JSON body; handled by status check below */
  }
  if (!res.ok || data.ok === false) {
    throw new LinkedoneBrokerError(
      (data.error as string) ?? "linkedone_error",
      (data.message as string) ?? `Linkedone returned HTTP ${res.status}`,
    );
  }

  return {
    ok: true,
    postId: data.postId as string | undefined,
    scheduledAt: (data.scheduledAt as string) ?? scheduledAtIso,
    scheduleArn: data.scheduleArn as string | undefined,
  };
}
