// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mission sections — the unit of intent placed in the mailbox and executed by
 * exactly one agent run (SPEC-container-runtime §13.8.2, PLAN-CONTAINER P1.1).
 *
 * Status is written by the HARNESS only, deterministically (W1). This module
 * is the pure state machine it obeys — no I/O, no LLM.
 */

export const MISSION_STATUSES = [
  "pending",
  "in_progress",
  "done",
  "failed",
  "interrupted",
  "waiting_input",
] as const;

export type MissionStatus = (typeof MISSION_STATUSES)[number];

export interface MissionSection {
  readonly id: string;
  readonly type: "mission";
  readonly status: MissionStatus;
  /** The intent — what to do. */
  readonly payload: string;
  /** Present on done/failed: the agent's report. */
  readonly result?: string;
  /** Present on waiting_input: the decision escalated to a human. */
  readonly question?: string;
  /** Optional link to a related/parent mission (continuity through the ethos). */
  readonly mission_ref?: string;
}

/** Terminal statuses never transition further. */
const TERMINAL: ReadonlySet<MissionStatus> = new Set(["done", "failed"]);

/** Legal transitions (W1). Only the harness performs these. */
const TRANSITIONS: Readonly<Record<MissionStatus, readonly MissionStatus[]>> = {
  pending: ["in_progress"],
  in_progress: ["done", "failed", "waiting_input", "interrupted"],
  waiting_input: ["pending"],
  interrupted: ["pending"], // a re-queued interrupted mission may run again
  done: [],
  failed: [],
};

export function isMissionStatus(v: unknown): v is MissionStatus {
  return typeof v === "string" && (MISSION_STATUSES as readonly string[]).includes(v);
}

export function isTerminal(status: MissionStatus): boolean {
  return TERMINAL.has(status);
}

export function canTransition(from: MissionStatus, to: MissionStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

/** Assert-and-return: throw if the transition is illegal (defensive W1 guard). */
export function assertTransition(from: MissionStatus, to: MissionStatus): void {
  if (!canTransition(from, to)) {
    throw new Error(`illegal mission transition ${from} → ${to}`);
  }
}

/** The outcome of one agent run, as the harness observes it. */
export type RunOutcome =
  | { kind: "done"; report?: string }
  | { kind: "failed"; report?: string }
  | { kind: "needs_input"; question: string }
  | { kind: "interrupted"; report?: string };

/** Map a run outcome to the mission status the harness must write. */
export function nextStatus(outcome: RunOutcome): MissionStatus {
  switch (outcome.kind) {
    case "done":
      return "done";
    case "failed":
      return "failed";
    case "needs_input":
      return "waiting_input";
    case "interrupted":
      return "interrupted";
  }
}

/** Structural parse + validation of a mission section (throws on anything off). */
export function parseMissionSection(raw: unknown): MissionSection {
  if (!raw || typeof raw !== "object") {
    throw new Error("mission section must be an object");
  }
  const o = raw as Record<string, unknown>;
  if (o["type"] !== "mission") {
    throw new Error('mission section: type must be "mission"');
  }
  if (typeof o["id"] !== "string" || !o["id"]) {
    throw new Error("mission section: id is required");
  }
  if (!isMissionStatus(o["status"])) {
    throw new Error(
      `mission section: status must be one of ${MISSION_STATUSES.join(", ")}`,
    );
  }
  if (typeof o["payload"] !== "string") {
    throw new Error("mission section: payload must be a string");
  }
  for (const opt of ["result", "question", "mission_ref"] as const) {
    if (o[opt] !== undefined && typeof o[opt] !== "string") {
      throw new Error(`mission section: ${opt} must be a string`);
    }
  }
  return {
    id: o["id"],
    type: "mission",
    status: o["status"],
    payload: o["payload"],
    ...(o["result"] !== undefined ? { result: o["result"] as string } : {}),
    ...(o["question"] !== undefined ? { question: o["question"] as string } : {}),
    ...(o["mission_ref"] !== undefined ? { mission_ref: o["mission_ref"] as string } : {}),
  };
}
