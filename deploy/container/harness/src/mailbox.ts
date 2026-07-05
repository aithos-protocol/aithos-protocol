// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * The mailbox — a designated ethos zone used as an asynchronous work queue
 * between a producer (the orchestrator) and the caged agent
 * (SPEC-container-runtime §13.8.2). The producer and the caged agent never
 * talk directly; they rendezvous here, which keeps the cage zero-ingress (N2)
 * and makes the exchange itself an auditable, signed gamma trail.
 *
 * The Mailbox is an interface so the harness can be tested without a gateway.
 * `InMemoryMailbox` is the test/local double; `EthosMailbox` (bin) is the real
 * one, whose atomic claim rides the ethos edition CAS (two harnesses racing a
 * claim: one wins the edition, the other's precondition fails — W2).
 */
import {
  parseMissionSection,
  assertTransition,
  type MissionSection,
  type MissionStatus,
} from "./mission.js";

export interface Mailbox {
  /** All missions currently `pending`, oldest first. */
  listPending(): Promise<MissionSection[]>;
  /**
   * Atomically move `pending` → `in_progress`. Returns true if THIS caller won
   * the claim, false if it was already claimed (idempotency, W2).
   */
  claim(id: string): Promise<boolean>;
  /** Write a terminal/escalation status + optional report/question (W1). */
  report(
    id: string,
    to: MissionStatus,
    fields?: { result?: string; question?: string },
  ): Promise<void>;
  /** Fetch one mission by id (diagnostics / tests). */
  get(id: string): Promise<MissionSection>;
}

/**
 * In-memory mailbox for tests and single-process local runs. The claim is
 * synchronous-atomic within the event loop, faithfully modelling the CAS the
 * ethos-backed mailbox gets from edition height.
 */
export class InMemoryMailbox implements Mailbox {
  private readonly missions = new Map<string, MissionSection>();

  constructor(seed: unknown[] = []) {
    for (const raw of seed) {
      const m = parseMissionSection(raw);
      this.missions.set(m.id, m);
    }
  }

  async listPending(): Promise<MissionSection[]> {
    return [...this.missions.values()].filter((m) => m.status === "pending");
  }

  async claim(id: string): Promise<boolean> {
    const m = this.missions.get(id);
    if (!m || m.status !== "pending") return false;
    assertTransition(m.status, "in_progress");
    this.missions.set(id, { ...m, status: "in_progress" });
    return true;
  }

  async report(
    id: string,
    to: MissionStatus,
    fields: { result?: string; question?: string } = {},
  ): Promise<void> {
    const m = this.missions.get(id);
    if (!m) throw new Error(`mailbox: no mission ${id}`);
    assertTransition(m.status, to);
    this.missions.set(id, {
      ...m,
      status: to,
      ...(fields.result !== undefined ? { result: fields.result } : {}),
      ...(fields.question !== undefined ? { question: fields.question } : {}),
    });
  }

  async get(id: string): Promise<MissionSection> {
    const m = this.missions.get(id);
    if (!m) throw new Error(`mailbox: no mission ${id}`);
    return m;
  }

  /** Test/orchestrator helper: a human answers a waiting_input mission, which
   * re-queues it to pending with the added context (W3). */
  async answer(id: string, humanContext: string): Promise<void> {
    const m = this.missions.get(id);
    if (!m) throw new Error(`mailbox: no mission ${id}`);
    assertTransition(m.status, "pending");
    this.missions.set(id, {
      ...m,
      status: "pending",
      payload: `${m.payload}\n\n[human]: ${humanContext}`,
      mission_ref: m.id,
    });
  }
}
