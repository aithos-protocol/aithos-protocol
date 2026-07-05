// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * The harness — the deterministic supervisor loop (SPEC-container-runtime
 * §13.8.3, PLAN-CONTAINER P1.2). NOT an LLM: "the deterministic loops, the
 * intelligence is invoked."
 *
 * Per iteration it MUST: poll the mailbox for pending missions; CLAIM one
 * (W2, atomic pending → in_progress); spawn a FRESH agent run bound to that
 * mission and a boot-generated config; and, on completion, record the terminal
 * status and report (W1). Each mission ↔ one agent run with fresh context ↔ a
 * bounded set of signed actions.
 *
 * The agent runner is injected (AgentRunner): the real one spawns Claude Code
 * (`claude -p`) against the gateway; tests inject a scripted double.
 */
import {
  nextStatus,
  type MissionSection,
  type RunOutcome,
} from "./mission.js";
import type { Mailbox } from "./mailbox.js";

/** Context handed to a run — chiefly the mission id the gateway attaches to
 * every gamma envelope (so each action traces to the intent that justified it). */
export interface RunContext {
  readonly missionId: string;
  /** Cooperative cancellation: true once the harness has been asked to stop. */
  readonly signal: { readonly stopped: boolean };
}

export interface AgentRunner {
  /** Execute ONE mission as a single fresh agent run; report its outcome. */
  run(mission: MissionSection, ctx: RunContext): Promise<RunOutcome>;
}

export interface HarnessOptions {
  readonly mailbox: Mailbox;
  readonly runner: AgentRunner;
  /** Poll interval for the idle loop. Default 30 000 ms (spec default). */
  readonly tickMs?: number;
  /** Diagnostics sink. Default: stderr. */
  readonly log?: (msg: string) => void;
  /** Injectable sleeper (tests). Default: setTimeout. */
  readonly sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class Harness {
  private readonly mailbox: Mailbox;
  private readonly runner: AgentRunner;
  private readonly tickMs: number;
  private readonly log: (msg: string) => void;
  private readonly sleep: (ms: number) => Promise<void>;
  private stopped = false;

  constructor(opts: HarnessOptions) {
    this.mailbox = opts.mailbox;
    this.runner = opts.runner;
    this.tickMs = opts.tickMs ?? 30_000;
    this.log = opts.log ?? ((m) => console.error(`aithos-harness: ${m}`));
    this.sleep = opts.sleep ?? defaultSleep;
  }

  /** Request shutdown; the loop exits after the current mission (if any). */
  stop(): void {
    this.stopped = true;
  }

  /**
   * One iteration: claim at most one pending mission and run it. Returns the
   * number of missions actually run (0 or 1). Never throws — a run failure is
   * recorded on the mission, the loop survives.
   */
  async tickOnce(): Promise<number> {
    const pending = await this.mailbox.listPending();
    for (const mission of pending) {
      // W2 — claim before run. If we lost the race, try the next candidate.
      const won = await this.mailbox.claim(mission.id);
      if (!won) continue;
      await this.execute({ ...mission, status: "in_progress" });
      return 1;
    }
    return 0;
  }

  /** Run every currently-pending mission (test/local convenience). */
  async drain(): Promise<number> {
    let total = 0;
    // Keep going while claims succeed; bounded by the mailbox emptying.
    // A safety cap guards against a misbehaving mailbox that never drains.
    for (let guard = 0; guard < 10_000; guard++) {
      const ran = await this.tickOnce();
      if (ran === 0) break;
      total += ran;
    }
    return total;
  }

  /**
   * The idle loop: process missions as they appear, sleeping tickMs between
   * empty polls. Exits when `stop()` is called. Resolves when the loop ends.
   */
  async run(): Promise<void> {
    this.log(`started (tick ${this.tickMs}ms)`);
    while (!this.stopped) {
      let ran = 0;
      try {
        ran = await this.tickOnce();
      } catch (e) {
        // tickOnce is defensive, but never let the loop die.
        this.log(`tick error: ${(e as Error).message}`);
      }
      if (this.stopped) break;
      if (ran === 0) await this.sleep(this.tickMs);
    }
    this.log("stopped");
  }

  /** Execute a claimed mission and write its terminal status (W1). */
  private async execute(mission: MissionSection): Promise<void> {
    const ctx: RunContext = {
      missionId: mission.id,
      signal: {
        get stopped() {
          return false;
        },
      } as RunContext["signal"],
    };
    // Bind cancellation to the harness's stop flag.
    Object.defineProperty(ctx.signal, "stopped", {
      get: () => this.stopped,
    });

    let outcome: RunOutcome;
    try {
      outcome = await this.runner.run(mission, ctx);
    } catch (e) {
      outcome = { kind: "failed", report: `run threw: ${(e as Error).message}` };
    }

    const to = nextStatus(outcome);
    const fields: { result?: string; question?: string } = {};
    if (outcome.kind === "needs_input") {
      fields.question = outcome.question;
    } else if ("report" in outcome && outcome.report !== undefined) {
      fields.result = outcome.report;
    }
    await this.mailbox.report(mission.id, to, fields);
    this.log(`mission ${mission.id} → ${to}`);
  }
}
