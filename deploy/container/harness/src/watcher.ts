// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Revocation / TTL watcher (SPEC-container-runtime §13.9 L2, PLAN P1.3).
 *
 * A sidecar OUTSIDE the cage that, on revocation or on reaching `not_after`,
 * pauses then stops the runtime. This is HYGIENE, not the security boundary:
 * L1 (per-call verification, fail-closed) has already cut every gateway call —
 * including inference — the instant the mandate died. So the watcher is
 * best-effort by design; if it lags, security does not move.
 *
 * Its value is narrative and operational: "the mandate dies, the process dies."
 * The set of running runtimes equals the set of live mandates (ps ≈ authority).
 *
 * The container control (pause/stop) and the revocation lookup are injected —
 * the real bin talks to the Docker socket and the mandate store; tests inject
 * fakes and a virtual clock.
 */

/** The subset of container control the watcher needs (docker pause/stop). */
export interface CageControl {
  pause(): Promise<void>;
  stop(): Promise<void>;
}

export interface RevocationWatcherOptions {
  readonly cage: CageControl;
  /** The mandate's not_after (ISO). Reaching it triggers teardown (TTL). */
  readonly notAfter: string;
  /** Fresh revocation lookup for the mandate. Best-effort: may reject. */
  isRevoked(): Promise<boolean>;
  /** Clock injection. Default: Date.now. */
  now?(): number;
  /** Poll interval for runUntilDone. Default 15 000 ms. */
  readonly pollMs?: number;
  /** Injectable sleeper (tests). Default: setTimeout. */
  sleep?(ms: number): Promise<void>;
  /** Diagnostics sink. Default: stderr. */
  log?(msg: string): void;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class RevocationWatcher {
  private readonly cage: CageControl;
  private readonly notAfterMs: number;
  private readonly isRevoked: () => Promise<boolean>;
  private readonly now: () => number;
  private readonly pollMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly log: (msg: string) => void;
  private actedReason: "revoked" | "expired" | null = null;

  constructor(opts: RevocationWatcherOptions) {
    this.cage = opts.cage;
    this.notAfterMs = Date.parse(opts.notAfter);
    this.isRevoked = opts.isRevoked;
    this.now = opts.now ?? (() => Date.now());
    this.pollMs = opts.pollMs ?? 15_000;
    this.sleep = opts.sleep ?? defaultSleep;
    this.log = opts.log ?? ((m) => console.error(`aithos-watcher: ${m}`));
  }

  /** True once the watcher has torn the cage down (idempotent thereafter). */
  get done(): boolean {
    return this.actedReason !== null;
  }

  /**
   * One check. Tears the cage down (pause → stop) if the mandate is expired or
   * revoked. Never throws: a lookup failure is logged and skipped (best-effort,
   * L1 still holds). Acts at most once.
   */
  async check(): Promise<void> {
    if (this.actedReason) return;

    if (Number.isFinite(this.notAfterMs) && this.now() > this.notAfterMs) {
      await this.teardown("expired");
      return;
    }

    let revoked = false;
    try {
      revoked = await this.isRevoked();
    } catch (e) {
      // Best-effort: the security boundary is L1, not this watcher.
      this.log(`revocation lookup failed (ignored): ${(e as Error).message}`);
      return;
    }
    if (revoked) await this.teardown("revoked");
  }

  /** Poll on `pollMs` until the watcher acts, then resolve. */
  async runUntilDone(): Promise<void> {
    this.log(`watching (poll ${this.pollMs}ms, not_after ${new Date(this.notAfterMs).toISOString()})`);
    while (!this.actedReason) {
      await this.check();
      if (this.actedReason) break;
      await this.sleep(this.pollMs);
    }
  }

  private async teardown(reason: "revoked" | "expired"): Promise<void> {
    this.actedReason = reason;
    this.log(`mandate ${reason} — pausing then stopping the cage`);
    try {
      await this.cage.pause();
    } catch (e) {
      this.log(`pause failed (continuing to stop): ${(e as Error).message}`);
    }
    try {
      await this.cage.stop();
    } catch (e) {
      this.log(`stop failed: ${(e as Error).message}`);
    }
  }
}
