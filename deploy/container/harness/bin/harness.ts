#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Harness entrypoint (PLAN-CONTAINER P1.2): wire the deterministic loop to the
 * REAL world inside the cage —
 *
 *   mailbox  = an ethos zone reached through the gateway MCP (ethos_search /
 *              ethos_read_sections to poll, ethos_update_section to claim +
 *              report). The gateway signs every write with the delegate key
 *              and attaches AITHOS_MISSION_ID → gamma correlation (§13.8.3).
 *   runner   = spawn a FRESH `claude -p` per mission against the same gateway,
 *              with the mission id exported so the gateway can stamp it.
 *
 * This file is intentionally thin: all the logic (and all the tests) live in
 * src/. It is exercised end to end when the container runs; the deterministic
 * core is what CI proves.
 *
 * NOTE: the EthosMailbox below is the P1 integration surface. It depends on the
 * mission-section tool contract the gateway exposes; until that ethos schema is
 * finalised (mission sections tagged `mission` in a dedicated zone), the job
 * mode (entrypoint-runtime.sh, one mission per container) remains the shipping
 * path. Set AITHOS_HARNESS=1 to opt into the loop.
 */
import { spawn } from "node:child_process";

import { Harness, type AgentRunner, type RunContext } from "../src/harness.js";
import type { Mailbox } from "../src/mailbox.js";
import {
  parseMissionSection,
  type MissionSection,
  type MissionStatus,
} from "../src/mission.js";

/* -------------------------------------------------------------------------- */
/* Ethos-backed mailbox (via the gateway MCP over HTTP)                        */
/* -------------------------------------------------------------------------- */

interface McpCaller {
  call(tool: string, args: Record<string, unknown>): Promise<unknown>;
}

/**
 * A mailbox whose sections live in a dedicated ethos zone, reached through the
 * gateway. Claim rides the edition CAS: `ethos_update_section` with the
 * observed version as a precondition — two harnesses racing a claim, one wins
 * the edition, the other's precondition fails (W2). The gateway owns the
 * signing + gamma; the harness only proposes transitions.
 */
export class EthosMailbox implements Mailbox {
  constructor(
    private readonly mcp: McpCaller,
    private readonly zone = process.env.AITHOS_MAILBOX_ZONE ?? "circle",
  ) {}

  async listPending(): Promise<MissionSection[]> {
    const res = (await this.mcp.call("ethos_search", {
      zone: this.zone,
      tag: "mission",
    })) as { sections?: unknown[] };
    return (res.sections ?? [])
      .map((s) => {
        try {
          return parseMissionSection(s);
        } catch {
          return null;
        }
      })
      .filter((m): m is MissionSection => m !== null && m.status === "pending");
  }

  async claim(id: string): Promise<boolean> {
    try {
      await this.mcp.call("ethos_update_section", {
        zone: this.zone,
        section_id: id,
        // The gateway enforces the pending→in_progress precondition + signs.
        body: JSON.stringify({ status: "in_progress" }),
        expect_status: "pending",
      });
      return true;
    } catch {
      return false; // lost the race, or already claimed
    }
  }

  async report(
    id: string,
    to: MissionStatus,
    fields: { result?: string; question?: string } = {},
  ): Promise<void> {
    await this.mcp.call("ethos_update_section", {
      zone: this.zone,
      section_id: id,
      body: JSON.stringify({ status: to, ...fields }),
    });
  }

  async get(id: string): Promise<MissionSection> {
    const res = (await this.mcp.call("ethos_read_section", {
      zone: this.zone,
      section_id: id,
    })) as unknown;
    return parseMissionSection(res);
  }
}

/* -------------------------------------------------------------------------- */
/* Claude Code runner                                                         */
/* -------------------------------------------------------------------------- */

/** Spawn a fresh `claude -p` bound to the mission; the mission id is exported
 * so the gateway stamps every gamma envelope with it (§13.8.3). */
export class ClaudeCodeRunner implements AgentRunner {
  constructor(
    private readonly mcpConfigPath: string,
    private readonly timeoutMs = Number(process.env.AITHOS_MISSION_TIMEOUT_MS ?? 600_000),
  ) {}

  run(mission: MissionSection, ctx: RunContext): Promise<import("../src/mission.js").RunOutcome> {
    return new Promise((resolve) => {
      const child = spawn(
        "claude",
        [
          "-p",
          mission.payload,
          "--output-format",
          "stream-json",
          "--mcp-config",
          this.mcpConfigPath,
          "--dangerously-skip-permissions",
        ],
        {
          env: { ...process.env, AITHOS_MISSION_ID: ctx.missionId },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );

      let out = "";
      let err = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
      }, this.timeoutMs);

      child.stdout.on("data", (d) => (out += d.toString()));
      child.stderr.on("data", (d) => (err += d.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        if (ctx.signal.stopped) {
          resolve({ kind: "interrupted", report: "harness stopping" });
        } else if (code === 0) {
          resolve({ kind: "done", report: summarise(out) });
        } else {
          resolve({ kind: "failed", report: summarise(err || out) || `exit ${code}` });
        }
      });
    });
  }
}

function summarise(s: string, max = 2000): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

async function main(): Promise<void> {
  const gateway = process.env.AITHOS_GATEWAY_URL;
  if (!gateway) throw new Error("AITHOS_GATEWAY_URL is required");
  const mcpConfig = process.env.AITHOS_MCP_CONFIG ?? "/tmp/.mcp.json";

  // The MCP caller is created lazily by the deployment (a thin HTTP MCP client
  // bound to the gateway bearer). Kept out of this file so the loop stays
  // transport-agnostic and unit-tested; the integration wiring is provided by
  // the image build. Until then, fail loud rather than pretend.
  throw new Error(
    "harness bin: EthosMailbox MCP client wiring is provided by the image " +
      "integration layer (P1 shipping path is job mode; set AITHOS_HARNESS=1 " +
      "only with the mission-zone schema in place). See README.",
  );
  // Example once the MCP client is injected:
  //   const mcp = await connectGatewayMcp(gateway, process.env.AITHOS_MCP_TOKEN!);
  //   const mailbox = new EthosMailbox(mcp);
  //   const runner = new ClaudeCodeRunner(mcpConfig);
  //   const harness = new Harness({ mailbox, runner });
  //   process.on("SIGTERM", () => harness.stop());
  //   process.on("SIGINT", () => harness.stop());
  //   await harness.run();
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "")) {
  main().catch((e) => {
    console.error(`aithos-harness: ${(e as Error).message}`);
    process.exit(1);
  });
}
