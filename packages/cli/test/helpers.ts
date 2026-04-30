// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Shared CLI-test helpers.
 *
 * Each scenario:
 *   1. Allocates a fresh, throwaway AITHOS_HOME.
 *   2. Spawns the built `aithos` binary (packages/cli/dist/index.js) with that
 *      env var set, so the CLI sees a clean keystore.
 *   3. After the test, removes the temp dir.
 *
 * Spawning the real binary — as opposed to calling `runX(...)` in-process —
 * is deliberate: it exercises the argument parsing, the `wrap(() => ...)`
 * error boundary, and the commander wiring, which function-level tests skip.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, type SpawnSyncOptions } from "node:child_process";

/** Absolute path to the built CLI entry — used as `node <path> ...`. */
export const CLI_BIN = resolve(
  fileURLToPath(new URL("../dist/index.js", import.meta.url)),
);

/** Create a fresh, isolated AITHOS_HOME and return its path. */
export function freshHome(): string {
  return mkdtempSync(join(tmpdir(), "aithos-cli-test-"));
}

/** Remove a home created by `freshHome`. Safe on a missing dir. */
export function cleanupHome(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

export interface RunResult {
  stdout: string;
  stderr: string;
  status: number;
}

export interface RunOpts {
  home: string;
  /** Extra env vars on top of process.env + AITHOS_HOME. */
  env?: Record<string, string>;
  /** Working directory for the child. Defaults to the home itself so
   * `aithos ethos pack` without --out lands in a predictable place. */
  cwd?: string;
  /** If true, throw instead of returning non-zero. Default: true. */
  expectOk?: boolean;
  /** Optional stdin payload. */
  input?: string;
}

/** Invoke `aithos <args...>` and return its exit status + captured streams. */
export function runCli(args: string[], opts: RunOpts): RunResult {
  const expectOk = opts.expectOk !== false;
  const spawnOpts: SpawnSyncOptions = {
    cwd: opts.cwd ?? opts.home,
    encoding: "utf8",
    env: {
      ...process.env,
      AITHOS_HOME: opts.home,
      ...(opts.env ?? {}),
    },
    ...(opts.input !== undefined ? { input: opts.input } : {}),
  };
  const res = spawnSync("node", [CLI_BIN, ...args], spawnOpts);

  const stdout = typeof res.stdout === "string" ? res.stdout : "";
  const stderr = typeof res.stderr === "string" ? res.stderr : "";
  const status = res.status ?? (res.signal ? 128 : 1);

  if (expectOk && status !== 0) {
    throw new Error(
      `aithos ${args.join(" ")} exited with status ${status}\n` +
        `  stdout: ${stdout}\n` +
        `  stderr: ${stderr}`,
    );
  }
  return { stdout, stderr, status };
}

/** Invoke the CLI with `--json` and parse the stdout as a JSON object. */
export function runCliJson<T = unknown>(args: string[], opts: RunOpts): T {
  const res = runCli([...args, "--json"], opts);
  try {
    return JSON.parse(res.stdout) as T;
  } catch (e) {
    throw new Error(
      `Failed to parse JSON from \`aithos ${args.join(" ")} --json\`: ` +
        `${(e as Error).message}\n  stdout: ${res.stdout}\n  stderr: ${res.stderr}`,
    );
  }
}
