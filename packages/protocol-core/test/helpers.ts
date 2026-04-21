/**
 * Shared test helpers.
 *
 * Tests run against a fresh, throwaway keystore each time. The trick: every
 * module in protocol-core reads `process.env.AITHOS_HOME` at import time, so
 * tests MUST set the env var *before* importing anything from the library.
 *
 * Pattern used by the test files:
 *
 *   import { mkdtempSync, rmSync } from "node:fs";
 *   import { tmpdir } from "node:os";
 *   import { join } from "node:path";
 *
 *   const tmp = mkdtempSync(join(tmpdir(), "aithos-test-"));
 *   process.env.AITHOS_HOME = tmp;
 *
 *   // Dynamic imports AFTER env is set — otherwise storage.ts has already
 *   // frozen AITHOS_HOME to ~/.aithos.
 *   const core = await import("../src/index.js");
 *
 * After the test suite, call `cleanupKeystore(tmp)` to remove the temp dir.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Create a fresh AITHOS_HOME-style temp dir and set the env var to point to
 * it. Returns the path so the test can clean up afterwards. Call this BEFORE
 * any dynamic import of protocol-core modules.
 */
export function freshKeystore(): string {
  const tmp = mkdtempSync(join(tmpdir(), "aithos-test-"));
  process.env.AITHOS_HOME = tmp;
  return tmp;
}

/** Remove a keystore created by freshKeystore. Safe to call on a missing dir. */
export function cleanupKeystore(path: string): void {
  rmSync(path, { recursive: true, force: true });
}
