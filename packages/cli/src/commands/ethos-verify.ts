/**
 * `aithos ethos verify` — integrity verification of an ethos.
 *
 * Two modes:
 *
 *   1. `--handle <h>` (default) — verify the installed live folder in the
 *      keystore. Full verification: signatures, chains, manifest, edition link
 *      with history/<prev>.manifest.json when present (§3.8, all checks).
 *
 *   2. `--path <dir|.ethos>` — stateless verification of a bundle. Does not
 *      require the identity to be installed in the keystore. See spec §9.4 for
 *      the exact scope; summary: checks 1, 2, 3, 4, 6, 8 always; checks 5 and
 *      7 fully for `public`, skipped with a warning for encrypted zones.
 *
 * Exit codes:
 *   - 0 → valid (may have warnings)
 *   - 1 → parsed but invalid (failed signatures, broken chains, …)
 *   - 2 → unparseable input (caller converts thrown errors)
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  loadIdentity,
  isTrackedIdentity,
  ethosDir,
  verifyEthos,
  verifyBundleAtPath,
  identityDir,
  loadConfig,
  readJson,
  type DidDocument,
} from "@aithos/protocol-core";

export interface EthosVerifyOpts {
  handle?: string;
  path?: string;
  json?: boolean;
  noDecrypt?: boolean;
}

export function runEthosVerify(opts: EthosVerifyOpts): void {
  if (opts.path) {
    return runVerifyPath(opts);
  }
  return runVerifyHandle(opts);
}

/* -------------------------------------------------------------------------- */
/*  Mode 1 — installed handle                                                 */
/* -------------------------------------------------------------------------- */

function runVerifyHandle(opts: EthosVerifyOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h> or --path <p>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }

  const didDoc = readJson<DidDocument>(join(identityDir(handle), "did.json"));
  // Tracked identities have no sealed seeds → we silently downgrade to
  // public-only verification (same effect as --no-decrypt).
  const tracked = isTrackedIdentity(handle);
  const identity = opts.noDecrypt || tracked ? null : loadIdentity(handle);

  const result = verifyEthos(handle, identity, didDoc);

  if (opts.json) {
    console.log(JSON.stringify({ mode: "handle", handle, tracked, ...result }, null, 2));
    process.exit(result.ok ? 0 : 1);
  }

  const trackedSuffix = tracked ? " [tracked — public-only verify]" : "";
  if (result.ok) {
    console.log(`[handle=${handle}]${trackedSuffix} ethos: OK`);
    for (const w of result.warnings) console.log(`  warning: ${w}`);
    return;
  }

  console.log(`[handle=${handle}]${trackedSuffix} ethos: FAILED`);
  for (const e of result.errors) console.log(`  - ${e}`);
  for (const w of result.warnings) console.log(`  warning: ${w}`);
  process.exit(1);
}

/* -------------------------------------------------------------------------- */
/*  Mode 2 — stateless path                                                   */
/* -------------------------------------------------------------------------- */

function runVerifyPath(opts: EthosVerifyOpts): void {
  const path = opts.path!;
  let result;
  try {
    result = verifyBundleAtPath(path);
  } catch (e) {
    // Unparseable bundle (missing path, bad zip, forbidden entries, etc.) — §9.4.
    const msg = (e as Error).message;
    if (opts.json) {
      console.log(JSON.stringify({ mode: "path", path, ok: false, unparseable: true, error: msg }, null, 2));
    } else {
      console.error(`aithos: ${msg}`);
    }
    process.exit(2);
  }

  if (opts.json) {
    console.log(JSON.stringify({ mode: "path", path, ...result }, null, 2));
    process.exit(result.ok ? 0 : 1);
  }

  const label = result.subject_handle
    ? `[path=${path}] (${result.subject_handle}, edition ${result.edition?.version}) bundle`
    : `[path=${path}] bundle`;

  const skippedSuffix = result.zones_skipped.length > 0
    ? ` [skipped: ${result.zones_skipped.join(", ")} (encrypted)]`
    : "";

  if (result.ok) {
    console.log(`${label}: OK${skippedSuffix}`);
    for (const w of result.warnings) console.log(`  warning: ${w}`);
    return;
  }

  console.log(`${label}: FAILED${skippedSuffix}`);
  for (const e of result.errors) console.log(`  - ${e}`);
  for (const w of result.warnings) console.log(`  warning: ${w}`);
  process.exit(1);
}
