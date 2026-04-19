/**
 * `aithos ethos verify` — full integrity verification of the live ethos folder.
 *
 * Verifies:
 *   - manifest signature (§3.3.1, §3.8 check 6)
 *   - did.json snapshot sha256 (§3.8 check 4)
 *   - per-zone plaintext sha256 + zone signature (§3.8 check 5, part of 7)
 *   - per-section hash chain and per-revision signatures (§2.5.4.2, §3.8 check 7)
 *   - signatures/<sec>.json agreement with the chain
 *   - edition self-consistency + link with history/<prev>.manifest.json when present
 *     (§3.8 check 8 / 9)
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { loadIdentity, isTrackedIdentity } from "../identity.js";
import { ethosDir, verifyEthos } from "../ethos.js";
import { identityDir, loadConfig, readJson } from "../storage.js";
import type { DidDocument } from "../identity.js";

export interface EthosVerifyOpts {
  handle?: string;
  json?: boolean;
  noDecrypt?: boolean;
}

export function runEthosVerify(opts: EthosVerifyOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
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
    console.log(JSON.stringify({ tracked, ...result }, null, 2));
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
