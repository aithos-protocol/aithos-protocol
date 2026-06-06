// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos init` — create the live on-disk Ethos layout and the first
 * edition (empty zones, height=1, prev_hash=null).
 *
 * Exposes a reusable `initializeEthos(handle, { force })` primitive so that
 * `aithos init` can create the ethos in the same call as the identity.
 */

import { existsSync, rmSync } from "node:fs";
import {
  loadIdentity,
  ensureEthosLayout,
  ethosDir,
  persistEdition,
  type Zones,
  loadConfig,
  type Manifest,
  type ManifestV03,
  defaultWriteFormat,
  initKeystoreV03,
} from "@aithos/protocol-core";

export interface EthosInitOpts {
  handle?: string;
  force?: boolean;
  json?: boolean;
}

/**
 * Pure primitive — creates the ethos layout and persists the first edition.
 * Throws if an ethos already exists at the target path unless `force` is set.
 * Does not print anything.
 *
 * Writes in the default on-disk format ({@link defaultWriteFormat}): v0.3 (an
 * empty per-section bundle) unless `AITHOS_FORMAT=v0.2` selects the legacy
 * monolithic layout.
 */
export function initializeEthos(
  handle: string,
  opts: { force?: boolean } = {},
): { dir: string; manifest: Manifest | ManifestV03 } {
  const dir = ethosDir(handle);
  if (existsSync(dir)) {
    if (!opts.force) {
      throw new Error(`Ethos already exists at ${dir}. Use --force to reset it.`);
    }
    rmSync(dir, { recursive: true, force: true });
  }

  const identity = loadIdentity(handle);

  if (defaultWriteFormat() === "v0.3") {
    const manifest = initKeystoreV03({ handle, identity });
    return { dir, manifest };
  }

  ensureEthosLayout(handle);
  const zones: Zones = {
    public: { sections: [] },
    circle: { sections: [] },
    self: { sections: [] },
  };
  const manifest = persistEdition(handle, identity, zones, { prevManifest: null });
  return { dir, manifest };
}

export function runEthosInit(opts: EthosInitOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h> or set a default via `aithos init`.");

  const { dir, manifest } = initializeEthos(handle, { force: opts.force });

  if (opts.json) {
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Ethos initialized`);
  console.log(`  Directory:    ${dir}`);
  console.log(`  Format:       ${manifest.aithos === "0.3.0" ? "v0.3 (per-section)" : "v0.2 (monolithic)"}`);
  console.log(`  Edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  console.log(`  Bundle id:    ${manifest.bundle_id}`);
  console.log(`  Zones:        public (clear), circle (encrypted), self (encrypted)`);
  console.log();
  console.log(`Next: aithos ethos add-section --zone public --title "Voice" --body "I prefer short paragraphs."`);
}
