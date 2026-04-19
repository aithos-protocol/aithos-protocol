/**
 * `aithos ethos init` — create the live on-disk Ethos layout and the first
 * edition (empty zones, height=1, prev_hash=null).
 */

import { existsSync, rmSync } from "node:fs";
import { loadIdentity } from "../identity.js";
import { ensureEthosLayout, ethosDir, persistEdition, type Zones } from "../ethos.js";
import { loadConfig } from "../storage.js";

export interface EthosInitOpts {
  handle?: string;
  force?: boolean;
  json?: boolean;
}

export function runEthosInit(opts: EthosInitOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h> or set a default via `aithos init`.");

  const dir = ethosDir(handle);
  if (existsSync(dir)) {
    if (!opts.force) {
      throw new Error(`Ethos already exists at ${dir}. Use --force to reset it.`);
    }
    rmSync(dir, { recursive: true, force: true });
  }

  ensureEthosLayout(handle);
  const identity = loadIdentity(handle);
  const zones: Zones = {
    public: { sections: [] },
    circle: { sections: [] },
    self: { sections: [] },
  };
  const manifest = persistEdition(handle, identity, zones, { prevManifest: null });

  if (opts.json) {
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }

  console.log(`Ethos initialized for "${handle}"`);
  console.log(`  Directory:    ${dir}`);
  console.log(`  Edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  console.log(`  Bundle id:    ${manifest.bundle_id}`);
  console.log(`  Zones:        public (clear), circle (encrypted), self (encrypted)`);
  console.log();
  console.log(`Next: aithos ethos add-section --zone public --title "Voice" --body "I prefer short paragraphs."`);
}
