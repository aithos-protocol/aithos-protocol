// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos delete-section` — remove a section from its zone while
 * preserving full audit history in the gamma deep-memory log.
 *
 * After this command runs:
 *   - the section no longer appears in the current edition (pack/install
 *     sees it as if it never existed in the live doc),
 *   - the gamma log retains the original `section.add` entry AND a new
 *     `section.delete` entry, both signed and hash-chained,
 *   - `manifest.gamma.head` advances to the new delete entry.
 *
 * Auth: --mandate + --agent-key for delegated deletes (works on tracked
 * installs); otherwise the subject must hold the zone's sphere key.
 */

import { existsSync } from "node:fs";
import {
  deleteSection,
  ethosDir,
  type Sphere,
  loadConfig,
  isV03Keystore,
  keystoreEditSection,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";
import { autoMigrateOwnerWrite } from "./_format.js";

export interface EthosDeleteSectionOpts {
  zone: string;
  section: string;
  reason?: string;
  mandate?: string;
  agentKey?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosDeleteSection(opts: EthosDeleteSectionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);

  const { author, mandate } = resolveAuthor({
    handle,
    zone,
    mandate: opts.mandate,
    agentKey: opts.agentKey,
  });

  // Default flip (lot 4b-3): the first owner write upgrades a v0.2 keystore.
  if (autoMigrateOwnerWrite(handle, Boolean(opts.mandate))) {
    console.error(`[handle=${handle}] Ethos auto-migrated to v0.3 (per-section); prior v0.2 edition archived in history/.`);
  }

  // v0.3-native keystore: drop the per-section blob in place.
  if (isV03Keystore(handle)) {
    const m = keystoreEditSection({ handle, author, zone, sectionId: opts.section, delete: true });
    if (opts.json) {
      console.log(JSON.stringify({ section_id: opts.section, zone, manifest: m }, null, 2));
      return;
    }
    console.log(`[handle=${handle}] Deleted ${opts.section} from zone ${zone} (v0.3)`);
    console.log(`  edition:  ${m.edition.version} (height=${m.edition.height})`);
    if (mandate) console.log(`  authorized: ${mandate.id}`);
    return;
  }

  const { manifest, gammaEntry, deletedTitle } = deleteSection({
    handle,
    author,
    zone,
    sectionId: opts.section,
    reason: opts.reason,
  });

  if (opts.json) {
    console.log(JSON.stringify({ manifest, gammaEntry, deletedTitle }, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Deleted section from zone ${zone}`);
  console.log(`  id:           ${opts.section}`);
  console.log(`  title:        ${deletedTitle}`);
  console.log(`  reason:       ${opts.reason ?? "(none)"}`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  console.log(`  gamma:        ${gammaEntry.id}`);
  console.log(`  gamma.head:   ${manifest.gamma?.head ?? "(none)"} (count=${manifest.gamma?.count ?? 0})`);
  if (mandate) console.log(`  authorized:   ${mandate.id}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}
