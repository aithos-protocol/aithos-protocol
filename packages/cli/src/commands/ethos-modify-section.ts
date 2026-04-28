// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * `aithos ethos modify-section` — apply an in-place modification to a section.
 *
 * In v0.2.0 there is no per-section revision array: every change is a signed
 * entry in the gamma log (spec §10.6.1). This command emits one signed
 * `section.modify` entry carrying the full new value of each field being
 * replaced, then updates the live section and its `gamma_ref`.
 *
 * At least one of --title, --body / --body-file, --tags (or --clear-tags)
 * must be provided.
 *
 * Auth: --mandate + --agent-key for delegated writes (works on tracked
 * installs); otherwise the subject must hold the zone's sphere key.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  modifySection,
  ethosDir,
  type Sphere,
  loadConfig,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";

export interface EthosModifySectionOpts {
  zone: string;
  sectionId: string;
  title?: string;
  body?: string;
  bodyFile?: string;
  tags?: string; // comma-separated; sets the full tag list
  clearTags?: boolean; // force tags := []
  mandate?: string;
  agentKey?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosModifySection(opts: EthosModifySectionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);
  const { title, body, tags } = resolveChanges(opts);

  if (title === undefined && body === undefined && tags === undefined) {
    throw new Error(
      "Nothing to modify. Pass at least one of --title, --body/--body-file, --tags, --clear-tags.",
    );
  }

  const { author, mandate } = resolveAuthor({
    handle,
    zone,
    mandate: opts.mandate,
    agentKey: opts.agentKey,
  });

  const { section, manifest, gammaEntry } = modifySection({
    handle,
    author,
    zone,
    sectionId: opts.sectionId,
    title,
    body,
    tags,
  });

  if (opts.json) {
    console.log(JSON.stringify({ section, manifest, gammaEntry }, null, 2));
    return;
  }

  const changed: string[] = [];
  if (title !== undefined) changed.push("title");
  if (body !== undefined) changed.push("body");
  if (tags !== undefined) changed.push("tags");

  console.log(`[handle=${handle}] Modified ${opts.sectionId} in ${zone} (${changed.join(", ")})`);
  console.log(`  gamma:        ${gammaEntry.id}`);
  console.log(`  gamma.head:   ${manifest.gamma?.head ?? "(none)"} (count=${manifest.gamma?.count ?? 0})`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  if (mandate) console.log(`  authorized:   ${mandate.id}`);
  console.log(`  section.gamma_ref: ${section.gamma_ref}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}

function resolveChanges(opts: EthosModifySectionOpts): {
  title?: string;
  body?: string;
  tags?: string[];
} {
  if (opts.body && opts.bodyFile) {
    throw new Error("Pass either --body or --body-file, not both.");
  }
  if (opts.tags && opts.clearTags) {
    throw new Error("Pass either --tags or --clear-tags, not both.");
  }

  const out: { title?: string; body?: string; tags?: string[] } = {};
  if (opts.title !== undefined) out.title = opts.title;
  if (opts.body !== undefined) out.body = opts.body;
  if (opts.bodyFile !== undefined) {
    out.body = readFileSync(opts.bodyFile, "utf8").replace(/\s+$/, "");
  }
  if (opts.tags !== undefined) {
    out.tags = opts.tags.split(",").map((t) => t.trim()).filter(Boolean);
  }
  if (opts.clearTags) out.tags = [];
  return out;
}
