// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos show` — inspect the current ethos state.
 *
 * Default: prints manifest summary (edition, zones, section counts).
 * --zone <z>: prints the zone markdown (decrypts with the local identity if
 * the zone is encrypted).
 * --section <id>: prints the current body of a specific section along with
 * its gamma_ref anchor. Full revision history is not inlined — use
 * `aithos gamma show --section <id>` for the signed mutation log.
 */

import { existsSync, readFileSync } from "node:fs";
import {
  loadIdentity,
  isTrackedIdentity,
  ethosDir,
  ethosZoneFile,
  loadZoneDoc,
  readManifest,
  type Author,
  type Identity,
  type Sphere,
  loadConfig,
  isV03Keystore,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";
import { runEthosRead } from "./ethos-read.js";

export interface EthosShowOpts {
  handle?: string;
  zone?: string;
  section?: string;
  /** Mandate id — for delegate reads of an encrypted zone on a tracked install. */
  mandate?: string;
  /** Delegate keyfile path — required when `mandate` is set. */
  agentKey?: string;
  json?: boolean;
}

export function runEthosShow(opts: EthosShowOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}". Run \`aithos ethos init\`.`);
  }

  // v0.3-native keystore: the ethos dir IS a v0.3 bundle — reuse the read path.
  if (isV03Keystore(handle)) {
    runEthosRead({
      path: ethosDir(handle),
      handle,
      ...(opts.section ? { section: opts.section } : {}),
      ...(opts.zone ? { zone: opts.zone } : {}),
      ...(!opts.section && !opts.zone ? { index: true } : {}),
      ...(opts.mandate ? { mandate: opts.mandate } : {}),
      ...(opts.agentKey ? { agentKey: opts.agentKey } : {}),
      ...(opts.json ? { json: true } : {}),
    });
    return;
  }

  const manifest = readManifest(handle);

  const tracked = isTrackedIdentity(handle);

  if (!opts.zone && !opts.section) {
    if (opts.json) {
      console.log(JSON.stringify({ ...manifest, tracked }, null, 2));
      return;
    }
    const trackedSuffix = tracked ? " [tracked]" : "";
    console.log(`[handle=${handle}]${trackedSuffix} Ethos`);
    console.log(`  DID:          ${manifest.subject_did}`);
    console.log(`  Edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
    console.log(`  Created:      ${manifest.edition.created_at}`);
    console.log(`  Bundle id:    ${manifest.bundle_id}`);
    if (manifest.gamma) {
      console.log(
        `  Gamma:        head=${manifest.gamma.head ?? "(none)"} count=${manifest.gamma.count}`,
      );
    }
    console.log();
    for (const z of ["public", "circle", "self"] as const) {
      const zm = manifest.zones[z];
      const enc = zm.encrypted ? "encrypted" : "clear";
      const lock = tracked && zm.encrypted ? " 🔒 no key" : "";
      console.log(
        `  ${z.padEnd(7)} ${enc} · ${zm.section_titles.length} section(s)${lock}`,
      );
      for (const t of zm.section_titles) console.log(`    - ${t}`);
    }
    return;
  }

  const zone = ensureZone(opts.zone ?? "public");
  // Three auth paths converge into a single `who: Identity | Author | undefined`
  // that gets passed into loadZoneDoc:
  //
  //   - Public zone, anyone:       no `who` needed (plaintext on disk).
  //   - Owned identity, any zone:  use the local Identity (full sphere keys).
  //   - Delegate read (--mandate): build a DelegateAuthor — works on tracked
  //                                installs because the delegate carries a
  //                                DEK wrap from grant-time rewrap.
  let who: Identity | Author | undefined;
  if (zone === "public") {
    who = undefined; // plaintext, no auth needed
    if (opts.mandate) {
      throw new Error(
        `--mandate is only meaningful when reading an encrypted zone (circle | self).`,
      );
    }
  } else if (opts.mandate) {
    const resolved = resolveAuthor({
      handle,
      zone,
      op: "read",
      mandate: opts.mandate,
      agentKey: opts.agentKey,
    });
    who = resolved.author;
  } else if (tracked) {
    throw new Error(
      `cannot read ${zone} zone of "${handle}": identity is tracked-only (no sphere key on disk). ` +
        `Pass --mandate <id> --agent-key <path> to read via a delegate mandate.`,
    );
  } else {
    who = loadIdentity(handle);
  }

  const doc = loadZoneDoc(handle, zone, who, manifest);

  if (opts.section) {
    const sec = doc.sections.find((s) => s.id === opts.section);
    if (!sec) throw new Error(`Section ${opts.section} not found in ${zone}`);
    if (opts.json) {
      console.log(JSON.stringify(sec, null, 2));
      return;
    }
    console.log(`[handle=${handle}] # ${sec.title} (${sec.id}) — zone: ${zone}`);
    console.log(`<!-- gamma_ref: ${sec.gamma_ref} -->`);
    if (sec.tags && sec.tags.length > 0) {
      console.log(`<!-- tags: ${JSON.stringify(sec.tags)} -->`);
    }
    console.log(sec.body);
    return;
  }

  // Zone requested: stream the markdown form.
  if (zone === "public") {
    console.log(readFileSync(ethosZoneFile(handle, zone), "utf8"));
  } else {
    // Re-render decrypted content.
    const md = renderForDisplay(doc, zone, manifest);
    console.log(md);
  }
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}

import {
  renderZoneMarkdown,
  type Manifest,
  type ZoneDoc,
} from "@aithos/protocol-core";

function renderForDisplay(doc: ZoneDoc, zone: Sphere, m: Manifest): string {
  return renderZoneMarkdown(zone, doc, {
    subjectDid: m.subject_did,
    subjectHandle: m.subject_handle,
    editionVersion: m.edition.version,
    createdAt: m.edition.created_at,
  });
}
