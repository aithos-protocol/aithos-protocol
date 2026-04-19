/**
 * `aithos ethos show` — inspect the current ethos state.
 *
 * Default: prints manifest summary (edition, zones, section counts).
 * --zone <z>: prints the zone markdown (decrypts with the local identity if
 * the zone is encrypted).
 * --section <id>: prints the current body of a specific section.
 */

import { existsSync, readFileSync } from "node:fs";
import { loadIdentity } from "../identity.js";
import { ethosDir, ethosZoneFile, loadZoneDoc, readManifest } from "../ethos.js";
import type { Sphere } from "../did.js";
import { loadConfig } from "../storage.js";

export interface EthosShowOpts {
  handle?: string;
  zone?: string;
  section?: string;
  json?: boolean;
  revisions?: boolean;
}

export function runEthosShow(opts: EthosShowOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}". Run \`aithos ethos init\`.`);
  }

  const manifest = readManifest(handle);

  if (!opts.zone && !opts.section) {
    if (opts.json) {
      console.log(JSON.stringify(manifest, null, 2));
      return;
    }
    console.log(`Ethos of "${handle}"`);
    console.log(`  DID:          ${manifest.subject_did}`);
    console.log(`  Edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
    console.log(`  Created:      ${manifest.edition.created_at}`);
    console.log(`  Bundle id:    ${manifest.bundle_id}`);
    console.log();
    for (const z of ["public", "circle", "self"] as const) {
      const zm = manifest.zones[z];
      const enc = zm.encrypted ? "encrypted" : "clear";
      console.log(`  ${z.padEnd(7)} ${enc} · ${zm.section_titles.length} section(s)`);
      for (const t of zm.section_titles) console.log(`    - ${t}`);
    }
    return;
  }

  const zone = ensureZone(opts.zone ?? "public");
  const identity = loadIdentity(handle);
  const doc = loadZoneDoc(handle, zone, identity, manifest);

  if (opts.section) {
    const sec = doc.sections.find((s) => s.id === opts.section);
    if (!sec) throw new Error(`Section ${opts.section} not found in ${zone}`);
    if (opts.json) {
      console.log(JSON.stringify(sec, null, 2));
      return;
    }
    console.log(`# ${sec.title} (${sec.id}) — zone: ${zone}`);
    if (opts.revisions) {
      for (const r of sec.revisions) {
        console.log(`\n<!-- rev ${r.revision} at ${r.at} hash ${r.hash} -->`);
        console.log(r.body);
      }
    } else {
      const current = sec.revisions[sec.revisions.length - 1];
      console.log(current.body);
    }
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

import { renderZoneMarkdown } from "../ethos.js";
import type { Manifest, ZoneDoc } from "../ethos.js";

function renderForDisplay(doc: ZoneDoc, zone: Sphere, m: Manifest): string {
  return renderZoneMarkdown(zone, doc, {
    subjectDid: m.subject_did,
    subjectHandle: m.subject_handle,
    editionVersion: m.edition.version,
    createdAt: m.edition.created_at,
  });
}
