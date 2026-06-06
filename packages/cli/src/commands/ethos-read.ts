// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos read`
 *
 * Read a v0.3 per-section bundle (the format produced by `migrate-to-v0.3`):
 *
 *   --index               print the section index per zone (id + title). The
 *                         self index is encrypted — titles are shown only when
 *                         the subject's key is available (--handle); otherwise
 *                         they appear as [hidden], exactly as a host would see.
 *   --section <id1,id2>   fetch one or more sections by id (decrypted body).
 *   (neither)             read every section (optionally filtered by --zone).
 *
 * This is the surface a hosting platform builds on: fetch the index to discover
 * section ids/titles, then fetch one or several sections by id.
 */

import { existsSync, readFileSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import AdmZip from "adm-zip";

import {
  loadConfig,
  loadIdentity,
  subjectRecipientFor,
  readSection,
  readZoneIndex,
  SPHERE_FRAGMENTS,
  type ManifestV03,
  type Sphere,
  type SectionReader,
  type Identity,
} from "@aithos/protocol-core";

export interface EthosReadOpts {
  path: string;
  handle?: string;
  section?: string;
  zone?: string;
  index?: boolean;
  json?: boolean;
}

function resolveBundleDir(path: string): { dir: string; cleanup: () => void } {
  if (!existsSync(path)) throw new Error(`Bundle not found: ${path}`);
  if (statSync(path).isDirectory()) return { dir: path, cleanup: () => {} };
  // .ethos zip → extract to a temp dir.
  const tmp = mkdtempSync(join(tmpdir(), "aithos-read-"));
  const zip = new AdmZip(path);
  for (const e of zip.getEntries()) {
    if (e.entryName.includes("..")) throw new Error(`Unsafe zip entry name: ${e.entryName}`);
  }
  zip.extractAllTo(tmp, true);
  return { dir: tmp, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

export function runEthosRead(opts: EthosReadOpts): void {
  const { dir, cleanup } = resolveBundleDir(opts.path);
  try {
    const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as ManifestV03;
    if (manifest.aithos !== "0.3.0") {
      throw new Error(`Not a v0.3 bundle (aithos=${manifest.aithos}). Use a bundle produced by 'migrate-to-v0.3'.`);
    }
    const subjectDid = manifest.subject_did;

    // Keys are optional: with them you decrypt circle/self + the self index;
    // without them you get the host view (public clear, self titles hidden).
    const handle = opts.handle ?? loadConfig().default_handle ?? undefined;
    let identity: Identity | null = null;
    if (handle) {
      try {
        identity = loadIdentity(handle);
      } catch {
        identity = null;
      }
    }
    const readerFor = (zone: Sphere): SectionReader | undefined => {
      if (zone === "public" || !identity) return undefined;
      const r = subjectRecipientFor(identity, zone as "circle" | "self");
      return { didUrl: r.did, x25519Secret: r.x25519Secret };
    };

    const zoneFilter = (opts.zone ? [opts.zone as Sphere] : [...SPHERE_FRAGMENTS]).filter((z) =>
      SPHERE_FRAGMENTS.includes(z as Sphere),
    ) as Sphere[];
    if (opts.zone && zoneFilter.length === 0) throw new Error(`Unknown zone: ${opts.zone}`);

    /* ----- index mode ------------------------------------------------------ */
    if (opts.index) {
      const out: Record<string, unknown> = {};
      for (const zn of zoneFilter) {
        const zm = manifest.zones[zn];
        if (!zm) continue;
        const rows = readZoneIndex(zn, zm, subjectDid, readerFor(zn));
        out[zn] = { index_encrypted: !!zm.index_encrypted, sections: rows };
      }
      if (opts.json) {
        console.log(JSON.stringify({ subject: manifest.subject_handle, bundle_id: manifest.bundle_id, zones: out }, null, 2));
        return;
      }
      console.log(`Index of ${manifest.subject_handle} — ${manifest.bundle_id}`);
      for (const zn of zoneFilter) {
        const zm = manifest.zones[zn];
        if (!zm) continue;
        const rows = readZoneIndex(zn, zm, subjectDid, readerFor(zn));
        const tag = zm.index_encrypted ? "encrypted index" : "clear index";
        console.log(`\n  ${zn} (${tag}) — ${rows.length} section(s):`);
        for (const r of rows) {
          console.log(`    ${r.section_id}  ${r.title_hidden ? "[hidden — need key]" : r.title}`);
        }
      }
      return;
    }

    /* ----- section read mode ---------------------------------------------- */
    // Build the id → zone map from the manifest.
    const locate = (id: string): Sphere | null => {
      for (const zn of zoneFilter) {
        if (manifest.zones[zn]?.sections.some((s) => s.section_id === id)) return zn;
      }
      return null;
    };

    let ids: string[];
    if (opts.section) {
      ids = opts.section.split(",").map((s) => s.trim()).filter(Boolean);
    } else {
      ids = [];
      for (const zn of zoneFilter) {
        for (const s of manifest.zones[zn]?.sections ?? []) ids.push(s.section_id);
      }
    }

    const results = ids.map((id) => {
      const zn = locate(id);
      if (!zn) return { section_id: id, accessible: false, reason: "not found in manifest" };
      const desc = manifest.zones[zn].sections.find((s) => s.section_id === id)!;
      const res = readSection(dir, manifest.zones[zn], desc, subjectDid, readerFor(zn));
      if (res.accessible && res.section) {
        return {
          zone: zn,
          section_id: id,
          accessible: true,
          title: res.section.title,
          body: res.section.body,
          ...(res.section.tags ? { tags: res.section.tags } : {}),
        };
      }
      return { zone: zn, section_id: id, accessible: false, reason: res.reason };
    });

    if (opts.json) {
      console.log(JSON.stringify({ subject: manifest.subject_handle, bundle_id: manifest.bundle_id, sections: results }, null, 2));
      return;
    }
    if (results.length === 0) {
      console.log("(no sections)");
      return;
    }
    for (const r of results) {
      if (r.accessible) {
        console.log(`\n[${r.zone}] ${r.section_id} — ${(r as { title: string }).title}`);
        const tags = (r as { tags?: string[] }).tags;
        if (tags && tags.length) console.log(`  tags: ${tags.join(", ")}`);
        console.log(
          (r as { body: string }).body
            .split("\n")
            .map((l) => `  ${l}`)
            .join("\n"),
        );
      } else {
        console.log(`\n[${(r as { zone?: string }).zone ?? "?"}] ${r.section_id} — INACCESSIBLE (${(r as { reason?: string }).reason})`);
      }
    }
  } finally {
    cleanup();
  }
}
