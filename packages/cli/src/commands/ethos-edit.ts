// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos write` / `aithos ethos rm`
 *
 * Targeted edit/delete of a section in a v0.3 bundle, by id. Produces a NEW
 * edition directory (`--out`); the source bundle is left untouched (it remains
 * the predecessor in the chain). Owner via `--handle`; delegate via
 * `--mandate` + `--agent-key`. Built on the reusable `editSectionV03` /
 * `deleteSectionV03` primitives.
 */

import { existsSync, readFileSync } from "node:fs";
import {
  editSectionV03,
  deleteSectionV03,
  loadConfig,
  type ManifestV03,
  type Sphere,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";

const ZONES: Sphere[] = ["public", "circle", "self"];

export interface EthosWriteOpts {
  path: string;
  section: string;
  zone?: string;
  title?: string;
  body?: string;
  bodyFile?: string;
  tags?: string;
  clearTags?: boolean;
  out?: string;
  handle?: string;
  mandate?: string;
  agentKey?: string;
  json?: boolean;
}

export interface EthosRmOpts {
  path: string;
  section: string;
  zone?: string;
  out?: string;
  handle?: string;
  mandate?: string;
  agentKey?: string;
  json?: boolean;
}

function loadManifest(path: string): ManifestV03 {
  if (!existsSync(path)) throw new Error(`Bundle not found: ${path}`);
  const m = JSON.parse(readFileSync(`${path.replace(/\/+$/, "")}/manifest.json`, "utf8")) as ManifestV03;
  if (m.aithos !== "0.3.0") throw new Error(`Not a v0.3 bundle (aithos=${m.aithos}).`);
  return m;
}

function locateZone(manifest: ManifestV03, sectionId: string): Sphere | null {
  for (const z of ZONES) {
    if (manifest.zones[z]?.sections.some((s) => s.section_id === sectionId)) return z;
  }
  return null;
}

function defaultOut(path: string, manifest: ManifestV03): string {
  return `${path.replace(/\/+$/, "")}-e${manifest.edition.height + 1}`;
}

export function runEthosWrite(opts: EthosWriteOpts): void {
  const manifest = loadManifest(opts.path);
  const existingZone = locateZone(manifest, opts.section);
  const zone = (opts.zone as Sphere | undefined) ?? existingZone ?? undefined;
  if (!zone) {
    throw new Error(`Section ${opts.section} not found; pass --zone <public|circle|self> to add it.`);
  }
  if (opts.zone && existingZone && existingZone !== opts.zone) {
    throw new Error(`Section ${opts.section} is in zone ${existingZone}, not ${opts.zone}.`);
  }

  let body = opts.body;
  if (opts.bodyFile) {
    if (body !== undefined) throw new Error("Pass only one of --body / --body-file.");
    body = readFileSync(opts.bodyFile, "utf8");
  }
  const tags = opts.tags?.split(",").map((s) => s.trim()).filter(Boolean);
  const change = {
    ...(opts.title !== undefined ? { title: opts.title } : {}),
    ...(body !== undefined ? { body } : {}),
    ...(tags ? { tags } : {}),
    ...(opts.clearTags ? { clearTags: true } : {}),
  };
  if (!existingZone && opts.title === undefined && body === undefined) {
    throw new Error("Adding a new section needs at least --title or --body.");
  }
  if (existingZone && Object.keys(change).length === 0) {
    throw new Error("Nothing to change. Pass --title, --body/--body-file, --tags or --clear-tags.");
  }

  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  const { author } = resolveAuthor({ handle, zone, op: "write", mandate: opts.mandate, agentKey: opts.agentKey });

  const out = opts.out ?? defaultOut(opts.path, manifest);
  const m = editSectionV03({ author, bundleDir: opts.path, outDir: out, zone, sectionId: opts.section, change });

  if (opts.json) {
    console.log(JSON.stringify({ out, bundle_id: m.bundle_id, zone, section_id: opts.section, action: existingZone ? "modified" : "added" }, null, 2));
    return;
  }
  console.log(`${existingZone ? "Modified" : "Added"} ${zone}/${opts.section} → ${out}`);
  console.log(`  bundle_id: ${m.bundle_id} (height ${m.edition.height})`);
}

export function runEthosRm(opts: EthosRmOpts): void {
  const manifest = loadManifest(opts.path);
  const zone = (opts.zone as Sphere | undefined) ?? locateZone(manifest, opts.section) ?? undefined;
  if (!zone) throw new Error(`Section ${opts.section} not found in the bundle.`);

  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  const { author } = resolveAuthor({ handle, zone, op: "write", mandate: opts.mandate, agentKey: opts.agentKey });

  const out = opts.out ?? defaultOut(opts.path, manifest);
  const m = deleteSectionV03({ author, bundleDir: opts.path, outDir: out, zone, sectionId: opts.section });

  if (opts.json) {
    console.log(JSON.stringify({ out, bundle_id: m.bundle_id, zone, section_id: opts.section, action: "deleted" }, null, 2));
    return;
  }
  console.log(`Deleted ${zone}/${opts.section} → ${out}`);
  console.log(`  bundle_id: ${m.bundle_id} (height ${m.edition.height})`);
}
