// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos pack` / `aithos ethos unpack`
 *
 * Pack turns the live ethos/ directory into a .ethos zip per spec §3.2:
 *   manifest.json, did.json, public.md, circle.md.enc, self.md.enc,
 *   gamma.jsonl.enc (sealed mutation log, spec §10), README.txt (optional).
 *
 * Unpack reverses it into a target directory (for distribution / import).
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { basename, isAbsolute, join, resolve, sep } from "node:path";
import AdmZip from "adm-zip";

import {
  ethosDir,
  ethosZoneFile,
  ethosManifestPath,
  readManifest,
  gammaFilePath,
  type Manifest,
  loadConfig,
  isV03Keystore,
  SPHERE_FRAGMENTS,
} from "@aithos/protocol-core";

const README_TXT = `This is an Aithos ethos bundle (.ethos).

It is a signed, structured description of a subject, partitioned into three
zones: public (clear), circle (encrypted), and self (encrypted). Every
section mutation is recorded in the sealed gamma log (gamma.jsonl.enc),
whose current tail is committed to by the signed manifest. See
https://aithos.dev/spec/v0.2 for the specification.

To open: any zip tool, then start with manifest.json.
`;

/* -------------------------------------------------------------------------- */
/*  Pack                                                                      */
/* -------------------------------------------------------------------------- */

export interface EthosPackOpts {
  out?: string;
  handle?: string;
  readme?: boolean;
  json?: boolean;
}

export function runEthosPack(opts: EthosPackOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) throw new Error(`No ethos for "${handle}".`);

  const manifest = readManifest(handle);
  const outPath = opts.out ?? join(process.cwd(), `${handle}-${manifest.edition.version}.ethos`);

  const v03 = isV03Keystore(handle);

  const zip = new AdmZip();
  zip.addLocalFile(ethosManifestPath(handle));
  zip.addLocalFile(join(ethosDir(handle), "did.json"));

  if (v03) {
    // v0.3 per-section layout: zip each zone subdir's blobs under its prefix
    // (public/<id>.md, circle|self/<id>.enc).
    for (const z of SPHERE_FRAGMENTS) {
      const zd = join(ethosDir(handle), z);
      if (!existsSync(zd)) continue;
      for (const fn of readdirSync(zd)) zip.addLocalFile(join(zd, fn), z);
    }
  } else {
    // v0.2 monolithic zone files.
    zip.addLocalFile(ethosZoneFile(handle, "public"));
    if (existsSync(ethosZoneFile(handle, "circle"))) zip.addLocalFile(ethosZoneFile(handle, "circle"));
    if (existsSync(ethosZoneFile(handle, "self"))) zip.addLocalFile(ethosZoneFile(handle, "self"));
  }

  // Sealed gamma log (spec §10). When present, the bundle carries the full
  // mutation history; when absent, the manifest's anchor still commits to the
  // head hash so late delivery of the log stays verifiable. v0.3 keeps the log
  // at the bundle root (gamma.jsonl.enc); v0.2 reads it from the gamma path.
  const gammaPath = v03 ? join(ethosDir(handle), "gamma.jsonl.enc") : gammaFilePath(handle);
  if (existsSync(gammaPath)) zip.addLocalFile(gammaPath);

  // README
  if (opts.readme !== false) zip.addFile("README.txt", Buffer.from(README_TXT, "utf8"));

  zip.writeZip(outPath);

  if (opts.json) {
    console.log(JSON.stringify({ bundle: outPath, bundle_id: manifest.bundle_id }, null, 2));
    return;
  }
  console.log(`[handle=${handle}] Packed ethos to ${outPath}`);
  console.log(`  bundle_id: ${manifest.bundle_id}`);
  if (manifest.gamma) {
    console.log(`  gamma:     head=${manifest.gamma.head ?? "(none)"} count=${manifest.gamma.count}`);
  }
}

/* -------------------------------------------------------------------------- */
/*  Unpack                                                                    */
/* -------------------------------------------------------------------------- */

export interface EthosUnpackOpts {
  path: string;
  out: string;
  json?: boolean;
}

export function runEthosUnpack(opts: EthosUnpackOpts): void {
  if (!existsSync(opts.path)) throw new Error(`Bundle not found: ${opts.path}`);
  mkdirSync(opts.out, { recursive: true, mode: 0o700 });

  const zip = new AdmZip(opts.path);
  const entries = zip.getEntries();

  // Reject forbidden entries (spec §3.2.4). Plaintext markdown is allowed only
  // for the public zone: the v0.2 monolithic `public.md`, or v0.3 per-section
  // `public/<id>.md`. Any other `.md` (a leaked circle/self body) is rejected.
  //
  // Security: bundles are explicitly designed to be imported from third
  // parties, so every entry name is untrusted. Reject absolute paths,
  // backslashes (Windows separators in a foreign bundle) and any traversal
  // (`..`) BEFORE any filesystem write, then re-verify containment of the
  // resolved target (zip-slip, CWE-22).
  const outRoot = resolve(opts.out);
  for (const e of entries) {
    const n = e.entryName;
    if (n.endsWith(".md") && n !== "public.md" && !n.startsWith("public/")) {
      throw new Error(`Forbidden plaintext zone file in bundle: ${n}`);
    }
    if (isAbsolute(n) || n.includes("\\") || /^[A-Za-z]:/.test(n)) {
      throw new Error(`Unsafe entry path in bundle (absolute or backslash): ${n}`);
    }
    if (n.split("/").includes("..")) {
      throw new Error(`Unsafe entry path in bundle (traversal): ${n}`);
    }
  }

  for (const e of entries) {
    const outPath = resolve(outRoot, e.entryName);
    if (outPath !== outRoot && !outPath.startsWith(outRoot + sep)) {
      throw new Error(`Entry escapes extraction root: ${e.entryName}`);
    }
    if (e.isDirectory) {
      mkdirSync(outPath, { recursive: true, mode: 0o700 });
      continue;
    }
    mkdirSync(join(outPath, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(outPath, e.getData(), { mode: 0o600 });
  }

  const m = JSON.parse(readFileSync(join(opts.out, "manifest.json"), "utf8")) as Manifest;
  if (opts.json) {
    console.log(JSON.stringify({ bundle: opts.path, extracted_to: opts.out, bundle_id: m.bundle_id }, null, 2));
    return;
  }
  console.log(`Unpacked ${basename(opts.path)}`);
  console.log(`  into:       ${opts.out}`);
  console.log(`  bundle_id:  ${m.bundle_id}`);
  console.log(`  edition:    ${m.edition.version} (height=${m.edition.height})`);
}
