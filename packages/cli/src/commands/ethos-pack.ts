/**
 * `aithos ethos pack` / `aithos ethos unpack`
 *
 * Pack turns the live ethos/ directory into a .ethos zip per spec §3.2:
 *   manifest.json, did.json, public.md, circle.md.enc, self.md.enc, signatures/,
 *   README.txt (optional, human-readable).
 *
 * Unpack reverses it into a target directory (for distribution / import).
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import AdmZip from "adm-zip";

import {
  ethosDir,
  ethosZoneFile,
  ethosSignaturesDir,
  ethosManifestPath,
  readManifest,
  type Manifest,
  loadConfig,
} from "@aithos/protocol-core";

const README_TXT = `This is an Aithos ethos bundle (.ethos).

It is a signed, structured description of a subject, partitioned into three
zones: public (clear), circle (encrypted), and self (encrypted). See
https://aithos.dev/spec/v0.1 for the specification.

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

  const zip = new AdmZip();
  zip.addLocalFile(ethosManifestPath(handle));
  zip.addLocalFile(join(ethosDir(handle), "did.json"));

  // Zone files
  zip.addLocalFile(ethosZoneFile(handle, "public"));
  if (existsSync(ethosZoneFile(handle, "circle"))) zip.addLocalFile(ethosZoneFile(handle, "circle"));
  if (existsSync(ethosZoneFile(handle, "self"))) zip.addLocalFile(ethosZoneFile(handle, "self"));

  // signatures/
  if (existsSync(ethosSignaturesDir(handle))) {
    for (const fn of readdirSync(ethosSignaturesDir(handle))) {
      zip.addLocalFile(join(ethosSignaturesDir(handle), fn), "signatures");
    }
  }

  // README
  if (opts.readme !== false) zip.addFile("README.txt", Buffer.from(README_TXT, "utf8"));

  zip.writeZip(outPath);

  if (opts.json) {
    console.log(JSON.stringify({ bundle: outPath, bundle_id: manifest.bundle_id }, null, 2));
    return;
  }
  console.log(`[handle=${handle}] Packed ethos to ${outPath}`);
  console.log(`  bundle_id: ${manifest.bundle_id}`);
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

  // Reject forbidden entries (spec §3.2.4).
  for (const e of entries) {
    const n = e.entryName;
    if (n.endsWith(".md") && n !== "public.md") {
      throw new Error(`Forbidden plaintext zone file in bundle: ${n}`);
    }
  }

  for (const e of entries) {
    const outPath = join(opts.out, e.entryName);
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
