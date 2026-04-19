/**
 * `aithos ethos list sections` — list all sections of a zone with their id,
 * title, current revision, and last-updated timestamp.
 */

import { existsSync } from "node:fs";
import { loadIdentity } from "../identity.js";
import { ethosDir, loadZoneDoc, readManifest } from "../ethos.js";
import type { Sphere } from "../did.js";
import { loadConfig } from "../storage.js";

export interface EthosListOpts {
  zone?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosList(opts: EthosListOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }

  const identity = loadIdentity(handle);
  const manifest = readManifest(handle);

  const zones: Sphere[] = opts.zone ? [ensureZone(opts.zone)] : ["public", "circle", "self"];

  const out: Array<{ zone: Sphere; id: string; title: string; revision: number; at: string }> = [];
  for (const z of zones) {
    const doc = loadZoneDoc(handle, z, identity, manifest);
    for (const s of doc.sections) {
      const last = s.revisions[s.revisions.length - 1];
      out.push({ zone: z, id: s.id, title: s.title, revision: last.revision, at: last.at });
    }
  }

  if (opts.json) {
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (out.length === 0) {
    console.log("(no sections)");
    return;
  }

  const w = (s: string, n: number) => s.padEnd(n);
  console.log(w("ZONE", 8) + w("ID", 14) + w("REV", 5) + w("UPDATED", 22) + "TITLE");
  for (const row of out) {
    console.log(
      w(row.zone, 8) + w(row.id, 14) + w(String(row.revision), 5) + w(row.at, 22) + row.title,
    );
  }
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}
