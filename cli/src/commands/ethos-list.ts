/**
 * `aithos ethos list sections` — list all sections of a zone with their id,
 * title, current revision, and last-updated timestamp.
 *
 * Output is a properly padded table with explicit column separators so that
 * IDs and revision numbers cannot visually collide (R3). A trailing
 * `[delegated]` marker is appended to rows whose latest revision was signed
 * via a write-mandate rather than directly by the sphere key (R7).
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

interface Row {
  zone: Sphere;
  id: string;
  title: string;
  revision: number;
  at: string;
  delegated: boolean;
  mandateId?: string;
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

  const rows: Row[] = [];
  for (const z of zones) {
    const doc = loadZoneDoc(handle, z, identity, manifest);
    for (const s of doc.sections) {
      const last = s.revisions[s.revisions.length - 1];
      const delegated = !!last.authorized_by;
      rows.push({
        zone: z,
        id: s.id,
        title: s.title,
        revision: last.revision,
        at: last.at,
        delegated,
        mandateId: last.authorized_by,
      });
    }
  }

  if (opts.json) {
    console.log(JSON.stringify(rows, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Ethos sections` + (opts.zone ? ` (zone=${opts.zone})` : ""));

  if (rows.length === 0) {
    console.log("(no sections)");
    return;
  }

  // Column widths. TITLE is unbounded (last column).
  const W_ZONE = 7;   // public | circle | self
  const W_ID = 16;    // sec_<12hex>
  const W_REV = 4;    // rev number
  const W_AT = 24;    // ISO 8601 with ms, e.g. 2026-04-19T07:42:40.863Z

  const pad = (s: string, n: number) => s.padEnd(n);
  const sep = " │ ";

  const header = [pad("ZONE", W_ZONE), pad("ID", W_ID), pad("REV", W_REV), pad("UPDATED", W_AT), "TITLE"].join(sep);
  const rule =
    "─".repeat(W_ZONE) + "─┼─" +
    "─".repeat(W_ID)   + "─┼─" +
    "─".repeat(W_REV)  + "─┼─" +
    "─".repeat(W_AT)   + "─┼─" +
    "─".repeat(5);

  console.log(header);
  console.log(rule);
  for (const r of rows) {
    const titleCell = r.delegated ? `${r.title}  [delegated: ${r.mandateId}]` : r.title;
    console.log(
      [
        pad(r.zone, W_ZONE),
        pad(r.id, W_ID),
        pad(String(r.revision), W_REV),
        pad(r.at, W_AT),
        titleCell,
      ].join(sep),
    );
  }
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}
