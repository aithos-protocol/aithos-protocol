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
import { loadIdentity, isTrackedIdentity, TrackedIdentityError } from "../identity.js";
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

interface SkippedZone {
  zone: Sphere;
  reason: string;
}

export function runEthosList(opts: EthosListOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }

  const tracked = isTrackedIdentity(handle);
  // Tracked identities can only load the public zone; circle/self are encrypted
  // and we don't hold the sphere secrets to decrypt them.
  const identity = tracked ? null : loadIdentity(handle);
  const manifest = readManifest(handle);

  const zones: Sphere[] = opts.zone ? [ensureZone(opts.zone)] : ["public", "circle", "self"];

  const rows: Row[] = [];
  const skipped: SkippedZone[] = [];
  for (const z of zones) {
    if (tracked && z !== "public") {
      skipped.push({
        zone: z,
        reason: "encrypted — no sphere key (identity is tracked-only)",
      });
      continue;
    }
    try {
      const doc = loadZoneDoc(handle, z, identity ?? undefined, manifest);
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
    } catch (e) {
      if (e instanceof TrackedIdentityError) {
        skipped.push({ zone: z, reason: e.message });
      } else {
        throw e;
      }
    }
  }

  if (opts.json) {
    console.log(JSON.stringify({ rows, skipped, tracked }, null, 2));
    return;
  }

  const trackedSuffix = tracked ? " [tracked]" : "";
  console.log(
    `[handle=${handle}]${trackedSuffix} Ethos sections` +
      (opts.zone ? ` (zone=${opts.zone})` : ""),
  );

  if (rows.length === 0 && skipped.length === 0) {
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

  if (rows.length > 0) {
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
  if (skipped.length > 0) {
    if (rows.length > 0) console.log();
    for (const s of skipped) {
      console.log(`  (${s.zone}: ${s.reason})`);
    }
  }
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}
