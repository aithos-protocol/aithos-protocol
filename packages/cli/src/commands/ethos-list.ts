// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * `aithos ethos list sections` — list all sections of a zone with their id,
 * title, current gamma_ref, and the timestamp of the latest gamma entry
 * affecting them.
 *
 * Output is a properly padded table with explicit column separators so that
 * IDs cannot visually collide (R3). A trailing `[delegated]` marker is
 * appended to rows whose latest gamma entry was signed via a write-mandate
 * rather than directly by the sphere key (R7).
 */

import { existsSync } from "node:fs";
import {
  loadIdentity,
  isTrackedIdentity,
  TrackedIdentityError,
  ethosDir,
  loadZoneDoc,
  readManifest,
  readGammaLog,
  latestGammaForSection,
  type Sphere,
  type GammaEntry,
  type Identity,
  loadConfig,
} from "@aithos/protocol-core";

export interface EthosListOpts {
  zone?: string;
  handle?: string;
  json?: boolean;
}

interface Row {
  zone: Sphere;
  id: string;
  title: string;
  gamma_ref: string;
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

  // Pull the gamma log once when we have the identity; we'll look up each
  // section's latest entry from memory.
  const gammaEntries: GammaEntry[] | null =
    identity ? safeReadGamma(handle, identity) : null;

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
        // Look up the gamma entry named by gamma_ref — it holds the canonical
        // `at` timestamp and tells us whether the mutation was delegated.
        const latest = gammaEntries
          ? gammaEntries.find((e) => e.id === s.gamma_ref) ??
            latestGammaForSection(gammaEntries, s.id)
          : null;
        rows.push({
          zone: z,
          id: s.id,
          title: s.title,
          gamma_ref: s.gamma_ref,
          at: latest?.at ?? "—",
          delegated: !!latest?.authorized_by,
          mandateId: latest?.authorized_by,
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
  const W_GAMMA = 32; // gamma_<26-char ULID>
  const W_AT = 24;    // ISO 8601 with ms

  const pad = (s: string, n: number) => s.padEnd(n);
  const sep = " │ ";

  const header = [pad("ZONE", W_ZONE), pad("ID", W_ID), pad("GAMMA_REF", W_GAMMA), pad("UPDATED", W_AT), "TITLE"].join(sep);
  const rule =
    "─".repeat(W_ZONE) + "─┼─" +
    "─".repeat(W_ID)   + "─┼─" +
    "─".repeat(W_GAMMA)+ "─┼─" +
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
          pad(r.gamma_ref, W_GAMMA),
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

function safeReadGamma(handle: string, identity: Identity): GammaEntry[] | null {
  try {
    return readGammaLog(handle, identity);
  } catch {
    // Log may be absent on identities that predate v0.2.0 or that have zero
    // sections yet. Treat as "no entries" rather than erroring the listing.
    return null;
  }
}
