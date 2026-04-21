/**
 * `aithos gamma show` — inspect the gamma deep-memory log.
 *
 * Modes:
 *   - default: one-line-per-entry index (id, at, op, zone, short target)
 *       followed by a footer with count + head hash.
 *   - `--section <id>`: filter to entries whose target.section_id matches.
 *   - `--id <gamma_id>`: show a single entry in full JSON.
 *   - `--head`: just print "<head>\tcount=<N>" (quick manifest cross-check).
 *   - `--json`: machine-readable JSON (array of entries, or a single entry).
 */

import { existsSync } from "node:fs";
import {
  loadIdentity,
  loadConfig,
  ethosDir,
  readGammaLog,
  gammaHead,
  readManifest,
  type GammaEntry,
} from "@aithos/protocol-core";

export interface GammaShowOpts {
  handle?: string;
  section?: string;
  id?: string;
  head?: boolean;
  json?: boolean;
}

export function runGammaShow(opts: GammaShowOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }
  const identity = loadIdentity(handle);

  // `--head`: cheapest mode, works even when the log is absent.
  if (opts.head) {
    const head = gammaHead(handle, identity);
    const entries = readGammaLog(handle, identity);
    if (opts.json) {
      console.log(JSON.stringify({ head, count: entries.length }, null, 2));
    } else {
      console.log(`${head ?? "(none)"}\tcount=${entries.length}`);
    }
    return;
  }

  const entries = readGammaLog(handle, identity);

  // `--id`: single-entry lookup.
  if (opts.id) {
    const match = entries.find((e) => e.id === opts.id);
    if (!match) throw new Error(`No gamma entry with id ${opts.id}`);
    if (opts.json) {
      console.log(JSON.stringify(match, null, 2));
    } else {
      printFullEntry(match);
    }
    return;
  }

  // `--section`: per-section filter.
  const filtered: GammaEntry[] = opts.section
    ? entries.filter(
        (e) => typeof e.target?.section_id === "string" && e.target.section_id === opts.section,
      )
    : entries;

  if (opts.json) {
    console.log(JSON.stringify(filtered, null, 2));
    return;
  }

  if (filtered.length === 0) {
    const scope = opts.section ? ` for section ${opts.section}` : "";
    console.log(`[handle=${handle}] (empty gamma log${scope})`);
    return;
  }

  const manifest = safeReadManifest(handle);
  const manifestHead = manifest?.gamma?.head ?? null;
  const actualHead = entries.length > 0 ? entries[entries.length - 1].hash : null;

  console.log(`[handle=${handle}] gamma log (${filtered.length} of ${entries.length} entries)`);
  for (const e of filtered) {
    console.log(formatIndexLine(e));
  }
  console.log("");
  console.log(`  head:       ${actualHead ?? "(none)"}`);
  console.log(`  count:      ${entries.length}`);
  if (manifestHead !== null) {
    const match = manifestHead === actualHead ? "ok" : "MISMATCH";
    console.log(`  manifest:   ${manifestHead} (${match})`);
  } else if (manifest) {
    console.log(`  manifest:   (no gamma anchor)`);
  }
}

function formatIndexLine(e: GammaEntry): string {
  const targetStr =
    typeof e.target?.section_id === "string"
      ? `section=${e.target.section_id}`
      : Object.keys(e.target ?? {}).length === 0
        ? "-"
        : JSON.stringify(e.target);
  const authored = e.authorized_by ? ` auth=${e.authorized_by}` : "";
  return `  ${e.at}  ${e.id}  ${padOp(e.op)}  ${e.zone.padEnd(7)}  ${targetStr}${authored}`;
}

function padOp(op: string): string {
  const width = "section.reorder".length;
  return op.length >= width ? op : op + " ".repeat(width - op.length);
}

function printFullEntry(e: GammaEntry): void {
  console.log(`id:                ${e.id}`);
  console.log(`at:                ${e.at}`);
  console.log(`subject_did:       ${e.subject_did}`);
  console.log(`zone:              ${e.zone}`);
  console.log(`op:                ${e.op}`);
  console.log(`target:            ${JSON.stringify(e.target)}`);
  console.log(`payload:           ${JSON.stringify(e.payload)}`);
  console.log(`prev_gamma_hash:   ${e.prev_gamma_hash ?? "(none)"}`);
  if (e.prev_section_gamma) console.log(`prev_section_gamma: ${e.prev_section_gamma}`);
  console.log(`hash:              ${e.hash}`);
  console.log(`signature.key:     ${e.signature.key}`);
  console.log(`signature.value:   ${e.signature.value.slice(0, 24)}…`);
  if (e.authorized_by) console.log(`authorized_by:     ${e.authorized_by}`);
  if (e.note) console.log(`note:              ${e.note}`);
}

function safeReadManifest(handle: string) {
  try {
    return readManifest(handle);
  } catch {
    return null;
  }
}
