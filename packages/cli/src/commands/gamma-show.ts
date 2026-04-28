// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

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
 *
 * Auth paths:
 *   - Owner (default): uses `loadIdentity()` — requires sealed seeds.
 *   - Delegate (`--mandate <id> --agent-key <path>`): works on tracked
 *     installs. The delegate must be on the gamma DEK wrap list, which
 *     `issueMandateWithRewrap` arranges at grant time for any write mandate
 *     bound to a pubkey (spec §10 + §4).
 */

import { existsSync } from "node:fs";
import {
  loadIdentity,
  loadConfig,
  ethosDir,
  readGammaLogForAuthor,
  gammaHeadForAuthor,
  readManifest,
  ownerAuthor,
  type Author,
  type GammaEntry,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";

export interface GammaShowOpts {
  handle?: string;
  section?: string;
  id?: string;
  head?: boolean;
  mandate?: string;
  agentKey?: string;
  json?: boolean;
}

export function runGammaShow(opts: GammaShowOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }

  const { author, isDelegate } = resolveGammaAuthor(handle, opts);

  // `--head`: cheapest mode, works even when the log is absent.
  if (opts.head) {
    const head = gammaHeadForAuthor(handle, author);
    const entries = readGammaLogForAuthor(handle, author);
    if (opts.json) {
      console.log(JSON.stringify({ head, count: entries.length }, null, 2));
    } else {
      console.log(`${head ?? "(none)"}\tcount=${entries.length}`);
    }
    return;
  }

  const entries = readGammaLogForAuthor(handle, author);

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

  const authLabel = isDelegate ? ` [via mandate ${opts.mandate}]` : "";
  console.log(
    `[handle=${handle}] gamma log (${filtered.length} of ${entries.length} entries)${authLabel}`,
  );
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

/**
 * Build an Author for gamma reads, supporting both paths:
 *
 *   - owner: no --mandate; loadIdentity requires sealed seeds.
 *   - delegate: --mandate + --agent-key; works on tracked installs.
 *
 * We don't enforce a specific scope here — the cryptographic wrap list on
 * the gamma DEK is the real access-control boundary. If the delegate wasn't
 * rewrapped in, decryption fails downstream with a clear "no matching
 * recipient" error.
 */
function resolveGammaAuthor(
  handle: string,
  opts: GammaShowOpts,
): { author: Author; isDelegate: boolean } {
  if (opts.mandate) {
    if (!opts.agentKey) {
      throw new Error("--mandate requires --agent-key <path>");
    }
    const { author } = resolveAuthor({ handle, mandate: opts.mandate, agentKey: opts.agentKey });
    return { author, isDelegate: true };
  }
  const identity = loadIdentity(handle);
  return { author: ownerAuthor(identity), isDelegate: false };
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
