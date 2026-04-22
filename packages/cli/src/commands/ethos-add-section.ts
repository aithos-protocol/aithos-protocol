/**
 * `aithos ethos add-section` — create a new section in a zone.
 *
 * Two auth paths, unified through `resolveAuthor`:
 *
 *   - Owner: no `--mandate`. The zone is signed directly by the subject's
 *     sphere key. Requires a fully-owned identity (all four sealed seeds).
 *
 *   - Delegate: `--mandate <id> --agent-key <path>`. Works on tracked
 *     installs (only `did.json` is required). The delegate must hold the
 *     matching Ed25519 seed, and the mandate must carry the
 *     `ethos.write.<zone>` scope, be within its validity window, and not
 *     be revoked. The emitted gamma/zone/manifest signatures all carry
 *     `authorized_by = mandate.id`.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  addSection,
  ethosDir,
  type Sphere,
  loadConfig,
} from "@aithos/protocol-core";
import { resolveAuthor } from "./_author.js";

export interface EthosAddSectionOpts {
  zone: string;
  title: string;
  body?: string;
  bodyFile?: string;
  tags?: string; // comma-separated
  mandate?: string; // mandate id for delegated write
  agentKey?: string; // path to keyfile
  handle?: string;
  json?: boolean;
}

export function runEthosAddSection(opts: EthosAddSectionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);
  const body = resolveBody(opts);
  const tags = opts.tags
    ? opts.tags.split(",").map((t) => t.trim()).filter(Boolean)
    : undefined;

  const { author, mandate } = resolveAuthor({
    handle,
    zone,
    mandate: opts.mandate,
    agentKey: opts.agentKey,
  });

  const { section, manifest, gammaEntry } = addSection({
    handle,
    author,
    zone,
    title: opts.title,
    body,
    tags,
  });

  if (opts.json) {
    console.log(JSON.stringify({ section, manifest, gammaEntry }, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Added section to zone ${zone}`);
  console.log(`  id:           ${section.id}`);
  console.log(`  title:        ${section.title}`);
  console.log(`  rev:          1`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  console.log(`  gamma:        ${gammaEntry.id}`);
  console.log(`  gamma.head:   ${manifest.gamma?.head ?? "(none)"} (count=${manifest.gamma?.count ?? 0})`);
  if (mandate) console.log(`  authorized:   ${mandate.id}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}

function resolveBody(opts: EthosAddSectionOpts): string {
  if (opts.body && opts.bodyFile) throw new Error("Pass either --body or --body-file, not both.");
  if (opts.body) return opts.body;
  if (opts.bodyFile) return readFileSync(opts.bodyFile, "utf8").replace(/\s+$/, "");
  throw new Error("Missing --body or --body-file for the first revision.");
}
