/**
 * `aithos ethos modify-section` — apply an in-place modification to a section.
 *
 * In v0.2.0 there is no per-section revision array: every change is a signed
 * entry in the gamma log (spec §10.6.1). This command emits one signed
 * `section.modify` entry carrying the full new value of each field being
 * replaced, then updates the live section and its `gamma_ref`.
 *
 * At least one of --title, --body / --body-file, --tags (or --clear-tags)
 * must be provided.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  loadIdentity,
  modifySection,
  ethosDir,
  type Sphere,
  loadConfig,
  readJson,
  loadMandate,
  findRevocation,
} from "@aithos/protocol-core";

export interface EthosModifySectionOpts {
  zone: string;
  sectionId: string;
  title?: string;
  body?: string;
  bodyFile?: string;
  tags?: string; // comma-separated; sets the full tag list
  clearTags?: boolean; // force tags := []
  mandate?: string;
  agentKey?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosModifySection(opts: EthosModifySectionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);
  const { title, body, tags } = resolveChanges(opts);

  if (title === undefined && body === undefined && tags === undefined) {
    throw new Error(
      "Nothing to modify. Pass at least one of --title, --body/--body-file, --tags, --clear-tags.",
    );
  }

  const identity = loadIdentity(handle);
  const delegate = opts.mandate ? resolveDelegate(opts.mandate, opts.agentKey, zone) : undefined;

  const { section, manifest, gammaEntry } = modifySection({
    handle,
    identity,
    zone,
    sectionId: opts.sectionId,
    title,
    body,
    tags,
    delegate,
  });

  if (opts.json) {
    console.log(JSON.stringify({ section, manifest, gammaEntry }, null, 2));
    return;
  }

  const changed: string[] = [];
  if (title !== undefined) changed.push("title");
  if (body !== undefined) changed.push("body");
  if (tags !== undefined) changed.push("tags");

  console.log(`[handle=${handle}] Modified ${opts.sectionId} in ${zone} (${changed.join(", ")})`);
  console.log(`  gamma:        ${gammaEntry.id}`);
  console.log(`  gamma.head:   ${manifest.gamma?.head ?? "(none)"} (count=${manifest.gamma?.count ?? 0})`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  if (delegate) console.log(`  authorized:   ${delegate.mandateId}`);
  console.log(`  section.gamma_ref: ${section.gamma_ref}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}

function resolveChanges(opts: EthosModifySectionOpts): {
  title?: string;
  body?: string;
  tags?: string[];
} {
  if (opts.body && opts.bodyFile) {
    throw new Error("Pass either --body or --body-file, not both.");
  }
  if (opts.tags && opts.clearTags) {
    throw new Error("Pass either --tags or --clear-tags, not both.");
  }

  const out: { title?: string; body?: string; tags?: string[] } = {};
  if (opts.title !== undefined) out.title = opts.title;
  if (opts.body !== undefined) out.body = opts.body;
  if (opts.bodyFile !== undefined) {
    out.body = readFileSync(opts.bodyFile, "utf8").replace(/\s+$/, "");
  }
  if (opts.tags !== undefined) {
    out.tags = opts.tags.split(",").map((t) => t.trim()).filter(Boolean);
  }
  if (opts.clearTags) out.tags = [];
  return out;
}

interface DelegateKeyfile {
  aithos?: string;
  id: string;
  seed_hex: string;
  pubkey_multibase: string;
}

function resolveDelegate(mandateId: string, agentKeyPath: string | undefined, zone: Sphere) {
  if (!agentKeyPath) throw new Error("--mandate requires --agent-key <path>");
  const key = readJson<DelegateKeyfile>(agentKeyPath);
  const mandate = loadMandate(mandateId);
  const writeScope = `ethos.write.${zone}`;
  if (!mandate.scopes.includes(writeScope)) {
    throw new Error(`Mandate ${mandateId} does not include scope ${writeScope}`);
  }
  if (mandate.grantee.pubkey && mandate.grantee.pubkey !== key.pubkey_multibase) {
    throw new Error(`Mandate grantee.pubkey does not match agent keyfile`);
  }
  const now = new Date();
  if (now < new Date(mandate.not_before)) {
    throw new Error(`Mandate ${mandateId} is not yet valid (not_before=${mandate.not_before})`);
  }
  if (now >= new Date(mandate.not_after)) {
    throw new Error(`Mandate ${mandateId} has expired (not_after=${mandate.not_after})`);
  }
  const revocation = findRevocation(mandateId);
  if (revocation) {
    throw new Error(
      `Mandate ${mandateId} was revoked at ${revocation.revoked_at} (reason: ${revocation.reason})`,
    );
  }
  return {
    mandateId,
    keySeed: Uint8Array.from(Buffer.from(key.seed_hex, "hex")),
    keyMultibase: key.pubkey_multibase,
  };
}
