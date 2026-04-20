/**
 * `aithos ethos add-section` — create a new section in a zone with its first
 * revision, signed either directly by the zone's sphere key or by a delegate
 * key authorized by a write mandate.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  loadIdentity,
  addSection,
  ethosDir,
  type Sphere,
  loadConfig,
  readJson,
  loadMandate,
  findRevocation,
} from "@aithos/protocol-core";

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
  const tags = opts.tags ? opts.tags.split(",").map((t) => t.trim()).filter(Boolean) : undefined;

  const identity = loadIdentity(handle);
  const delegate = opts.mandate
    ? resolveDelegate(opts.mandate, opts.agentKey, zone)
    : undefined;

  const { section, manifest } = addSection({
    handle,
    identity,
    zone,
    title: opts.title,
    body,
    tags,
    delegate,
  });

  if (opts.json) {
    console.log(JSON.stringify({ section, manifest }, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Added section to zone ${zone}`);
  console.log(`  id:           ${section.id}`);
  console.log(`  title:        ${section.title}`);
  console.log(`  rev:          1`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  if (delegate) console.log(`  authorized:   ${delegate.mandateId}`);
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
