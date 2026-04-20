/**
 * `aithos ethos add-revision` — append a revision to an existing section.
 *
 * The previous revision's `hash` becomes the new revision's `prev_hash`; the
 * new `at` must be strictly after the previous one; the chain is append-only.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  loadIdentity,
  addRevision,
  ethosDir,
  type Sphere,
  loadConfig,
  readJson,
  loadMandate,
  findRevocation,
} from "@aithos/protocol-core";

export interface EthosAddRevisionOpts {
  zone: string;
  sectionId: string;
  body?: string;
  bodyFile?: string;
  mandate?: string;
  agentKey?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosAddRevision(opts: EthosAddRevisionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);
  const body = resolveBody(opts);
  const identity = loadIdentity(handle);
  const delegate = opts.mandate ? resolveDelegate(opts.mandate, opts.agentKey, zone) : undefined;

  const { revision, manifest } = addRevision({
    handle,
    identity,
    zone,
    sectionId: opts.sectionId,
    body,
    delegate,
  });

  if (opts.json) {
    console.log(JSON.stringify({ revision, manifest }, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Appended revision ${revision.revision} to ${opts.sectionId} (${zone})`);
  console.log(`  at:           ${revision.at}`);
  console.log(`  prev_hash:    ${revision.prev_hash}`);
  console.log(`  hash:         ${revision.hash}`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  if (delegate) console.log(`  authorized:   ${delegate.mandateId}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
}

function resolveBody(opts: EthosAddRevisionOpts): string {
  if (opts.body && opts.bodyFile) throw new Error("Pass either --body or --body-file, not both.");
  if (opts.body) return opts.body;
  if (opts.bodyFile) return readFileSync(opts.bodyFile, "utf8").replace(/\s+$/, "");
  throw new Error("Missing --body or --body-file for the new revision.");
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
