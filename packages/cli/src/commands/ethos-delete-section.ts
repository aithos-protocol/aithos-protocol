/**
 * `aithos ethos delete-section` — remove a section from its zone while
 * preserving full audit history in the gamma deep-memory log.
 *
 * After this command runs:
 *   - the section no longer appears in the current edition (pack/install
 *     sees it as if it never existed in the live doc),
 *   - the gamma log retains the original `section.add` entry AND a new
 *     `section.delete` entry, both signed and hash-chained,
 *   - `manifest.gamma.head` advances to the new delete entry.
 *
 * Auth semantics mirror `add-section` / `add-revision`:
 *   - Without `--mandate`, the delete is signed directly by the zone's
 *     sphere key (i.e. the subject themselves).
 *   - With `--mandate <id> --agent-key <path>`, an agent that holds a
 *     `ethos.write.<zone>` mandate can sign the delete.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  loadIdentity,
  deleteSection,
  ethosDir,
  type Sphere,
  loadConfig,
  readJson,
  loadMandate,
  findRevocation,
} from "@aithos/protocol-core";

export interface EthosDeleteSectionOpts {
  zone: string;
  section: string;
  reason?: string;
  mandate?: string;
  agentKey?: string;
  handle?: string;
  json?: boolean;
}

export function runEthosDeleteSection(opts: EthosDeleteSectionOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos initialized for "${handle}". Run \`aithos ethos init\`.`);
  }

  const zone = ensureZone(opts.zone);
  const identity = loadIdentity(handle);
  const delegate = opts.mandate
    ? resolveDelegate(opts.mandate, opts.agentKey, zone)
    : undefined;

  const { manifest, gammaEntry, deletedTitle } = deleteSection({
    handle,
    identity,
    zone,
    sectionId: opts.section,
    reason: opts.reason,
    delegate,
  });

  if (opts.json) {
    console.log(JSON.stringify({ manifest, gammaEntry, deletedTitle }, null, 2));
    return;
  }

  console.log(`[handle=${handle}] Deleted section from zone ${zone}`);
  console.log(`  id:           ${opts.section}`);
  console.log(`  title:        ${deletedTitle}`);
  console.log(`  reason:       ${opts.reason ?? "(none)"}`);
  console.log(`  edition:      ${manifest.edition.version} (height=${manifest.edition.height})`);
  console.log(`  gamma:        ${gammaEntry.id}`);
  console.log(`  gamma.head:   ${manifest.gamma?.head ?? "(none)"} (count=${manifest.gamma?.count ?? 0})`);
  if (delegate) console.log(`  authorized:   ${delegate.mandateId}`);
}

function ensureZone(z: string): Sphere {
  if (z === "public" || z === "circle" || z === "self") return z;
  throw new Error(`Invalid --zone ${z}. Expected public | circle | self.`);
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
