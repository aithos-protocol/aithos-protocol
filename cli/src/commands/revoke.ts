/**
 * `aithos revoke <mandate-id> --reason <r>` — revoke a previously-issued mandate.
 * `aithos revoke --all [--sphere <s>] [--agent <id>] [--include-expired]`
 *                                       — revoke every local mandate matching the filters.
 *
 * The revocation is signed by the same sphere key that issued the mandate (a
 * mandate may only be revoked by its issuing sphere). Writes a revocation
 * document to `~/.aithos/revocations/`.
 *
 * `--all` iterates over `~/.aithos/mandates/` and emits one individual revocation
 * per mandate. This is NOT a special "mass revocation" document — each revocation
 * is a standalone §4.6 object, so any verifier holding the current revocation list
 * or the individual file will see the mandate as invalid.
 */

import { loadIdentity } from "../identity.js";
import { loadConfig, listMandates, mandatesDir, revocationsDir } from "../storage.js";
import { join } from "node:path";
import { existsSync } from "node:fs";
import {
  loadMandate,
  createRevocation,
  writeRevocation,
  type Mandate,
} from "../mandate.js";
import { readJson } from "../storage.js";

const KNOWN_REASONS = [
  "device_lost",
  "device_sold",
  "agent_retired",
  "superseded",
  "policy_change",
  "user_request",
  "incident",
  "device_suspect",
  "other",
];

export interface RevokeOpts {
  mandateId?: string;
  reason?: string;
  handle?: string;
  all?: boolean;
  sphere?: string;
  agent?: string;
  includeExpired?: boolean;
  yes?: boolean;
  json?: boolean;
}

export function runRevoke(opts: RevokeOpts): void {
  const config = loadConfig();
  const handle = opts.handle ?? config.default_handle;
  if (!handle) {
    throw new Error("No identity specified. Pass --handle or set a default via `aithos init`.");
  }
  const id = loadIdentity(handle);

  const reason = opts.reason ?? "user_request";
  if (!KNOWN_REASONS.includes(reason)) {
    console.warn(
      `Note: "${reason}" is not in the recognized reason vocabulary. Allowed values are: ${KNOWN_REASONS.join(", ")}. Continuing.`,
    );
  }

  // Bulk path
  if (opts.all) {
    if (opts.mandateId) {
      throw new Error("Pass EITHER <mandate-id> OR --all, not both.");
    }
    runRevokeAll(id, { reason, sphere: opts.sphere, agent: opts.agent, includeExpired: opts.includeExpired, yes: opts.yes, json: opts.json });
    return;
  }

  if (!opts.mandateId) {
    throw new Error(
      "Pass a mandate id, or --all to revoke every local mandate. See `aithos revoke --help`.",
    );
  }

  const mandate = loadMandate(opts.mandateId);
  const rev = createRevocation({ issuer: id, mandate, reason });
  const path = writeRevocation(rev);

  if (opts.json) {
    console.log(JSON.stringify({ revocation: rev, path }, null, 2));
    return;
  }

  console.log(`Revoked ${rev.mandate_id}`);
  console.log(`  Reason:     ${rev.reason}`);
  console.log(`  Revoked at: ${rev.revoked_at}`);
  console.log(`  Issued by:  ${rev.issued_by_key}`);
  console.log(`  Path:       ${path}`);
}

interface RevokeAllOpts {
  reason: string;
  sphere?: string;
  agent?: string;
  includeExpired?: boolean;
  yes?: boolean;
  json?: boolean;
}

function runRevokeAll(
  id: ReturnType<typeof loadIdentity>,
  opts: RevokeAllOpts,
): void {
  const now = new Date();
  const files = listMandates();

  const candidates: Mandate[] = [];
  const skipped: { id: string; why: string }[] = [];
  const alreadyRevoked: string[] = [];

  for (const f of files) {
    const m = readJson<Mandate>(join(mandatesDir(), f));

    if (opts.sphere && m.actor_sphere !== opts.sphere) {
      skipped.push({ id: m.id, why: `actor_sphere=${m.actor_sphere}` });
      continue;
    }
    if (opts.agent && m.grantee.id !== opts.agent) {
      skipped.push({ id: m.id, why: `grantee=${m.grantee.id}` });
      continue;
    }
    if (!opts.includeExpired && new Date(m.not_after) <= now) {
      skipped.push({ id: m.id, why: "already expired" });
      continue;
    }
    // Skip mandates that already have a revocation on disk
    const existing = join(revocationsDir(), `revocation_${m.id.replace(/^mandate_/, "")}.json`);
    if (existsSync(existing)) {
      alreadyRevoked.push(m.id);
      continue;
    }

    candidates.push(m);
  }

  if (candidates.length === 0) {
    console.log("No mandates matched the filters.");
    if (skipped.length) {
      console.log(`  ${skipped.length} skipped (use --include-expired or remove --sphere/--agent filters to widen):`);
      for (const s of skipped.slice(0, 10)) console.log(`    ${s.id}  (${s.why})`);
      if (skipped.length > 10) console.log(`    … +${skipped.length - 10} more`);
    }
    if (alreadyRevoked.length) {
      console.log(`  ${alreadyRevoked.length} already have a revocation on disk.`);
    }
    return;
  }

  if (!opts.yes) {
    console.log(`About to revoke ${candidates.length} mandate(s):`);
    for (const m of candidates.slice(0, 20)) {
      console.log(
        `  ${m.id}  sphere=${m.actor_sphere}  grantee=${m.grantee.id}  not_after=${m.not_after}`,
      );
    }
    if (candidates.length > 20) console.log(`  … +${candidates.length - 20} more`);
    console.log();
    console.log(`Reason: ${opts.reason}`);
    console.log();
    console.log(
      `Pass --yes to proceed, or narrow with --sphere <public|circle|self> / --agent <id>.`,
    );
    return;
  }

  const results: { id: string; path: string }[] = [];
  for (const m of candidates) {
    const rev = createRevocation({ issuer: id, mandate: m, reason: opts.reason });
    const path = writeRevocation(rev);
    results.push({ id: m.id, path });
  }

  if (opts.json) {
    console.log(JSON.stringify({ revoked: results, skipped, alreadyRevoked }, null, 2));
    return;
  }

  console.log(`Revoked ${results.length} mandate(s):`);
  for (const r of results) console.log(`  ${r.id}  → ${r.path}`);
  if (alreadyRevoked.length) {
    console.log();
    console.log(`Left untouched (already had a revocation on disk): ${alreadyRevoked.length}`);
  }
  console.log();
  console.log(
    "Note: revocation is forward-only. Actions already taken by these agents remain attributable.",
  );
  console.log(
    "For a nuclear kill-switch (e.g. unknown mandates issued from another device), rotate the sphere key: `aithos rotate --sphere <s>`.",
  );
}
