// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos grant` — issue a mandate.
 *
 * Usage:
 *   aithos grant <agent-id> \
 *     --sphere <public|circle|self> \
 *     --scope <s1,s2,...> \
 *     --ttl <duration> \
 *     [--handle <identity>] \
 *     [--label <human-readable>] \
 *     [--pubkey <multibase>] \
 *     [--domains <d1,d2,...>] \
 *     [--rate-limit <key=N,key=N>] \
 *     [--counter-sign <s1,s2,...>] \
 *     [--json]
 *
 * The agent-id may be any URN (e.g. `urn:aithos:agent:gmail-agent@host`)
 * or a DID (did:aithos:, did:key:, did:web:).
 */

import { existsSync } from "node:fs";
import {
  loadIdentity,
  loadConfig,
  createMandate,
  writeMandate,
  parseTtl,
  issueMandateWithRewrap,
  ethosDir,
  type MandateConstraints,
  type SectionScope,
  type Sphere,
} from "@aithos/protocol-core";

export interface GrantOpts {
  agent: string;
  sphere: string;
  scope: string;
  ttl: string;
  handle?: string;
  label?: string;
  pubkey?: string;
  domains?: string;
  rateLimit?: string;
  counterSign?: string;
  /** Comma-separated section ids to scope the read/write to (§4.7′). */
  sections?: string;
  /** Comma-separated tags to scope the read/write to (a section matches if it carries any). */
  sectionTags?: string;
  json?: boolean;
}

export function runGrant(opts: GrantOpts): void {
  if (!["public", "circle", "self"].includes(opts.sphere)) {
    throw new Error(`--sphere must be one of public|circle|self`);
  }

  const config = loadConfig();
  const handle = opts.handle ?? config.default_handle;
  if (!handle) {
    throw new Error("No identity specified. Pass --handle or set a default via `aithos init`.");
  }
  const id = loadIdentity(handle);

  const scopes = opts.scope.split(",").map((s) => s.trim()).filter(Boolean);
  if (scopes.length === 0) {
    throw new Error("At least one --scope is required");
  }

  const ttlSeconds = parseTtl(opts.ttl);

  const constraints: MandateConstraints = {};
  if (opts.domains) {
    constraints.domains = opts.domains.split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (opts.rateLimit) {
    constraints.rate_limit = {};
    for (const pair of opts.rateLimit.split(",")) {
      const [k, v] = pair.split("=");
      if (!k || !v) throw new Error(`Invalid --rate-limit entry: ${pair}`);
      constraints.rate_limit[k.trim()] = parseInt(v.trim(), 10);
    }
  }
  if (opts.counterSign) {
    constraints.require_counter_sign = opts.counterSign
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // Optional section_scope (§4.7′): narrows the read/write to a subset.
  let sectionScope: SectionScope | undefined;
  const scopeIds = opts.sections?.split(",").map((s) => s.trim()).filter(Boolean);
  const scopeTags = opts.sectionTags?.split(",").map((s) => s.trim()).filter(Boolean);
  if ((scopeIds && scopeIds.length) || (scopeTags && scopeTags.length)) {
    sectionScope = {
      ...(scopeIds && scopeIds.length ? { ids: scopeIds } : {}),
      ...(scopeTags && scopeTags.length ? { tags: scopeTags } : {}),
    };
  }

  const m = createMandate({
    issuer: id,
    actorSphere: opts.sphere as Sphere,
    grantee: {
      id: opts.agent,
      ...(opts.label ? { label: opts.label } : {}),
      ...(opts.pubkey ? { pubkey: opts.pubkey } : {}),
    },
    scopes,
    ttlSeconds,
    ...(Object.keys(constraints).length ? { constraints } : {}),
    ...(sectionScope ? { sectionScope } : {}),
  });

  const path = writeMandate(m);

  // When the mandate authorises access to the current encrypted state, we
  // must make it effective — the mandate alone is a signed grant on paper,
  // with no cryptographic effect on existing zones / the gamma readers list.
  // `issueMandateWithRewrap` bumps a fresh edition:
  //
  //   - `ethos.write.<zone>` / `ethos.read.<zone>` (or `ethos.read.all`) →
  //     the target zone is re-encrypted with the delegate on the DEK wrap
  //     list.
  //   - `gamma.read` → the delegate is added to `manifest.gamma.readers`
  //     so FUTURE gamma entries will seal an envelope for them. Past entries
  //     stay unreadable (per-entry seal is forward-only, spec §10.5.4').
  //
  // Without `gamma.read`, a write-only mandate NEVER grants any gamma access.
  // That's the whole point of the v0.3 per-entry envelope format.
  let rewroteManifest = false;
  const touchesEthos = m.scopes.some(
    (s) =>
      s.startsWith("ethos.write.") ||
      s.startsWith("ethos.read.") ||
      s === "gamma.read",
  );
  // A section_scope cannot be honored by the v0.2 whole-zone rewrap (one DEK per
  // zone) — applying it would over-grant the whole zone. So a section-scoped
  // mandate is recorded only; it takes effect when the ethos is authored in v0.3
  // (the per-section author path wraps only the matching sections, §3.5.4′).
  const deferredForV03 = !!sectionScope;
  if (touchesEthos && !deferredForV03 && m.grantee.pubkey && existsSync(ethosDir(handle))) {
    issueMandateWithRewrap({ handle, identity: id, mandate: m });
    rewroteManifest = true;
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        { mandate: m, path, rewrapped: rewroteManifest, section_scope_deferred_to_v03: deferredForV03 },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Issued mandate ${m.id}`);
  console.log(`  Grantee:    ${m.grantee.id}`);
  console.log(`  Sphere:     ${m.actor_sphere}`);
  console.log(`  Scopes:     ${m.scopes.join(", ")}`);
  console.log(`  Not before: ${m.not_before}`);
  console.log(`  Not after:  ${m.not_after}`);
  if (m.constraints) {
    console.log(`  Constraints:`);
    if (m.constraints.domains) console.log(`    domains:              ${m.constraints.domains.join(", ")}`);
    if (m.constraints.rate_limit) {
      console.log(`    rate_limit:           ${JSON.stringify(m.constraints.rate_limit)}`);
    }
    if (m.constraints.require_counter_sign) {
      console.log(`    require_counter_sign: ${m.constraints.require_counter_sign.join(", ")}`);
    }
  }
  if (m.section_scope) {
    const parts: string[] = [];
    if (m.section_scope.ids) parts.push(`ids=[${m.section_scope.ids.join(", ")}]`);
    if (m.section_scope.tags) parts.push(`tags=[${m.section_scope.tags.join(", ")}]`);
    console.log(`  Section:    ${parts.join(" ")}`);
  }
  console.log(`  Path:       ${path}`);
  if (rewroteManifest) {
    console.log(
      `  Rewrap:     bumped a new ethos edition with the delegate on every wrap list (gamma + encrypted zones).`,
    );
  }
  if (deferredForV03) {
    console.log(
      `  Note:       section-scoped grant recorded; it takes effect under v0.3 (per-section wraps). ` +
        `The v0.2 whole-zone rewrap was skipped to avoid over-granting.`,
    );
  }
}
