/**
 * `aithos show-mandate <id>` — pretty-print a mandate with its derived status
 * (active / expired / revoked), validity window, scopes, and grantee.
 *
 * Complements `aithos verify <path>`, which only reports pass/fail on
 * cryptographic integrity. This command is the human-readable view.
 */

import { loadMandate, findRevocation } from "../mandate.js";

export interface ShowMandateOpts {
  id: string;
  json?: boolean;
}

type Status =
  | { kind: "active" }
  | { kind: "not_yet_valid"; not_before: string }
  | { kind: "expired"; not_after: string }
  | { kind: "revoked"; revoked_at: string; reason: string };

export function runShowMandate(opts: ShowMandateOpts): void {
  const m = loadMandate(opts.id);
  const rev = findRevocation(opts.id);

  const now = new Date();
  let status: Status;
  if (rev) {
    status = { kind: "revoked", revoked_at: rev.revoked_at, reason: rev.reason };
  } else if (now < new Date(m.not_before)) {
    status = { kind: "not_yet_valid", not_before: m.not_before };
  } else if (now >= new Date(m.not_after)) {
    status = { kind: "expired", not_after: m.not_after };
  } else {
    status = { kind: "active" };
  }

  if (opts.json) {
    console.log(JSON.stringify({ mandate: m, revocation: rev ?? null, status }, null, 2));
    return;
  }

  const statusLine = formatStatus(status);

  console.log(`Mandate ${m.id}`);
  console.log(`  status:       ${statusLine}`);
  console.log(`  issuer:       ${m.issuer}`);
  console.log(`  actor_sphere: ${m.actor_sphere}`);
  console.log(`  issued_at:    ${m.issued_at}`);
  console.log(`  issued_by:    ${m.issued_by_key}`);
  console.log(
    `  grantee:      ${m.grantee.id}` +
      (m.grantee.label ? ` (${m.grantee.label})` : "") +
      (m.grantee.pubkey ? `\n                pubkey=${m.grantee.pubkey}` : ""),
  );
  console.log(`  scopes:       ${m.scopes.join(", ")}`);
  console.log(`  valid:        ${m.not_before}  →  ${m.not_after}`);
  const c = m.constraints;
  if (c?.domains && c.domains.length > 0) {
    console.log(`  domains:      ${c.domains.join(", ")}`);
  }
  if (c?.rate_limit && Object.keys(c.rate_limit).length > 0) {
    console.log(
      `  rate_limit:   ${Object.entries(c.rate_limit)
        .map(([k, v]) => `${k}=${v}`)
        .join(", ")}`,
    );
  }
  if (c?.require_counter_sign && c.require_counter_sign.length > 0) {
    console.log(`  counter_sign: ${c.require_counter_sign.join(", ")}`);
  }
  if (rev) {
    console.log();
    console.log(`Revocation`);
    console.log(`  revoked_at:   ${rev.revoked_at}`);
    console.log(`  reason:       ${rev.reason}`);
  }
}

function formatStatus(s: Status): string {
  switch (s.kind) {
    case "active":
      return "active";
    case "not_yet_valid":
      return `not yet valid (not_before=${s.not_before})`;
    case "expired":
      return `expired (not_after=${s.not_after})`;
    case "revoked":
      return `revoked at ${s.revoked_at} (reason: ${s.reason})`;
  }
}
