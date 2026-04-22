/**
 * `aithos mandate add <path>` — import a mandate received out-of-band.
 *
 * Spec: §9.5.
 *
 * Accepts a JSON file containing a single mandate document (spec §4.2). Before
 * storing it under ~/.aithos/mandates/<id>.json, it:
 *
 *   - parses the file as a Mandate,
 *   - resolves the issuer DID — either from the bundle's subject identity if
 *     that identity is installed locally (owned or tracked), OR from a DID
 *     document supplied via --did <path>,
 *   - verifies the mandate signature against that DID doc (§4.4),
 *   - checks the current time falls within [not_before, not_after) unless
 *     --allow-expired is set,
 *   - refuses an install that would silently overwrite an existing mandate at
 *     the same id (unless --force).
 *
 * Accepting a mandate does not by itself grant the caller read access — the
 * decryption still requires an X25519 key wrap to a recipient the caller
 * controls. Whether that requirement is met is orthogonal to whether the
 * mandate is cryptographically valid.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { join, basename } from "node:path";

import {
  loadMandate,
  verifyMandate,
  writeMandate,
  findRevocation,
  type Mandate,
  identityDir,
  mandatesDir,
  listIdentities,
  type DidDocument,
} from "@aithos/protocol-core";

export interface MandateAddOpts {
  path: string;
  did?: string;           // optional DID document path (JSON)
  allowExpired?: boolean; // import a mandate outside its validity window
  force?: boolean;        // overwrite an existing mandate at the same id
  json?: boolean;
}

export function runMandateAdd(opts: MandateAddOpts): void {
  if (!existsSync(opts.path)) {
    throw new Error(`Mandate file not found: ${opts.path}`);
  }
  if (!statSync(opts.path).isFile()) {
    throw new Error(`Not a file: ${opts.path}`);
  }

  const raw = readFileSync(opts.path, "utf8");
  let mandate: Mandate;
  try {
    mandate = JSON.parse(raw) as Mandate;
  } catch (e) {
    throw new Error(`Not valid JSON: ${(e as Error).message}`);
  }

  // Accept the pre-E2E envelope (0.1.0), the delegate-aware envelope (0.2.1),
  // and the v0.3 envelope that introduced the `gamma.read` scope.
  // protocol-core's `verifyMandate` enforces the same set.
  if (
    mandate["aithos-mandate"] !== "0.1.0" &&
    mandate["aithos-mandate"] !== "0.2.1" &&
    mandate["aithos-mandate"] !== "0.3.0"
  ) {
    throw new Error(
      `Unsupported mandate version "${mandate["aithos-mandate"]}" (expected 0.1.0, 0.2.1, or 0.3.0)`,
    );
  }
  if (!mandate.id || !mandate.issuer) {
    throw new Error(`Mandate is missing required fields (id/issuer)`);
  }

  /* ------- Resolve the issuer's DID document. -------------------------- */
  const didDoc = resolveIssuerDidDoc(mandate, opts.did);

  /* ------- Cryptographic verification. --------------------------------- */
  const result = verifyMandate(mandate, didDoc);
  if (!result.ok) {
    // If the ONLY failures are validity-window related and --allow-expired was
    // passed, let it through.
    const nonWindow = result.errors.filter(
      (e) => !e.startsWith("Mandate not yet valid") && !e.startsWith("Mandate has expired"),
    );
    if (nonWindow.length > 0 || !opts.allowExpired) {
      throw new Error(
        `mandate failed verification; refusing to add:\n  - ` +
          result.errors.join("\n  - "),
      );
    }
  }

  /* ------- Revocation awareness. --------------------------------------- */
  const existingRev = findRevocation(mandate.id);

  /* ------- Collision handling. ----------------------------------------- */
  const targetPath = join(mandatesDir(), `${mandate.id}.json`);
  if (existsSync(targetPath) && !opts.force) {
    try {
      const current = loadMandate(mandate.id);
      if (JSON.stringify(current) === JSON.stringify(mandate)) {
        // Idempotent — don't error, just report.
        if (opts.json) {
          console.log(JSON.stringify({ added: false, unchanged: true, mandate_id: mandate.id }, null, 2));
          return;
        }
        console.log(`Mandate ${mandate.id} already present (identical). No change.`);
        return;
      }
    } catch {
      /* if we can't load the current one, force is required */
    }
    throw new Error(
      `mandate ${mandate.id} already present locally with different content. ` +
        `Re-run with --force to overwrite.`,
    );
  }

  writeMandate(mandate);

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          added: true,
          mandate_id: mandate.id,
          issuer: mandate.issuer,
          actor_sphere: mandate.actor_sphere,
          scopes: mandate.scopes,
          not_before: mandate.not_before,
          not_after: mandate.not_after,
          path: targetPath,
          warnings: buildWarnings(result, existingRev, opts),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`Added mandate ${mandate.id}`);
  console.log(`  issuer:        ${mandate.issuer}`);
  console.log(`  actor_sphere:  ${mandate.actor_sphere}`);
  console.log(`  scopes:        ${mandate.scopes.join(", ")}`);
  console.log(`  validity:      ${mandate.not_before} → ${mandate.not_after}`);
  console.log(`  path:          ${targetPath}`);

  const warnings = buildWarnings(result, existingRev, opts);
  for (const w of warnings) console.log(`  warning: ${w}`);
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function resolveIssuerDidDoc(mandate: Mandate, didPathOpt?: string): DidDocument {
  // Explicit path wins.
  if (didPathOpt) {
    if (!existsSync(didPathOpt)) {
      throw new Error(`DID document file not found: ${didPathOpt}`);
    }
    const doc = JSON.parse(readFileSync(didPathOpt, "utf8")) as DidDocument;
    if (doc.id !== mandate.issuer) {
      throw new Error(
        `--did document has id=${doc.id} but mandate.issuer=${mandate.issuer}`,
      );
    }
    return doc;
  }

  // Otherwise scan the local keystore for a handle whose did.json matches
  // mandate.issuer — works for both owned and tracked identities.
  for (const h of listIdentities()) {
    const p = join(identityDir(h), "did.json");
    if (!existsSync(p)) continue;
    try {
      const d = JSON.parse(readFileSync(p, "utf8")) as DidDocument;
      if (d.id === mandate.issuer) return d;
    } catch {
      /* ignore malformed */
    }
  }
  throw new Error(
    `cannot resolve issuer DID ${mandate.issuer} — ` +
      `not installed locally. Either install the issuer's ethos first ` +
      `('aithos ethos install <bundle>') or pass --did <did.json>.`,
  );
}

function buildWarnings(
  verifyResult: { ok: boolean; errors: string[] },
  existingRev: ReturnType<typeof findRevocation>,
  opts: MandateAddOpts,
): string[] {
  const w: string[] = [];
  if (opts.allowExpired && !verifyResult.ok) {
    for (const e of verifyResult.errors) {
      if (e.startsWith("Mandate not yet valid") || e.startsWith("Mandate has expired")) {
        w.push(`added despite validity window check: ${e}`);
      }
    }
  }
  if (existingRev) {
    w.push(
      `a revocation for this mandate is already on file (revoked_at=${existingRev.revoked_at}, reason=${existingRev.reason}). The mandate is cryptographically valid but has been withdrawn.`,
    );
  }
  return w;
}

// basename is imported only for the spec-level label if we extend this later;
// silence unused warning.
void basename;
