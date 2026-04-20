/**
 * `aithos verify <path> [--did-document <path>] [--mandate <path>]`
 *
 * Dispatches based on the `aithos-*` schema field inside the JSON at <path>:
 *
 *   aithos-mandate     → verify mandate signature + time window against DID doc
 *   aithos-revocation  → verify revocation signature
 *   aithos-action      → verify action artifact (requires accompanying mandate
 *                        and DID doc, either via flags or auto-discovery)
 *
 * DID documents are resolved locally in this reference CLI. A production
 * verifier would resolve through a network layer (a mirror, a peer exchange,
 * a discovery doc, …).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  verifyMandate,
  verifyRevocation,
  verifyActionArtifact,
  loadMandate,
  type Mandate,
  type Revocation,
  type ActionArtifact,
  type DidDocument,
  identityDir,
  listIdentities,
} from "@aithos/protocol-core";

export interface VerifyOpts {
  path: string;
  didDocument?: string;
  mandate?: string;
  at?: string; // RFC 3339, for verifying mandates as-of a given time
}

export function runVerify(opts: VerifyOpts): void {
  const raw = readFileSync(opts.path, "utf8");
  const doc = JSON.parse(raw);

  if (doc["aithos-mandate"]) {
    const m = doc as Mandate;
    const didDoc = resolveDidDocument(m.issuer, opts.didDocument);
    const at = opts.at ? new Date(opts.at) : new Date();
    const r = verifyMandate(m, didDoc, at);
    report("Mandate", m.id, r);
    if (!r.ok) process.exitCode = 1;
    return;
  }

  if (doc["aithos-revocation"]) {
    const rev = doc as Revocation;
    const didDoc = resolveDidDocument(rev.issuer, opts.didDocument);
    const r = verifyRevocation(rev, didDoc);
    report("Revocation", `${rev.mandate_id} (revoked ${rev.revoked_at})`, r);
    if (!r.ok) process.exitCode = 1;
    return;
  }

  if (doc["aithos-action"]) {
    const a = doc as ActionArtifact;
    const mandate = opts.mandate ? JSON.parse(readFileSync(opts.mandate, "utf8")) : loadMandate(a.mandate_id);
    const didDoc = resolveDidDocument(mandate.issuer, opts.didDocument);
    const r = verifyActionArtifact(a, mandate, didDoc);
    report("Action artifact", a.id, r);
    if (!r.ok) process.exitCode = 1;
    return;
  }

  console.error(
    `Cannot determine document type from ${opts.path}. Expected one of: aithos-mandate, aithos-revocation, aithos-action.`,
  );
  process.exitCode = 1;
}

function resolveDidDocument(did: string, explicitPath?: string): DidDocument {
  if (explicitPath) {
    return JSON.parse(readFileSync(explicitPath, "utf8")) as DidDocument;
  }

  // Scan local identities for one whose DID matches.
  for (const handle of listIdentities()) {
    const candidate = join(identityDir(handle), "did.json");
    try {
      const doc = JSON.parse(readFileSync(candidate, "utf8")) as DidDocument;
      if (doc.id === did) return doc;
    } catch {
      // ignore
    }
  }

  throw new Error(
    `Cannot resolve DID document for ${did}. Pass --did-document <path> to specify.`,
  );
}

function report(kind: string, subject: string, r: { ok: boolean; errors: string[] }): void {
  if (r.ok) {
    console.log(`${kind} ${subject} — OK`);
    return;
  }
  console.log(`${kind} ${subject} — INVALID`);
  for (const e of r.errors) console.log(`  - ${e}`);
}
