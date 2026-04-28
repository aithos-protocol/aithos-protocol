// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * Bundle module — stateless operations on `.ethos` bundles.
 *
 * Where `ethos.ts` operates on the live, keystore-installed representation of
 * an ethos (nested under `~/.aithos/identities/<handle>/ethos/<zone>/…`), this
 * module operates on the *flat* bundle layout that a `.ethos` zip unpacks to:
 *
 *   <bundle-dir>/
 *   ├── manifest.json
 *   ├── did.json
 *   ├── public.md
 *   ├── circle.md.enc   (optional)
 *   ├── self.md.enc     (optional)
 *   ├── gamma.jsonl.enc (optional — the sealed mutation log, spec §10)
 *   └── README.txt      (optional, informative)
 *
 * The entry point is {@link verifyBundleAtPath}, which performs the stateless
 * subset of spec §3.8 — everything that can be done without the subject's
 * sphere keys or the local keystore. See spec/09-local-store.md §9.4 for the
 * exact scope.
 *
 * In v0.2.0 the signatures/ side-files are gone: section mutation history
 * lives in the gamma log, whose current tail is committed to by the
 * manifest's `gamma.head` / `gamma.count` anchor (spec §10.7). The stateless
 * bundle check therefore verifies the *shape* of the anchor and — if the
 * log file is present in the bundle — its advertised byte length; it cannot
 * decrypt the log without the subject's sphere keys.
 */

import { existsSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { statSync } from "node:fs";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import AdmZip from "adm-zip";

import {
  AITHOS_VERSION,
  type Manifest,
  type VerifyEthosResult,
  verifyManifestSignature,
  verifyZoneSignature,
  parseZoneMarkdown,
  canonicalManifestHashHex,
} from "./ethos.js";
import { type DidDocument, verifyDidDocument } from "./identity.js";
import { SPHERE_FRAGMENTS, type Sphere } from "./did.js";

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

export interface BundleVerifyResult extends VerifyEthosResult {
  bundle_id?: string;
  edition?: { version: string; height: number };
  subject_handle?: string;
  zones_skipped: Sphere[];
}

/**
 * Optional knobs for {@link verifyBundleAtPath}.
 *
 * `resolveDelegatePubkey` lets a caller (typically `aithos ethos install` or a
 * keystore-aware verifier) resolve `authorized_by` references on the zone or
 * manifest signature to the delegate's raw Ed25519 public key. The pure
 * stateless caller — a stranger verifying a bundle on a fresh machine — has
 * no such resolver and so will fail closed on delegate-signed bundles.
 */
export interface BundleVerifyOpts {
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

/**
 * Verify a bundle at a filesystem path. `pathArg` may be either:
 *   - a directory containing the flat unpacked layout, or
 *   - a `.ethos` zip file (any extension is accepted — detection is by header).
 *
 * Stateless by default: does not touch `~/.aithos/`, does not require any
 * sealed seed. Encrypted zones have their content checks recorded as
 * `skipped`. Callers that DO have local state (e.g. installed mandates) can
 * pass `opts.resolveDelegatePubkey` to enable verification of delegate-signed
 * bundles.
 *
 * The caller should distinguish exit codes:
 *   - ok=true  → exit 0 (valid; may have warnings)
 *   - ok=false → exit 1 (parsed but invalid signatures / chains)
 *   - exceptions thrown → exit 2 (unparseable; caller wraps)
 */
export function verifyBundleAtPath(
  pathArg: string,
  opts: BundleVerifyOpts = {},
): BundleVerifyResult {
  if (!existsSync(pathArg)) {
    throw new Error(`Bundle path not found: ${pathArg}`);
  }

  let dir: string;
  let cleanup: (() => void) | null = null;

  if (statSync(pathArg).isDirectory()) {
    dir = pathArg;
  } else {
    // Assume zip. Extract into a private temp dir.
    const tmp = mkdtempSync(join(tmpdir(), "aithos-verify-"));
    try {
      const zip = new AdmZip(pathArg);
      const entries = zip.getEntries();
      // Spec §3.2.4: no plaintext zone file other than public.md.
      for (const e of entries) {
        const n = e.entryName;
        if (n.endsWith(".md") && n !== "public.md") {
          rmSync(tmp, { recursive: true, force: true });
          throw new Error(`Forbidden plaintext zone file in bundle: ${n}`);
        }
      }
      zip.extractAllTo(tmp, /* overwrite */ true);
      dir = tmp;
      cleanup = () => rmSync(tmp, { recursive: true, force: true });
    } catch (e) {
      rmSync(tmp, { recursive: true, force: true });
      throw e;
    }
  }

  try {
    return verifyBundleDir(dir, opts);
  } finally {
    if (cleanup) cleanup();
  }
}

/* -------------------------------------------------------------------------- */
/*  Directory-level verifier (flat layout)                                    */
/* -------------------------------------------------------------------------- */

function verifyBundleDir(dir: string, opts: BundleVerifyOpts): BundleVerifyResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const zonesSkipped: Sphere[] = [];

  // Check 1: required entries present (already partly enforced by zip extract;
  // we re-check at the directory level so the same code path applies to an
  // already-unpacked bundle dir).
  const manifestPath = join(dir, "manifest.json");
  const didPath = join(dir, "did.json");
  const publicMdPath = join(dir, "public.md");

  for (const [label, p] of [
    ["manifest.json", manifestPath],
    ["did.json", didPath],
    ["public.md", publicMdPath],
  ] as const) {
    if (!existsSync(p)) {
      errors.push(`bundle missing required entry: ${label}`);
    }
  }
  if (errors.length > 0) {
    return { ok: false, errors, warnings, zones_skipped: zonesSkipped };
  }

  // Check 2: manifest parses + lightly validates.
  let manifest: Manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Manifest;
  } catch (e) {
    return {
      ok: false,
      errors: [`manifest.json: not valid JSON (${(e as Error).message})`],
      warnings,
      zones_skipped: zonesSkipped,
    };
  }
  if (manifest.aithos !== AITHOS_VERSION) {
    errors.push(`manifest.aithos is not ${AITHOS_VERSION}`);
  }

  // Check 3: did.json parses + root signature verifies.
  let didDoc: DidDocument;
  try {
    didDoc = JSON.parse(readFileSync(didPath, "utf8")) as DidDocument;
  } catch (e) {
    return {
      ok: false,
      errors: [`did.json: not valid JSON (${(e as Error).message})`],
      warnings,
      zones_skipped: zonesSkipped,
    };
  }
  if (!verifyDidDocument(didDoc)) {
    errors.push("did.json root signature does not verify");
  }

  // Check 4: did.json hash ↔ manifest.integrity.sha256_of_did_json.
  const didContent = readFileSync(didPath, "utf8");
  const didHashHex = Buffer.from(sha256fn(new TextEncoder().encode(didContent))).toString("hex");
  if (didHashHex !== manifest.integrity.sha256_of_did_json) {
    errors.push(
      `sha256_of_did_json mismatch: bundle=${didHashHex} manifest=${manifest.integrity.sha256_of_did_json}`,
    );
  }

  // Manifest must commit to this DID.
  if (manifest.subject_did !== didDoc.id) {
    errors.push(`manifest.subject_did (${manifest.subject_did}) differs from did.json id (${didDoc.id})`);
  }

  // Check 6: manifest signature. Pass through the optional delegate resolver
  // so install-time callers (which have the local mandate set) can verify
  // bundles re-packed by a delegate.
  const manSig = verifyManifestSignature(manifest, didDoc, {
    resolveDelegatePubkey: opts.resolveDelegatePubkey,
  });
  if (!manSig.ok) errors.push(manSig.error ?? "manifest signature failed");

  // Per-zone checks (5, 7).
  for (const z of SPHERE_FRAGMENTS) {
    const zm = manifest.zones[z];
    if (!zm) {
      errors.push(`manifest.zones.${z} missing`);
      continue;
    }

    if (zm.encrypted) {
      // Encrypted zones are not decryptable statelessly: skip content-dependent
      // checks, but still surface the declared shape so auditors see it.
      zonesSkipped.push(z);
      warnings.push(
        `zone ${z}: content checks skipped (encrypted; no decryption key) — ` +
          `manifest declares ${zm.section_titles.length} section(s), ` +
          `${zm.cipher?.wraps?.length ?? 0} wrap recipient(s)`,
      );
      continue;
    }

    // Plaintext zone (public). Read the on-disk bytes; they ARE the canonical
    // plaintext that was hashed into the manifest at persist time. Hashing a
    // re-render here would diverge any time the renderer's edition-dependent
    // metadata moves (e.g. when a later edition carries forward an unchanged
    // public zone), even though the bytes on disk haven't changed.
    const zonePath = join(dir, "public.md");
    if (!existsSync(zonePath)) {
      errors.push(`zone ${z}: public.md missing`);
      continue;
    }
    const markdown = readFileSync(zonePath, "utf8");

    let doc;
    try {
      doc = parseZoneMarkdown(markdown, z);
    } catch (e) {
      errors.push(`zone ${z}: failed to parse (${(e as Error).message})`);
      continue;
    }

    // 5: plaintext hash — direct over the on-disk bytes.
    const hex = Buffer.from(sha256fn(new TextEncoder().encode(markdown))).toString("hex");
    if (hex !== zm.sha256_of_plaintext) {
      errors.push(
        `zone ${z}: sha256_of_plaintext mismatch (on-disk=${hex} manifest=${zm.sha256_of_plaintext})`,
      );
    }

    // section_titles consistency.
    const actualTitles = doc.sections.map((s) => s.title);
    if (JSON.stringify(actualTitles) !== JSON.stringify(zm.section_titles)) {
      errors.push(`zone ${z}: section_titles mismatch`);
    }

    // Zone signature (§3.3.1). Same delegate-resolver passthrough as above.
    const zs = verifyZoneSignature(doc, zm.signature, didDoc, {
      resolveDelegatePubkey: opts.resolveDelegatePubkey,
    });
    if (!zs.ok) errors.push(`zone ${z}: ${zs.error}`);

    // Every live section must carry a gamma_ref — the signed gamma entry
    // that produced the current state. We can't validate the target entry
    // statelessly (the log is encrypted), but the manifest's gamma anchor
    // pins its tail. That's checked below.
    for (const sec of doc.sections) {
      if (!sec.gamma_ref) {
        errors.push(`zone ${z} section ${sec.id}: missing gamma_ref`);
      }
    }
  }

  // Gamma anchor shape (stateless — no decryption).
  //
  // Spec §10.7: the signed manifest commits to the log's current tail via
  // `gamma.head` + `gamma.count`. We can't open the sealed .jsonl.enc without
  // sphere keys, but we can at least assert:
  //   - the anchor is internally consistent (head null iff count 0),
  //   - if the bundle ships the log file, its byte length is nonzero when
  //     count > 0, and the file is absent when count == 0.
  if (manifest.gamma) {
    const { head, count } = manifest.gamma;
    if (count < 0 || !Number.isInteger(count)) {
      errors.push(`gamma.count must be a non-negative integer`);
    }
    if ((head === null) !== (count === 0)) {
      errors.push(
        `gamma anchor inconsistent: head=${head ?? "null"} but count=${count}`,
      );
    }
    const logPath = join(dir, "gamma.jsonl.enc");
    const hasLog = existsSync(logPath);
    if (hasLog) {
      const sz = statSync(logPath).size;
      if (count === 0 && sz > 0) {
        errors.push(
          `gamma anchor declares count=0 but gamma.jsonl.enc is ${sz} bytes`,
        );
      }
      if (count > 0 && sz === 0) {
        errors.push(
          `gamma anchor declares count=${count} but gamma.jsonl.enc is empty`,
        );
      }
      warnings.push(
        `gamma log present in bundle (${sz} bytes, sealed) — deep verification skipped (no sphere key)`,
      );
    } else if (count > 0) {
      warnings.push(
        `gamma anchor declares ${count} entr${count === 1 ? "y" : "ies"} (head=${head}) but gamma.jsonl.enc is not in the bundle — log verification deferred to subject`,
      );
    }
  } else {
    // No anchor. Allowed only for a completely empty-history ethos, i.e. no
    // sections at all in any zone. But every section is born from a gamma
    // entry, so if any zone has titles the anchor is required.
    const anyTitles = SPHERE_FRAGMENTS.some(
      (z) => (manifest.zones[z]?.section_titles?.length ?? 0) > 0,
    );
    if (anyTitles) {
      errors.push(
        `manifest has sections but no gamma anchor — every section must be born from a signed gamma entry (spec §10)`,
      );
    }
  }

  // Check 8: edition self-consistency.
  if (manifest.edition.height < 1) errors.push("edition.height must be >= 1");
  if ((manifest.edition.prev_hash === null) !== (manifest.edition.supersedes === null)) {
    errors.push("edition.prev_hash must be null iff edition.supersedes is null");
  }

  // Check 9 (inter-edition link) is intentionally NOT done — the predecessor
  // lives in the keystore, not the bundle. See spec §9.4.
  if (manifest.edition.supersedes) {
    warnings.push(
      `edition supersedes ${manifest.edition.supersedes} — inter-edition link ` +
        `not checked (predecessor not in bundle; use 'ethos verify --handle' after install)`,
    );
  }

  // Bonus: compute canonical hash of this manifest, useful for tracing.
  try {
    canonicalManifestHashHex(manifest);
  } catch {
    /* non-fatal */
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    bundle_id: manifest.bundle_id,
    edition: { version: manifest.edition.version, height: manifest.edition.height },
    subject_handle: manifest.subject_handle,
    zones_skipped: zonesSkipped,
  };
}

/** Pretty one-line description for log output. */
export function describeBundle(dir: string): string {
  try {
    const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as Manifest;
    return `${m.subject_handle} — edition ${m.edition.version} (height ${m.edition.height})`;
  } catch {
    return `(unreadable bundle at ${basename(dir)})`;
  }
}
