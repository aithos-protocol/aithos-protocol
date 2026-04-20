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
 *   ├── signatures/
 *   │   └── <section_id>.json
 *   └── README.txt      (optional, informative)
 *
 * The entry point is {@link verifyBundleAtPath}, which performs the stateless
 * subset of spec §3.8 — everything that can be done without the subject's
 * sphere keys or the local keystore. See spec/09-local-store.md §9.4 for the
 * exact scope.
 */

import { existsSync, readFileSync, readdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { statSync } from "node:fs";
import { sha256 as sha256fn } from "@noble/hashes/sha256";
import AdmZip from "adm-zip";

import {
  type Manifest,
  type SignaturesFile,
  type VerifyEthosResult,
  verifyManifestSignature,
  verifyZoneSignature,
  parseZoneMarkdown,
  renderZoneMarkdown,
  canonicalManifestHashHex,
  verifySectionChain,
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
 * Verify a bundle at a filesystem path. `pathArg` may be either:
 *   - a directory containing the flat unpacked layout, or
 *   - a `.ethos` zip file (any extension is accepted — detection is by header).
 *
 * Stateless: does not touch `~/.aithos/`, does not require any sealed seed.
 * Encrypted zones have their content checks recorded as `skipped`.
 *
 * The caller should distinguish exit codes:
 *   - ok=true  → exit 0 (valid; may have warnings)
 *   - ok=false → exit 1 (parsed but invalid signatures / chains)
 *   - exceptions thrown → exit 2 (unparseable; caller wraps)
 */
export function verifyBundleAtPath(pathArg: string): BundleVerifyResult {
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
    return verifyBundleDir(dir);
  } finally {
    if (cleanup) cleanup();
  }
}

/* -------------------------------------------------------------------------- */
/*  Directory-level verifier (flat layout)                                    */
/* -------------------------------------------------------------------------- */

function verifyBundleDir(dir: string): BundleVerifyResult {
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
  if (manifest.aithos !== "0.1.0") errors.push(`manifest.aithos is not 0.1.0`);

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

  // Check 6: manifest signature.
  const manSig = verifyManifestSignature(manifest, didDoc);
  if (!manSig.ok) errors.push(manSig.error ?? "manifest signature failed");

  // Signatures side-files — read all under signatures/ so parseZoneMarkdown
  // can consume them.
  const sigDir = join(dir, "signatures");
  const sigFiles: Record<string, SignaturesFile> = {};
  if (existsSync(sigDir)) {
    for (const fn of readdirSync(sigDir)) {
      if (!fn.endsWith(".json")) continue;
      try {
        const sf = JSON.parse(readFileSync(join(sigDir, fn), "utf8")) as SignaturesFile;
        sigFiles[sf.section_id] = sf;
      } catch (e) {
        warnings.push(`signatures/${fn}: unparseable (${(e as Error).message})`);
      }
    }
  }

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

    // Plaintext zone (public). Read, parse, hash, verify zone signature, chains.
    const zonePath = join(dir, "public.md");
    if (!existsSync(zonePath)) {
      errors.push(`zone ${z}: public.md missing`);
      continue;
    }
    const markdown = readFileSync(zonePath, "utf8");

    let doc;
    try {
      doc = parseZoneMarkdown(markdown, sigFiles, z, { subjectDid: manifest.subject_did });
    } catch (e) {
      errors.push(`zone ${z}: failed to parse (${(e as Error).message})`);
      continue;
    }

    // 5: plaintext hash. Re-render and compare to manifest declaration.
    // Re-rendering from the parsed doc gives us the canonical zone markdown
    // that the manifest's sha256_of_plaintext should match.
    const md = renderZoneMarkdown(z, doc, {
      subjectDid: manifest.subject_did,
      subjectHandle: manifest.subject_handle,
      editionVersion: manifest.edition.version,
      createdAt: manifest.edition.created_at,
    });
    const hex = Buffer.from(sha256fn(new TextEncoder().encode(md))).toString("hex");
    if (hex !== zm.sha256_of_plaintext) {
      errors.push(
        `zone ${z}: sha256_of_plaintext mismatch (rendered=${hex} manifest=${zm.sha256_of_plaintext})`,
      );
    }

    // section_titles consistency.
    const actualTitles = doc.sections.map((s) => s.title);
    if (JSON.stringify(actualTitles) !== JSON.stringify(zm.section_titles)) {
      errors.push(`zone ${z}: section_titles mismatch`);
    }

    // Zone signature (§3.3.1).
    const zs = verifyZoneSignature(doc, zm.signature, didDoc);
    if (!zs.ok) errors.push(`zone ${z}: ${zs.error}`);

    // Section hash chain + per-revision signatures (§2.5.4.2).
    for (const sec of doc.sections) {
      const res = verifySectionChain(sec, z, didDoc, manifest);
      for (const e of res.errors) errors.push(`zone ${z} section ${sec.id}: ${e}`);
      for (const w of res.warnings) warnings.push(`zone ${z} section ${sec.id}: ${w}`);

      // signatures/<sec>.json agreement.
      const sigFile = sigFiles[sec.id];
      if (!sigFile) {
        errors.push(`zone ${z} section ${sec.id}: signatures/${sec.id}.json missing`);
        continue;
      }
      if (sigFile.zone !== z) {
        errors.push(`zone ${z} section ${sec.id}: sig file records zone=${sigFile.zone}`);
      }
      for (const r of sec.revisions) {
        const entry = sigFile.revisions.find((e) => e.revision === r.revision);
        if (!entry) {
          errors.push(`section ${sec.id} rev ${r.revision}: no entry in signatures side-file`);
        } else if (entry.hash !== r.hash) {
          errors.push(`section ${sec.id} rev ${r.revision}: hash mismatch between chain and sig file`);
        } else if (entry.signature_value !== r.signature.value) {
          errors.push(`section ${sec.id} rev ${r.revision}: signature_value mismatch`);
        }
      }
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
