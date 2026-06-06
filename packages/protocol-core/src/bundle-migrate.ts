// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * v0.2 ↔ v0.3 boundary: the compat read path (§3.10.2′) and the one-shot
 * v0.2 → v0.3 migration (§3.10.3′).
 *
 * A v0.3 runtime MUST be able to *read* a v0.2 bundle, and MUST be able to
 * *migrate* one forward into the per-section format. Both live here so the
 * v0.2-decode logic has a single home and the migration reuses it verbatim.
 *
 * Neither path re-encrypts historical editions (§3.10.4′): migration produces a
 * single forward edition whose `supersedes` / `prev_hash` point back at the
 * unchanged v0.2 predecessor.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  type Manifest,
  type Section,
  decryptZone,
  parseZoneMarkdown,
  authorZoneDecryptRecipient,
  subjectRecipientFor,
  canonicalManifestHashHex,
} from "./ethos.js";
import { type Author } from "./author.js";
import { type Identity } from "./identity.js";
import { type Sphere, SPHERE_FRAGMENTS } from "./did.js";
import {
  authorBundleV03,
  readSection,
  type ManifestV03,
  type SectionRecipient,
  type SectionReader,
} from "./bundle-v03.js";

/* -------------------------------------------------------------------------- */
/*  Version detection (§3.10.1′)                                              */
/* -------------------------------------------------------------------------- */

/** True for a v0.1.x / v0.2.x bundle marker (the compat-read regime). */
export function isV02Aithos(aithos: unknown): boolean {
  return (
    typeof aithos === "string" && (aithos.startsWith("0.1.") || aithos.startsWith("0.2."))
  );
}

/* -------------------------------------------------------------------------- */
/*  Compat read path (§3.10.2′)                                               */
/* -------------------------------------------------------------------------- */

export interface DecodedV02Bundle {
  manifest: Manifest;
  /** Decrypted, parsed sections per zone. */
  zones: Record<Sphere, Section[]>;
}

/**
 * Read a v0.2 (monolithic) bundle directory into per-zone sections, decrypting
 * `circle` / `self` with the v0.2 zone-DEK construction (§3.4.2). `who` is the
 * owner identity (or an authorised Author) holding the sphere secrets.
 */
export function decodeBundleV02(dir: string, who: Identity | Author): DecodedV02Bundle {
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as Manifest;
  if (!isV02Aithos(manifest.aithos)) {
    throw new Error(`decodeBundleV02: not a v0.2 bundle (aithos=${manifest.aithos})`);
  }

  const zones = {} as Record<Sphere, Section[]>;
  for (const zone of SPHERE_FRAGMENTS) {
    const zm = manifest.zones?.[zone];
    if (!zm) {
      zones[zone] = [];
      continue;
    }
    const file = join(dir, zm.file);
    let markdown: string;
    if (!zm.encrypted) {
      markdown = existsSync(file) ? readFileSync(file, "utf8") : "";
    } else {
      if (!existsSync(file)) {
        zones[zone] = [];
        continue;
      }
      if (!zm.cipher) throw new Error(`v0.2 manifest missing cipher for zone ${zone}`);
      const recipient = authorZoneDecryptRecipient(who, zone as "circle" | "self");
      markdown = decryptZone(
        new Uint8Array(readFileSync(file)),
        zm.cipher,
        manifest.subject_did,
        recipient.did,
        recipient.x25519Secret,
      );
    }
    zones[zone] = markdown ? parseZoneMarkdown(markdown, zone).sections : [];
  }

  return { manifest, zones };
}

/* -------------------------------------------------------------------------- */
/*  Unified reader — handles BOTH v0.2 and v0.3 (§ sequencing step 7)        */
/* -------------------------------------------------------------------------- */

/**
 * Read any bundle directory (v0.2 or v0.3) into per-zone sections. Dispatches
 * on the top-level `aithos` marker. For v0.3, encrypted-zone sections are
 * decrypted with the subject sphere readers derived from `owner`; sections the
 * reader is not entitled to are simply omitted (§3.4.2′). For v0.2, defers to
 * {@link decodeBundleV02}.
 */
export function readBundleSections(
  dir: string,
  owner: Identity,
): Record<Sphere, Section[]> {
  const raw = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as {
    aithos?: unknown;
  };

  if (isV02Aithos(raw.aithos)) {
    return decodeBundleV02(dir, owner).zones;
  }

  const manifest = raw as unknown as ManifestV03;
  const out = {} as Record<Sphere, Section[]>;
  for (const zone of SPHERE_FRAGMENTS) {
    const zm = manifest.zones?.[zone];
    if (!zm) {
      out[zone] = [];
      continue;
    }
    let reader: SectionReader | undefined;
    if (zm.encrypted) {
      const r = subjectRecipientFor(owner, zone as "circle" | "self");
      reader = { didUrl: r.did, x25519Secret: r.x25519Secret };
    }
    const sections: Section[] = [];
    for (const desc of zm.sections) {
      const res = readSection(dir, zm, desc, manifest.subject_did, reader);
      if (res.accessible && res.section) sections.push(res.section);
    }
    out[zone] = sections;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  One-shot migration v0.2 → v0.3 (§3.10.3′)                                 */
/* -------------------------------------------------------------------------- */

export interface MigrateV02ToV03Args {
  /** Owner identity (must hold the sphere secrets to decrypt the v0.2 zones). */
  identity: Identity;
  /** Directory of the v0.2 bundle to migrate. */
  v02Dir: string;
  /** Directory to write the v0.3 migration edition into. */
  outDir: string;
  now?: Date;
  /** Override recipients per encrypted zone (default: subject only). */
  recipientsFor?: (zone: "circle" | "self") => SectionRecipient[];
}

/**
 * Migrate a v0.2 bundle to a v0.3 migration edition (§3.10.3′). Decrypts and
 * splits each v0.2 zone into per-section blobs, freshly encrypting `circle` /
 * `self` sections under independent per-section DEKs and writing `public`
 * sections as plaintext files. The new edition's `supersedes` / `prev_hash`
 * point back at the unchanged v0.2 predecessor (computed via the v0.2
 * canonicalizer), so the chain cross-validates across the version boundary.
 *
 * Note: the migration's `bundle.migrate.v0.3` gamma entry (§3.10.3′) is part of
 * the gamma-v0.3 op vocabulary, tracked separately; this function produces the
 * bundle-layer migration edition only.
 */
export function migrateBundleV02ToV03(args: MigrateV02ToV03Args): ManifestV03 {
  const decoded = decodeBundleV02(args.v02Dir, args.identity);
  const v02 = decoded.manifest;

  return authorBundleV03({
    identity: args.identity,
    outDir: args.outDir,
    zones: decoded.zones,
    now: args.now,
    recipientsFor: args.recipientsFor,
    prevEdition: {
      version: v02.edition.version,
      bundleId: v02.bundle_id,
      manifestHashHex: canonicalManifestHashHex(v02),
      height: v02.edition.height,
    },
  });
}
