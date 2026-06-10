// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Keystore-native v0.3 (opt-in) — lot 4b-2.
 *
 * The live ethos dir (`~/.aithos/identities/<handle>/ethos/`) for a v0.3 ethos
 * IS a v0.3 bundle directory: `manifest.json` (aithos 0.3.0), `did.json`,
 * `public/<id>.md`, `circle|self/<id>.enc`, `gamma.jsonl.enc`, `history/`. This
 * module lets the keystore hold + mutate that v0.3 layout, ALONGSIDE the v0.2
 * monolithic format — nothing here flips the default; callers dispatch on
 * {@link keystoreEthosVersion}.
 *
 * Mutations reuse the bundle primitives ({@link editSectionV03} /
 * {@link deleteSectionV03}): a new edition is authored into a temp dir, then
 * swapped into the keystore (the prior manifest is archived under `history/`).
 * The keystore lives under the user's home — not the FUSE code mount — so the
 * swap's unlinks are unrestricted.
 */

import { existsSync, readdirSync, rmSync, copyFileSync, mkdtempSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  ethosDir,
  ethosHistoryDir,
  ethosManifestPath,
  packEthosToDir,
  AITHOS_VERSION_V03,
} from "./ethos.js";
import { ensureDir, readJson, writeJson } from "./storage.js";
import { type Sphere, SPHERE_FRAGMENTS } from "./did.js";
import { type Identity } from "./identity.js";
import { type Author } from "./author.js";
import { type Section } from "./ethos.js";
import { type ManifestV03, authorBundleV03 } from "./bundle-v03.js";
import { migrateBundleV02ToV03, isV02Aithos, readBundleSections } from "./bundle-migrate.js";
import { editSectionV03, deleteSectionV03, editSectionsV03, type BatchSectionEdit, type SectionChange } from "./bundle-edit.js";

/* -------------------------------------------------------------------------- */
/*  Write-format default (lot 4b-3)                                            */
/* -------------------------------------------------------------------------- */

/** The on-disk format a NEW edition is written in. */
export type WriteFormat = "v0.2" | "v0.3";

/**
 * The default on-disk write format. v0.3 (per-section) is now the default;
 * set `AITHOS_FORMAT=v0.2` (or `0.2.0`) to opt back into the legacy monolithic
 * format for a fresh `init` and to suppress auto-migration on the first write.
 * Any other value (unset, `v0.3`, `0.3.0`) selects v0.3.
 */
export function defaultWriteFormat(): WriteFormat {
  const v = process.env.AITHOS_FORMAT?.trim();
  if (v === "v0.2" || v === "0.2.0") return "v0.2";
  return "v0.3";
}

/** The `aithos` version of the installed ethos, or `null` if there is no ethos. */
export function keystoreEthosVersion(handle: string): string | null {
  const p = ethosManifestPath(handle);
  if (!existsSync(p)) return null;
  try {
    return (readJson<{ aithos?: string }>(p).aithos ?? null) as string | null;
  } catch {
    return null;
  }
}

/** True if the installed ethos is stored in the v0.3 per-section format. */
export function isV03Keystore(handle: string): boolean {
  return keystoreEthosVersion(handle) === AITHOS_VERSION_V03;
}

/* -------------------------------------------------------------------------- */
/*  Edition swap (replace the ethos dir with a freshly-authored edition)      */
/* -------------------------------------------------------------------------- */

function copyTree(src: string, dst: string): void {
  ensureDir(dst);
  for (const e of readdirSync(src)) {
    const s = join(src, e);
    const d = join(dst, e);
    if (statSync(s).isDirectory()) copyTree(s, d);
    else copyFileSync(s, d);
  }
}

/**
 * Make the keystore ethos dir equal to a freshly-authored v0.3 edition in
 * `newDir`: archive the prior manifest, copy the new edition in, then remove
 * any stale zone blobs (the v0.2 monolithic files, or sections deleted in the
 * new edition) and the old `gamma/` subdir (v0.3 keeps the log at the root).
 */
function swapKeystoreEdition(handle: string, newDir: string, oldManifest: { edition: { version: string } }): void {
  const dir = ethosDir(handle);
  ensureDir(ethosHistoryDir(handle));
  writeJson(join(ethosHistoryDir(handle), `${oldManifest.edition.version}.manifest.json`), oldManifest, 0o600);

  copyTree(newDir, dir);

  const m = readJson<ManifestV03>(join(newDir, "manifest.json"));
  for (const z of SPHERE_FRAGMENTS) {
    const keep = new Set(m.zones[z].sections.map((s) => s.file.split("/")[1]));
    const zd = join(dir, z);
    if (!existsSync(zd)) continue;
    for (const fn of readdirSync(zd)) {
      if (!keep.has(fn)) rmSync(join(zd, fn), { force: true });
    }
  }
  const oldGamma = join(dir, "gamma");
  if (existsSync(oldGamma)) rmSync(oldGamma, { recursive: true, force: true });
}

/* -------------------------------------------------------------------------- */
/*  Migrate the keystore in place (v0.2 → v0.3)                               */
/* -------------------------------------------------------------------------- */

export interface MigrateKeystoreArgs {
  handle: string;
  identity: Identity;
  now?: Date;
}

/**
 * Migrate the installed v0.2 ethos to the v0.3 per-section format IN PLACE. The
 * ethos dir becomes a v0.3 bundle; the prior v0.2 manifest is archived under
 * `history/`. Idempotent guard: throws if the ethos is already v0.3.
 */
export function migrateKeystoreInPlace(args: MigrateKeystoreArgs): ManifestV03 {
  const { handle, identity } = args;
  const cur = readJson<{ aithos: string; edition: { version: string } }>(ethosManifestPath(handle));
  if (cur.aithos === AITHOS_VERSION_V03) throw new Error(`Ethos "${handle}" is already v0.3.`);
  if (!isV02Aithos(cur.aithos)) throw new Error(`Ethos "${handle}" is not a v0.2 ethos (aithos=${cur.aithos}).`);

  const v02tmp = mkdtempSync(join(tmpdir(), "aithos-ks-v02-"));
  const v03tmp = mkdtempSync(join(tmpdir(), "aithos-ks-v03-"));
  try {
    packEthosToDir({ handle, identity, outDir: v02tmp });
    const mig = migrateBundleV02ToV03({ identity, v02Dir: v02tmp, outDir: v03tmp, now: args.now });
    swapKeystoreEdition(handle, v03tmp, cur);
    return mig;
  } finally {
    rmSync(v02tmp, { recursive: true, force: true });
    rmSync(v03tmp, { recursive: true, force: true });
  }
}

/**
 * Create a fresh, EMPTY v0.3 ethos directly in the keystore (edition height 1,
 * no predecessor). Used by `ethos init` / `aithos init` when v0.3 is the write
 * default ({@link defaultWriteFormat}). The caller must have already ensured the
 * target ethos dir is absent (or wiped under `--force`); the identity's
 * `did.json` must exist on disk (authorBundleV03 copies + hashes it).
 */
export function initKeystoreV03(args: { handle: string; identity: Identity; now?: Date }): ManifestV03 {
  const dir = ethosDir(args.handle);
  const tmp = mkdtempSync(join(tmpdir(), "aithos-ks-init-"));
  try {
    const m = authorBundleV03({
      identity: args.identity,
      outDir: tmp,
      zones: { public: [], circle: [], self: [] },
      now: args.now,
    });
    ensureDir(dir);
    copyTree(tmp, dir);
    return m;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * On the owner write path, migrate an installed v0.2 ethos to v0.3 IN PLACE when
 * v0.3 is the default write format ({@link defaultWriteFormat}). No-op when the
 * default is v0.2, when the ethos is already v0.3, or when there is no ethos.
 * Returns true iff a migration ran. Requires the owner identity (sphere keys);
 * delegate writers cannot migrate and should not call this.
 */
export function autoMigrateKeystoreIfDefault(args: MigrateKeystoreArgs): boolean {
  if (defaultWriteFormat() !== "v0.3") return false;
  const v = keystoreEthosVersion(args.handle);
  if (v === null || v === AITHOS_VERSION_V03) return false;
  migrateKeystoreInPlace(args);
  return true;
}

/* -------------------------------------------------------------------------- */
/*  Mutate a v0.3 keystore                                                    */
/* -------------------------------------------------------------------------- */

export interface KeystoreEditArgs {
  handle: string;
  author: Identity | Author;
  zone: Sphere;
  sectionId: string;
  /** Upsert (add/modify). Omit for a delete. */
  change?: SectionChange;
  delete?: boolean;
  gammaRef?: string;
  now?: Date;
}

/**
 * Add/modify/delete a section in the installed v0.3 ethos, writing a new
 * edition into the keystore (only the touched section is re-encrypted; the rest
 * carry forward; the prior manifest is archived). Owner or delegate.
 */
export function keystoreEditSection(args: KeystoreEditArgs): ManifestV03 {
  const dir = ethosDir(args.handle);
  const cur = readJson<{ edition: { version: string } }>(join(dir, "manifest.json"));
  const tmp = mkdtempSync(join(tmpdir(), "aithos-ks-edit-"));
  try {
    const m = args.delete
      ? deleteSectionV03({
          author: args.author,
          bundleDir: dir,
          outDir: tmp,
          zone: args.zone,
          sectionId: args.sectionId,
          now: args.now,
        })
      : editSectionV03({
          author: args.author,
          bundleDir: dir,
          outDir: tmp,
          zone: args.zone,
          sectionId: args.sectionId,
          change: args.change,
          gammaRef: args.gammaRef,
          now: args.now,
        });
    swapKeystoreEdition(args.handle, tmp, cur);
    return m;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** Read the installed v0.3 ethos into per-zone sections (decrypting with the owner's keys). */
export function keystoreReadSectionsV03(handle: string, owner: Identity): Record<Sphere, Section[]> {
  return readBundleSections(ethosDir(handle), owner);
}

/**
 * Apply N section edits to the installed v0.3 ethos in ONE new edition
 * (P2 transactional path — the batch counterpart of {@link keystoreEditSection}).
 * Same tmp-build + atomic swap + history-archive flow.
 */
export function keystoreEditSections(args: {
  handle: string;
  author: Identity | Author;
  edits: readonly BatchSectionEdit[];
  now?: Date;
}): ManifestV03 {
  const dir = ethosDir(args.handle);
  const cur = readJson<{ edition: { version: string } }>(join(dir, "manifest.json"));
  const tmp = mkdtempSync(join(tmpdir(), "aithos-ks-edit-"));
  try {
    const m = editSectionsV03({
      author: args.author,
      bundleDir: dir,
      outDir: tmp,
      edits: args.edits,
      now: args.now,
    });
    swapKeystoreEdition(args.handle, tmp, cur);
    return m;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
