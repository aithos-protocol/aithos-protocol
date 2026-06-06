// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos ethos migrate-to-v0.3`
 *
 * Migrate the subject's v0.2 (zone-monolithic) ethos into a v0.3 per-section
 * bundle (spec draft bundle-v0.3, §3.10.3′). The live keystore ethos is packed
 * into a transient v0.2 bundle, decoded with the owner's sphere keys, and
 * re-authored into a v0.3 bundle written to `--out`: every zone is split into
 * per-section blobs (`public/<id>.md`, `circle|self/<id>.enc`) under fresh
 * per-section DEKs, and the migration edition chains back to the unchanged v0.2
 * predecessor via `supersedes` / `prev_hash`.
 *
 * Scope note: this PRODUCES a v0.3 bundle directory; it does NOT rewrite the
 * keystore's live ethos, which stays v0.2. The on-disk format default flips to
 * v0.3 in a later release once v0.3 is promoted to normative — until then the
 * two formats coexist (v0.2 default, v0.3 opt-in).
 */

import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  ethosDir,
  readManifest,
  loadConfig,
  loadIdentity,
  packEthosToDir,
  migrateBundleV02ToV03,
  migrateKeystoreInPlace,
  isV02Aithos,
} from "@aithos/protocol-core";

export interface EthosMigrateOpts {
  handle?: string;
  out?: string;
  inPlace?: boolean;
  json?: boolean;
}

export function runEthosMigrateToV03(opts: EthosMigrateOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) throw new Error(`No ethos for "${handle}".`);

  const manifest = readManifest(handle);
  if (!isV02Aithos(manifest.aithos)) {
    throw new Error(
      `Ethos "${handle}" declares aithos=${manifest.aithos}, which is not a v0.2 bundle — nothing to migrate.`,
    );
  }

  // Owner keys are required to decrypt circle/self before re-encrypting per-section.
  const identity = loadIdentity(handle);

  // --in-place: convert the live keystore ethos to v0.3 (it becomes the write format).
  if (opts.inPlace) {
    const mig = migrateKeystoreInPlace({ handle, identity });
    if (opts.json) {
      console.log(JSON.stringify({ handle, in_place: true, bundle_id: mig.bundle_id, edition: mig.edition }, null, 2));
      return;
    }
    console.log(`[handle=${handle}] Migrated the live ethos to v0.3 IN PLACE`);
    console.log(`  bundle_id:  ${mig.bundle_id}`);
    console.log(`  edition:    ${mig.edition.version} (height=${mig.edition.height})`);
    console.log(`  note: add/modify/delete-section now write per-section. v0.2 editions are archived in history/.`);
    return;
  }

  const outDir = opts.out ?? join(process.cwd(), `${handle}-${manifest.edition.version}-v0.3`);

  // Pack the live ethos into a transient v0.2 bundle, then migrate it forward.
  const srcTmp = mkdtempSync(join(tmpdir(), "aithos-migrate-src-"));
  try {
    packEthosToDir({ handle, identity, outDir: srcTmp });
    const mig = migrateBundleV02ToV03({ identity, v02Dir: srcTmp, outDir });

    if (opts.json) {
      console.log(
        JSON.stringify(
          {
            handle,
            migrated_to: outDir,
            bundle_id: mig.bundle_id,
            supersedes: mig.edition.supersedes,
            prev_hash: mig.edition.prev_hash,
            edition: { version: mig.edition.version, height: mig.edition.height },
            sections: {
              public: mig.zones.public.sections.length,
              circle: mig.zones.circle.sections.length,
              self: mig.zones.self.sections.length,
            },
          },
          null,
          2,
        ),
      );
      return;
    }

    const counts = (["public", "circle", "self"] as const)
      .map((z) => `${z}=${mig.zones[z].sections.length}`)
      .join(" ");
    console.log(`[handle=${handle}] Migrated ethos to v0.3 → ${outDir}`);
    console.log(`  bundle_id:  ${mig.bundle_id}`);
    console.log(`  supersedes: ${mig.edition.supersedes}`);
    console.log(`  edition:    ${mig.edition.version} (height=${mig.edition.height})`);
    console.log(`  sections:   ${counts}`);
    console.log(
      `  note: wrote a v0.3 BUNDLE; your live keystore ethos stays v0.2 (the format default flips later).`,
    );
  } finally {
    rmSync(srcTmp, { recursive: true, force: true });
  }
}
