/**
 * `aithos ethos install <path>` — install a `.ethos` bundle into the local
 * keystore as a **tracked identity**.
 *
 * Spec: §9.3.
 *
 * A tracked identity has public data (did.json + ethos/) but no sealed seeds.
 * It can be listed, read (public zone), verified (per §9.4), and — once
 * mandates have been granted to agents on this machine — used to read or write
 * non-public zones via those mandates.
 *
 *   <bundle> ──unpack──▶ flat layout ──verify─▶ ethos layout
 *
 * Layout produced (see storage.ts):
 *
 *   ~/.aithos/identities/<handle>/
 *   ├── did.json                     ← copied from bundle
 *   └── ethos/
 *       ├── manifest.json            ← copied from bundle
 *       ├── did.json                 ← snapshot (same bytes as above)
 *       ├── public/public.md         ← copied from bundle
 *       ├── circle/circle.md.enc     ← copied if encrypted zone present
 *       ├── self/self.md.enc         ← copied if encrypted zone present
 *       └── gamma/gamma.jsonl.enc    ← copied if the bundle carries the sealed
 *                                       mutation log (spec §10)
 *
 * No sealed seeds, so the keystore flags this as tracked (isTrackedIdentity).
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdtempSync,
  rmSync,
  statSync,
  copyFileSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import AdmZip from "adm-zip";

import {
  verifyBundleAtPath,
  keystoreDelegateResolver,
  type Manifest,
  type DidDocument,
  ethosDir,
  ethosZoneDir,
  ethosZoneFile,
  ethosHistoryDir,
  ethosManifestPath,
  identityDir,
  ensureDir,
  gammaDir,
  gammaFilePath,
  loadConfig,
  saveConfig,
} from "@aithos/protocol-core";

export interface EthosInstallOpts {
  path: string;
  as?: string;   // override handle
  force?: boolean; // allow overwriting an existing tracked identity at same handle
  setDefault?: boolean; // make this the default handle
  json?: boolean;
}

export function runEthosInstall(opts: EthosInstallOpts): void {
  if (!existsSync(opts.path)) {
    throw new Error(`Bundle path not found: ${opts.path}`);
  }

  /* 1 — materialize the flat layout (unpack if zip) */
  const src = materialize(opts.path);

  try {
    /* 2 — verify the bundle. We have local state (the keystore) so we can
     * resolve `authorized_by` references on delegate-signed manifests / zones
     * via locally-installed mandates. A pure stateless caller would skip the
     * resolver and fail closed; install-time we expect to know the mandates,
     * so we wire it up. */
    const bundleDidDoc = JSON.parse(
      readFileSync(join(src.dir, "did.json"), "utf8"),
    ) as DidDocument;
    const result = verifyBundleAtPath(src.dir, {
      resolveDelegatePubkey: keystoreDelegateResolver(bundleDidDoc),
    });
    if (!result.ok) {
      throw new Error(
        `bundle failed verification; refusing to install:\n  - ` +
          result.errors.join("\n  - "),
      );
    }

    /* 3 — decide target handle + do safety checks against the keystore. */
    const manifest = JSON.parse(
      readFileSync(join(src.dir, "manifest.json"), "utf8"),
    ) as Manifest;

    const handle = opts.as ?? manifest.subject_handle;
    if (!handle) throw new Error("manifest has no subject_handle and --as was not supplied");

    const targetDir = identityDir(handle);
    if (existsSync(targetDir)) {
      // If there's an existing identity at this handle, it must be the SAME
      // subject (same DID) and we must have permission to overwrite. Otherwise
      // refuse with a clear message — this is where someone else tries to
      // shadow a local owned identity or a previously installed tracked one.
      const existingDidPath = join(targetDir, "did.json");
      if (existsSync(existingDidPath)) {
        const existingDid = JSON.parse(readFileSync(existingDidPath, "utf8")).id;
        if (existingDid !== manifest.subject_did) {
          throw new Error(
            `identity "${handle}" already exists with a different DID ` +
              `(${existingDid} vs bundle's ${manifest.subject_did}). ` +
              `Use --as <other-handle> to install under a different name.`,
          );
        }
      }
      // Same DID — check whether we're shadowing an *owned* identity (which
      // has sealed seeds we must never clobber). With --force we still allow
      // the install: `installIntoKeystore` only writes did.json, manifest.json,
      // zone files, and the gamma log — sealed seeds are left alone. This is
      // the path an owner takes to pull a delegate-produced edition back into
      // their own keystore.
      const hasSealedSeeds = ["root", "public", "circle", "self"].some((r) =>
        existsSync(join(targetDir, `${r}.sealed.json`)),
      );
      if (hasSealedSeeds && !opts.force) {
        throw new Error(
          `identity "${handle}" is owned locally (sealed seeds present). ` +
            `Pass --force to overwrite the ethos files (sealed seeds are preserved). ` +
            `Use this to pull back an edition produced by one of your delegates.`,
        );
      }
      // Same DID, tracked-only already. Allow only with --force to avoid
      // accidentally rolling back to an older edition.
      if (!hasSealedSeeds && !opts.force) {
        throw new Error(
          `identity "${handle}" is already installed (tracked). ` +
            `Re-run with --force to overwrite with the bundle's edition.`,
        );
      }
    }

    /* 4 — install into the nested ethos layout. */
    installIntoKeystore(handle, src.dir, manifest);

    if (opts.setDefault) {
      const cfg = loadConfig();
      cfg.default_handle = handle;
      saveConfig(cfg);
    }

    if (opts.json) {
      console.log(
        JSON.stringify(
          {
            installed: true,
            handle,
            did: manifest.subject_did,
            edition: manifest.edition.version,
            height: manifest.edition.height,
            tracked: true,
            dir: targetDir,
            warnings: result.warnings,
          },
          null,
          2,
        ),
      );
      return;
    }

    console.log(`Installed bundle as tracked identity "${handle}"`);
    console.log(`  DID:      ${manifest.subject_did}`);
    console.log(`  Edition:  ${manifest.edition.version} (height=${manifest.edition.height})`);
    console.log(`  Dir:      ${targetDir}`);
    console.log(`  Tracked:  yes (no sealed seeds — read-only unless mandates are granted)`);
    if (result.warnings.length > 0) {
      console.log(`  Verify warnings:`);
      for (const w of result.warnings) console.log(`    - ${w}`);
    }
    console.log(``);
    console.log(`Next:`);
    console.log(`  aithos ethos list --handle ${handle}`);
    console.log(`  aithos ethos verify --handle ${handle}`);
  } finally {
    if (src.cleanup) src.cleanup();
  }
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

interface MaterializedBundle {
  dir: string;
  cleanup: (() => void) | null;
}

function materialize(pathArg: string): MaterializedBundle {
  if (statSync(pathArg).isDirectory()) {
    return { dir: pathArg, cleanup: null };
  }
  const tmp = mkdtempSync(join(tmpdir(), "aithos-install-"));
  try {
    const zip = new AdmZip(pathArg);
    for (const e of zip.getEntries()) {
      const n = e.entryName;
      if (n.endsWith(".md") && n !== "public.md") {
        rmSync(tmp, { recursive: true, force: true });
        throw new Error(`forbidden plaintext zone file in bundle: ${n}`);
      }
    }
    zip.extractAllTo(tmp, true);
    return { dir: tmp, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
  } catch (e) {
    rmSync(tmp, { recursive: true, force: true });
    throw e;
  }
}

function installIntoKeystore(handle: string, src: string, manifest: Manifest): void {
  const target = identityDir(handle);
  ensureDir(target);

  // Keystore-level did.json (authoritative for the identity).
  const didPath = join(target, "did.json");
  writeFileSync(didPath, readFileSync(join(src, "did.json")));
  chmodSync(didPath, 0o644);

  // ethos/ native layout.
  ensureDir(ethosDir(handle));
  ensureDir(ethosZoneDir(handle, "public"));
  ensureDir(ethosZoneDir(handle, "circle"));
  ensureDir(ethosZoneDir(handle, "self"));
  ensureDir(gammaDir(handle));
  ensureDir(ethosHistoryDir(handle));

  // manifest.json
  writeFileSync(ethosManifestPath(handle), readFileSync(join(src, "manifest.json")));
  chmodSync(ethosManifestPath(handle), 0o644);

  // did.json snapshot inside ethos/ (same bytes — needed for §3.8 check 4).
  const ethosDid = join(ethosDir(handle), "did.json");
  writeFileSync(ethosDid, readFileSync(join(src, "did.json")));
  chmodSync(ethosDid, 0o644);

  // public.md
  const publicSrc = join(src, "public.md");
  if (existsSync(publicSrc)) {
    copyFileSync(publicSrc, ethosZoneFile(handle, "public"));
    chmodSync(ethosZoneFile(handle, "public"), 0o644);
  }

  // circle.md.enc
  const circleSrc = join(src, "circle.md.enc");
  if (existsSync(circleSrc)) {
    copyFileSync(circleSrc, ethosZoneFile(handle, "circle"));
    chmodSync(ethosZoneFile(handle, "circle"), 0o600);
  }

  // self.md.enc
  const selfSrc = join(src, "self.md.enc");
  if (existsSync(selfSrc)) {
    copyFileSync(selfSrc, ethosZoneFile(handle, "self"));
    chmodSync(ethosZoneFile(handle, "self"), 0o600);
  }

  // gamma.jsonl.enc — sealed mutation log (spec §10). Optional: when absent,
  // the tracked identity still has the manifest anchor and can receive the
  // log later out-of-band.
  const gammaSrc = join(src, "gamma.jsonl.enc");
  if (existsSync(gammaSrc)) {
    copyFileSync(gammaSrc, gammaFilePath(handle));
    chmodSync(gammaFilePath(handle), 0o600);
  }

  // Reference manifest to silence unused-var linter warnings, while also
  // proving we inspected it — useful if we later gate on manifest fields.
  void manifest.bundle_id;
}
