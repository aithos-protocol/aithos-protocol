// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * FilesystemStorage — the default {@link AithosStorage} backed by
 * `$AITHOS_HOME` on disk.
 *
 * This is a thin adapter over the existing filesystem helpers in
 * `storage.ts`, `identity.ts`, `ethos.ts`, and `mandate.ts`. It adds no new
 * protocol logic; every method is a synchronous call wrapped in an async
 * shell so the interface is natural for remote impls as well.
 *
 * The direct filesystem helpers (`loadIdentity`, `readManifest`,
 * `addSection`, …) remain exported from the package root — callers that
 * know they are on the filesystem and want synchronous semantics (CLI
 * commands, snapshot tools) may keep using them. Protocol hosts that want
 * to stay backend-agnostic should go through the `AithosStorage` surface.
 */

import fs from "node:fs";
import path from "node:path";

import type {
  AithosStorage,
  AppliedEditResult,
  ApplyEditsResult,
  EthosEdit,
  WriteAuth,
  SectionWriteResult,
  SectionDeleteResult,
  SectionIndexEntry,
  SectionFetchResult,
  SectionReadOpts,
} from "./backend.js";
import { type Sphere, SPHERE_FRAGMENTS } from "./did.js";
import {
  type DidDocument,
  type Identity,
  type IdentityMetadata,
  isTrackedIdentity,
  loadIdentity,
  loadIdentityMetadata,
} from "./identity.js";
import {
  addSection as coreAddSection,
  authorZoneDecryptRecipient,
  deleteSection as coreDeleteSection,
  ethosDir,
  ethosHistoryDir,
  ethosZoneFile,
  keystoreDelegateResolver,
  loadZoneDoc,
  modifySection as coreModifySection,
  newSectionId,
  readManifest,
  subjectRecipientFor,
  verifyEthos,
  type AddSectionArgs as CoreAddSectionArgs,
  type Manifest,
  type ModifySectionArgs as CoreModifySectionArgs,
  type Section,
  type VerifyEthosResult,
  type ZoneDoc,
} from "./ethos.js";
import { type Author, delegateAuthor } from "./author.js";
import { isV03Keystore, keystoreEditSection, keystoreEditSections } from "./keystore-v3.js";
import type { BatchSectionEdit } from "./bundle-edit.js";
import {
  readSection,
  readZoneIndex,
  verifyBundleV03Dir,
  type ManifestV03,
  type SectionReader,
} from "./bundle-v03.js";
import { type Mandate, type Revocation } from "./mandate.js";
import { findRevocation, loadMandate } from "./mandate-store.js";
import {
  identityDir,
  listIdentities,
  loadConfig,
  readJson,
} from "./storage.js";

/* -------------------------------------------------------------------------- */
/*  FilesystemStorage                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Default on-disk backend. Single-instance; reads `$AITHOS_HOME` from
 * `storage.ts` at call-time so the env variable can still be overridden
 * for tests that point the home at a scratch directory.
 */
export class FilesystemStorage implements AithosStorage {
  /* -------- identity domain -------------------------------------------- */

  async listHandles(): Promise<string[]> {
    return listIdentities();
  }

  async loadIdentityMetadata(handle: string): Promise<IdentityMetadata> {
    return loadIdentityMetadata(handle);
  }

  async loadIdentity(handle: string): Promise<Identity> {
    return loadIdentity(handle);
  }

  async loadDidDocument(handle: string): Promise<DidDocument> {
    return readJson<DidDocument>(path.join(identityDir(handle), "did.json"));
  }

  async isTrackedIdentity(handle: string): Promise<boolean> {
    return isTrackedIdentity(handle);
  }

  /* -------- ethos domain (reads) --------------------------------------- */

  async readManifest(handle: string): Promise<Manifest> {
    return readManifest(handle);
  }

  async readZoneDoc(
    handle: string,
    zone: Sphere,
    opts?: { identity?: Identity; manifest?: Manifest },
  ): Promise<ZoneDoc> {
    if (isV03Keystore(handle)) {
      const m = v03Manifest(handle);
      const zm = m.zones[zone];
      if (!zm) return { sections: [] };
      const reader = zoneReader(opts?.identity, zone);
      const sections: Section[] = [];
      for (const desc of zm.sections) {
        const res = readSection(ethosDir(handle), zm, desc, m.subject_did, reader);
        if (res.accessible && res.section) sections.push(res.section);
      }
      return { sections };
    }
    return loadZoneDoc(handle, zone, opts?.identity, opts?.manifest);
  }

  async readZoneBytes(handle: string, zone: Sphere): Promise<Uint8Array> {
    if (isV03Keystore(handle)) {
      throw new Error(
        `readZoneBytes: "${handle}" is a v0.3 per-section ethos — there is no single ` +
          `zone blob. Use readSectionIndex / readSections to fetch sections by id.`,
      );
    }
    return new Uint8Array(fs.readFileSync(ethosZoneFile(handle, zone)));
  }

  /* -------- ethos domain (per-section reads, v0.3) --------------------- */

  async readSectionIndex(
    handle: string,
    zone: Sphere,
    opts?: SectionReadOpts,
  ): Promise<SectionIndexEntry[]> {
    if (isV03Keystore(handle)) {
      const m = v03Manifest(handle);
      const zm = m.zones[zone];
      if (!zm) return [];
      const rows = readZoneIndex(zone, zm, m.subject_did, zoneReader(opts?.identity, zone));
      const dir = ethosDir(handle);
      return rows.map((r) => {
        const desc = zm.sections.find((s) => s.section_id === r.section_id);
        // Best-effort blob size (V1): stat the stored blob — content-addressed
        // path first (dedup store), then the per-edition file. Zero reads.
        let approx: number | undefined;
        if (desc) {
          for (const p of [
            desc.blob_sha ? path.join(dir, "blobs", desc.blob_sha) : undefined,
            path.join(dir, desc.file),
          ]) {
            if (!p) continue;
            try {
              approx = fs.statSync(p).size;
              break;
            } catch {
              /* keep probing */
            }
          }
        }
        return {
          section_id: r.section_id,
          ...(r.title !== undefined ? { title: r.title } : {}),
          ...(r.tags ? { tags: r.tags } : {}),
          title_hidden: r.title_hidden,
          gamma_ref: desc?.gamma_ref ?? "",
          ...(approx !== undefined ? { approx_size_bytes: approx } : {}),
        };
      });
    }
    // v0.2 fallback: the monolithic zone has no clear index, so we decrypt the
    // whole zone (requires the identity for circle/self) to synthesize one.
    const doc = await this.readZoneDoc(handle, zone, opts);
    return doc.sections.map((s) => ({
      section_id: s.id,
      title: s.title,
      ...(s.tags ? { tags: s.tags } : {}),
      title_hidden: false,
      gamma_ref: s.gamma_ref,
    }));
  }

  async readSections(
    handle: string,
    ids: string[],
    opts?: SectionReadOpts & { zone?: Sphere },
  ): Promise<SectionFetchResult[]> {
    const zones: Sphere[] = opts?.zone ? [opts.zone] : [...SPHERE_FRAGMENTS];

    if (isV03Keystore(handle)) {
      const m = v03Manifest(handle);
      const dir = ethosDir(handle);
      return ids.map((id) => {
        let zone: Sphere | null = null;
        for (const z of zones) {
          if (m.zones[z]?.sections.some((s) => s.section_id === id)) {
            zone = z;
            break;
          }
        }
        if (!zone) {
          return { zone: opts?.zone ?? "public", section_id: id, accessible: false, reason: "not found in manifest" };
        }
        const zm = m.zones[zone];
        const desc = zm.sections.find((s) => s.section_id === id)!;
        const res = readSection(dir, zm, desc, m.subject_did, zoneReader(opts?.identity, zone));
        return res.accessible && res.section
          ? { zone, section_id: id, accessible: true, section: res.section }
          : { zone, section_id: id, accessible: false, reason: res.reason };
      });
    }

    // v0.2 fallback: decrypt each needed zone once, then locate the ids.
    const cache = new Map<Sphere, Section[]>();
    const loadZone = async (z: Sphere): Promise<Section[]> => {
      const hit = cache.get(z);
      if (hit) return hit;
      let secs: Section[] = [];
      try {
        secs = (await this.readZoneDoc(handle, z, opts)).sections;
      } catch {
        secs = [];
      }
      cache.set(z, secs);
      return secs;
    };
    const out: SectionFetchResult[] = [];
    for (const id of ids) {
      let found: { zone: Sphere; section: Section } | null = null;
      for (const z of zones) {
        const s = (await loadZone(z)).find((x) => x.id === id);
        if (s) {
          found = { zone: z, section: s };
          break;
        }
      }
      out.push(
        found
          ? { zone: found.zone, section_id: id, accessible: true, section: found.section }
          : { zone: opts?.zone ?? "public", section_id: id, accessible: false, reason: "not found" },
      );
    }
    return out;
  }

  /* -------- ethos domain (writes) -------------------------------------- */

  async addSection(
    args: Omit<CoreAddSectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult> {
    if (isV03Keystore(args.handle)) {
      const author = v03Author(args.handle, auth, "addSection");
      const sectionId = newSectionId();
      const change = {
        title: args.title,
        body: args.body,
        ...(args.tags ? { tags: args.tags } : {}),
      };
      const m = keystoreEditSection({ handle: args.handle, author, zone: args.zone, sectionId, change });
      return v03WriteResult(args.handle, args.zone, sectionId, author, m);
    }
    const identity = requireIdentity(auth, "addSection");
    const result = coreAddSection({
      ...args,
      identity,
      delegate: auth.delegate,
    });
    return toSectionWriteResult(result);
  }

  async modifySection(
    args: Omit<CoreModifySectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult> {
    if (isV03Keystore(args.handle)) {
      const author = v03Author(args.handle, auth, "modifySection");
      const change = {
        ...(args.title !== undefined ? { title: args.title } : {}),
        ...(args.body !== undefined ? { body: args.body } : {}),
        ...(args.tags !== undefined ? { tags: args.tags } : {}),
      };
      const m = keystoreEditSection({
        handle: args.handle,
        author,
        zone: args.zone,
        sectionId: args.sectionId,
        change,
      });
      return v03WriteResult(args.handle, args.zone, args.sectionId, author, m);
    }
    const identity = requireIdentity(auth, "modifySection");
    const result = coreModifySection({
      ...args,
      identity,
      delegate: auth.delegate,
    });
    return toSectionWriteResult(result);
  }

  async deleteSection(
    args: { handle: string; zone: Sphere; sectionId: string; reason?: string },
    auth: WriteAuth,
  ): Promise<SectionDeleteResult> {
    if (isV03Keystore(args.handle)) {
      const author = v03Author(args.handle, auth, "deleteSection");
      const m = keystoreEditSection({
        handle: args.handle,
        author,
        zone: args.zone,
        sectionId: args.sectionId,
        delete: true,
      });
      return { sectionId: args.sectionId, manifest: m as unknown as Manifest };
    }
    const identity = requireIdentity(auth, "deleteSection");
    const { manifest, gammaEntry, deletedTitle } = coreDeleteSection({
      handle: args.handle,
      identity,
      delegate: auth.delegate,
      zone: args.zone,
      sectionId: args.sectionId,
      ...(args.reason !== undefined ? { reason: args.reason } : {}),
    });
    return { sectionId: args.sectionId, deletedTitle, manifest, gammaEntry };
  }

  /* -------- edition history (P3) ----------------------------------------- */

  /**
   * Resolve the archived manifest at exactly `height` from the keystore's
   * `history/` directory (the current manifest answers its own height too).
   * v0.3 keystores archive one manifest per superseded edition; `null` when
   * the height is unknown or predates the archive.
   */
  async readManifestAt(handle: string, height: number): Promise<Manifest | null> {
    if (!isV03Keystore(handle)) return null;
    const cur = v03Manifest(handle);
    if (cur.edition.height === height) return cur as unknown as Manifest;
    const hist = ethosHistoryDir(handle);
    let entries: string[];
    try {
      entries = fs.readdirSync(hist).filter((f) => f.endsWith(".manifest.json"));
    } catch {
      return null;
    }
    for (const name of entries) {
      try {
        const m = readJson<ManifestV03>(path.join(hist, name));
        if (m.edition?.height === height) return m as unknown as Manifest;
      } catch {
        /* skip corrupt archives */
      }
    }
    return null;
  }

  /* -------- transactional edits (P2) ------------------------------------ */

  /**
   * Apply N semantic edits as ONE v0.3 edition ({@link keystoreEditSections}
   * → `patchEditionV03`: touched sections re-encrypted, siblings carried
   * forward byte-identical, one manifest re-sign). v0.2 keystores do not
   * support batching — migrate to v0.3 (`aithos migrate`) or run the host
   * with per-write auto-commit.
   */
  async applyEdits(
    handle: string,
    edits: readonly EthosEdit[],
    auth: WriteAuth,
  ): Promise<ApplyEditsResult> {
    if (!isV03Keystore(handle)) {
      throw new Error(
        "FilesystemStorage.applyEdits: transactional edits require a v0.3 " +
          "ethos (run `aithos migrate`); v0.2 hosts must use per-write " +
          "auto-commit",
      );
    }
    const author = v03Author(handle, auth, "applyEdits");
    const batch: BatchSectionEdit[] = edits.map((e) => {
      if (e.op === "delete") {
        return { op: "delete", zone: e.zone, sectionId: e.sectionId };
      }
      if (e.op === "add") {
        return {
          op: "upsert",
          zone: e.zone,
          sectionId: e.sectionId ?? newSectionId(),
          change: {
            title: e.title,
            body: e.body,
            ...(e.tags ? { tags: [...e.tags] } : {}),
          },
        };
      }
      return {
        op: "upsert",
        zone: e.zone,
        sectionId: e.sectionId,
        change: {
          ...(e.title !== undefined ? { title: e.title } : {}),
          ...(e.body !== undefined ? { body: e.body } : {}),
          ...(e.tags !== undefined ? { tags: [...e.tags] } : {}),
          ...(e.clearTags ? { clearTags: true } : {}),
        },
      };
    });
    const m = keystoreEditSections({ handle, author, edits: batch });
    const results: AppliedEditResult[] = batch.map((b, i) => {
      const src = edits[i]!;
      if (b.op === "delete") {
        return { op: "delete", zone: b.zone, sectionId: b.sectionId };
      }
      const w = v03WriteResult(handle, b.zone, b.sectionId, author, m);
      return {
        op: src.op === "add" ? "add" : "modify",
        zone: b.zone,
        section: w.section,
      };
    });
    return { manifest: m as unknown as Manifest, results };
  }

  /* -------- ethos verification ----------------------------------------- */

  async verifyEthos(
    handle: string,
    identity: Identity | null,
    didDoc: DidDocument,
  ): Promise<VerifyEthosResult> {
    if (isV03Keystore(handle)) {
      const readers: SectionReader[] = [];
      if (identity) {
        for (const z of ["circle", "self"] as const) {
          const r = subjectRecipientFor(identity, z);
          readers.push({ didUrl: r.did, x25519Secret: r.x25519Secret });
        }
      }
      const dir = ethosDir(handle);
      const cur = v03Manifest(handle);
      let predecessorManifest: ManifestV03 | undefined;
      if (cur.edition.supersedes) {
        const pv = cur.edition.supersedes.split(":").pop();
        const pp = path.join(ethosHistoryDir(handle), `${pv}.manifest.json`);
        if (pv && fs.existsSync(pp)) predecessorManifest = readJson<ManifestV03>(pp);
      }
      const r = verifyBundleV03Dir(dir, {
        readers,
        resolveDelegatePubkey: keystoreDelegateResolver(didDoc),
        ...(predecessorManifest ? { predecessorManifest } : {}),
      });
      return { ok: r.ok, errors: r.errors, warnings: r.warnings };
    }
    return verifyEthos(handle, identity, didDoc);
  }

  /* -------- mandate domain --------------------------------------------- */

  async loadMandate(id: string): Promise<Mandate> {
    return loadMandate(id);
  }

  async findRevocation(mandateId: string): Promise<Revocation | null> {
    return findRevocation(mandateId);
  }

  /* -------- backend-instance state ------------------------------------- */

  async defaultHandle(): Promise<string | null> {
    return loadConfig().default_handle;
  }
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

/** Read the v0.3 keystore manifest (per-section). */
function v03Manifest(handle: string): ManifestV03 {
  return readJson<ManifestV03>(path.join(ethosDir(handle), "manifest.json"));
}

/** Derive the per-section decrypt reader for an encrypted zone from the owner identity. */
function zoneReader(identity: Identity | undefined, zone: Sphere): SectionReader | undefined {
  if (zone === "public" || !identity) return undefined;
  const r = subjectRecipientFor(identity, zone as "circle" | "self");
  return { didUrl: r.did, x25519Secret: r.x25519Secret };
}

/**
 * Resolve the v0.3 write author from a {@link WriteAuth}: the delegate when
 * `auth.delegate` is set (built from the subject metadata + the mandate it
 * names), otherwise the owner identity. The delegate path works on tracked
 * installs (only `did.json` + the mandate are needed).
 */
function v03Author(handle: string, auth: WriteAuth, op: string): Identity | Author {
  if (auth.delegate) {
    const subject = loadIdentityMetadata(handle);
    const mandate = loadMandate(auth.delegate.mandateId);
    return delegateAuthor({
      subject,
      seed: auth.delegate.keySeed,
      pubkeyMultibase: auth.delegate.keyMultibase,
      mandate,
    });
  }
  return requireIdentity(auth, op);
}

/**
 * Build a {@link SectionWriteResult} after a v0.3 per-section write: read the
 * authoritative section back (with the author's own reader, so a delegate sees
 * the section it just wrote), then project it. `gammaEntry` is omitted on v0.3
 * (the signed log append lands with gamma-v0.3); the section's `gamma_ref` is
 * the provenance anchor.
 */
function v03WriteResult(
  handle: string,
  zone: Sphere,
  sectionId: string,
  author: Identity | Author,
  manifest: ManifestV03,
): SectionWriteResult {
  const dir = ethosDir(handle);
  const zm = manifest.zones[zone];
  const desc = zm?.sections.find((s) => s.section_id === sectionId);
  let reader: SectionReader | undefined;
  if (zone !== "public") {
    const r = authorZoneDecryptRecipient(author, zone as "circle" | "self");
    reader = { didUrl: r.did, x25519Secret: r.x25519Secret };
  }
  const res = desc ? readSection(dir, zm, desc, manifest.subject_did, reader) : undefined;
  const sec = res?.section;
  return {
    section: {
      id: sectionId,
      title: sec?.title ?? "",
      gamma_ref: sec?.gamma_ref ?? desc?.gamma_ref ?? "",
      tags: sec?.tags ?? [],
    },
    manifest: manifest as unknown as Manifest,
  };
}

function requireIdentity(auth: WriteAuth, op: string): Identity {
  if (!auth.identity) {
    throw new Error(
      `FilesystemStorage.${op}: auth.identity is required (the subject's ` +
        `manifest signing key must be on disk). For delegate-only writes, ` +
        `use a RemoteStorage backend or load the subject identity locally.`,
    );
  }
  return auth.identity;
}

function toSectionWriteResult(result: {
  section: { id: string; title: string; gamma_ref: string; tags?: string[] };
  manifest: Manifest;
  gammaEntry: SectionWriteResult["gammaEntry"];
}): SectionWriteResult {
  const { section, manifest, gammaEntry } = result;
  return {
    section: {
      id: section.id,
      title: section.title,
      gamma_ref: section.gamma_ref,
      tags: section.tags ?? [],
    },
    manifest,
    gammaEntry,
  };
}
