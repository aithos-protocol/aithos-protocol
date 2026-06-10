// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Targeted section editing on a v0.3 bundle (lot 4a / lot b).
 *
 * `editSectionV03` / `deleteSectionV03` produce a NEW edition of a v0.3 bundle
 * with a single section upserted or removed, via {@link patchEditionV03}: only
 * the touched section is (re)encrypted; every sibling carries forward verbatim
 * WITHOUT being decrypted. To MODIFY, only the target section is read; to ADD or
 * DELETE, nothing is read. This is what lets a section-scoped delegate manage
 * its OWN self sections (add/edit/delete) — each self title lives in its own
 * `title_cipher`, so adding a section just seals its title to that section's
 * recipients, with no global index to rebuild.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type Sphere, SPHERE_FRAGMENTS } from "./did.js";
import { type Identity } from "./identity.js";
import { type Author, ownerAuthor } from "./author.js";
import { type Section, authorZoneDecryptRecipient } from "./ethos.js";
import { newGammaId } from "./gamma.js";
import {
  patchEditionV03,
  readSection,
  type ManifestV03,
  type SectionReader,
  type ZonePatch,
} from "./bundle-v03.js";

function toAuthor(subject: Identity | Author): Author {
  const a = subject as Author;
  if (a.kind === "owner" || a.kind === "delegate") return a;
  return ownerAuthor(subject as Identity);
}

/** Fields to set on a section. Absent fields are kept; `clearTags` wins over `tags`. */
export interface SectionChange {
  title?: string;
  body?: string;
  tags?: string[];
  clearTags?: boolean;
}

export interface EditSectionV03Args {
  /** Owner identity or an Author (owner/delegate). */
  author: Identity | Author;
  /** Current bundle directory (the predecessor edition). */
  bundleDir: string;
  /** Directory to write the new edition into. */
  outDir: string;
  zone: Sphere;
  sectionId: string;
  /** The change to apply (upsert). Omit/`undefined` only for a delete. */
  change?: SectionChange;
  /** Gamma ref to stamp on the mutated section (defaults to a fresh id). */
  gammaRef?: string;
  now?: Date;
}

function applyChange(cur: Section | undefined, sectionId: string, change: SectionChange, gammaRef: string): Section {
  const tags = change.clearTags ? undefined : change.tags !== undefined ? change.tags : cur?.tags;
  return {
    id: sectionId,
    title: change.title !== undefined ? change.title : (cur?.title ?? ""),
    body: change.body !== undefined ? change.body : (cur?.body ?? ""),
    ...(tags && tags.length > 0 ? { tags } : {}),
    gamma_ref: gammaRef,
  };
}

/**
 * Upsert one section (modify if present, add if absent) and write a new edition.
 * Re-encrypts only the touched section; all others carry forward byte-identical.
 */
export function editSectionV03(args: EditSectionV03Args): ManifestV03 {
  return mutate(args, /* del */ false);
}

/** Remove one section by id and write a new edition (the rest carry forward). */
export function deleteSectionV03(args: Omit<EditSectionV03Args, "change">): ManifestV03 {
  return mutate({ ...args, change: undefined }, /* del */ true);
}

function mutate(args: EditSectionV03Args, del: boolean): ManifestV03 {
  const author = toAuthor(args.author);
  const manifest = JSON.parse(
    readFileSync(join(args.bundleDir, "manifest.json"), "utf8"),
  ) as ManifestV03;

  const authoredZones: Sphere[] =
    author.kind === "owner" ? [...SPHERE_FRAGMENTS] : [author.mandate.actor_sphere];
  if (!authoredZones.includes(args.zone)) {
    throw new Error(
      `editSectionV03: author may not write zone ${args.zone} (authored: ${authoredZones.join(", ")})`,
    );
  }

  const zm = manifest.zones[args.zone];
  const prevDesc = zm?.sections.find((s) => s.section_id === args.sectionId);

  const patch: Partial<Record<Sphere, ZonePatch>> = {};
  if (del) {
    if (!prevDesc) throw new Error(`section ${args.sectionId} not found in zone ${args.zone}`);
    patch[args.zone] = { deletes: [args.sectionId] };
  } else {
    const gammaRef = args.gammaRef ?? newGammaId();
    let cur: Section | undefined;
    if (prevDesc) {
      // Read ONLY the target section to apply a partial change.
      let reader: SectionReader | undefined;
      if (args.zone !== "public") {
        const r = authorZoneDecryptRecipient(author, args.zone as "circle" | "self");
        reader = { didUrl: r.did, x25519Secret: r.x25519Secret };
      }
      const res = readSection(args.bundleDir, zm, prevDesc, manifest.subject_did, reader);
      if (!res.accessible || !res.section) {
        throw new Error(
          `editSectionV03: cannot read target section ${args.sectionId}: ${res.reason ?? "inaccessible"}`,
        );
      }
      cur = res.section;
    }
    const next = applyChange(cur, args.sectionId, args.change ?? {}, gammaRef);
    patch[args.zone] = { upserts: [next] };
  }

  return patchEditionV03({
    author,
    outDir: args.outDir,
    prev: { manifest, dir: args.bundleDir },
    patch,
    now: args.now,
  });
}

/* -------------------------------------------------------------------------- */
/*  Batched edits — N section changes, ONE edition (P2, D3 transactional)      */
/* -------------------------------------------------------------------------- */

/**
 * One resolved entry of a batch: upsert (add/modify) or delete. `sectionId`
 * is always explicit here — callers mint ids for adds (the storage layer
 * uses `newSectionId()`), so a batch is fully addressable before it runs.
 */
export type BatchSectionEdit =
  | {
      readonly op: "upsert";
      readonly zone: Sphere;
      readonly sectionId: string;
      readonly change: SectionChange;
      readonly gammaRef?: string;
    }
  | { readonly op: "delete"; readonly zone: Sphere; readonly sectionId: string };

export interface EditSectionsV03Args {
  /** Owner identity or an Author (owner/delegate). */
  author: Identity | Author;
  /** Current bundle directory (the predecessor edition). */
  bundleDir: string;
  /** Directory to write the new edition into. */
  outDir: string;
  /** Edits, applied IN ORDER (later edits see earlier ones in the batch). */
  edits: readonly BatchSectionEdit[];
  now?: Date;
}

/**
 * Apply N section edits and write ONE new edition (the transactional
 * counterpart of {@link editSectionV03} / {@link deleteSectionV03}).
 *
 * Semantics:
 *   - Edits resolve sequentially against (persisted state + earlier edits in
 *     the SAME batch): modify-after-add composes, delete-after-add cancels
 *     out (and is dropped from the patch), the second upsert of a section
 *     wins over the first.
 *   - Only touched sections are (re)encrypted; untouched siblings carry
 *     forward byte-identical via {@link patchEditionV03} — exactly one
 *     manifest re-sign for the whole batch.
 *   - A batch that nets out to zero changes throws (`empty batch`): callers
 *     (the MCP `ethos_commit` handler, SdkStorage) treat that as a refusal,
 *     not a no-op edition.
 *   - Authorization mirrors the single-edit path: every edit's zone must be
 *     authored by `author` (owner: all zones; delegate: its actor sphere).
 */
export function editSectionsV03(args: EditSectionsV03Args): ManifestV03 {
  if (args.edits.length === 0) {
    throw new Error("editSectionsV03: empty batch");
  }
  const author = toAuthor(args.author);
  const manifest = JSON.parse(
    readFileSync(join(args.bundleDir, "manifest.json"), "utf8"),
  ) as ManifestV03;

  const authoredZones: Sphere[] =
    author.kind === "owner" ? [...SPHERE_FRAGMENTS] : [author.mandate.actor_sphere];

  // Per-zone working state: the net effect of the batch so far.
  const pendingUpserts = new Map<Sphere, Map<string, Section>>();
  const pendingDeletes = new Map<Sphere, Set<string>>();
  const upsertsOf = (z: Sphere): Map<string, Section> => {
    let m = pendingUpserts.get(z);
    if (!m) pendingUpserts.set(z, (m = new Map()));
    return m;
  };
  const deletesOf = (z: Sphere): Set<string> => {
    let s = pendingDeletes.get(z);
    if (!s) pendingDeletes.set(z, (s = new Set()));
    return s;
  };

  /** Read the PERSISTED section (predecessor edition), or undefined. */
  const readPersisted = (zone: Sphere, sectionId: string): Section | undefined => {
    const zm = manifest.zones[zone];
    const desc = zm?.sections.find((s) => s.section_id === sectionId);
    if (!desc) return undefined;
    let reader: SectionReader | undefined;
    if (zone !== "public") {
      const r = authorZoneDecryptRecipient(author, zone as "circle" | "self");
      reader = { didUrl: r.did, x25519Secret: r.x25519Secret };
    }
    const res = readSection(args.bundleDir, zm, desc, manifest.subject_did, reader);
    if (!res.accessible || !res.section) {
      throw new Error(
        `editSectionsV03: cannot read target section ${sectionId}: ${res.reason ?? "inaccessible"}`,
      );
    }
    return res.section;
  };

  for (const e of args.edits) {
    if (!authoredZones.includes(e.zone)) {
      throw new Error(
        `editSectionsV03: author may not write zone ${e.zone} (authored: ${authoredZones.join(", ")})`,
      );
    }
    if (e.op === "delete") {
      const had = upsertsOf(e.zone).delete(e.sectionId);
      const persisted = manifest.zones[e.zone]?.sections.some(
        (s) => s.section_id === e.sectionId,
      );
      if (persisted) {
        deletesOf(e.zone).add(e.sectionId);
      } else if (!had) {
        throw new Error(
          `editSectionsV03: section ${e.sectionId} not found in zone ${e.zone}`,
        );
      }
      continue;
    }
    // upsert — base = earlier batch state, else the persisted section (unless
    // deleted earlier in the batch, which makes this a fresh add under the id).
    const deletedEarlier = deletesOf(e.zone).has(e.sectionId);
    const cur =
      upsertsOf(e.zone).get(e.sectionId) ??
      (deletedEarlier ? undefined : readPersisted(e.zone, e.sectionId));
    const next = applyChange(cur, e.sectionId, e.change, e.gammaRef ?? newGammaId());
    upsertsOf(e.zone).set(e.sectionId, next);
    deletesOf(e.zone).delete(e.sectionId);
  }

  const patch: Partial<Record<Sphere, ZonePatch>> = {};
  for (const zone of SPHERE_FRAGMENTS) {
    const ups = pendingUpserts.get(zone);
    const dels = pendingDeletes.get(zone);
    const zp: ZonePatch = {};
    if (ups && ups.size > 0) zp.upserts = [...ups.values()];
    if (dels && dels.size > 0) zp.deletes = [...dels];
    if (zp.upserts || zp.deletes) patch[zone] = zp;
  }
  if (Object.keys(patch).length === 0) {
    throw new Error("editSectionsV03: batch nets out to no changes");
  }

  return patchEditionV03({
    author,
    outDir: args.outDir,
    prev: { manifest, dir: args.bundleDir },
    patch,
    now: args.now,
  });
}
