// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Targeted section editing on a v0.3 bundle (lot 4a).
 *
 * `editSectionV03` / `deleteSectionV03` produce a NEW edition of a v0.3 bundle
 * with a single section upserted or removed, carrying everything else forward
 * (the per-section carry-forward of §3.5.3′ re-encrypts only the touched
 * section). They are the reusable primitive behind `aithos ethos write` /
 * `aithos ethos rm` and the future keystore-native v0.3 mutation commands.
 *
 * Author model:
 *   - Owner → reads + re-authors all three zones (it holds every key).
 *   - Delegate → re-authors only its mandate's `actor_sphere`; the other zones
 *     are carried forward WHOLESALE by `authorBundleV03` (§3.8′ #5). A delegate
 *     must be able to read every section of the zone it authors (whole-zone
 *     read), since re-authoring re-renders the full zone — a section-scoped
 *     delegate that cannot read a sibling section will fail loudly here.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type Sphere, SPHERE_FRAGMENTS } from "./did.js";
import { type Identity } from "./identity.js";
import { type Author, ownerAuthor } from "./author.js";
import { type Section, authorZoneDecryptRecipient } from "./ethos.js";
import { newGammaId } from "./gamma.js";
import {
  authorBundleV03,
  readSection,
  type ManifestV03,
  type SectionReader,
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

/** Read every section of `zone` from `bundleDir` as the author (throws if any is unreadable). */
function readZoneAsAuthor(
  bundleDir: string,
  manifest: ManifestV03,
  author: Author,
  zone: Sphere,
): Section[] {
  const zm = manifest.zones[zone];
  let reader: SectionReader | undefined;
  if (zone !== "public") {
    const r = authorZoneDecryptRecipient(author, zone as "circle" | "self");
    reader = { didUrl: r.did, x25519Secret: r.x25519Secret };
  }
  const out: Section[] = [];
  for (const desc of zm.sections) {
    const res = readSection(bundleDir, zm, desc, manifest.subject_did, reader);
    if (!res.accessible || !res.section) {
      throw new Error(
        `editSectionV03: cannot read section ${desc.section_id} of zone ${zone} ` +
          `(needed to re-author the zone): ${res.reason ?? "inaccessible"}`,
      );
    }
    out.push(res.section);
  }
  return out;
}

function applyChange(cur: Section | undefined, sectionId: string, change: SectionChange, gammaRef: string): Section {
  const tags = change.clearTags
    ? undefined
    : change.tags !== undefined
      ? change.tags
      : cur?.tags;
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
      `editSectionV03: author may not write zone ${args.zone} ` +
        `(authored: ${authoredZones.join(", ")})`,
    );
  }

  const zones: Partial<Record<Sphere, Section[]>> = {};
  for (const z of authoredZones) {
    zones[z] = readZoneAsAuthor(args.bundleDir, manifest, author, z);
  }

  const list = zones[args.zone]!;
  const idx = list.findIndex((s) => s.id === args.sectionId);
  if (del) {
    if (idx < 0) throw new Error(`section ${args.sectionId} not found in zone ${args.zone}`);
    list.splice(idx, 1);
  } else {
    const gammaRef = args.gammaRef ?? newGammaId();
    const next = applyChange(idx >= 0 ? list[idx] : undefined, args.sectionId, args.change ?? {}, gammaRef);
    if (idx >= 0) list[idx] = next;
    else list.push(next);
  }

  return authorBundleV03({
    author,
    outDir: args.outDir,
    zones,
    prev: { manifest, dir: args.bundleDir },
    now: args.now,
  });
}
