// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Ethos scope grammar + authorization predicate.
//
// Spec: drafts/bundle-v0.3-section-verb-scopes.md. This module is the SINGLE
// source of truth for "does this scope set authorize <operation> on <section>
// of <zone>". It is imported by:
//   - the bundle author (recipient derivation, §3.5.7′),
//   - the CLI / SDK mandate issuance,
//   - the Ethos API write enforcement (§4.8.3′),
//   - protocol-client,
// so the client-side guard and the server-side enforcement can never diverge.
//
// Grammar (§4.8′):
//   ethos.<verb>.<zone>[#<selector>]
//   verb     := read | edit | append | delete | write
//   zone     := public | circle | self      (plus the legacy read-all: `all`)
//   selector := id=<section_id> | prefix=<id_prefix> | tag=<tag>   (absent ⇒ whole zone)

import type { Sphere } from "./did.js";

export type EthosVerb = "read" | "edit" | "append" | "delete" | "write";

export type EthosSelector =
  | { readonly kind: "all" }
  | { readonly kind: "id"; readonly id: string }
  | { readonly kind: "prefix"; readonly prefix: string }
  | { readonly kind: "tag"; readonly tag: string };

export interface ParsedEthosScope {
  readonly verb: EthosVerb;
  /** A concrete sphere, or `"all"` for the legacy whole-everything `ethos.read.all`. */
  readonly zone: Sphere | "all";
  readonly selector: EthosSelector;
}

const VERBS: ReadonlySet<string> = new Set([
  "read",
  "edit",
  "append",
  "delete",
  "write",
]);
const ZONES: ReadonlySet<string> = new Set(["public", "circle", "self", "all"]);

/**
 * Parse `ethos.<verb>.<zone>[#<selector>]`. Returns `null` if the string is not
 * an ethos scope or the grammar is malformed — callers MUST treat `null` as
 * "grants nothing" (fail-closed, §4.8.5′), never as a whole-zone grant.
 */
export function parseEthosScope(scope: string): ParsedEthosScope | null {
  if (!scope.startsWith("ethos.")) return null;
  const hashIdx = scope.indexOf("#");
  const head = hashIdx === -1 ? scope : scope.slice(0, hashIdx);
  const selStr = hashIdx === -1 ? "" : scope.slice(hashIdx + 1);

  const parts = head.split(".");
  if (parts.length !== 3) return null;
  const verb = parts[1]!;
  const zone = parts[2]!;
  if (!VERBS.has(verb) || !ZONES.has(zone)) return null;
  // `all` is only meaningful as `ethos.read.all` (whole-everything read).
  if (zone === "all" && verb !== "read") return null;

  let selector: EthosSelector;
  if (hashIdx === -1) {
    selector = { kind: "all" };
  } else {
    // a bare trailing '#' (empty selector body) is malformed → fail closed
    if (selStr === "") return null;
    // a selector on `ethos.read.all` is not meaningful
    if (zone === "all") return null;
    const eq = selStr.indexOf("=");
    if (eq <= 0) return null;
    const k = selStr.slice(0, eq);
    const v = selStr.slice(eq + 1);
    if (v === "") return null;
    if (k === "id") selector = { kind: "id", id: v };
    else if (k === "prefix") selector = { kind: "prefix", prefix: v };
    else if (k === "tag") selector = { kind: "tag", tag: v };
    else return null;
  }

  return { verb: verb as EthosVerb, zone: zone as Sphere | "all", selector };
}

/** A section as seen for authorization. `tags` is absent when the zone index is
 *  encrypted (self at the provider) — a tag selector then does NOT match
 *  (§4.8.4′: tag write-perimeters on self are advisory, not provider-enforced). */
export interface SectionRef {
  readonly id: string;
  readonly tags?: readonly string[];
}

/** §4.8.1′ — does `section` match `selector`? */
export function matchSection(section: SectionRef, selector: EthosSelector): boolean {
  switch (selector.kind) {
    case "all":
      return true;
    case "id":
      return section.id === selector.id;
    case "prefix":
      return section.id.startsWith(selector.prefix);
    case "tag":
      return !!section.tags && section.tags.includes(selector.tag);
  }
}

/** The three structural operations a publish can perform on a section. */
export type EthosOp = "create" | "edit" | "delete";

/** Which operations a verb authorizes on its perimeter (§4.8.2′). */
function verbGrantsOp(verb: EthosVerb, op: EthosOp): boolean {
  switch (verb) {
    case "read":
      return false;
    case "edit":
      return op === "edit";
    case "append":
      return op === "create" || op === "edit";
    case "delete":
      return op === "delete";
    case "write":
      return true; // create + edit + delete
  }
}

/**
 * Whether a verb bears read (recipient) on its perimeter. All mutating verbs
 * imply readership EXCEPT `delete` — removing a section needs only its clear id,
 * not its plaintext (§4.8.2′ + Open Questions).
 */
function verbBearsRead(verb: EthosVerb): boolean {
  return verb === "read" || verb === "edit" || verb === "append" || verb === "write";
}

function zoneMatches(scopeZone: Sphere | "all", zone: Sphere): boolean {
  return scopeZone === "all" || scopeZone === zone;
}

/**
 * §4.8.3′ — does the scope set authorize `op` on `section` of `zone`?
 *
 * `ethos.read.all` never authorizes a write (it is a read grant). Tag selectors
 * only match when `section.tags` is provided; the Ethos API passes `tags`
 * undefined for `self` (encrypted index), making tag write-perimeters on `self`
 * non-enforceable there by design (§4.8.4′).
 */
export function coversOperation(
  scopes: readonly string[],
  zone: Sphere,
  op: EthosOp,
  section: SectionRef,
): boolean {
  for (const s of scopes) {
    const p = parseEthosScope(s);
    if (!p) continue;
    if (p.zone === "all") continue; // read-all never authorizes writes
    if (!zoneMatches(p.zone, zone)) continue;
    if (!verbGrantsOp(p.verb, op)) continue;
    if (matchSection(section, p.selector)) return true;
  }
  return false;
}

/**
 * §3.5.7′ — is the holder a recipient of `section` of `zone`? True iff it holds
 * a read-bearing verb (read/edit/append/write) on `zone` whose selector matches.
 */
export function coversRead(
  scopes: readonly string[],
  zone: Sphere,
  section: SectionRef,
): boolean {
  for (const s of scopes) {
    const p = parseEthosScope(s);
    if (!p) continue;
    if (!verbBearsRead(p.verb)) continue;
    if (!zoneMatches(p.zone, zone)) continue;
    if (matchSection(section, p.selector)) return true;
  }
  return false;
}

/**
 * Whether the scope set has ANY read-bearing ethos scope on `zone` (selector
 * ignored). Used to pre-filter delegate grants before per-section matching.
 */
export function hasReadBearingEthosScopeForZone(
  scopes: readonly string[],
  zone: Sphere,
): boolean {
  for (const s of scopes) {
    const p = parseEthosScope(s);
    if (!p) continue;
    if (!verbBearsRead(p.verb)) continue;
    if (zoneMatches(p.zone, zone)) return true;
  }
  return false;
}

/** Whether `s` is a mutating ethos scope (edit/append/delete/write on a concrete
 *  zone) — used to require `grantee.pubkey` and an actor_sphere match at mint. */
export function isEthosMutatingScope(s: string): boolean {
  const p = parseEthosScope(s);
  return (
    !!p &&
    p.zone !== "all" &&
    (p.verb === "edit" || p.verb === "append" || p.verb === "delete" || p.verb === "write")
  );
}

/** Whether the scope set carries any mutating ethos scope. */
export function hasEthosMutatingScope(scopes: readonly string[]): boolean {
  return scopes.some(isEthosMutatingScope);
}
