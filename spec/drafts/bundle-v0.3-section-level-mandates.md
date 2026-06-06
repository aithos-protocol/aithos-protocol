# Draft · Section-level mandates (v0.3 companion)

> **Status:** Draft. Companion to `bundle-v0.3-per-section-encryption.md`. Defines the mandate vocabulary that lets an agent be a recipient of a **subset** of a zone's sections, rather than the whole zone. Not yet normative.
>
> **Scope.** This draft extends chapter 4 (mandates) with an optional `section_scope` and §3.5′ (recipients) with per-section recipient derivation. It depends on the per-section bundle format (`bundle-v0.3-per-section-encryption.md`) and the delegate-authoring model (manifest `authorized_by`, §3.8′ #5).

## Motivation

v0.3 wraps each section's DEK to a list of recipients. By default a read mandate on a zone (`ethos.read.self`) makes the agent a recipient of **every** section in that zone — it can decrypt all of `self`. That is too coarse for the real agent use case: a Gmail agent should read only the `gmail:*` sections of `self`, not the user's private journal sections that happen to live in the same zone.

Per-section DEKs already make this expressible at the crypto layer (a recipient can be on section X's wraps but not section Y's — §3.5.3′). What is missing is the **mandate vocabulary** to say "this delegate reads only these sections," and the **recipient-derivation rule** that turns such a mandate into the right per-section wraps. This draft supplies both.

## 4.7′ `section_scope` on a mandate

A mandate MAY carry an optional top-level `section_scope` that narrows its `ethos.read.<zone>` / `ethos.write.<zone>` scopes to a subset of the zone's sections:

```json
{
  "aithos-mandate": "0.4.0",
  "actor_sphere": "self",
  "scopes": ["ethos.read.self"],
  "section_scope": { "tags": ["gmail"] },
  "...": "..."
}
```

```
section_scope := { ids?: string[], tags?: string[] }
```

- `ids` — an explicit list of `section_id`s the mandate covers.
- `tags` — a list of tags; a section is covered if it carries **any** of these tags (§2.5.1 section `tags`).

`section_scope` is part of the signed mandate body (it is included in the canonical bytes the issuer signs, §4.4), so it cannot be widened or forged after issuance.

### 4.7.1′ Matching

A section `S` **matches** a `section_scope` `P` iff:

```
match(S, P) :=
    P is absent                          (whole-zone — back-compat)
  OR (P.ids  is present AND S.id ∈ P.ids)
  OR (P.tags is present AND S.tags ∩ P.tags ≠ ∅)
```

A mandate with **no** `section_scope` covers the **entire** zone — this is the existing v0.2/v0.3 behaviour, so every mandate issued before this draft keeps working unchanged.

A mandate with a `section_scope` that matches no current section is valid but confers no decryption — it is a forward-looking grant (e.g. tags `["gmail"]` before any `gmail`-tagged section exists). When a matching section is later authored, the delegate becomes a recipient of it.

### 4.7.2′ Scope kinds

`section_scope` narrows **read** and **write** scopes alike:

- A **read** section-scope (`ethos.read.<zone>` + `section_scope`) makes the delegate a recipient of the matching sections only (this draft's primary case).
- A **write** section-scope (`ethos.write.<zone>` + `section_scope`) additionally restricts which sections the delegate may (re)author. Authoring enforcement is specified in §4.7.5′; the recipient rule below applies to both.

## 3.5.4′ Per-section recipient derivation (revised)

When an **owner** authors an encrypted zone `Z` (§3.4.1′), recipients are computed **per section** rather than per zone:

```
recipients(S) :=
    { subject #<Z>-kex }                              (always — §3.5.1′)
  ∪ { delegate D : D's mandate covers read/write of Z
                   AND match(S, D.section_scope) }
```

A whole-zone delegate (no `section_scope`) matches every section, reproducing the v0.3 behaviour exactly. A section-scoped delegate is added only to the wraps of the sections it matches.

A **delegate** author (§3.8′ #5) does not re-derive other delegates' grants; its authored sections are wrapped to `{ subject, self }` as in §3.5.2′. Adding/removing section-scoped delegates is an **owner** operation (the owner re-authors the affected sections), mirroring `issueMandateWithRewrap` / `repinAfterRevocation`.

### 3.5.5′ Per-section titles and section-scoped delegates

The self index is **per section**: each section carries its own `title_cipher` (§3.3.2′), sealed to **that section's** recipients (the same set as the body). There is no zone-wide index blob. Consequences:

- A reader recovers a section's title iff it is one of that section's recipients. So the subject (recipient of every section) sees all self titles; a **section-scoped delegate sees the titles of exactly the sections it can read** — and never the others'. The host sees none.
- **A section-scoped delegate can add/edit/delete its OWN self sections.** Adding a section just writes that section's body + `title_cipher`, both sealed to the section's recipients (subject + the adding delegate). No zone-wide index has to be rebuilt, so the delegate never needs the titles of sections it cannot read. Editing/deleting touches only the target section; all siblings carry forward verbatim (their blobs and `title_cipher`s are copied without decryption — the patch-authoring model). This is the capture-agent case: an email agent appending one self section per inbound message (spec §3 motivation), scoped to e.g. `gmail`, never sees the subject's other self titles.

`circle`'s index is clear, so a circle delegate's titles are visible to the host regardless.

### 3.5.6′ Recipient-set change ⇒ re-encryption

Carry-forward (§3.5.3′ / B3) reuses a section's prior ciphertext only when its plaintext **and recipient set** are unchanged. Granting or revoking a section-scoped delegate changes the recipient set of exactly the matching sections, so only those sections are re-encrypted on the next edition; non-matching sections of the same zone carry forward byte-identical.

### 4.7.5′ Write enforcement (informative)

A delegate authoring under a section-scoped **write** mandate MAY only create/modify/delete sections matching its `section_scope`; a verifier with the gamma log SHOULD reject a delegate-signed section mutation whose target section does not match the signing mandate's `section_scope`. Bundle-layer verification (§3.8′) cannot enforce this on its own (it has no per-section authorship record without gamma); the binding check lives with the gamma authorship cross-check (§3.8′ #9). Full write-scope enforcement is tracked with the gamma-v0.3 integration.

## 3.7.1′ Metadata leak (section-scope addendum)

The clear manifest still exposes each section's **recipient set** (§3.7′). Therefore granting a delegate access to one specific section is **visible** to anyone who can read the manifest (the host, on `circle`; the subject, on `self` — but on `self` the per-section recipient list is a structural clear field too). Concretely:

- A `circle` section wrapped to an extra recipient reveals, in clear, that this section is shared with that delegate.
- A `self` section's recipient set is also a clear structural field, so the host sees that *some* self section is shared with delegate X — but, because the self index is encrypted and not shared with the section-scoped delegate, the host does not learn **which titled** section it is from the manifest alone.

Authors who treat "which section is shared with whom" as sensitive should be aware this shape is visible; hiding it would require the encrypted-manifest variant tracked in §3.13′.

## 3.12.1′ Test matrix (section-level)

| Test | Assertion |
|---|---|
| M1 — Section-scoped read (by id) | A delegate with `ethos.read.self` + `section_scope.ids = [X]` decrypts section X but NOT section Y of the same zone (no wrap on Y). |
| M2 — Section-scoped read (by tag) | A delegate with `section_scope.tags = ["gmail"]` decrypts exactly the `gmail`-tagged sections; untagged/other-tagged sections stay opaque to it. |
| M3 — Per-section titles | The section-scoped delegate of M1/M2 decrypts the `title_cipher` of its granted section (sees its title) but NOT the `title_cipher` of a non-granted section (title stays hidden); the subject sees all. |
| M4 — Whole-zone unchanged | A mandate with no `section_scope` still wraps every section (back-compat). |
| M5 — Granting re-encrypts only matches | Adding a section-scoped delegate re-encrypts only the matching sections; non-matching sections carry forward byte-identical (§3.5.6′). |
| M6 — Forward-looking scope | A `section_scope` matching no current section is valid; a later-authored matching section is wrapped to the delegate automatically. |
| M7 — Section-scoped delegate appends | A delegate with `ethos.write.self` + a `section_scope` ADDS a new self section: its body + `title_cipher` are sealed to subject + delegate, every other self section carries forward byte-identical (never decrypted), the manifest is delegate-signed, the subject reads the new title, and the delegate never learns the subject's other self titles. |

## Open questions

- **Hiding which section is shared.** §3.7.1′ leaves the per-section recipient set in clear. An encrypted recipient set (or the encrypted-manifest variant of §3.13′) would hide it. Out of scope here.
- **Selector richness.** This draft supports `ids` and `tags`. Glob/prefix selectors (`gmail:*` as a literal id-prefix rather than a tag) are a possible extension; for now `gmail:*` is modelled as the tag `gmail`.
- **Write-scope enforcement at the bundle layer.** §4.7.5′ defers per-section write enforcement to the gamma authorship cross-check; revisit when gamma-v0.3 authorship lands.
