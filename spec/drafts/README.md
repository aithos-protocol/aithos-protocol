# Active drafts

This directory holds spec proposals under active design. Drafts are not normative
— the source of truth for the current published protocol is the numbered chapters
in [`spec/`](../). A draft graduates into a numbered chapter (or amendment to
one) when it is ratified for the next protocol version.

Comments, critique, and pull requests are welcome on every entry below. Open an
issue to start a discussion, or a PR to propose changes to a draft directly.

## Index

| Draft | Targets | Status | Summary |
|---|---|---|---|
| [`bundle-v0.4-incremental-manifest-and-zone-keys.md`](./bundle-v0.4-incremental-manifest-and-zone-keys.md) | §3, §10 | **Promoted / Implemented** | Incremental content-addressed manifest (~3 KB, O(1)) referencing immutable zone objects (ZoneShard / KeyRing / ExtraWraps) by sha. One 32-byte **zone key** per encrypted zone (sealed once per recipient in the KeyRing); per-section DEKs sealed symmetrically under the zone key via `enc_dek`; ExtraWraps carry per-section DEK wraps (v0.3 format, bit-for-bit) for targeted scopes. `sealGrant` on a zone scope is **O(1)**; hard revocation is a zone-key rotation that re-seals `enc_dek` **without re-encrypting the bodies**. New MCP route `aithos.get_ethos_objects`, new errors `-32043`/`-32044`/`-32045 ethos_spec_version_regression`/`-32046`. **Validated & implemented (core 0.11.3, platform dual-read live, SDK 0.2.0 v0.4-only). Part II (N1–N13) is now fully promoted into the numbered chapters — the normative body §3A of chapter 3 and the v0.4 primitive behavior of chapter 10 (§10.5.3, §10.5.4a, §10.6.3a, §10.9). It is the current on-disk format (manifest marker `aithos: 0.4.0`); §3.2–§3.10 are retained as the v0.2/v0.3 historical annex for dual-read.** |
| [`bundle-v0.3-per-section-encryption.md`](./bundle-v0.3-per-section-encryption.md) | §3 | **Promoted** | Split each zone into per-section blobs (one ciphertext file per section in `circle` / `self`, one plaintext markdown file per section in `public`). Editing one section costs O(section size) instead of O(zone size). Symmetric across all three zones. **Promoted as of protocol-core 0.8.0; superseded by v0.4 as the default on-disk format but remains readable via dual-read. Kept here as the per-section reference.** |
| [`bundle-v0.3-section-level-mandates.md`](./bundle-v0.3-section-level-mandates.md) | §3, §4 | **Promoted** | Per-section `title_cipher` + mandate `section_scope` so a section-scoped delegate can add/read/edit/delete exactly its own sections (e.g. an email capture-agent appending to `self`) without seeing the rest of the index. **Promoted as of protocol-core 0.8.0; the per-section mandate model carries into v0.4 via ExtraWraps.** |
| [`bundle-v0.3-section-verb-scopes.md`](./bundle-v0.3-section-verb-scopes.md) | §4, §3.5 | Draft | Per-scope section selectors (`#id=` / `#prefix=` / `#tag=`) + a verb vocabulary (`read` / `edit` / `append` / `delete` / `write`) so one mandate expresses **distinct read vs write perimeters** and bounds *what* a delegate may do (edit-only ≠ may-create ≠ may-delete). Refines the top-level `section_scope`. Additive: `aithos-mandate` 0.5.0; `id=`/`prefix=` write perimeters are provider-enforceable from the clear manifest, `tag=` writes on `self` defer to gamma. |
| [`gamma-v0.3-per-entry-envelopes.md`](./gamma-v0.3-per-entry-envelopes.md) | §10, §4 | Draft | Per-entry envelopes in the gamma log. Decouples append capability from read capability — a write-delegate no longer gets retroactive read access to the subject's history. Adds a new `gamma.read` scope. |
| [`sponsorship-mandate-v0.1.md`](./sponsorship-mandate-v0.1.md) | new §13, §4, §10, §11 | Draft | Commercial sponsorship between Ethos. A sponsor signs a persistent `SponsorshipMandate` declaring it will absorb the cost of operations performed by consumers within explicit budget and scope constraints. A designated accounting-authority subject signs a `ConsumptionReceipt` on every debit, archived V1 and gamma-anchored V2. No currency, no consensus, no token — pure composition of existing signatures. |
| [`gamma-deep-memory.md`](./gamma-deep-memory.md) | §10 | Promoted | Original draft for the gamma deep-memory log. Already promoted to normative §10 in the current spec. Kept here for historical reference. |

## Coordination across drafts

Some drafts are designed to ship together. The two `v0.3` drafts above are
independent in scope (one touches the bundle layer, the other touches the gamma
log layer) but are intended to land in the same protocol release. An
implementation must adopt both to claim v0.3 conformance.

The companion draft extending the mandate scope grammar to per-scope selectors
(`ethos.edit.self#id=…`, `ethos.append.self#prefix=gmail:`,
`ethos.read.self#tag=…`) and a **verb vocabulary** is now
[`bundle-v0.3-section-verb-scopes.md`](./bundle-v0.3-section-verb-scopes.md). It
depends on `bundle-v0.3-per-section-encryption.md` for its cryptographic
substrate (per-section DEKs and per-section recipient lists) but specifies an
additive change to chapter 4 and §3.5 only (`aithos-mandate` 0.5.0).

## What goes here, what doesn't

A draft belongs in this directory if:

- It proposes a normative change to one or more spec chapters.
- It is structured as a self-contained document that could replace or amend a
  numbered section.
- It is far enough along that another contributor can read it and form an
  opinion (problem statement, target design, threat model diff, test matrix or
  test sketch, open questions).

Pure exploratory notes, brainstorms, or platform-specific design decisions
belong elsewhere — typically in the implementation repos that consume the
protocol, or in a personal notes file outside this repo.

## Lifecycle

A draft progresses through three phases:

1. **Open** — present in this directory, status `Draft`. Comments and PRs
   welcome.
2. **Frozen for review** — author signals the design is settled and the spec
   chapter rewrite is imminent. Window for objections; usually a few weeks.
3. **Promoted** — content moves into the relevant numbered chapter and the
   draft file is either deleted or kept here marked `Promoted` for historical
   reference (the latter is preferred for designs that fundamentally reshaped
   a chapter, like `gamma-deep-memory.md`).

A draft that loses momentum or is superseded by a better design MAY be moved to
`spec/drafts/archive/` rather than deleted, with a short note at the top
explaining why it didn't ship.
