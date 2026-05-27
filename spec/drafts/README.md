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
| [`bundle-v0.3-per-section-encryption.md`](./bundle-v0.3-per-section-encryption.md) | §3 | Draft | Split each zone into per-section blobs (one ciphertext file per section in `circle` / `self`, one plaintext markdown file per section in `public`). Editing one section costs O(section size) instead of O(zone size). Symmetric across all three zones. |
| [`gamma-v0.3-per-entry-envelopes.md`](./gamma-v0.3-per-entry-envelopes.md) | §10, §4 | Draft | Per-entry envelopes in the gamma log. Decouples append capability from read capability — a write-delegate no longer gets retroactive read access to the subject's history. Adds a new `gamma.read` scope. |
| [`sponsorship-mandate-v0.1.md`](./sponsorship-mandate-v0.1.md) | new §13, §4, §10, §11 | Draft | Commercial sponsorship between Ethos. A sponsor signs a persistent `SponsorshipMandate` declaring it will absorb the cost of operations performed by consumers within explicit budget and scope constraints. A designated accounting-authority subject signs a `ConsumptionReceipt` on every debit, archived V1 and gamma-anchored V2. No currency, no consensus, no token — pure composition of existing signatures. |
| [`gamma-deep-memory.md`](./gamma-deep-memory.md) | §10 | Promoted | Original draft for the gamma deep-memory log. Already promoted to normative §10 in the current spec. Kept here for historical reference. |

## Coordination across drafts

Some drafts are designed to ship together. The two `v0.3` drafts above are
independent in scope (one touches the bundle layer, the other touches the gamma
log layer) but are intended to land in the same protocol release. An
implementation must adopt both to claim v0.3 conformance.

A companion draft for **section-level mandates** (extending the mandate scope
grammar to `ethos.write.self#section_id=…`, `ethos.write.self#tag=…`,
`ethos.write.self#prefix=gmail:*`) is in design and will be added here once the
first iteration is ready for review. It depends on
`bundle-v0.3-per-section-encryption.md` for its cryptographic substrate (per-
section DEKs and per-section recipient lists) but specifies an additive change
to chapter 4 only.

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
