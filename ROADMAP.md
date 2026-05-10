# Roadmap

> Living document. Phases describe direction and ordering, not committed
> dates. A phase opens when the previous one's blocking work has shipped, not
> when a calendar tells us to.
>
> The current published protocol version is **0.2.1**. The next planned cut is
> **0.3.0**, designed in the open under [`spec/drafts/`](./spec/drafts/).

This roadmap is split into protocol evolution (sections 1–5) and orthogonal
work tracks that proceed in parallel (sections 6–7). Section 8 lists explicit
non-goals — areas the protocol does not address by design.

For the founding rationale and the *why*, read the
[whitepaper](./WHITEPAPER.md) first. For the formal specification, the index
is [`SPEC.md`](./SPEC.md). For active drafts, see
[`spec/drafts/`](./spec/drafts/).

---

## 1. Near-term — v0.2.x hardening

Patch-level work that keeps the published protocol healthy while v0.3 design
matures. None of this requires breaking the wire format.

- **Repo housekeeping.** Align the [`SPEC.md`](./SPEC.md) chapter index with
  the chapters actually present under [`spec/`](./spec/) (chapters 11 and 12
  are not yet listed). Resolve `0.5.2` source vs. `0.5.1` published-tag
  inconsistency in `@aithos/protocol-core`.
- **Section parser fix.** The current section splitter in
  `packages/protocol-core/src/ethos.ts` breaks if a revision body starts with
  a Markdown heading. Replace the regex with a sentinel-based delimiter or
  move the split rule to be unambiguous.
- **CI.** Add a minimal GitHub Actions workflow running `npm test` and
  type-check across the three packages on every PR.
- **Issue and PR templates.** Provide `.github/ISSUE_TEMPLATE/` for spec
  proposals, bug reports, and questions; PR template enforcing the SPDX header
  reminder and commit-prefix conventions per [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- **Good-first-issue triage.** Open a vetted set of issues with the
  `good-first-issue` label drawn from §3.13 / §10.9 / §2.9 open questions and
  from the section parser fix above.

## 2. v0.3 — Section addressability and read/write separation

The first breaking change after v0.2. v0.3 ships two independent format
revisions that together unlock **per-section operational granularity** and
**cryptographic separation between append and read capabilities**.

### 2.1 What ships in v0.3

- **[Bundle v0.3 — per-section encryption](./spec/drafts/bundle-v0.3-per-section-encryption.md)** *(draft, in review)*
  - Each zone — `public`, `circle`, `self` — is split into per-section blobs.
    Editing one section means rewriting one file, not the whole zone.
  - For `circle` and `self`: per-section XChaCha20-Poly1305 ciphertexts under
    independent DEKs, with per-section recipient wraps. Compromise of one
    section's DEK exposes only that section.
  - For `public`: per-section plaintext markdown files. Same operational
    benefit (one-file fetch / one-file write) without the encryption layer.
  - AAD binds ciphertexts to both `bundle_id` and `section_id`, preventing
    cross-bundle and cross-section replay.
- **[Gamma v0.3 — per-entry envelopes](./spec/drafts/gamma-v0.3-per-entry-envelopes.md)** *(draft, in review)*
  - Per-entry sealed envelopes in the gamma log replace the v0.2 single-DEK
    log file.
  - Append capability and read capability are split: a delegate with
    `ethos.write.<zone>` can append signed gamma entries without holding any
    decryption key, and therefore without retroactive access to the subject's
    history.
  - New `gamma.read` scope grants read access by adding the delegate's X25519
    public key to the manifest's gamma reader list.
- **Section-level mandates** *(companion draft, in design)*
  - Extends mandate scope grammar with section selectors:
    `ethos.write.self#gmail:*`, `ethos.read.self#section_id=sec_xxx`,
    `ethos.write.circle#tag=work`.
  - Cryptographic substrate is the per-section recipient lists from the
    bundle v0.3 draft.
  - Companion draft to be added to [`spec/drafts/`](./spec/drafts/) as soon as
    the first iteration is ready for review.
- **Mandate lifecycle as gamma events** *(companion proposal, scope TBD)*
  - Promoting `mandate.issue` and `mandate.revoke` to first-class gamma
    operations. Unifies the subject's authoring history and authorization
    timeline into a single signed, hash-chained log.
  - Trade-off: tighter coupling between the mandate machinery and the gamma
    log. The corresponding partial-fetch primitive (Merkle commitment over the
    log) becomes a natural companion — listed in §4 below.

### 2.2 What does not ship in v0.3

- **Discovery.** Resolving a human-readable handle (`@mathieu@aithos.be`) to
  a `did:aithos:…` is essential for adoption but is independent of the v0.3
  encryption work. It rides in §3 below, in parallel.
- **Conformance test suite.** Same — independent of v0.3 wire format, ships
  in parallel.
- **Encrypted manifest.** v0.3 increases the metadata leak surface for
  encrypted zones (section count, per-section sizes, per-section recipient
  sets). An opt-in encrypted manifest variant is planned for v0.4 (§4).

## 3. Parallel to v0.3 — Adoption and usability

These tracks do not modify the v0.3 wire format. They make the protocol usable
by humans and verifiable across implementations.

- **Discovery via `did:web` companion.**
  - Specify how a subject publishes a `did:web` companion record at
    `https://<domain>/.well-known/did.json` cross-referencing their
    `did:aithos:…`.
  - Define handle resolution: `<local>@<domain>` → `did:web:<domain>` →
    cross-reference → canonical `did:aithos:…`.
  - Domain is the namespace authority. Within a domain the local part is
    unique by construction — handle collisions are resolved by domain
    qualification, never globally.
  - Targets a new chapter alongside §6 (Transport) or an extension of
    chapter 1.
- **Conformance test suite.**
  - A separate repository (or a `/conformance/` subdirectory in this one)
    containing golden test vectors: signed bundles, mandates, gamma logs,
    revocations, action artifacts.
  - Every conformant implementation MUST validate against the suite.
  - Without this, every non-reference implementation is a leap of faith. The
    suite is what turns a draft into a protocol.
- **Encrypted indexing — levels 1 and 2.**
  - **Level 1 (client-side RAG).** SDK-level: client computes embeddings on
    decrypted sections, stores the vector index locally (e.g. IndexedDB),
    serves top-K queries to the agent. No protocol change.
  - **Level 2 (index persisted as a zone section).** The vector index is
    stored as a section of type `index:embeddings:v1` inside one of the
    subject's zones, encrypted as any other section. Cross-device sync via
    the existing recipient mechanics. Depends on §2.1 (per-section
    encryption) for incremental updates to scale.
  - Higher levels (TEE-backed retrieval, vector search on ciphertext) are
    research-grade and tracked under §6.
- **Revocation list mirroring.**
  - Operational hardening: a subject SHOULD publish their revocation list at
    multiple identical mirrors so a verifier can fall through if the primary
    is unreachable. Specifying mirror conventions and signed list-expiry
    windows for offline verification.

## 4. v0.4+ — Considered, not committed

Items here are real ideas with concrete motivation, but the design cost or
the dependency chain pushes them out of v0.3. They are listed so contributors
know they are on the radar and so the maintainers are not asked the same
question twice.

- **Encrypted manifest opt-in.** A two-file manifest variant for subjects who
  want to hide section titles, counts, sizes, and recipient sets on `circle`
  and `self`. Outer manifest carries only routing fields; inner manifest is
  encrypted to the subject.
- **Sub-audiences in `circle`.** Concentric circles (`circle.work`,
  `circle.family`) versus flat circle with per-recipient differentiation via
  mandates. Open question §2.9.
- **Diff / patch payloads in gamma.** `section.modify` currently carries the
  full new body. Diff payloads matter once gamma logs grow into the multi-MB
  range. Open question §2.9.
- **Sharding the gamma log.** Rolling chunks (one encrypted file per N
  entries) replacing the current whole-file rewrite on every append. Open
  question §10.9.
- **Partial fetches via Merkle commitment.** Allows a verifier to prove
  inclusion of a single gamma entry without holding the full log. Natural
  companion to mandate-as-gamma-events.
- **Delegation chains.** Mark S. Miller-style chained capabilities — a
  delegate with the appropriate scope can sub-delegate. Disabled in v0.1.0;
  may return as a `can_subdelegate` capability if real usage demands it.
  Open question §4.10.
- **Offline verification with signed revocation-list expiry.** Lets a
  verifier without live network access bound how stale a cached revocation
  list can be. Open question §4.10.
- **t-of-n social recovery for the root key.** A quorum of pre-designated
  trustees can co-sign a root-key replacement. Open question §7.5.2.
- **Localization of section content.** Per-language section variants. Open
  question §2.9.

## 5. v1.0 — Freeze

At `1.0.0` the wire format becomes stable under strict semantic versioning.
Any breaking change after that point requires a new identifier namespace
(e.g. `did:aithos2:…`).

Reaching `1.0` requires:

- A frozen v0.3 (or v0.4) wire format with no known major design debt.
- Conformance suite published and at least two independent implementations
  passing it.
- Discovery layer specified and at least one production deployment using it.
- The licensing decision recorded in
  [`ARCHITECTURE-DECISIONS.md`](./ARCHITECTURE-DECISIONS.md) (ADR-0007) for
  the 1.x line.

The 0.x line will remain under Apache-2.0 forever — that grant is
irrevocable. The 1.x line may transition to a different license at the
maintainers' discretion; see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the
rationale.

## 6. Implementation tracks

These tracks proceed in parallel to spec evolution. Each tracks the spec
version with its own release cadence.

| Implementation | Path | State (May 2026) | Target |
|---|---|---|---|
| TypeScript reference (`@aithos/protocol-core`) | [`packages/protocol-core/`](./packages/protocol-core/) | `0.5.x` published | Conformance-100% on every spec release |
| TypeScript CLI (`aithos`) | [`packages/cli/`](./packages/cli/) | `0.5.x` published | Same as above; first surface that adopts each new spec version |
| TypeScript MCP server (`@aithos/mcp`) | [`packages/mcp/`](./packages/mcp/) | `0.6.x` published | Same |
| Rust (`aithos`) | [`stubs/aithos-rs/`](./stubs/aithos-rs/) | Placeholder `0.0.1` on crates.io | Full implementation; high priority (verification performance, embedded use) |
| Python (`aithos`) | [`stubs/aithos-py/`](./stubs/aithos-py/) | Placeholder `0.0.1` on PyPI | Full implementation; medium priority (data / agent ecosystem fit) |
| Go (`github.com/aithos-protocol/aithos`) | [`stubs/aithos-go/`](./stubs/aithos-go/) | Placeholder `0.0.1` | Full implementation; lower priority, on-demand |
| Protocol client SDK (`@aithos/protocol-client`) | external repo | `0.1.0-alpha.x` | Beta on v0.3 freeze, 1.0 on spec freeze |

A real Rust or Python implementation is a substantial contribution and an
explicit invitation. The placeholder packages exist so that the package names
are reserved and the protocol's signed birth artifacts are distributed
alongside whichever language registry a future implementer prefers.

## 7. Research-grade work

Items here are not on the engineering roadmap but are listed as **explicit
calls for contribution**, typically suited to academic research, theses, or
applied cryptography R&D.

- **Vector search on encrypted embeddings.** SANNS (secure approximate
  nearest neighbour search) variants, PIR (private information retrieval)
  schemes, FHE on inner products, functional encryption for cosine
  similarity. Replaces level 3/4 of the indexing track in §3 with a
  zero-trust-server design. Maturity: 2-3 years out for production use.
- **TEE-backed inference and retrieval.** Running model inference on the
  subject's ethos inside an AWS Nitro Enclave (or Intel TDX / AMD SEV-SNP),
  with attestation-gated key release. The protocol must specify the DEK
  release-conditional-on-attestation primitive; implementation is multi-month
  engineering plus security review.
- **Per-user LoRA adapters as ethos distillation.** Fine-tune a small
  per-user adapter from the ethos so the LLM never needs the ethos in
  context at inference time. Adapter is small (~10–100 MB) and can itself be
  treated as an encrypted ethos zone.
- **Forward-secure reader rotation.** Per-entry derivation of reader keys so
  that a leaked X25519 reader key does not expose every prior gamma entry
  sealed to it. Bounded blast radius via ratchet construction. Open
  question §10.17′ in the gamma v0.3 draft.

If you are interested in any of these and want to discuss a contribution
arrangement, open an issue tagged `research` or contact the maintainers
directly.

## 8. Non-goals — explicit

The protocol does **not** address the following, by design. Implementers who
need these properties should layer them on top, accept the gap, or use a
different system.

- **Duress passwords / panic mode.** No "secret password that wipes
  everything." Out of scope; this is operational security, not protocol
  design. See §7.2.6.
- **Plausible deniability.** No way to claim a signed artifact is not
  yours. The whole point of the protocol is the opposite.
- **Recovery of a compromised root key.** The root key *is* the identity. A
  recovery path that lets you replace the root key while keeping the
  identifier is, by construction, a backdoor. Compromised root key means
  moving to a new DID; see §7.5.2. (A t-of-n social recovery layer is being
  considered for v0.4 — see §4.)
- **Defense against deepfakes at the protocol layer.** Cryptography proves
  *who* signed *what*. It cannot prove that an unsigned video sounding like
  the subject is fake. The defense is cultural — counterparties must demand
  signed artifacts for anything consequential.
- **Legal binding.** Whether a mandate is a valid power of attorney, a
  binding commercial authorization, or a lawful delegation of speech is a
  jurisdiction-specific question. The protocol provides the cryptographic
  substrate; it does not presume any jurisdiction has yet built the legal
  framework on top.
- **Anti-traffic-analysis / metadata hygiene at the network layer.** A
  hosted bundle URL reveals its access patterns to whoever runs the server
  and the network path. Subjects who need stronger metadata privacy should
  host on privacy-respecting infrastructure (hidden services, private CDNs)
  and accept the operational cost.
- **Content authenticity beyond authorship.** A signed bundle proves the
  subject said this. It does not prove what they said is true. Truth is
  downstream.

## 9. How to contribute

- **Read [`CONTRIBUTING.md`](./CONTRIBUTING.md)** first for the workflow,
  CLA, commit conventions, and SPDX header rules.
- **Browse [`spec/drafts/`](./spec/drafts/)** for active proposals and
  comment via issue or PR.
- **Open an issue** for non-trivial work before sending a PR — drive-by PRs
  not tied to a discussed issue may be closed without review.
- **Pick a `good-first-issue`** if you want a smaller scope to start with.

A draft loses momentum when no one reads it. If you read one and disagree —
say so in an issue. That is a contribution.
