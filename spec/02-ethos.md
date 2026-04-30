# 2 · Ethos document

## 2.1 Overview

An **ethos** is the structured artifact that describes a subject. It exists in two forms:

- A **document form** — a JSON object whose canonical serialization is what gets signed.
- A **bundle form** — the markdown rendition of the same content, packaged as a `.ethos` zip (chapter 3) for transport and storage.

The two forms are isomorphic. The document form is normative for signing; the bundle form is normative for distribution. Implementations MUST be able to convert between them losslessly.

## 2.2 The document model

```json
{
  "aithos": "0.2.0",
  "id": "urn:aithos:john-doe:2026.04.19-1",
  "subject": {
    "did": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9",
    "handle": "john-doe",
    "display_name": "John Doe"
  },
  "edition": {
    "version": "2026.04.19-1",
    "created_at": "2026-04-19T08:14:23Z",
    "supersedes": "urn:aithos:john-doe:2026.04.10-1",
    "canonical_url": "https://aithos.example/u/john-doe.ethos"
  },
  "zones": {
    "public": { "sections": [ … ] },
    "circle": { "sections": [ … ] },
    "self":   { "sections": [ … ] }
  }
}
```

The signatures (one per zone, plus one over the document as a whole) live in the bundle manifest, not in the document itself; see chapter 3. This separation is what allows a server to ship only the public zone to an unauthorized reader without invalidating the signatures on the zones it withholds.

### 2.2.1 Required top-level fields

| Field | Type | Description |
|---|---|---|
| `aithos` | string | Protocol version. MUST be `"0.2.0"` for this draft. |
| `id` | string (URI) | Globally unique identifier. URN form `urn:aithos:<handle>:<edition.version>` is REQUIRED. |
| `subject` | object | Subject identity (§2.3). |
| `edition` | object | Edition metadata (§2.4). |
| `zones` | object | The content, partitioned by zone (§2.5). |

### 2.2.2 Optional top-level fields

Implementations MAY add fields under a `x-` prefix for experimental extensions (`x-pricing`, `x-vendor-foo`, …). Conformant verifiers MUST ignore unknown `x-` prefixed fields. Conformant verifiers MUST reject unknown non-`x-` fields.

## 2.3 Subject

```json
{
  "did": "did:aithos:z6Mkr…",
  "handle": "john-doe",
  "display_name": "John Doe"
}
```

- `did` — REQUIRED. The subject's `did:aithos` (chapter 1).
- `handle` — REQUIRED. DNS-friendly, lowercase, 1–63 characters from `[a-z0-9._-]`. Unique within the namespace of whichever resolver hosts the bundle. Used in the `id` URN.
- `display_name` — REQUIRED. Free text, 1–80 characters, no constraint on script. The string an interface should display to a human.

## 2.4 Edition

```json
{
  "version": "2026.04.19-1",
  "created_at": "2026-04-19T08:14:23Z",
  "supersedes": "urn:aithos:john-doe:2026.04.10-1",
  "canonical_url": "https://aithos.example/u/john-doe.ethos"
}
```

- `version` — REQUIRED. A string unique within the subject's history. Convention: `YYYY.MM.DD-N` where `N` increments for multiple editions on the same date. Other conventions are permitted; what matters is uniqueness within the subject.
- `created_at` — REQUIRED. RFC 3339 UTC timestamp.
- `supersedes` — REQUIRED. The `id` URN of the prior edition, or `null` for the first.
- `canonical_url` — OPTIONAL. The URL at which this edition is authoritatively served, if any.

Editions are immutable. Any change to the document — content, signatures, metadata — requires a new edition with a new `version` string.

## 2.5 Zones

The `zones` object MUST contain exactly the three keys `public`, `circle`, `self`. Each value is a **zone object** of the shape:

```json
{
  "sections": [ ZoneSection, … ]
}
```

A zone with no sections is permitted: `{ "sections": [] }`. A subject who chooses to publish only a `public` ethos and keep nothing in `circle` or `self` simply ships those zones empty.

### 2.5.1 ZoneSection

```json
{
  "id": "sec_a1b2c3",
  "title": "Voice",
  "body": "I still prefer short paragraphs for casual exchanges, but I'll write long-form prose when the subject warrants it.",
  "tags": ["voice"],
  "gamma_ref": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W"
}
```

- `id` — REQUIRED. A short stable identifier, unique within the zone. Convention: `sec_` followed by 6+ characters from `[a-z0-9]`. Used to reference a section across editions and as an anchor for gamma cross-references.
- `title` — REQUIRED. A free-form string (1–120 characters). The protocol provides a non-normative list of canonical titles (§2.5.3) but does not require them. The title MAY change over time through `section.modify` (§10.6); the `id` anchors continuity, not the title.
- `body` — REQUIRED. The section's **current** content as a markdown string. Past bodies are not kept in the bundle — they live in the gamma log (§10).
- `tags` — OPTIONAL. Array of short tag strings for indexing/search. Informative.
- `gamma_ref` — REQUIRED. The `id` of the gamma entry that produced this current state — the most recent `section.add` or `section.modify` targeting this section. A verifier with access to the gamma log can cross-check that the referenced entry's `payload` reproduces this section's `title`, `body`, and `tags`, and can replay the section's history by walking `prev_section_gamma` backward from `gamma_ref`. See §10.7.

Sections do **not** carry embedded history. Every mutation — creation, title change, body revision, tag change, deletion — is recorded as one signed entry in the gamma log (§10). The bundle commits to the log via the `gamma.head` field in the manifest (§3.3), which is signed by the subject's `#public` sphere key.

A section's current state MAY be produced either by a sphere-key-signed gamma entry or by a delegate-key-signed entry authorized by a write mandate (§4.5.4). In the delegated case, the referenced gamma entry additionally carries an `authorized_by` field naming the mandate (§10.5.2).

### 2.5.2 Section ordering

Sections within a zone are an ordered array. The order is significant: it is the order in which an agent should consider the content when constructing context. The author controls the order at editing time.

### 2.5.4 Section history — see chapter 10

Section history is not embedded in the bundle. Each mutation to a section — creation, modification, title or tag change, deletion, reorder, redaction — produces one signed entry in the gamma log (§10). The bundle commits to the log via the signed `gamma.head` in the manifest (§3.3) and via each section's `gamma_ref` (§2.5.1).

For the normative semantics of mutations, the gamma entry schema, the append rules, and the verification tiers (light vs full), see [chapter 10 — Gamma](./10-gamma.md).

#### 2.5.4.1 Delegated writes

A section's current state MAY be produced by a delegate key authorized by a write mandate (§4.5.4) rather than directly by the zone's sphere key. The gamma entry referenced by `gamma_ref` then carries an `authorized_by` field naming the mandate (§10.5.2). A verifier resolves the mandate, checks it against §4.7 at the entry's `at`, confirms scopes include `ethos.write.<zone>`, and matches `signature.key` against the mandate's `grantee.pubkey`.

### 2.5.3 Canonical section titles (informative)

The following titles are commonly used and SHOULD be recognized by editors offering autocomplete. They have no special semantics in the protocol — they are convention, not schema.

```
Identity        Voice           Positioning      Refusals
Tone            Expertise       Availability     Relations
Pricing         Voice (intimate)  Current projects  Negotiation
Reflections     Hidden context  Private notes    Health
Finances        Tech stack      Bug bounties     Testnet wallet
Culinary tastes Morning routine Reading list     Work hours
```

A subject is free to use none, all, or entirely different titles. The point of an LLM-readable ethos is precisely that the model is good at adapting to whatever titles the author chose.

## 2.6 Bundle (markdown) form

The bundle form is one markdown file per zone (§3.2). A zone file has a YAML frontmatter, and a body whose top-level `# Title` headings delimit sections. Each section's **current body** is inlined; past bodies are in the gamma log (§10), not in the bundle.

```markdown
---
aithos: "0.2.0"
zone: public
subject_did: did:aithos:z6Mkr…
subject_handle: john-doe
edition: 2026.04.19-3
created_at: 2026-04-19T08:14:23Z
---

# Voice <!-- sec_a1b2c3 · gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W -->

I still prefer short paragraphs for casual exchanges, but I'll write long-form prose when the subject warrants it.

# Tech stack <!-- sec_9f8e7d · gamma_01J9YC1V6P0J2N3Q4R5S6T7U8V -->

- TypeScript / Node ≥ 20
- AWS (S3, CloudFront, Lambda, DynamoDB, Bedrock)
- Vite + React on the frontend
```

### 2.6.1 Conversion rules

To convert the **document form** to the **bundle form** for a given zone:

1. Open with a YAML frontmatter populated from the document fields (`aithos`, `zone`, `subject.did`, `subject.handle`, `edition.version`, `edition.created_at`).
2. For each section in `zones.<zone>.sections`, in order:
   - Write `# <title> <!-- <section_id> · <gamma_ref> -->\n\n`.
   - Write the section `body`, then a blank line.
3. If the section has tags, write `<!-- tags: ["tag1","tag2"] -->` on the line immediately following the heading.
4. Trim trailing whitespace.

To convert the **bundle form** back to the **document form**:

1. Parse YAML frontmatter to recover edition metadata.
2. Split the body on `^# ` (start-of-line `# ` with one space).
3. In each section chunk, extract `title`, `id`, and `gamma_ref` from the heading line (both ids from the `<!-- sec_… · gamma_… -->` comment).
4. The remaining content is the section's current `body`.
5. If the next line is a `<!-- tags: […] -->` comment, parse it into the section's `tags` array.
6. To verify history, fetch the gamma log and follow §10.7.

### 2.6.2 Lossless invariants

The conversion is lossless if:

- Section IDs and `gamma_ref` are preserved across the round-trip (via the `<!-- sec_… · gamma_… -->` comment).
- Tags, if present, are preserved via the `<!-- tags: […] -->` comment.

For humans reading the zone file manually, the markdown is legible — the `<!-- … -->` comments are skippable. For tools, the metadata is all there; the signed history is reachable via `gamma_ref` into the gamma log.

## 2.7 Free sections, not fixed schema

A deliberate choice of v0.2 (carried forward into v0.1.0 of the protocol) is that a zone's content is a flat, ordered list of free-titled sections rather than a fixed schema with named slots like `bio`, `voice`, `availability`.

The reasoning:

- An LLM is good at adapting to varied input. Forcing the human into pre-named slots loses richness for marginal machine-readability gain.
- A real person is more than a list of canonical attributes. The dimensions that make someone *them* — culinary tastes, morning rituals, idiosyncratic refusals, the contents of their bookshelf — do not fit in a vendor's schema.
- Schemas evolve. Free sections do not need to.

Tooling MAY use the canonical titles in §2.5.3 as autocomplete suggestions, but MUST NOT reject sections whose titles fall outside that list.

## 2.8 Immutability, hash-chaining, and the history spine

The protocol enforces immutability at two levels, which together form the document's **history spine**.

### 2.8.1 Gamma log — the mutation spine

Every mutation to the ethos produces one signed entry in the gamma log (§10). Entries are SHA-256 hash-chained via `prev_gamma_hash`, so any alteration of a past entry breaks the chain: the next entry's `prev_gamma_hash` no longer matches, and subsequent signatures fail to verify. The bundle's manifest commits to the log's head hash (`manifest.gamma.head`), so an author cannot silently rewrite the past without simultaneously re-signing every downstream entry and the manifest.

This gives the ethos the property of a **write-once log**. An author can always add, modify, reorder, or delete — each as a new signed entry. An author cannot silently alter what was previously signed. The only path to erase past content from the log is the public, logged `section.redact` (§10.8).

### 2.8.2 Per-edition spine

Each bundle edition's manifest carries `edition.prev_hash`, the SHA-256 of the JCS-canonicalized manifest of the immediately preceding edition (§3.3.3). The first edition's `prev_hash` is `null`.

An edition chain is verified by walking backward: for edition N, fetch edition N-1, recompute its manifest hash, compare against N's `edition.prev_hash`. A verifier who can reach the first edition can reconstruct the entire chain and know no link has been tampered with.

### 2.8.3 Not a blockchain

The hash chain borrows the *integrity* property of a blockchain (append-only, tamper-evident) without the rest. There is:

- **No consensus** — the subject alone decides what goes into the chain.
- **No distributed ledger** — chains live wherever the subject chooses to host them.
- **No mining or proof-of-work** — signing with your sphere key is the only work.
- **No tokens, no fees, no staking** — it is a cryptographic artifact, not an economic one.

What remains is what matters for digital ethos: **the past is recorded, signed, and provable.**

### 2.8.4 Why this matters

An ethos that can be silently rewritten is worth nothing. A counterparty reading "the subject does not work on weekends" needs to know whether that was said yesterday or three years ago, and whether it has been amended. An agent that has been trained on last year's voice needs to know whether today's voice has diverged and by how much. A court, someday, may need to know what a subject said on a specific date.

Immutability is not a feature; it is the precondition for treating an ethos as evidence of anything at all.

## 2.9 Open questions

- **Sub-audiences.** Should `circle` admit sub-zones (`circle.work`, `circle.family`)? Currently no — the mandate system (chapter 4) handles per-recipient differentiation by issuing different scopes to different agents, all reading the same circle zone. A future version may revisit if real usage demands it.
- **Diff / patch format.** Gamma `section.modify` currently carries the full new body (§10.6.1). A future version may introduce a diff payload variant if log size becomes a concern.
- **Localization.** A section with multilingual content currently relies on the author writing in multiple languages within a single body. Whether to introduce explicit per-language section variants is open.

---

Next: [chapter 3 — Bundle](./03-bundle.md).
