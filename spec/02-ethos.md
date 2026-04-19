# 2 · Ethos document

## 2.1 Overview

An **ethos** is the structured artifact that describes a subject. It exists in two forms:

- A **document form** — a JSON object whose canonical serialization is what gets signed.
- A **bundle form** — the markdown rendition of the same content, packaged as a `.ethos` zip (chapter 3) for transport and storage.

The two forms are isomorphic. The document form is normative for signing; the bundle form is normative for distribution. Implementations MUST be able to convert between them losslessly.

## 2.2 The document model

```json
{
  "aithos": "0.1.0",
  "id": "urn:aithos:mathieu:2026.04.19-1",
  "subject": {
    "did": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9",
    "handle": "mathieu",
    "display_name": "Mathieu Colla"
  },
  "edition": {
    "version": "2026.04.19-1",
    "created_at": "2026-04-19T08:14:23Z",
    "supersedes": "urn:aithos:mathieu:2026.04.10-1",
    "canonical_url": "https://aithos.example/u/mathieu.ethos"
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
| `aithos` | string | Protocol version. MUST be `"0.1.0"` for this draft. |
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
  "handle": "mathieu",
  "display_name": "Mathieu Colla"
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
  "supersedes": "urn:aithos:mathieu:2026.04.10-1",
  "canonical_url": "https://aithos.example/u/mathieu.ethos"
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
  "revisions": [
    {
      "revision": 1,
      "at": "2026-02-10T09:00:00Z",
      "body": "I write in short paragraphs. Bulleted lists irritate me.",
      "prev_hash": null,
      "hash": "sha256:a8b2f1ef…",
      "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#public", "value": "p8R…" }
    },
    {
      "revision": 2,
      "at": "2026-04-19T08:14:23Z",
      "body": "I still prefer short paragraphs for casual exchanges, but I'll write long-form prose when the subject warrants it.",
      "prev_hash": "sha256:a8b2f1ef…",
      "hash": "sha256:d12e07bc…",
      "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#public", "value": "k7Q…" }
    }
  ],
  "tags": ["voice"]
}
```

- `id` — REQUIRED. A short stable identifier, unique within the zone. Convention: `sec_` followed by 6+ characters from `[a-z0-9]`. Used to reference a section across editions for diffing and as an anchor in the history chain.
- `title` — REQUIRED. A free-form string (1–120 characters). The protocol provides a non-normative list of canonical titles (§2.5.3) but does not require them. The title MAY change across revisions of the bundle; the `id` anchors continuity, not the title.
- `revisions` — REQUIRED. A non-empty, ordered array of **revisions**. Each revision is a dated, signed entry carrying a `body`. Revisions are **append-only** — see §2.5.4 and §2.8.
- `tags` — OPTIONAL. Array of short tag strings for indexing/search. Implementations SHOULD treat tags as informative. Tags apply to the section as a whole and may evolve; they are not individually hash-chained.

A section's **current body** is the `body` of its highest-numbered revision. The full history is available to agents that want it.

A revision MAY be signed directly by the zone's sphere key, or by a **delegate key** authorized by a write mandate (§4.5.4). In the delegated case the revision additionally carries an `authorized_by` field naming the mandate. See §2.5.4 for the schema and §2.5.4.2 for verification.

### 2.5.2 Section ordering

Sections within a zone are an ordered array. The order is significant: it is the order in which an agent should consider the content when constructing context. The author controls the order at editing time.

### 2.5.4 Revisions — the per-section hash chain

Each section is an **append-only signed log**. New content is added as a new revision; old content is never removed from the bundle in v0.1.0.

A revision is a JSON object:

```json
{
  "revision": 2,
  "at": "2026-04-19T08:14:23Z",
  "body": "…",
  "prev_hash": "sha256:a8b2f1ef…",
  "hash": "sha256:d12e07bc…",
  "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#public", "value": "…" }
}
```

- `revision` — REQUIRED. A monotonically increasing integer starting at 1 for the first revision of a section. Each subsequent revision MUST be exactly one greater than the preceding revision. No gaps, no reuse.
- `at` — REQUIRED. RFC 3339 UTC timestamp of when the revision was authored. MUST be strictly greater than the `at` of the preceding revision.
- `body` — REQUIRED. The section content at this revision, as a markdown string. Same constraints as the pre-0.1.0 `body` field.
- `prev_hash` — REQUIRED. For `revision > 1`, the `hash` value of the preceding revision. For `revision == 1`, `null`.
- `hash` — REQUIRED. `"sha256:"` followed by the lowercase hex SHA-256 of the JCS-canonicalized revision object **with `hash` and `signature.value` both replaced by `""`**. This is a self-hash, deterministic from the other fields.
- `signature` — REQUIRED. Ed25519 signature over the JCS-canonicalized revision object with `signature.value` replaced by `""`. The signing key is either:
  - the **sphere key** whose fragment matches the zone (`#public` for public zone, `#circle` for circle, `#self` for self) — the "direct" form; or
  - a **delegate key** authorized by a write mandate (§4.5.4) — the "delegated" form. In this case, the revision object MUST also carry an `authorized_by` field naming the mandate.
  Revisions are signed one at a time.
- `authorized_by` — REQUIRED IF AND ONLY IF `signature.key` is not a sphere key. A mandate id (`mandate_<ULID>`) naming the write mandate that authorizes this revision. Absent for revisions signed directly by the sphere key.

#### 2.5.4.1 Computing a new revision

To add a revision to section `S` whose current highest revision is `R_prev`:

1. Prepare the new revision object with `revision = R_prev.revision + 1`, `at = now()`, `body = new_body`, `prev_hash = R_prev.hash`, `hash = ""`, `signature.value = ""`.
2. If signing with a delegate key rather than the zone's sphere key, set `authorized_by` to the write mandate's id, and set `signature.key` to the delegate's multibase Ed25519 public key.
3. Compute `hash = "sha256:" + hex(sha256(jcs(object)))`. The self-hash commits to every other field, including `authorized_by` when present.
4. Set the `hash` field to this value.
5. Re-canonicalize the object (now with the correct `hash`, still with empty signature value) and sign. The signing key is the sphere key (direct form) or the delegate key named by the write mandate (delegated form).
6. Append to `S.revisions`.

#### 2.5.4.2 Verifying a section chain

To verify section `S`:

1. Walk `S.revisions` in order.
2. For revision 1: check `prev_hash == null`, verify `hash` against the computed SHA-256, verify `signature`.
3. For each subsequent revision `R`: check `R.revision == prev.revision + 1`, `R.at > prev.at`, `R.prev_hash == prev.hash`, verify `R.hash`, verify `R.signature`.
4. If `R.authorized_by` is present, the signing key is a delegate key. The verifier MUST additionally:
   - Resolve `R.authorized_by` to the write mandate (§4.5.4). Verify the mandate per §4.7 **at time `R.at`** (not "now") — past revisions remain attributable even after the mandate expires or is revoked.
   - Check that the mandate's `scopes` include `ethos.write.<zone>` for the zone the section belongs to.
   - Check that `R.signature.key` matches the mandate's `grantee.pubkey`.
   - If the mandate specifies `constraints.sections`, check that the section's `id` appears in that list.
5. If any step fails, the section is **broken** and the bundle is invalid (§3.8).

#### 2.5.4.3 Redaction and the right to forget

Revisions are append-only; they are **not** engraved in stone. If an author wants to erase the text of a past revision — whether because it was wrong, private, or painful — they issue a **redaction revision**: a new revision whose `body` is a structured marker and whose presence is documented in the chain.

A redaction revision has `body` of the form:

```json
"body": "[aithos-redaction]\nredacts: 3\nreason: user_request\nredacted_at: 2026-05-15T10:00:00Z"
```

The redaction revision does **not** overwrite the old body in a valid bundle. Removing the old body from the zone file is an explicit second operation: the author may publish a new edition of the bundle whose section history contains only the redaction revision, with the old revisions omitted. In that case:

- The manifest records `section_titles_with_redaction: ["Voice"]` on the affected zone.
- The previous revisions' hashes are preserved as a `history_anchor` array on the section, so the chain's existence is still provable (their order, their dates, their signatures' existence) even if their `body` values are gone.
- A verifier who sees the pre-redaction edition can confirm the current edition's anchor hashes match the prior bodies.

This preserves cryptographic integrity while honoring the author's wish to erase. The tension — immutability for third parties, right-to-forget for the author — is resolved by making redaction public, logged, and dated.

#### 2.5.4.4 Adding a new section

A section newly introduced at edition N starts with a single revision `{ revision: 1, prev_hash: null, ... }`. Its `id` MUST be unique within the zone, not reused from a deleted section.

#### 2.5.4.5 Removing a section

A section cannot be "deleted" in the append-only sense. To stop publishing a section, the author either:

- Adds a redaction revision (§2.5.4.3) that empties the body, and keeps the shell of the section in the zone, or
- Produces a new edition whose zone omits the section entirely. The manifest of the new edition records the omission in an `omitted_sections` list so the chain-of-editions verifier can tell the omission was deliberate.

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

The bundle form is one markdown file per zone (§3.2). A zone file has a YAML frontmatter, and a body whose top-level `# Title` headings delimit sections. Each section's history is inlined as an ordered sequence of dated blocks.

```markdown
---
aithos: "0.1.0"
zone: public
subject_did: did:aithos:z6Mkr…
subject_handle: mathieu
edition: 2026.04.19-1
created_at: 2026-04-19T08:14:23Z
---

# Voice <!-- sec_a1b2c3 -->

<!-- rev 1 · 2026-02-10T09:00:00Z · sha256:a8b2f1ef… · sig:p8R… -->
I write in short paragraphs. Bulleted lists irritate me.

<!-- rev 2 · 2026-04-19T08:14:23Z · prev:sha256:a8b2f1ef… · sha256:d12e07bc… · sig:k7Q… -->
I still prefer short paragraphs for casual exchanges, but I'll write long-form prose when the subject warrants it.

# Tech stack <!-- sec_9f8e7d -->

<!-- rev 1 · 2026-04-19T08:14:23Z · sha256:c3f8… · sig:… -->
- TypeScript / Node ≥ 20
- AWS (S3, CloudFront, Lambda, DynamoDB, Bedrock)
- Vite + React on the frontend
```

### 2.6.1 Conversion rules

To convert the **document form** to the **bundle form** for a given zone:

1. Open with a YAML frontmatter populated from the document fields (`aithos`, `zone`, `subject.did`, `subject.handle`, `edition.version`, `edition.created_at`).
2. For each section in `zones.<zone>.sections`, in order:
   - Write `# <title> <!-- <section_id> -->\n\n`.
   - For each revision, in order, write a metadata HTML comment on its own line containing `rev <N>`, `at`, `prev_hash` (absent for rev 1), `hash`, and the first 12 characters of the signature, separated by `·`. Then a blank line, then the revision body, then a blank line.
3. Trim trailing whitespace.

The metadata comments are the **carrier** of the signed chain in markdown form. A reader extracts them and reconstructs the document-form revisions.

To convert the **bundle form** back to the **document form**:

1. Parse YAML frontmatter to recover edition metadata.
2. Split the body on `^# ` (start-of-line `# ` with one space).
3. In each section chunk, extract `title` and `id` from the heading line (id from the `<!-- sec_… -->` comment).
4. Split the remaining content on `<!-- rev N · … -->` markers. Each chunk is a revision body, preceded by its metadata comment. Parse the comment to recover `revision`, `at`, `prev_hash`, `hash`, and the signature prefix.
5. The full signature value (64 bytes base64url) lives in a side file `signatures/<section_id>.json` — see §3.2. The metadata comment carries only the first 12 characters as a human visual check, not the authoritative value.
6. Verify the chain per §2.5.4.2.

### 2.6.2 Lossless invariants

The conversion is lossless if:

- Section IDs are preserved across the round-trip (via the `<!-- sec_… -->` comment).
- Revision dates, `prev_hash`, `hash`, and signatures are preserved (via the `<!-- rev N · … -->` comments plus the `signatures/` directory).
- Tags are emitted as a YAML list under each section's heading: `<!-- tags: ["voice","public"] -->`. (This is admittedly ugly; the document form is canonical for any tooling that cares about tags.)

For humans reading the zone file manually, the markdown is still legible — the `<!-- … -->` comments are skippable. For tools, the metadata is all there.

## 2.7 Free sections, not fixed schema

A deliberate choice of v0.2 (carried forward into v0.1.0 of the protocol) is that a zone's content is a flat, ordered list of free-titled sections rather than a fixed schema with named slots like `bio`, `voice`, `availability`.

The reasoning:

- An LLM is good at adapting to varied input. Forcing the human into pre-named slots loses richness for marginal machine-readability gain.
- A real person is more than a list of canonical attributes. The dimensions that make someone *them* — culinary tastes, morning rituals, idiosyncratic refusals, the contents of their bookshelf — do not fit in a vendor's schema.
- Schemas evolve. Free sections do not need to.

Tooling MAY use the canonical titles in §2.5.3 as autocomplete suggestions, but MUST NOT reject sections whose titles fall outside that list.

## 2.8 Immutability, hash-chaining, and the history spine

The protocol enforces immutability at two levels, which together form the document's **history spine**.

### 2.8.1 Per-section spine

Each section's `revisions` array is a SHA-256 hash chain, signed revision by revision. Any alteration of a past revision — changing a character in an old body, shifting a timestamp, removing a revision — breaks the chain: the next revision's `prev_hash` no longer matches, and the subsequent signatures fail to verify.

This gives the section the property of a **write-once log**. An author can always add. An author cannot silently rewrite the past. The only path to "remove" content is the public, logged redaction of §2.5.4.3.

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

- **Sub-audiences.** Should `circle` admit sub-zones (`circle.work`, `circle.family`)? Currently no — the mandate system (chapter 4) handles per-recipient differentiation by issuing different scopes to different agents, all reading the same circle zone. v0.2 may revisit if real usage demands it.
- **Diff / patch format.** Editions are full snapshots. A future version may define a diff format so an agent can know "what changed between 2026.04.10-1 and 2026.04.19-1" without loading both fully.
- **Localization.** A section with multilingual content currently relies on the author writing in multiple languages within a single body. Whether to introduce explicit per-language section variants is open.

---

Next: [chapter 3 — Bundle](./03-bundle.md).
