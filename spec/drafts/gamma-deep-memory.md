# Draft · Gamma — the deep memory log

> **Status:** design draft on branch `design/gamma-deep-memory`. Not part of the normative 0.1.0 spec. Supersedes the per-section revision chain (§2.5.4) and reframes the history spine (§2.8) if adopted.
>
> **Intent:** shrink the `.ethos` bundle to "who I am *now*" and move "how I became this" into a separate, optional, still-cryptographically-provable log. Same append-only integrity guarantees, different storage split.

## D.1 Motivation

The 0.1.0 bundle embeds the full revision history of every section inline. This has three compounding costs:

1. **Bundle size.** A subject who edits their Voice section twenty times over three years ships twenty bodies, twenty dates, twenty signatures, every time anyone fetches the ethos.
2. **Operational awkwardness.** Modifying, reordering, and especially *deleting* a section all have to be expressed through the append-only revisions primitive — redaction revisions, `omitted_sections` manifest fields, `history_anchor` arrays. The machinery is real but heavy, and it leaks into every tool that reads a bundle.
3. **Audience mismatch.** The two readers of an ethos want different things. A counterparty fetching `public.ethos` to brief an agent wants the current body. An auditor, a court, or the subject themselves wants the full chain. Serving both from the same file forces the bundle to be maximal.

**Gamma** is the proposal to split the two: current state in the bundle, complete history in a companion log, an anchor hash binding them.

## D.2 Concept

Every mutation of the ethos — add a section, modify its body, change its title, reorder the zone, delete a section, touch zone-level metadata — produces one **gamma entry**. Gamma entries form an append-only, hash-chained, signed log. The subject's deep memory.

The bundle carries:

- each section's **current state** only (no `revisions[]` array);
- on each section, a `gamma_ref` pointing to the gamma entry that produced the current body;
- in the manifest, a `gamma.head` — the hash of the most recent gamma entry — anchoring the bundle to the log.

The gamma log lives **separately**. Typically:

- served from the subject's server as a paginated endpoint or a companion `.gamma` artifact;
- cached on readers that want history;
- kept in full locally by the subject.

A reader who only needs "who is Mathieu right now" fetches the bundle. A reader who needs "what did Mathieu say about weekends in March 2025" fetches the relevant gamma page and walks the chain.

## D.3 Analogy — SPV-light, not blockchain-heavy

Bitcoin light clients do not carry the full chain; they carry block headers and trust the chain of hashes to prove inclusion. They can still verify authenticity — they just don't store everything.

Gamma applies the same split to an ethos:

- **Light consumer** — has the bundle, trusts `gamma.head` as an anchor hash, does not need to own the log to use the ethos.
- **Full consumer** — fetches the log, walks from `gamma.head` backward, verifies each hash and signature, can reconstruct any past state by replaying forward.

No consensus, no mining, no tokens — same as before (§2.8.3). What's borrowed from Bitcoin is purely the idea that a small anchor commits to a large history.

## D.4 Gamma entry schema

```json
{
  "aithos-gamma": "0.1.0",
  "id": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W",
  "at": "2026-04-21T10:12:03Z",
  "subject_did": "did:aithos:z6Mkr…",
  "zone": "public",
  "op": "section.modify",
  "target": { "section_id": "sec_a1b2c3" },
  "payload": {
    "title": "Voice",
    "body": "I still prefer short paragraphs for casual exchanges, but I'll write long-form prose when the subject warrants it.",
    "tags": ["voice"]
  },
  "prev_gamma_hash": "sha256:…",
  "prev_section_gamma": "gamma_01J9XA1V6P0J2N3Q4R5S6T7U8V",
  "hash": "sha256:…",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#public",
    "value": "k7Q…"
  }
}
```

### D.4.1 Required fields

| Field | Type | Description |
|---|---|---|
| `aithos-gamma` | string | Schema version. `"0.1.0"` for this draft. |
| `id` | string | `gamma_` + 26-char Crockford-base32 ULID. |
| `at` | string | RFC 3339 UTC timestamp. MUST be strictly greater than the `at` of the entry referenced by `prev_gamma_hash`. |
| `subject_did` | string | The subject's DID. Redundant with the bundle but necessary when the log is fetched standalone. |
| `zone` | string | `"public"`, `"circle"`, or `"self"`. |
| `op` | string | One of the operations in §D.5. |
| `target` | object | What the op acts on (shape depends on `op`). |
| `payload` | object | The op's arguments (shape depends on `op`). |
| `prev_gamma_hash` | string \| null | SHA-256 of the JCS-canonicalized previous gamma entry (over the whole log). `null` only for the very first entry. |
| `hash` | string | `"sha256:"` + hex SHA-256 of the JCS-canonicalized entry with `hash` and `signature.value` set to `""`. |
| `signature` | object | Ed25519 signature per §5. Key is the sphere key for `zone`, or a delegate key authorized by a write mandate. |

### D.4.2 Optional fields

- `prev_section_gamma` — the `id` of the previous gamma entry that acted on the *same section* (convenience pointer for per-section replay without walking the whole log). Absent for `section.add` and for entries whose target isn't a section.
- `authorized_by` — REQUIRED IF AND ONLY IF `signature.key` is a delegate key; value is the mandate's id. Same semantics as §2.5.4 of 0.1.0.
- `note` — OPTIONAL free-text annotation by the author ("fixed typo", "reworded after interview"). Informative.

## D.5 Operations

Non-exhaustive initial set. Extensible under `x-` prefix for experimental ops, same rule as unknown bundle fields.

| Op | Target | Payload | Effect on bundle |
|---|---|---|---|
| `section.add` | `{ zone, section_id, index }` | `{ title, body, tags? }` | New section appears at `index`. |
| `section.modify` | `{ section_id }` | `{ title?, body?, tags? }` | Fields present in payload replace current values. |
| `section.delete` | `{ section_id }` | `{ reason? }` | Section removed from current state; history preserved in gamma. |
| `section.reorder` | `{ zone }` | `{ order: [section_id, …] }` | Zone's section order replaced. |
| `zone.meta.set` | `{ zone, field }` | `{ value }` | Zone-level metadata field set. |
| `section.redact` | `{ section_id, targets: [gamma_id, …] }` | `{ reason }` | Marks past gamma entries as redacted; the referenced entries MAY have their `payload.body` replaced by a hash placeholder. |
| `identity.rotate` | `{ zone }` | `{ new_key: did:aithos:…#public_2 }` | Sphere key rotation recorded in the log. |
| `mandate.issue` / `mandate.revoke` | `{ mandate_id }` | `{ … }` | Optional: make mandate lifecycle a first-class gamma event. |

Unknown ops MUST cause a full-node verifier to reject the log. Light consumers that only care about the `head` anchor MAY skip op-level semantics.

## D.6 Bundle changes

### D.6.1 Section shape

The 0.1.0 section:

```json
{
  "id": "sec_a1b2c3",
  "title": "Voice",
  "revisions": [ { … }, { … } ],
  "tags": ["voice"]
}
```

becomes:

```json
{
  "id": "sec_a1b2c3",
  "title": "Voice",
  "body": "I still prefer short paragraphs for casual exchanges…",
  "tags": ["voice"],
  "gamma_ref": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W"
}
```

Current body is a direct field. `gamma_ref` points to the gamma entry that produced it. A verifier with access to the gamma log can cross-check that this entry's `payload.body` matches the bundle's body byte-for-byte (after whitespace normalization if any is defined).

### D.6.2 Manifest additions

```json
{
  …existing manifest fields…,
  "gamma": {
    "head": "sha256:…",
    "count": 247,
    "url": "https://aithos.example/u/mathieu.gamma"
  }
}
```

- `head` — REQUIRED when the subject has any history at all. SHA-256 of the JCS-canonicalized latest gamma entry. `null` for a brand-new subject with zero gamma entries.
- `count` — OPTIONAL advisory count of entries. Trust but verify.
- `url` — OPTIONAL URL where the full log is served. A subject who keeps the log local-only omits this.

### D.6.3 What goes away

- `revisions[]` on sections — replaced by `body` + `gamma_ref`.
- Per-section `signatures/<section_id>.json` files in the bundle — signatures now live on gamma entries.
- `history_anchor` arrays and `omitted_sections` manifest fields — redaction and deletion are gamma ops.

The `signatures/` directory may still exist for a single top-of-chain signature that covers the bundle as a whole (TBD — see §D.10).

## D.7 Verification tiers

### D.7.1 Light (bundle only)

A light reader fetches the bundle and:

1. Verifies the subject's DID and sphere keys (chapter 1).
2. Verifies the manifest signature.
3. Trusts `gamma.head` as an opaque anchor — does *not* need to retrieve the log.

The reader knows the bundle is authentic at time of retrieval. It cannot independently confirm the history. This is sufficient for "brief the agent about who Mathieu is now."

### D.7.2 Full (bundle + gamma)

A full reader additionally:

1. Fetches the gamma log (via `gamma.url`, or out-of-band).
2. Walks from the latest entry backward via `prev_gamma_hash`, verifying each entry's `hash` and `signature`.
3. Confirms the latest entry's hash equals the manifest's `gamma.head`.
4. For each section in the bundle, confirms `gamma_ref` resolves to an entry whose `payload.body` matches the bundle's `body`.
5. Optionally replays the log forward from the first entry to reconstruct any past state.

If any step fails, the bundle's link to its claimed history is **broken** and the reader MUST reject the history claim (though the bundle's *current state* may still be accepted by a light reader who doesn't care about history).

## D.8 Redaction and right-to-forget

The `section.redact` op is the explicit, logged path to remove content from gamma itself:

1. The author issues a `section.redact` entry naming the previous gamma ids whose bodies are to be erased.
2. The redaction entry is appended normally (signed, hash-chained).
3. A compaction pass may then replace the referenced entries' `payload.body` with a `body_hash` placeholder (SHA-256 of the redacted body) while leaving every other field intact.

After compaction:

- The chain still verifies — entries' self-hashes were computed with the full body, so the redaction entry commits to the *hash*, not the body. A redacted entry's self-hash can still be recomputed if a verifier trusts the `body_hash` as a stand-in.
- The *fact* of the past revision (date, author, shape) is preserved.
- The content is gone.

This resolves the same tension as §2.5.4.3 — immutability for third parties, erasure for the author — but without the `history_anchor` gymnastics.

## D.9 Migration from 0.1.0

Forward (revisions → gamma) is mechanical:

1. For each section, for each revision in chronological order, emit one gamma entry:
   - `section.add` for revision 1;
   - `section.modify` for subsequent revisions;
   - `section.redact` for redaction revisions.
2. Preserve `at` timestamps exactly.
3. Copy the signatures onto the corresponding gamma entries.
4. Compute the new chain's hashes on the way.
5. Build the new bundle from the latest state.

Backward (gamma → revisions) is lossy: gamma knows about `section.delete` and `section.reorder`; the 0.1.0 model has no expression for either without bundle-level workarounds.

## D.10 Open questions

- **Sharding the log.** A subject with decades of history could produce hundreds of thousands of gamma entries. Do we need paginated logs, Merkle summaries, periodic checkpoints (every N entries, sign the whole chain so far)? Probably yes, at v0.2+.
- **Partial fetches.** A reader who wants "everything since January 2026" should be able to prove it has a contiguous sub-chain without holding the full log. A Merkle tree over the log, committed in `gamma.head`, would unlock this. Open.
- **Gossip and mirroring.** Can another server mirror a subject's gamma log? Yes trivially (it's all signed), but a discovery protocol is out of scope.
- **Mandate lifecycle as gamma events.** Making `mandate.issue` / `mandate.revoke` gamma ops unifies the subject's history but couples two currently-independent chapters. Need to decide before adopting.
- **Bundle-level signature.** With sections no longer carrying per-revision signatures, is a single bundle-level signature over the manifest + section list sufficient, or do we still want per-section anchoring signatures in the bundle?
- **Timestamp monotonicity across zones.** Gamma is a single log spanning all three zones. Do we require a global `at` monotonic order, or monotonic-per-zone? Single log is simpler; per-zone may be needed if zones are authored on disconnected devices.
- **Storage format of the log file.** JSONL (one entry per line) is trivial to stream. A single JSON array is easier to canonicalize but harder to append to. Decide at implementation time.

## D.11 Why this is worth the branch

The 0.1.0 model is correct but heavy. Gamma keeps every cryptographic property — signed, hash-chained, tamper-evident, redaction-aware — while moving the weight to where the weight belongs. An ethos is a living description of a person. A person's history is long; their current self is short. The artifact should reflect that.

The bundle becomes small enough to email. The history remains provable to a court.
