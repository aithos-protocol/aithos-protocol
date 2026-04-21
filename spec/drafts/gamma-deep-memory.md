# Draft · Gamma — the deep memory log

> **Status:** design draft on branch `design/gamma-deep-memory`. Not part of the normative 0.1.0 spec. Supersedes the per-section revision chain (§2.5.4) and reframes the history spine (§2.8) if adopted.
>
> **Intent:** shrink the `.ethos` bundle to "who I am *now*" and move "how I became this" into a separate, still-cryptographically-provable log. Same append-only integrity guarantees, different storage split.

## D.1 Motivation

The 0.1.0 bundle embeds the full revision history of every section inline. This has three compounding costs:

1. **Bundle size.** A subject who edits their Voice section twenty times over three years ships twenty bodies, twenty dates, twenty signatures, every time anyone fetches the ethos.
2. **Operational awkwardness.** Modifying, reordering, and especially *deleting* a section all have to be expressed through the append-only revisions primitive — redaction revisions, `omitted_sections` manifest fields, `history_anchor` arrays. The machinery is real but heavy, and it leaks into every tool that reads a bundle.
3. **Audience mismatch.** The two readers of an ethos want different things. A counterparty fetching `public.ethos` to brief an agent wants the current body. An auditor, a court, or the subject themselves wants the full chain. Serving both from the same file forces the bundle to be maximal.

**Gamma** is the proposal to split the two: current state in the bundle, complete history in a companion log, an anchor hash binding them.

## D.2 Concept

Every mutation of the ethos — add a section, modify its body, change its title, reorder the zone, delete a section, touch zone-level metadata — produces one **gamma entry**. Gamma entries form a **single append-only, hash-chained, signed log** spanning all three zones. One chain, one `prev_gamma_hash`, one global `gamma.head` in the manifest. The subject's deep memory.

The bundle carries:

- each section's **current state** only (no `revisions[]` array);
- on each section, a `gamma_ref` pointing to the gamma entry that produced the current body;
- in the manifest, a `gamma.head` — the hash of the most recent gamma entry — anchoring the bundle to the log.

The gamma log lives **separately**. Typically:

- kept in full locally by the subject;
- optionally served from the subject's server as a paginated endpoint or a companion `.gamma` artifact, for counterparties who want to verify history;
- cached on readers that want history.

A reader who only needs "who is Mathieu right now" fetches the bundle. A reader who needs "what did Mathieu say about weekends in March 2025" fetches the gamma log and walks the chain.

## D.3 Analogy — SPV-light, not blockchain-heavy

Bitcoin light clients do not carry the full chain; they carry block headers and trust the chain of hashes to prove inclusion. They can still verify authenticity — they just don't store everything.

Gamma applies the same split to an ethos:

- **Light consumer** — has the bundle, trusts `gamma.head` as an anchor hash, does not need to own the log to use the ethos.
- **Full consumer** — fetches the log, walks from `gamma.head` backward, verifies each hash and signature, can reconstruct any past state by replaying forward.

No consensus, no mining, no tokens — same as before (§2.8.3). What's borrowed from Bitcoin is purely the idea that a small anchor commits to a large history.

## D.4 Storage layout

### D.4.1 On disk (local store)

```
~/.aithos/identities/<handle>/ethos/
├── manifest.json                     (gains gamma.head + gamma.count)
├── public/public.md                  (current-state zone files, §2.6)
├── circle/circle.md.enc
├── self/self.md.enc
└── gamma/
    └── gamma.jsonl.enc               (the single unified encrypted log)
```

Only one file. One chain. All three zones' ops live here, interleaved in global timestamp order.

### D.4.2 File format

The plaintext form of the log is **JSONL** — one gamma entry per line, in insertion order. Each line is the JCS-canonicalized serialization of one entry, followed by a single `\n`. Empty lines are not permitted.

```
{"aithos-gamma":"0.1.0","id":"gamma_01J9YB2X7Q…", …}
{"aithos-gamma":"0.1.0","id":"gamma_01J9YD3K8L…", …}
```

JSONL was chosen over a JSON array for three reasons: atomic append (open-O_APPEND-close without rewriting), streamable (a verifier can process entries without loading the whole file), and one-line-per-entry matches the one-entry-per-op mental model. The tradeoff is that the file is not itself a single JSON value; tooling reads line-by-line.

### D.4.3 Encryption

The plaintext JSONL is never written to disk. The whole log is encrypted end-to-end using the same construction as `circle.md.enc` / `self.md.enc` (§3.4): **XChaCha20-Poly1305** with a per-file data encryption key, and **multiple recipient wraps** wrapping that key.

In v0.1.0, the log has **three wraps by default** — one for each sphere key (`#public`, `#circle`, `#self`). The subject holds all three, so can always decrypt. Future mandates that grant gamma-read access to an agent will add additional wraps (same mechanism as bundle zone sharing).

```json
{
  "aithos-gamma-file": "0.1.0",
  "cipher": {
    "alg": "xchacha20poly1305-ietf",
    "nonce": "base64url(24 bytes)",
    "wraps": [
      { "recipient": "did:aithos:z6M…#public",  "alg": "x25519-hkdf-sha256-aead", "ephemeral_public": "…", "wrap_nonce": "…", "wrapped_key": "…" },
      { "recipient": "did:aithos:z6M…#circle",  "alg": "x25519-hkdf-sha256-aead", "ephemeral_public": "…", "wrap_nonce": "…", "wrapped_key": "…" },
      { "recipient": "did:aithos:z6M…#self",    "alg": "x25519-hkdf-sha256-aead", "ephemeral_public": "…", "wrap_nonce": "…", "wrapped_key": "…" }
    ]
  },
  "ciphertext": "base64url(XChaCha20-Poly1305(whole JSONL plaintext))"
}
```

### D.4.4 Append semantics

To append an entry, the implementation MUST:

1. Decrypt the current log into plaintext JSONL.
2. Parse the last line; take its `hash` as `prev_gamma_hash` for the new entry.
3. Canonicalize and sign the new entry (see §D.6).
4. Append `jcs(entry) + "\n"` to the plaintext.
5. Re-encrypt the whole plaintext under a **fresh** nonce and wrap the DEK for the same recipients.
6. Write atomically (write-temp-then-rename).

This is O(file size) per append. Fine for logs up to a few MB. Rolling chunks, pre-encrypted append, and Merkle commitments are v0.2+ concerns (§D.12).

### D.4.5 Manifest additions

The bundle manifest gains a top-level `gamma` object:

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

- `head` — SHA-256 of the last gamma entry's canonical JSON (the `hash` field of that entry). `null` if no entries exist yet.
- `count` — advisory entry count. Informative; a verifier recomputes by walking.
- `url` — OPTIONAL URL where the full log is served. Local-only subjects omit this.

Signing the manifest (§3.3) therefore implicitly signs `gamma.head`, anchoring the bundle to the log.

## D.5 Gamma entry schema

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

### D.5.1 Required fields

| Field | Type | Description |
|---|---|---|
| `aithos-gamma` | string | Schema version. `"0.1.0"` for this draft. |
| `id` | string | `gamma_` + 26-char Crockford-base32 ULID. |
| `at` | string | RFC 3339 UTC timestamp. MUST be strictly greater than the `at` of the entry referenced by `prev_gamma_hash`. |
| `subject_did` | string | The subject's DID. Redundant with the bundle but necessary when the log is fetched standalone. |
| `zone` | string | `"public"`, `"circle"`, or `"self"`. Determines which sphere key signs (unless delegated). |
| `op` | string | One of the operations in §D.6. |
| `target` | object | What the op acts on (shape depends on `op`). |
| `payload` | object | The op's arguments (shape depends on `op`). |
| `prev_gamma_hash` | string \| null | The `hash` value of the immediately preceding gamma entry (global, across zones). `null` only for the very first entry. |
| `hash` | string | `"sha256:"` + hex SHA-256 of the JCS-canonicalized entry with `hash` and `signature.value` set to `""`. |
| `signature` | object | Ed25519 signature per §5. Key is the sphere key corresponding to `zone`, or a delegate key authorized by a write mandate. |

### D.5.2 Optional fields

- `prev_section_gamma` — the `id` of the previous gamma entry that acted on the *same section* (convenience pointer for per-section replay without walking the whole log). Absent for `section.add` and for entries whose target isn't a section.
- `authorized_by` — REQUIRED IF AND ONLY IF `signature.key` is a delegate key; value is the mandate's id. Same semantics as §2.5.4 of 0.1.0.
- `note` — OPTIONAL free-text annotation by the author ("fixed typo", "reworded after interview"). Informative.

## D.6 Operations

Non-exhaustive initial set. Extensible under `x-` prefix for experimental ops, same rule as unknown bundle fields.

| Op | Target | Payload | Effect on bundle |
|---|---|---|---|
| `section.add` | `{ section_id, index }` | `{ title, body, tags? }` | New section appears at `index`. |
| `section.modify` | `{ section_id }` | `{ title?, body?, tags? }` | Fields present in payload replace current values. |
| `section.delete` | `{ section_id }` | `{ reason? }` | Section removed from current state; history preserved in gamma. |
| `section.reorder` | `{}` | `{ order: [section_id, …] }` | Zone's section order replaced. |
| `zone.meta.set` | `{ field }` | `{ value }` | Zone-level metadata field set. |
| `section.redact` | `{ section_id, targets: [gamma_id, …] }` | `{ reason }` | Marks past gamma entries as redacted; the referenced entries MAY have their `payload.body` replaced by a hash placeholder. |
| `identity.rotate` | `{}` | `{ new_key: did:aithos:…#public_2 }` | Sphere key rotation recorded in the log. |
| `mandate.issue` / `mandate.revoke` | `{ mandate_id }` | `{ … }` | Optional: make mandate lifecycle a first-class gamma event. |

`target` never duplicates `zone` — the top-level `zone` field is the single source of truth for which zone an op applies to. Unknown ops MUST cause a full-node verifier to reject the log. Light consumers that only care about the `head` anchor MAY skip op-level semantics.

## D.7 Worked example — the Mathieu walkthrough

This section traces, step by step, what happens on disk and in the log when a subject adds a private section and then deletes it. It is the precise scenario targeted by the first implementation slice.

### D.7.1 Step 1 — init

```
$ aithos init --handle mathieu --display-name "Mathieu Colla"
```

On disk under `~/.aithos/identities/mathieu/ethos/`:

```
manifest.json                        gamma: { head: null, count: 0 }
public/public.md                     empty frontmatter only
circle/circle.md.enc                 empty encrypted
self/self.md.enc                     empty encrypted
gamma/gamma.jsonl.enc                empty ciphertext (or file absent)
```

### D.7.2 Step 2 — add a section to the self zone

```
$ aithos ethos add-section --zone self \
    --title "Testnet wallet" \
    --body  "seed: apple pie refrigerator helmet ..."
```

One gamma entry is appended. Its canonical form:

```json
{
  "aithos-gamma": "0.1.0",
  "id": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W",
  "at": "2026-04-21T10:14:03Z",
  "subject_did": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9",
  "zone": "self",
  "op": "section.add",
  "target": { "section_id": "sec_7x2f9a", "index": 0 },
  "payload": {
    "title": "Testnet wallet",
    "body": "seed: apple pie refrigerator helmet ..."
  },
  "prev_gamma_hash": null,
  "hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#self",
    "value": "k7Q…"
  }
}
```

State after step 2:

- `gamma/gamma.jsonl.enc` contains one entry.
- `self/self.md.enc` now encrypts a document with one section whose `body` matches `payload.body`, and whose `gamma_ref` is `gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W`.
- `manifest.json.gamma.head` = `sha256:a1b2c3…`, `manifest.json.gamma.count` = `1`.

### D.7.3 Step 3 — show the zone

```
$ aithos ethos show --zone self
## Testnet wallet (sec_7x2f9a)
seed: apple pie refrigerator helmet ...
  (gamma_ref: gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W)
```

### D.7.4 Step 4 — show the gamma log

```
$ aithos gamma show
[1] gamma_01J9YB2X7Q…   2026-04-21T10:14:03Z   zone=self   op=section.add
    target: sec_7x2f9a (index 0)
    payload.title: "Testnet wallet"
    payload.body:  "seed: apple pie refrigerator helmet ..."
    hash:            sha256:a1b2c3…
    prev_gamma_hash: null
    signature: ed25519 by did:aithos:z6M…#self  ✓
```

### D.7.5 Step 5 — delete the section

```
$ aithos ethos delete-section --zone self --id sec_7x2f9a --reason "moved offline"
```

A second gamma entry is appended:

```json
{
  "aithos-gamma": "0.1.0",
  "id": "gamma_01J9YD3K8L5M7N9P2Q4R6S8T0V",
  "at": "2026-04-21T10:16:42Z",
  "subject_did": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9",
  "zone": "self",
  "op": "section.delete",
  "target": { "section_id": "sec_7x2f9a" },
  "payload": { "reason": "moved offline" },
  "prev_gamma_hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "prev_section_gamma": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W",
  "hash": "sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#self",
    "value": "m9S…"
  }
}
```

State after step 5:

- `gamma/gamma.jsonl.enc` contains two entries.
- `self/self.md.enc` encrypts an **empty** zone document (no sections).
- `manifest.json.gamma.head` = `sha256:d4e5f6…`, `manifest.json.gamma.count` = `2`.

### D.7.6 Step 6 — self zone is empty

```
$ aithos ethos show --zone self
(zone self is empty)
```

### D.7.7 Step 7 — gamma still has the full history

```
$ aithos gamma show
[1] gamma_01J9YB2X7Q…   2026-04-21T10:14:03Z   zone=self   op=section.add
    target: sec_7x2f9a (index 0)
    payload.title: "Testnet wallet"
    payload.body:  "seed: apple pie refrigerator helmet ..."
    hash:            sha256:a1b2c3…
    prev_gamma_hash: null
    signature: ed25519 by did:aithos:z6M…#self  ✓

[2] gamma_01J9YD3K8L…   2026-04-21T10:16:42Z   zone=self   op=section.delete
    target: sec_7x2f9a
    payload.reason: "moved offline"
    hash:                sha256:d4e5f6…
    prev_gamma_hash:     sha256:a1b2c3…
    prev_section_gamma:  gamma_01J9YB2X7Q…
    signature: ed25519 by did:aithos:z6M…#self  ✓
```

The deleted content is no longer in the current ethos, but its existence, its content, the time it was added, the time it was deleted, and who signed both ops are all preserved in the log. Verifiable against `manifest.gamma.head`.

### D.7.8 What a full verify does

```
$ aithos gamma verify
walking 2 entries …
 [1] hash ok, signature ok, prev_gamma_hash=null ok
 [2] hash ok, signature ok, prev_gamma_hash ok (matches [1].hash)
last entry hash = manifest.gamma.head  ✓
gamma log verified.
```

## D.8 Bundle changes

### D.8.1 Section shape

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

Current body is a direct field. `gamma_ref` points to the gamma entry that produced it. A verifier with access to the gamma log can cross-check that this entry's `payload.body` matches the bundle's body byte-for-byte.

### D.8.2 What goes away

- `revisions[]` on sections — replaced by `body` + `gamma_ref`.
- Per-section `signatures/<section_id>.json` files in the bundle — signatures now live on gamma entries.
- `history_anchor` arrays and `omitted_sections` manifest fields — redaction and deletion are gamma ops.

(These removals happen in the cutover commits after the initial gamma-in-parallel slice lands.)

## D.9 Verification tiers

### D.9.1 Light (bundle only)

A light reader fetches the bundle and:

1. Verifies the subject's DID and sphere keys (chapter 1).
2. Verifies the manifest signature.
3. Trusts `gamma.head` as an opaque anchor — does *not* need to retrieve the log.

The reader knows the bundle is authentic at time of retrieval. It cannot independently confirm the history. This is sufficient for "brief the agent about who Mathieu is now."

### D.9.2 Full (bundle + gamma)

A full reader additionally:

1. Fetches the gamma log (via `gamma.url`, or out-of-band).
2. Walks from the latest entry backward via `prev_gamma_hash`, verifying each entry's `hash` and `signature`.
3. Confirms the latest entry's hash equals the manifest's `gamma.head`.
4. For each section in the bundle, confirms `gamma_ref` resolves to an entry whose `payload.body` matches the bundle's `body`.
5. Optionally replays the log forward from the first entry to reconstruct any past state.

If any step fails, the bundle's link to its claimed history is **broken** and the reader MUST reject the history claim (though the bundle's *current state* may still be accepted by a light reader who doesn't care about history).

## D.10 Redaction and right-to-forget

The `section.redact` op is the explicit, logged path to remove content from gamma itself:

1. The author issues a `section.redact` entry naming the previous gamma ids whose bodies are to be erased.
2. The redaction entry is appended normally (signed, hash-chained).
3. A compaction pass may then replace the referenced entries' `payload.body` with a `body_hash` placeholder (SHA-256 of the redacted body) while leaving every other field intact.

After compaction:

- The chain still verifies — entries' self-hashes were computed with the full body, so the redaction entry commits to the *hash*, not the body. A redacted entry's self-hash can still be recomputed if a verifier trusts the `body_hash` as a stand-in.
- The *fact* of the past revision (date, author, shape) is preserved.
- The content is gone.

This resolves the same tension as §2.5.4.3 — immutability for third parties, erasure for the author — but without the `history_anchor` gymnastics.

## D.11 Migration from 0.1.0

Forward (revisions → gamma) is mechanical:

1. For each section, for each revision in chronological order, emit one gamma entry:
   - `section.add` for revision 1;
   - `section.modify` for subsequent revisions;
   - `section.redact` for redaction revisions.
2. Preserve `at` timestamps exactly (they already satisfy per-section monotonicity; when interleaving across zones, keep the original ordering — monotonicity across zones is a soft property in v0.1.0 of the gamma draft, see §D.12).
3. Copy the signatures onto the corresponding gamma entries.
4. Compute the new chain's hashes on the way.
5. Build the new bundle from the latest state.

Backward (gamma → revisions) is lossy: gamma knows about `section.delete` and `section.reorder`; the 0.1.0 model has no expression for either without bundle-level workarounds.

## D.12 Open questions

- **Sharding the log.** A subject with decades of history could produce hundreds of thousands of gamma entries. Rewriting the whole file on every append (§D.4.4) stops being practical above a few MB. v0.2+ needs rolling chunks (e.g. one encrypted file per N entries), with each chunk committing to the previous chunk's hash. The `gamma.head` anchor then commits to the chain of chunks.
- **Partial fetches.** A reader who wants "everything since January 2026" should be able to prove it has a contiguous sub-chain without holding the full log. A Merkle tree over the log, committed in `gamma.head`, would unlock this. Open.
- **Gossip and mirroring.** Can another server mirror a subject's gamma log? Yes trivially (it's all signed), but a discovery protocol is out of scope.
- **Mandate lifecycle as gamma events.** Making `mandate.issue` / `mandate.revoke` gamma ops unifies the subject's history but couples two currently-independent chapters. Need to decide before adopting.
- **Bundle-level signature.** With sections no longer carrying per-revision signatures, is a single bundle-level signature over the manifest + section list sufficient, or do we still want per-section anchoring signatures in the bundle?
- **Cross-zone monotonic `at`.** The log is a single chain, but zones may be authored on disconnected devices. Do we enforce strict global monotonicity of `at`, or allow soft ordering (the chain order is authoritative, `at` is advisory)? Leaning toward soft in v0.1.0.

## D.13 Why this is worth the branch

The 0.1.0 model is correct but heavy. Gamma keeps every cryptographic property — signed, hash-chained, tamper-evident, redaction-aware — while moving the weight to where the weight belongs. An ethos is a living description of a person. A person's history is long; their current self is short. The artifact should reflect that.

The bundle becomes small enough to email. The history remains provable to a court.
