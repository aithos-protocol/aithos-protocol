# 10 · Gamma — the deep memory log

The ethos document (§2) describes **who the subject is now**. Gamma describes **how the subject became that** — the complete, signed, hash-chained log of every mutation to the ethos since identity creation.

Gamma is a separate artifact from the bundle. A reader who only needs the current state does not need the log. A reader who needs history fetches it separately. The bundle anchors to the log via a signed `gamma.head` hash in the manifest (§3), so the commitment to the history is carried even by readers who never retrieve it.

## 10.1 Concept

Every mutation to the ethos — adding a section, modifying its body, changing its title, reordering a zone, deleting a section — produces exactly one **gamma entry**. Gamma entries form a **single append-only, SHA-256 hash-chained, Ed25519-signed log** spanning all three zones. One chain, one `prev_gamma_hash`, one global `gamma.head` in the manifest.

The bundle (§3) carries:

- each section's **current state** only (no embedded history);
- on each section, a `gamma_ref` pointing to the last gamma entry that produced that current state;
- in the manifest, a `gamma.head` — the hash of the most recent gamma entry — anchoring the bundle to the log.

The gamma log lives separately from the bundle. Typically the subject keeps it in full locally, and optionally serves it from their host as a paginated endpoint or companion `.gamma` artifact for counterparties who want to verify history. The bundle MAY carry a `gamma.url` pointer but the log content is never embedded.

## 10.2 Analogy — SPV-light, not blockchain-heavy

Bitcoin light clients do not carry the full chain; they carry block headers and trust the chain of hashes to prove inclusion. Gamma applies the same split to an ethos:

- **Light consumer** — has the bundle, trusts `gamma.head` as an anchor hash, does not need the log to use the ethos.
- **Full consumer** — fetches the log, walks from `gamma.head` backward, verifies each hash and signature, can reconstruct any past state by replaying forward.

No consensus, no mining, no tokens — same as §2.8.3. What is borrowed from Bitcoin is the idea that a small anchor commits to a large history.

## 10.3 Storage layout

### 10.3.1 On disk (local store)

```
~/.aithos/identities/<handle>/ethos/
├── manifest.json                (carries gamma.head + gamma.count)
├── public/public.md             current-state zone files (§2.6)
├── circle/circle.md.enc
├── self/self.md.enc
└── gamma/
    └── gamma.jsonl.enc          single unified encrypted log
```

One file. One chain. All three zones' operations interleaved in global append order.

### 10.3.2 Plaintext log format

The plaintext form of the log is **JSONL** — one gamma entry per line, in insertion order. Each line is the JCS-canonicalized serialization of one entry, followed by a single `\n`. Empty lines are not permitted.

```
{"aithos-gamma":"0.1.0","id":"gamma_01J9YB2X7Q…", …}
{"aithos-gamma":"0.1.0","id":"gamma_01J9YD3K8L…", …}
```

JSONL is chosen over a JSON array for three reasons: atomic append semantics, streamable reads, and one-line-per-entry matches the one-entry-per-op mental model.

### 10.3.3 Encryption

The plaintext JSONL is never written to disk. The whole log is encrypted end-to-end using the same construction as `circle.md.enc` / `self.md.enc` (§3.4): **XChaCha20-Poly1305** with a per-file data-encryption key, wrapped to one or more recipients.

In v0.2.0, the log has **three wraps by default** — one for each sphere key (`#public`, `#circle`, `#self`). The subject holds all three and can always decrypt. Mandates that grant gamma-read access to an agent add additional wraps using the same mechanism as bundle zone sharing.

File shape:

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

### 10.3.4 Append semantics

To append an entry, an implementation MUST:

1. Decrypt the current log into plaintext JSONL (empty string if the log file does not yet exist).
2. If the plaintext is non-empty, take the `hash` field of the last line as `prev_gamma_hash` for the new entry. Otherwise `prev_gamma_hash = null`.
3. Canonicalize and sign the new entry (see §10.5).
4. Append `jcs(entry) + "\n"` to the plaintext.
5. Re-encrypt the whole plaintext under a **fresh** 24-byte random nonce and wrap the DEK for the same recipients.
6. Write atomically (write-temp-then-rename).

This is O(file size) per append. Acceptable for logs up to a few MB. Rolling chunks, pre-encrypted append, and Merkle commitments are future work (§10.9).

### 10.3.5 Manifest additions

The bundle manifest (§3.3) carries a top-level `gamma` object:

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

- `head` — `"sha256:"` + hex SHA-256 of the most recent gamma entry's canonical JSON (the `hash` field of that entry). `null` if no entries exist yet.
- `count` — entry count. Informative; a full-node verifier recomputes by walking.
- `url` — OPTIONAL URL where the full log is served. Local-only subjects omit this.

Signing the manifest (§3.3) therefore implicitly signs `gamma.head`, binding the bundle to the log.

## 10.4 Section shape (revised)

The Section model for v0.2.0 is:

```json
{
  "id": "sec_a1b2c3",
  "title": "Voice",
  "body": "I still prefer short paragraphs for casual exchanges…",
  "tags": ["voice"],
  "gamma_ref": "gamma_01J9YB2X7Q1K3P4R5S6T7U8V9W"
}
```

- `id` — REQUIRED. Unique within the zone. `sec_` prefix + 6+ characters from `[a-z0-9]`.
- `title` — REQUIRED. 1–120 characters.
- `body` — REQUIRED. The section content as a markdown string. The **current** body; past bodies live in gamma.
- `tags` — OPTIONAL. Informative.
- `gamma_ref` — REQUIRED. The `id` of the gamma entry that produced this current state (the most recent `section.add` or `section.modify` targeting this section). A verifier with the gamma log can replay `section_id = target.section_id` entries backward from `gamma_ref` to recover the section's history.

Sections no longer carry `revisions[]`, `history_anchor`, or per-section signatures. All of this moves to gamma.

## 10.5 Gamma entry schema

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

### 10.5.1 Required fields

| Field | Type | Description |
|---|---|---|
| `aithos-gamma` | string | Schema version. `"0.1.0"` for this draft of the gamma format. |
| `id` | string | `gamma_` + 26-character Crockford-base32 ULID. |
| `at` | string | RFC 3339 UTC timestamp. MUST be strictly greater than the `at` of the entry referenced by `prev_gamma_hash`. |
| `subject_did` | string | The subject's DID. Redundant with the bundle but necessary when the log is fetched standalone. |
| `zone` | string | `"public"`, `"circle"`, or `"self"`. Determines which sphere key signs (unless delegated). |
| `op` | string | One of the operations in §10.6. |
| `target` | object | What the op acts on (shape depends on `op`). |
| `payload` | object | The op's arguments (shape depends on `op`). |
| `prev_gamma_hash` | string \| null | The `hash` value of the immediately preceding gamma entry (global, across zones). `null` only for the very first entry. |
| `hash` | string | `"sha256:"` + hex SHA-256 of the JCS-canonicalized entry with `hash` and `signature.value` both replaced by `""`. |
| `signature` | object | Ed25519 signature per §5. Signing key is the sphere key matching `zone`, or a delegate key authorized by a write mandate. |

### 10.5.2 Optional fields

- `prev_section_gamma` — the `id` of the previous gamma entry that acted on the *same* `target.section_id`. A convenience pointer that lets a reader replay a section's history in O(section events) instead of O(all events). Absent for `section.add` (no prior section event) and for entries whose `target` has no `section_id`.
- `authorized_by` — REQUIRED IF AND ONLY IF `signature.key` is a delegate key. Value is the mandate's id. Same semantics as §4.5.4.
- `note` — OPTIONAL free-text annotation by the author. Informative.

### 10.5.3 Hash and signature computation

Given a candidate gamma entry `G`:

1. Set `G.hash = ""` and `G.signature.value = ""`.
2. Compute `G.hash = "sha256:" + hex(sha256(jcs(G)))`.
3. Set `G.hash` to the computed value.
4. Re-canonicalize with the correct `hash`, the empty `signature.value`, and sign. Signing key is determined by `zone` (direct form) or by the write mandate (delegated form, §4.5.4).
5. Set `G.signature.value` to the signature.

## 10.6 Operations

The initial v0.2.0 operation set:

| Op | Target | Payload | Effect on current state |
|---|---|---|---|
| `section.add` | `{ section_id, index? }` | `{ title, body, tags? }` | New section appears at `index` (default: end of zone). |
| `section.modify` | `{ section_id }` | `{ title?, body?, tags? }` | Each field present in payload replaces the corresponding current value. |
| `section.delete` | `{ section_id }` | `{ reason? }` | Section removed from current state; history preserved in gamma. |
| `section.reorder` | `{}` | `{ order: [section_id, …] }` | Zone's section order replaced by `order`. |
| `section.redact` | `{ section_id, targets: [gamma_id, …] }` | `{ reason }` | Marks past gamma entries as redacted (see §10.8). |

Implementations MAY add experimental operations under an `x-` prefix. Unknown ops without an `x-` prefix MUST cause a full-node verifier to reject the log. Light consumers that only care about the `head` anchor MAY skip op-level semantics.

`target` MUST NOT duplicate `zone` — the top-level `zone` field is the single source of truth for which zone an op applies to.

### 10.6.1 section.modify payload (option a — full new state)

For v0.2.0, `section.modify.payload` carries the **full new value** of each field being changed (not a diff). A modify that changes only the body still sends the complete new body; a modify that changes title and body sends both. This keeps replay O(1) at each entry and avoids a diff/patch algorithm in the critical path.

A future version MAY introduce a diff payload variant under a distinct op (e.g. `x-section.patch`) if log size becomes a concern.

## 10.7 Verification tiers

### 10.7.1 Light (bundle only)

A light reader fetches the bundle and:

1. Verifies the subject's DID and sphere keys (§1).
2. Verifies the manifest signature (§3.3).
3. Treats `gamma.head` as an opaque anchor — does **not** retrieve the log.

The reader knows the bundle is authentic at time of retrieval. It cannot independently confirm history. This is sufficient for "brief the agent about who Mathieu is now."

### 10.7.2 Full (bundle + gamma)

A full reader additionally:

1. Fetches the gamma log (via `gamma.url`, or out-of-band).
2. Walks the log, verifying each entry's `hash`, `signature`, and chain linkage (`prev_gamma_hash` matches previous entry's `hash`; `at` strictly increases).
3. Confirms that the last entry's `hash` equals the manifest's `gamma.head` and the entry count equals `gamma.count`.
4. For each section in the bundle, confirms `section.gamma_ref` resolves to a gamma entry (via filtered walk on `target.section_id`) whose `payload` reproduces the bundle's current state.

If any step fails, the bundle's link to its claimed history is **broken** and the reader MUST reject the history claim (though the bundle's current state MAY still be accepted by a light reader that does not require history).

### 10.7.3 Section replay

To reconstruct the state of section `S` at some past entry `G_t`:

1. Starting from the most recent entry targeting `S` (found via `prev_section_gamma` from `S.gamma_ref`, or by filter), walk backward along `prev_section_gamma` until reaching an entry at or before `G_t`.
2. If the chosen entry is `section.add` or `section.modify`, its `payload` is the state of `S` at time `G_t.at`.
3. If the chosen entry is `section.delete`, `S` did not exist in the current state at time `G_t.at`.

## 10.8 Redaction and right-to-forget

The `section.redact` op is the explicit, logged path to remove content from gamma itself:

1. The author issues a `section.redact` entry naming the gamma ids whose `payload.body` (and/or `payload.title`) is to be erased.
2. The redaction entry is appended normally (signed, hash-chained).
3. A compaction pass MAY then replace the referenced entries' `payload.body` with a `body_hash` placeholder (SHA-256 of the redacted body) while leaving every other field intact.

After compaction:

- Each entry's `hash` field still commits to the full body (it was computed before redaction), so a verifier that trusts the `body_hash` placeholder as a stand-in can continue the chain walk.
- The *fact* of the past revision (date, author, shape) is preserved.
- The content is gone.

A verifier MUST distinguish a redacted entry (whose `payload` contains a `body_hash` placeholder) from a live entry when reporting results.

## 10.9 Open questions

- **Sharding the log.** A subject with years of history will eventually produce tens of thousands of gamma entries. The whole-file re-encryption in §10.3.4 stops being practical above a few MB. A future version will introduce rolling chunks (e.g. one encrypted file per N entries), each chunk committing to the previous chunk's hash.
- **Partial fetches.** A Merkle tree over the log, committed in `gamma.head`, would let a reader prove inclusion of a sub-range without holding the full log. Not specified in v0.2.0.
- **Gossip and mirroring.** Another server can trivially mirror a subject's gamma log (it is all signed), but a discovery protocol is out of scope for v0.2.0.
- **Mandate lifecycle as gamma events.** Making `mandate.issue` / `mandate.revoke` first-class gamma ops would unify the subject's history with their authorization timeline. Under consideration for v0.3.
- **Cross-zone monotonic `at`.** Zones MAY be authored on disconnected devices. v0.2.0 treats chain order as authoritative and `at` as advisory — strict cross-zone monotonicity is not enforced.

---

Next: return to [chapter 3 — Bundle](./03-bundle.md) for how `gamma.head` is carried in the manifest, or [chapter 5 — Signing](./05-signing.md) for the canonicalization rules that apply to gamma entries.
