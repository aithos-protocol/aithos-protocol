# 3 · Bundle — the `.ethos` container

> **Format status (protocol-core 0.11.3).** The **current, normative on-disk
> format is v0.4** (manifest marker `aithos: "0.4.0"`), specified in the body of
> this chapter by **§3A (v0.4 — incremental manifest & zone keys)**. It is an
> incremental content-addressed manifest (~3 KB, O(1)) that references immutable
> zone objects — ZoneShard / KeyRing / ExtraWraps — by sha, with one 32-byte
> **zone key** per encrypted zone sealed once per recipient, and per-section
> DEKs sealed symmetrically under the zone key (`enc_dek`). §3A is the promotion
> into this chapter of Part II (§N1–N13) of
> [`bundle-v0.4-incremental-manifest-and-zone-keys.md`](./drafts/bundle-v0.4-incremental-manifest-and-zone-keys.md).
>
> **v0.3 (per-section)** — split each zone into per-section blobs
> (`public/<id>.md` plaintext, `circle|self/<id>.enc` ciphertext under a fresh
> per-section DEK), `self` index via per-section `title_cipher` — remains
> **readable via dual-read**, specified by the two promoted drafts
> [`bundle-v0.3-per-section-encryption.md`](./drafts/bundle-v0.3-per-section-encryption.md)
> and [`bundle-v0.3-section-level-mandates.md`](./drafts/bundle-v0.3-section-level-mandates.md).
> However, a subject once migrated to v0.4 **refuses any subsequent v0.3
> publish** — `aithos` never regresses (server error
> `-32045 ethos_spec_version_regression`, §3A.10 / §10.9). The **v0.2 monolithic
> format**, described in the **historical annex §3.2–§3.10** at the end of this
> chapter, **remains readable and verifiable** for legacy inspection, but
> authoring v0.2 is a **hard error on the SDK side**. Runtimes detect the format
> from the manifest `aithos` marker (`0.2.x` / `0.3.0` / `0.4.0`).
>
> **Chapter layout.** §3.1 is common (the ZIP container rationale). **§3A is the
> normative body** (v0.4). **§3.2–§3.10 are the historical annex** (v0.2/v0.3),
> retained verbatim for dual-read and legacy verification; per-`§3.x` banners in
> the annex point back to the §3A section that supersedes them.

## 3.1 Overview

A bundle is a **ZIP archive** (PKZIP) with the `.ethos` extension. It carries one ethos edition (chapter 2), its encrypted zones, the signed DID document, and a manifest that glues them together.

The choice of ZIP is deliberate. ZIP is understood everywhere, has good tooling, preserves file structure, and is the container underlying `.docx`, `.apk`, `.epub`, and countless other established formats. A curious reader can always `unzip` a bundle to see what's inside.

> **v0.4 note.** Under v0.4 the container carries content-addressed **objects**
> (§3A.1) rather than whole-zone files: the ZIP (or the platform object store,
> §10.3) holds the signed manifest, the immutable zone objects
> (ZoneShard / KeyRing / ExtraWraps) under `objects/{sha}`, the per-section
> blobs under their own sha, and `did.json`. The whole-zone `circle.md.enc` /
> `self.md.enc` layout of §3.2 is v0.2 and is retained only in the annex.

## 3A · v0.4 — incremental manifest & zone keys (NORMATIVE)

This section is the normative on-disk model for the current format
(`aithos: "0.4.0"`). It supersedes the corresponding parts of the historical
annex §3.2–§3.6. Everything not redefined here is inherited unchanged from the
v0.3 drafts (per-section encryption, section-level mandates, section verb
scopes): the §11 envelopes, the edition chain (§3A.5), the content-addressed
blobs, the wrap construction (§3A.4.3 / §3.6), the scope grammar, and the
`did.json` / revocation-epoch model.

Three coupled changes define v0.4:

1. The **manifest becomes O(1)**: it no longer carries the zone descriptors, only
   content-addressed references to zone objects. Only the manifest is signed
   (JCS, as before); the integrity of everything else follows from the sha it
   references (recursively).
2. The **wraps leave the manifest** (and every anonymously-served object): they
   live in objects served only over the authenticated channel.
3. A **per-zone master key** is encrypted: a zone-scoped mandate receives ONE
   wrap (the zone key), not one per section. Per-section DEKs remain, sealed
   symmetrically under the zone key.

### 3A.1 Content-addressed objects

An **object** is a JSON document canonicalized with **JCS (RFC 8785)**; its
identifier is `sha256(canonical_bytes)` in lowercase hex. Objects are stored at
`ethos/{did}/objects/{sha}` — a namespace distinct from blobs, with its own ACL
and GC. Objects are immutable; any "modification" is a new object referenced by
the next manifest. Every object carries `{"object": "<type>", "v": 1, …}` as a
discriminant.

There are three object types: `zone_shard` (§3A.2), `keyring` and `extra_wraps`
(§3A.4). Blobs (the section bodies) are content-addressed as in v0.3 and are
carried by sha across editions with zero re-upload.

### 3A.2 ZoneShard

A ZoneShard holds `1/N` of a zone's index, partitioned by `section_id`:

```jsonc
{ "object": "zone_shard", "v": 1,
  "zone": "circle",
  "entries": [ {
      "section_id": "…",
      "title": "…",            // public/circle: cleartext (v0.3 spec unchanged)
      "tags": ["…"],           // optional, cleartext where title is cleartext
      "title_cipher": { "n": "...", "ct": "..." },  // self: AEAD(DEK) — see §3A.2.1
      "blob_sha": "…", "sha256_of_plaintext": "…", "gamma_ref": "…",
      "n": "…",                // body nonce (REQUIRED circle/self, absent public) —
                               // v0.3 carried it in cipher.nonce; here blobs stay
                               // bit-identical across migration (carried by sha)
      "approx_size_bytes": 1234,                        // P3 hint (optional, zero-cost)
      "enc_dek": { "kid": "zk…", "n": "…", "c": "…" }   // absent ⇢ see §3A.9.3
  } ] }
```

Rules:

- `entries` MUST be sorted by `section_id` (bytewise) — this determinism is
  what makes the shard sha reproducible.
- **Sharding.** `shard_count = next_pow2(ceil(n / 128))` bounded to `[1, 64]`,
  recomputed at each edition from the zone's TOTAL section count.
  `shard_index = u32be(sha256(section_id)[0..4]) mod shard_count`. A change of
  `shard_count` (a threshold crossing) rewrites all shards of the zone (bodies
  untouched); it is rare and amortized, and the power-of-two step avoids
  yo-yoing.
- `public`: `entries` carry neither `enc_dek` nor `title_cipher` (blobs are
  cleartext).
- `self`: `title`/`tags` are ABSENT and `title_cipher` is REQUIRED — see §3A.2.1.

Editing one section rewrites **its** shard only (plus the manifest, and the
blob when the body changed).

#### 3A.2.1 `title_cipher` (self)

For `self`, the title index is sealed under the section DEK:

```
title_cipher = XChaCha20-Poly1305(DEK, n, jcs({title, tags?}))
AAD          = "aithos-title-v2\0" ‖ subject_did ‖ "\0" ‖ section_id
```

This is v2 (sealed under the section DEK, not per-recipient as v0.3 sealed the
title): whoever can open the body can read the title, with the same recipients
by construction — the v0.3 disclosure contract is preserved and simplified.

### 3A.3 Zone key & `enc_dek`

- **Zone key.** 32 random bytes, identified by `kid = "zk" ‖ 16 random hex`.
  One per encrypted zone (`circle`, `self`).
- **`enc_dek`.** The per-section DEK is sealed symmetrically under the zone key:
  ```
  enc_dek = XChaCha20-Poly1305(zone_key, n, DEK)
  AAD     = "aithos-dek-v1\0" ‖ subject_did ‖ "\0" ‖ zone ‖ "\0" ‖ section_id ‖ "\0" ‖ kid
  ```
  The section DEK is still the key that encrypts the blob (and `title_cipher` in
  `self`) — so v0.3 blobs are portable as-is.
- A zone has ONE current `kid`. After a rotation all entries carry the new
  `kid` (rewriting the shards is part of the rotation edition — a manifest MUST
  NOT reference two `kid`s for the same zone).

### 3A.4 KeyRing & ExtraWraps (authenticated channel only)

```jsonc
{ "object": "keyring", "v": 1, "zone": "circle", "kid": "zk…",
  "wraps": [ { "recipient": "<v0.3 label, unchanged>",
               "wrap": { /* §3.6 over jcs({kid, zone_key}) */ } } ] }

{ "object": "extra_wraps", "v": 1, "zone": "circle",
  "entries": [ { "section_id": "…",
                 "wraps": [ { "recipient": "…", "wrap": { /* §3.6 over DEK — IDENTICAL to v0.3 */ } } ] } ] }
```

- `recipient` uses the v0.3 label format (`granteeId#pubkeyMultibase` |
  `did#<zone>-kex`).
- The owner (`did#<zone>-kex`) MUST ALWAYS appear in the KeyRing.
- ExtraWraps' `wrap`s are bit-for-bit the v0.3 format (migration is a copy).
- `entries` and `wraps` MUST be sorted (by `section_id`, then `recipient`) for
  determinism.

A **zone-scoped** mandate gets a single wrap of the **zone key** in the KeyRing
and thereby opens every section of the zone. **Per-section** grants (`#id=` /
`#prefix=` / `#tag=`) do NOT receive the zone key; they go through ExtraWraps
(per-section DEK wraps). The KeyRing is normally tiny (recipients × ~120 bytes);
ExtraWraps is normally empty.

#### 3A.4.3 Wrap construction

The wrap construction is unchanged from §3.6 (X25519-HKDF-SHA256-AEAD). In v0.4
it is applied to the **zone key** in the KeyRing (over `jcs({kid, zone_key})`)
and, unchanged, to the **per-section DEK** in ExtraWraps. See §3.6 for the full
procedure.

### 3A.5 Manifest v0.4

```jsonc
{ "aithos": "0.4.0", "bundle_id": "…", "subject_did": "…",
  "subject_handle": "…", "display_name": "…",
  "edition": { "version": "…", "created_at": "…", "supersedes": null,
               "prev_hash": "…", "height": 107 },
  "zones": {
    "public": { "n": 3,   "shard_count": 1, "shard_shas": ["…"] },
    "circle": { "n": 209, "shard_count": 2, "shard_shas": ["…","…"],
                 "keyring_sha": "…", "extrawraps_sha": "…" },
    "self":   { "n": 12,  "shard_count": 1, "shard_shas": ["…"],
                 "keyring_sha": "…" } },
  "integrity": { "sha256_of_did_json": "…",
                  "manifest_signature": { /* §3.8 form, unchanged: owner #public or delegate+authorized_by, JCS with blank value */ } } }
```

- `shard_shas` lists the shard object shas for the zone, ordered by
  `shard_index`.
- `keyring_sha` is REQUIRED for encrypted zones (`circle`, `self`).
- `extrawraps_sha` is OPTIONAL — absent iff the zone has no ExtraWraps entry.
- `edition.prev_hash` / `edition.height` are the edition chain, unchanged from
  §3.3.3 (sha of the previous canonical manifest; genesis `prev_hash: null`,
  `height: 1`).
- The signature covers ONLY this manifest document; the integrity of the
  objects and blobs follows from the sha it references (recursively). The
  `integrity` envelope (`sha256_of_did_json`, `manifest_signature`) is the same
  as §3.8.

### 3A.6 Publish (extension of the §11 envelope)

`aithos.publish_ethos_edition` (§10.6.3a) accepts, in v0.4:

```
params = { manifest, objects: { "<sha>": b64, … }, blobs: { "<sha>": b64, … } }
```

The server validation order is normative and specified in §10.6.3a. In outline:
envelope + manifest signature + `height`/`prev_hash` + `sha256_of_did_json`
(unchanged); object/blob **integrity** (every key equals the real sha256 of its
content, every manifest-referenced sha is uploaded or carried by induction from
the previous edition — the analogue of `carriedShaSet`); **body carry** (for
each shard new to this edition, each `entries[].blob_sha` is uploaded or
carried); **delegated authorization** by diff of the changed shards; then
persistence with the DDB row written last (atomicity unchanged).

Dual-write: the server keeps accepting v0.3 publishes, but a subject already
migrated to v0.4 that attempts a later v0.3 publish is refused —
`-32045 ethos_spec_version_regression` (`aithos` never regresses; §3A.10,
§10.9).

### 3A.7 Reads

- `aithos.get_ethos_manifest` returns the manifest as stored (`0.3.0` or
  `0.4.0`).
- `aithos.get_ethos_objects` (§10.5.4a) batch-fetches objects (≤64 shas) and
  reports `missing[]`. ACL by object type: `zone_shard` follows the manifest
  ACL (anonymous readers admitted — a shard exposes no recipient label);
  `keyring` and `extra_wraps` require read-auth (owner or an active delegate),
  exactly as `circle`/`self` bodies. `missing` covers *absent-or-forbidden*
  alike — no authorization oracle.
- Blobs are read with `aithos.get_ethos_section` / `get_ethos_sections`,
  unchanged.

### 3A.8 Read algorithm (informative, expected of clients)

Owner/delegate: manifest → the zone's shards (one `get_ethos_objects` batch) →
`keyring` (authenticated) → unwrap the zone key (session cache keyed by `kid`) →
`enc_dek` → DEK → blob. Without a zone key (a per-section grant): use
ExtraWraps. `readable(entry)` = (zone key held ∧ `enc_dek` present) ∨ (an
ExtraWraps entry under my label) — computable without touching bodies, exactly
as v0.3. Anonymous: full `public`; `circle` titles/ids; `self` ids only. A
delegate without access sees the same surfaces as an anonymous reader (v0.3
parity preserved).

### 3A.9 Write algorithms (normative)

1. **Edit / add / delete (owner).** Rewrite the touched shard(s) (+ blob),
   manifest, publish. When editing a section the owner MUST refresh its
   `enc_dek` under the current `kid` and MUST prune from that section's
   ExtraWraps entry the labels of dead mandates (the v0.3 auto-cleanup, now per
   section AND per object).
2. **Edit (zone delegate).** The delegate holds the zone key → new DEK, blob,
   `enc_dek` under the current `kid`, shard, manifest. NO grant resolution
   (no `list`/`get_mandate` crawl) — the zone key already covers zone
   delegates, and existing ExtraWraps are carried as-is (additive doctrine).
3. **Create (delegate WITHOUT the zone key)** (a `#prefix=` fence / append):
   generate the DEK, write the entry WITHOUT `enc_dek`, and set ExtraWraps to
   `{author, owner}` (the v0.3 "sealed to both" contract). The next owner edit
   of that section (or a `sealGrant`) endows it with an `enc_dek` — the
   "resync at the edition" rule is unchanged.
4. **`sealGrant` (owner).** Zone scope → one wrap added to the KeyRing (**O(1)**);
   per-section scope → DEK wraps into ExtraWraps for the covered sections (the
   owner unwraps the DEKs via its own `enc_dek` — no body read).
5. **`pruneWraps` (owner).** Remove the labels of revoked/expired mandates from
   the KeyRing and ExtraWraps. Pure metadata, v0.3 semantics unchanged.
6. **`reseal({mode:"rotate"})` (owner).** New zone key (new `kid`); the KeyRing
   is re-sealed to the still-active grants + owner; EVERY entry's `enc_dek` is
   re-sealed symmetrically under the new zone key; shards rewritten; **bodies
   untouched, no blob re-encrypted**. This cuts the crypto path for future
   editions; real access denial is served by the server gate (`circle`/`self`
   bodies never leave the authenticated channel).
7. **`reseal({mode:"rotate-deep"})` (owner).** `rotate` + fresh DEKs + bodies
   re-encrypted and re-uploaded (+ `self` `title_cipher`) — the strong
   cryptographic erasure, for "this content must no longer exist for anyone."

### 3A.10 Migration v0.3 → v0.4 (owner publish, one edition)

1. Read the v0.3 manifest; for each encrypted section, unwrap ITS owner wrap →
   DEK (local, no body read).
2. Generate the zone keys; build shards (fields carried as-is, `blob_sha`
   carried, `enc_dek` sealed), the KeyRing (owner + ACTIVE zone-scoped mandates
   — the kex pubkey is extracted from the v0.3 label), ExtraWraps (v0.3 wraps
   copied bit-for-bit for active per-section mandates; dead ones pruned).
3. Publish `aithos: "0.4.0"`, `height + 1`: the uploads are objects + manifest,
   **zero blob**. The server validates the full carry via `carriedShaSet(prev)`.
4. A delegate NEVER initiates the migration: on a v0.3 subject a delegate keeps
   writing v0.3. Mandate bundles are unchanged and valid on both sides. The
   server accepts v0.3 publishes without a time limit for now.

Bundles of mandate, `did.json`, the revocation epoch and the §11 envelopes are
**unchanged** across the migration.

### 3A.11 GC

Objects join blobs in the offline GC scope: alive = referenced by a retained
edition. This is an extension of the existing runbook (`RUNBOOK-MANDATE-GC`) —
append-only storage plus offline GC, no new primitive.

### 3A.12 New errors (v0.4)

| Code    | Name                              | When |
|---------|-----------------------------------|------|
| -32043  | `ethos_object_missing`            | A sha referenced by the manifest is neither uploaded nor carried. |
| -32044  | `ethos_object_hash_mismatch`      | An uploaded object/blob's content does not match its announced sha. |
| -32045  | `ethos_spec_version_regression`   | A v0.3 publish on a subject already migrated to v0.4. |
| -32046  | `ethos_keyring_forbidden`         | `keyring_sha` or `shard_count` changed outside an owner publish. |

These are also listed in the platform error table §10.9.

### 3A.13 What v0.4 does NOT change (locked perimeter)

The public API surface (`Ethos` / zones / sections / mandates / `sealGrant` /
`reseal` / `pruneWraps`), the scope grammar, the §11 envelopes, the edition
chain (`height` / `prev_hash`), content-addressed blobs, `did.json` + the
revocation epoch, the "`circle`/`self` bodies never leave the authenticated
channel" policy, and the anonymous/public semantics are all unchanged. The
security posture (gate / prune / rotate) is unchanged: the server remains the
instantaneous guard (mandate verified per request, fresh `did.json` for the
epoch, ConsistentRead on revocations), and rotation remains the rare, explicit
cryptographic act.

---

## 3.2 Layout (v0.2 historical annex)

> ⚠ **Historical annex — v0.2/v0.3.** §3.2–§3.10 describe the older whole-zone
> (v0.2) and per-section (v0.3) models. They are retained verbatim for dual-read
> and legacy verification. The **normative body is §3A** above. Per-section
> banners in this annex point to the §3A section that supersedes each part.

> ⚠ **v0.2 historical layout.** The single-file-per-zone layout below is the
> v0.2 monolithic form. v0.3 splits each zone into per-section blobs, and v0.4
> stores content-addressed objects under `ethos/{did}/objects/{sha}` referenced
> from an incremental manifest (§3A.1 / §3A.5). See the format status banner at
> the top of this chapter.

```
john-doe.ethos
├── manifest.json                     (UTF-8 JSON, §3.3)
├── did.json                          (signed DID document, chapter 1)
├── public.md                         (plaintext markdown, §2.6)
├── circle.md.enc                     (XChaCha20-Poly1305 ciphertext, §3.4)
├── self.md.enc                       (XChaCha20-Poly1305 ciphertext, §3.4)
├── signatures/
│   ├── <section_id>.json             (per-section revision signatures, §3.2.5)
│   └── …
└── README.txt                        (human-readable explanation, OPTIONAL)
```

### 3.2.1 Required entries

- `manifest.json` — the manifest, described in §3.3. REQUIRED.
- `did.json` — the subject's signed DID document, as produced by chapter 1. REQUIRED.
- `public.md` — the public zone in markdown form. REQUIRED even if empty (in which case it contains only a valid frontmatter).

### 3.2.2 Conditional entries

- `circle.md.enc` — REQUIRED if the bundle's manifest declares a non-empty circle zone.
- `self.md.enc` — REQUIRED if the bundle's manifest declares a non-empty self zone.

### 3.2.3 Optional entries

- `README.txt` — a short human-readable explanation of what the file is, safe to include so a curious recipient can understand what they have.

### 3.2.4 Forbidden entries

Conformant bundles MUST NOT include:

- Plaintext files for the `circle` or `self` zones (only their encrypted forms).
- Executable code of any kind.
- Symbolic links or other non-regular ZIP entries.

Readers MUST reject bundles that contain forbidden entries.

### 3.2.5 The `signatures/` directory

> **v0.2.0 transition note.** The per-section, per-revision signatures described below are a v0.1.x artifact. In v0.2.0 each section's signed history lives in the gamma log (§10) — every `section.add` / `section.modify` / `section.delete` entry in gamma carries its own Ed25519 signature, reachable from a section's `gamma_ref`. The bundle's `signatures/` directory in v0.2.0 therefore carries only zone signatures (one per zone) and MAY omit the `revisions[]` inner structure entirely. The full restructuring of this section ships with the verification refactor.

The `signatures/` directory carries the **full signature values** for each section's revisions. The bundle markdown files (§2.6) carry only short truncated signature prefixes in their HTML-comment metadata for human visual checks; the authoritative signatures are here.

Layout:

```
signatures/
├── sec_a1b2c3.json
├── sec_9f8e7d.json
└── …
```

Each file has the shape:

```json
{
  "aithos": "0.1.0",
  "section_id": "sec_a1b2c3",
  "zone": "public",
  "revisions": [
    {
      "revision": 1,
      "hash": "sha256:a8b2f1ef…",
      "signature_value": "p8RabcDEFabcDEFabcDEFabcDEFabcDEFabcDEFabcDEFabcDEFabcDEFabcDEF"
    },
    {
      "revision": 2,
      "hash": "sha256:d12e07bc…",
      "signature_value": "k7QabcDEF…"
    }
  ]
}
```

Readers reconstitute the full document-form revision objects (§2.5.1) by combining:

- The metadata in the zone's markdown body (revision number, date, prev_hash, hash, body).
- The `signature_value` field from `signatures/<section_id>.json`.
- The signing key identity (`did:aithos:z6Mkr…#<zone>`), derivable from the zone name plus the subject DID in the frontmatter.

## 3.3 The manifest

`manifest.json` is the single source of truth for what's in the bundle.

```json
{
  "aithos": "0.1.0",
  "bundle_id": "urn:aithos:john-doe:2026.04.19-1",
  "subject_did": "did:aithos:z6Mkr…",
  "subject_handle": "john-doe",
  "display_name": "John Doe",
  "edition": {
    "version": "2026.04.19-1",
    "created_at": "2026-04-19T08:14:23Z",
    "supersedes": "urn:aithos:john-doe:2026.04.10-1",
    "prev_hash": "sha256:b47c91ad4e20f6…",
    "height": 14
  },
  "zones": {
    "public": {
      "file": "public.md",
      "encrypted": false,
      "sha256_of_plaintext": "f3a8…",
      "section_titles": ["Identity", "Voice", "Tech stack", "Availability"],
      "signature": {
        "alg": "ed25519",
        "key": "did:aithos:z6Mkr…#public",
        "value": "m8K…"
      }
    },
    "circle": {
      "file": "circle.md.enc",
      "encrypted": true,
      "sha256_of_plaintext": "9b12…",
      "section_titles": ["Day rate", "Active projects", "Negotiation preferences"],
      "cipher": {
        "alg": "xchacha20poly1305-ietf",
        "nonce": "bK3x…",
        "wraps": [
          {
            "recipient": "did:aithos:z6Mkr…#circle-kex",
            "alg": "x25519-hkdf-sha256-aead",
            "ephemeral_public": "z6LSephemeralX25519…",
            "wrapped_key": "cP2r…"
          }
        ]
      },
      "signature": {
        "alg": "ed25519",
        "key": "did:aithos:z6Mkr…#circle",
        "value": "k7Q…"
      }
    },
    "self": {
      "file": "self.md.enc",
      "encrypted": true,
      "sha256_of_plaintext": "7fe0…",
      "section_titles": ["Testnet wallet", "Morning routine", "Reflections"],
      "cipher": { … same shape as circle … },
      "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#self", "value": "r9S…" }
    }
  },
  "integrity": {
    "sha256_of_did_json": "b24a…",
    "manifest_signature": {
      "alg": "ed25519",
      "key": "did:aithos:z6Mkr…#public",
      "value": "z9V…"
    }
  }
}
```

### 3.3.1 Field reference

| Field | Description |
|---|---|
| `aithos` | Protocol version. Matches §0.5. |
| `bundle_id` | URN of this bundle, identical to the ethos `id` in §2.2. |
| `subject_did` | Subject's root DID. |
| `subject_handle` / `display_name` | As in §2.3. |
| `edition` | Edition metadata. Shape per §2.4, extended with `prev_hash` (§3.3.3) and `height`. |
| `zones.<name>.file` | Name of the zone file within the zip. |
| `zones.<name>.encrypted` | Boolean. `false` for public, `true` for circle/self. |
| `zones.<name>.sha256_of_plaintext` | Hex SHA-256 of the markdown plaintext (UTF-8, no BOM, LF line endings). For encrypted zones, computed over the plaintext *before* encryption. Integrity check. |
| `zones.<name>.section_titles` | Array of section titles in order. For encrypted zones, this is a metadata leak — see §3.7. |
| `zones.<name>.cipher` | §3.4. Encrypted zones only. |
| `zones.<name>.signature` | Ed25519 signature over the canonical form of the zone document (§5.1.3), signed by the sphere key whose fragment matches the zone name. |
| `integrity.sha256_of_did_json` | Hex SHA-256 of `did.json` bytes. |
| `integrity.manifest_signature` | Signature over the canonical form of the manifest with `integrity.manifest_signature.value` replaced by `""`. Signed by the `#public` sphere key. |

### 3.3.2 Required vs. optional

All fields listed above are REQUIRED except `edition.supersedes` (MAY be `null` for the first edition), `edition.prev_hash` (MUST be `null` if and only if `edition.supersedes` is `null`), and `zones.<name>.section_titles` (MAY be `[]` for an empty zone).

### 3.3.3 The edition chain

`edition.prev_hash` is the SHA-256 of the **JCS-canonicalized form of the previous edition's manifest**, with `integrity.manifest_signature.value` replaced by `""` (i.e. the same canonical form used for signing the previous manifest).

The first edition has `prev_hash: null` and `height: 1`. Each subsequent edition has `height = prev.height + 1` and `prev_hash = sha256(canonical(prev.manifest_with_blank_sig))`.

This is the **per-edition spine** described in §2.8.2. Tampering with edition N's manifest causes any edition N+1 to fail validation: the verifier computes the hash of the (tampered) edition N and finds it does not match the `prev_hash` recorded in edition N+1.

Verifiers that have access to the chain SHOULD walk it to the genesis edition (`prev_hash == null`). Verifiers that have only one edition can still verify *that* edition's signatures and section chains; they simply cannot verify the inter-edition link without the prior bundle.

### 3.3.4 Genesis editions and chain breaks

A subject who needs to start a new chain — for example after a root-key compromise and migration to a new DID — produces a new **genesis edition** with `prev_hash: null` and `height: 1`. The break is visible to anyone walking the chain backward: the chain ends at a non-zero height with a `null` prev_hash.

A subject MAY include a `migrated_from` field when starting a new chain on a new identity, pointing to the URN of the last edition under the previous identity:

```json
"edition": {
  "version": "2027.01.01-1",
  "prev_hash": null,
  "height": 1,
  "migrated_from": "urn:aithos:john-doe:2026.12.30-3"
}
```

The `migrated_from` field is informative; it does not establish cryptographic continuity (which would require the old root key, which is presumed compromised). It does establish *narrative* continuity — a counterparty can see "this new identity claims to be a continuation of that old one."

## 3.4 Encryption of circle and self zones

> ⚠ **v0.2/v0.3 historical — superseded by §3A.2–§3A.4.** This section describes
> a **per-zone DEK** wrapped once per recipient in the manifest. The current
> model is v0.4 (§3A.2–§3A.4): each encrypted zone has **one 32-byte zone key**;
> the per-section DEK still encrypts the section body but is itself sealed
> **symmetrically** under the zone key (`enc_dek`, AAD bound to `section_id`),
> and the recipient wrap (§3.6) now applies to the **zone key** in the KeyRing
> rather than to a per-zone or per-section DEK.

Encrypted zones use **XChaCha20-Poly1305-IETF**, per the libsodium construction.

### 3.4.1 Procedure (author side)

For each non-public zone:

1. Produce the markdown form of the zone (§2.6).
2. Generate a fresh 32-byte **Data Encryption Key (DEK)** from a CSPRNG.
3. Generate a fresh 24-byte **nonce** from a CSPRNG.
4. Compute `ciphertext = XChaCha20-Poly1305.encrypt(key=DEK, nonce=nonce, aad="aithos-zone-v1\0" ‖ bundle_id, plaintext=markdown)`.
5. For each recipient (see §3.5), **wrap** the DEK (§3.6) and append a `wraps` entry.
6. Write the `ciphertext` to the zone file (e.g. `circle.md.enc`).
7. Record `cipher.nonce` (base64url of the 24-byte nonce) and the `wraps` array in the manifest.

### 3.4.2 Procedure (reader side)

For each non-public zone the reader is entitled to:

1. Iterate `wraps` looking for one whose `recipient` matches a DID URL fragment the reader holds the key for.
2. Unwrap the DEK using the reader's X25519 private key (§3.6).
3. Decrypt `ciphertext` with the recovered DEK and the nonce from `cipher.nonce`.
4. Verify `sha256(plaintext) == sha256_of_plaintext` from the manifest.
5. Verify the zone signature per §5.1.3.

A reader who cannot find a matching wrap MUST NOT attempt decryption and MUST report the zone as inaccessible.

### 3.4.3 AAD binding

The AEAD additional data MUST be `"aithos-zone-v1\0"` (the ASCII bytes, including the trailing NUL) followed by the UTF-8 encoding of the bundle's `bundle_id`. This binds the ciphertext to the bundle — it cannot be replayed into a different edition.

## 3.5 Recipients

> ⚠ **v0.2/v0.3 historical — superseded by §3A.4.** In v0.4 the recipient list
> lives in the per-zone **KeyRing** object (`{ kid, wraps[] }`, §3A.4), served
> only over the authenticated channel, and each `wrap` seals the **zone key**
> (not a DEK) once per recipient. A recipient granted a zone-scoped mandate
> opens **every** section of the zone through that single wrap; per-section
> (`#id=` / `#prefix=` / `#tag=`) grants instead go through **ExtraWraps**
> (per-section DEK wraps, bit-for-bit the v0.3 format). See §3A.3 / §3A.4 /
> §3A.8.

The `wraps` array lists every recipient that can decrypt the zone. Each recipient is identified by a DID URL fragment whose key is X25519.

### 3.5.1 Subject as recipient

The subject MUST be listed as a recipient of their own `circle` and `self` zones. For `circle`, the recipient is `did:aithos:z6Mkr…#circle-kex`. For `self`, it is `did:aithos:z6Mkr…#self-kex`.

This is not redundant: it means the subject can re-decrypt their own bundle on a fresh install of the CLI using only their keystore, without additional mandates.

### 3.5.2 Agent as recipient

An agent that has been granted a mandate (chapter 4) over a zone is a recipient *only if* the grant was a long-lived encryption-scope mandate (§4.5). Most mandates do not confer recipient status; they confer the right to request decrypted content from a server that holds the keys. Recipient status is the strongest form — it means the agent's key material is in the bundle forever.

Authors SHOULD avoid granting recipient status liberally; the more recipients, the larger the attack surface. A typical bundle has one (the subject) or two (the subject + a known partner) recipients on `circle`, and one (the subject) on `self`.

### 3.5.3 Adding and removing recipients

> ⚠ **Corrected by v0.4 — see §3A.9.** The paragraph below (v0.2/v0.3) claims
> that *adding a recipient requires re-encrypting the zone*. **This is no longer
> true.** In v0.4 (§3A.3 / §3A.4 / §3A.8 / §3A.9.4 / §3A.9.6):
> - **Adding a recipient (`sealGrant`, zone scope) is O(1)**: the author adds one
>   `wrap` of the **zone key** to the KeyRing. No new DEK, no new nonce, no body
>   re-encryption. (A per-section grant adds a DEK wrap to ExtraWraps, also O(1).)
> - **Hard revocation is a zone-key rotation** (`reseal({mode:"rotate"})`): a new
>   zone key is generated, the KeyRing is re-sealed to the still-active grants,
>   and every section's `enc_dek` is re-sealed symmetrically under the new zone
>   key — **the section bodies are left untouched, no blob is re-encrypted**. It
>   cuts the crypto path for future editions; real access is denied by the
>   server gate (bodies for `circle`/`self` never leave the authenticated
>   channel). Full cryptographic erasure of the bodies is the separate, opt-in
>   `reseal({mode:"rotate-deep"})`.

Adding a recipient requires re-encrypting the zone (new DEK, new nonce, all wraps regenerated). The old bundle remains readable by the old recipient set, forever — this is the reality of giving someone ciphertext. Removing a recipient is the same operation: a new edition with the ex-recipient omitted from the wraps. An author who needs to actually revoke prior access has no cryptographic path; they must accept that the data is out.

## 3.6 Key wrapping (X25519-HKDF-SHA256-AEAD)

> ⚠ **Still current, but re-targeted in v0.4 — see §3A.4.3.** The wrap
> construction below is unchanged and remains normative. In v0.4 it is applied
> to the **zone key** (in the KeyRing, over `jcs({kid, zone_key})`) rather than
> to a per-zone DEK; per-section DEK wraps in ExtraWraps use this exact same
> construction, bit-for-bit as in v0.3. See §3A.4.

To wrap a DEK for a given recipient:

1. Generate a fresh ephemeral X25519 key pair `(esk, epk)`.
2. Compute `shared = X25519(esk, recipient_pk)`.
3. Derive `wrap_key = HKDF-SHA256(ikm=shared, salt=utf8("aithos-wrap-v1"), info=utf8(recipient_did_url), length=32)`.
4. Generate a fresh 24-byte nonce.
5. Compute `wrapped = XChaCha20-Poly1305.encrypt(key=wrap_key, nonce=nonce, aad=utf8(recipient_did_url), plaintext=DEK)`.
6. Store in the manifest:
   ```json
   {
     "recipient": "did:aithos:z6Mkr…#circle-kex",
     "alg": "x25519-hkdf-sha256-aead",
     "ephemeral_public": "<multibase of epk>",
     "wrap_nonce": "<base64url of nonce>",
     "wrapped_key": "<base64url of wrapped>"
   }
   ```

Zero out `esk` and `shared` after use.

To unwrap:

1. Recompute `shared = X25519(recipient_sk, ephemeral_public)`.
2. Derive `wrap_key` as above.
3. Decrypt `wrapped` with `wrap_key`, `wrap_nonce`, and the same AAD. On success, the plaintext is the DEK.

## 3.7 Section-title metadata leak

The manifest lists, in clear, the section titles of every zone — including encrypted ones. A reader without the passphrase still knows "there is a section titled `Testnet wallets` in the self zone."

This is a **deliberate tradeoff** at v0.1.0:

- **For:** a server can index bundles, an agent can know in advance whether to bother requesting the circle zone, a curious counterparty can see the *shape* of your disclosure without forcing you to reveal content.
- **Against:** leaking that a subject maintains a section titled, say, `Burnout notes` in their self zone is itself information. A paranoid author may want the titles encrypted.

An opt-in "encrypted section index" is under consideration for v0.2. Until then, the rule is: **do not put sensitive words in your section titles.** Use anodyne titles like `Private notes` for everything you want opaque.

## 3.8 Integrity

A bundle is considered **valid** iff:

1. The ZIP file extracts without error.
2. `manifest.json` parses and validates against the JSON Schema.
3. `did.json` parses and its root signature verifies (§1.6.2).
4. `integrity.sha256_of_did_json` matches the actual SHA-256 of `did.json`'s bytes.
5. For each present zone, `sha256_of_plaintext` matches the decrypted content.
6. `integrity.manifest_signature` verifies against the `#public` sphere key, over the canonical form of the manifest with that `value` field blanked.
7. For each present zone, the **per-section hash chain** verifies as in §2.5.4.2, and each revision's signature verifies against the corresponding sphere key. The `signatures/<section_id>.json` side-files MUST agree with the metadata in the markdown body.
8. The **edition chain** check passes for this edition in isolation: `edition.prev_hash` is `null` iff `edition.supersedes` is `null`; `edition.height` is a positive integer.
9. If the verifier additionally has access to the predecessor edition, the SHA-256 of that predecessor's canonical manifest (with blank sig) MUST equal `edition.prev_hash` of the current edition.

A reader MUST reject a bundle that fails any of checks 1–8. A reader MAY skip check 9 if the predecessor is not available locally; in that case the inter-edition chain is unverified for this hop, and the reader SHOULD record the gap.

A reader MAY cache a successfully-validated bundle.

## 3.9 Size constraints (informative)

- A typical bundle is 10–100 KB.
- The protocol does not impose a size cap.
- Authors SHOULD keep bundles under 10 MB for practical transport. Anything larger suggests attached media belongs elsewhere.

## 3.10 Reading from a bundle (agent workflow)

The expected agent workflow:

1. Fetch the bundle (any transport, chapter 6).
2. Validate per §3.8.
3. For each zone the agent is entitled to (public always; circle/self per mandate or key possession), decrypt and parse.
4. Expose the resulting ethos document to the agent's runtime as context.

The reference MCP server at `Ethos-poc/mcp/` implements this workflow faithfully.

---

Next: [chapter 4 — Mandates](./04-mandates.md).
