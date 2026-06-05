# Draft · Bundle v0.3 — per-section encryption

> **Status:** Draft. Source of truth for the v0.3 bundle format. Not yet normative. Promotion target: `spec/03-bundle.md` on release, with v0.2 content moved to `spec/drafts/bundle-v0.2-archive.md`.
>
> **Scope.** This draft replaces §3.2, §3.3, §3.4, §3.5, §3.7, and §3.8 of the current bundle spec. Chapter 2 (ethos data model) is unaffected — sections themselves are unchanged. Chapter 4 (mandates) is unaffected; the section-level mandate scopes that this format enables are specified in a separate companion draft (`bundle-v0.3-section-level-mandates.md`).
>
> **Coordination.** v0.3 of the protocol bundles two encryption changes that are independent but ship together: this draft (per-section encryption of the bundle) and `gamma-v0.3-per-entry-envelopes.md` (per-entry envelopes in the gamma log). Implementations MUST roll out both to claim v0.3 conformance.

## Motivation

v0.2 encrypts each non-public zone (`circle`, `self`) as a single ciphertext file (`circle.md.enc`, `self.md.enc`) under a single zone DEK. Any mutation — a one-character edit to a single section, an append, a deletion — requires the author to fetch the full zone ciphertext, decrypt, rebuild the markdown, generate a fresh DEK and nonce, re-encrypt the entire zone, regenerate every recipient's wrap, and re-upload. The cost scales with the **size of the whole zone**, not with the size of the change.

For capture-heavy use cases (an email agent appending one section per inbound message, a calendar agent appending one section per event, a notes agent appending freely), the cost becomes prohibitive past a few thousand sections. A subject with 1000 captured emails (~4 MB markdown plaintext) pays ~5.4 MB of base64 payload on every append, every key rotation, every modification anywhere in the zone — even when the change touches a single section.

v0.3 splits **every** zone — `public`, `circle`, `self` — into independently-addressed **per-section blobs**. The zone is no longer a single file; it is a **collection** of per-section files whose ordering, identity, and integrity metadata live in the manifest. For `circle` and `self`, each per-section blob is an XChaCha20-Poly1305 ciphertext under a fresh per-section DEK. For `public`, each per-section blob is plaintext markdown — encryption serves no purpose on a zone that is public by design, but section-level addressability does. Modifying section X rewrites only section X's blob. Adding section Y appends one new blob file and one new manifest entry. The cost of a mutation scales with the size of the section it touches, not with the size of the zone.

The uniform v2 layout across all three zones is a deliberate design choice. It means a single code path handles every zone (with an `encrypted: bool` flag at zone level deciding whether the AEAD layer runs), and operational requirements — payload size on RPC, request latency, partial-fetch capability via MCP — are met symmetrically for `public`, `circle`, and `self`.

The change is invisible to the ethos data model (chapter 2): sections continue to carry the same fields (`id`, `title`, `body`, `tags`, `gamma_ref`). It is visible at the bundle layer: the `manifest.zones.<name>` schema gains a `format_version` discriminator and a `sections[]` list of per-section metadata.

## 3.2′ Bundle layout (revised)

A v0.3 bundle is a ZIP archive with the `.ethos` extension, exactly as in v0.2 (§3.2 of the current spec). The internal layout is uniform across all three zones, with encrypted zones using `.enc` files and the public zone using `.md` files:

```
john-doe.ethos
├── manifest.json                     (UTF-8 JSON, §3.3′)
├── did.json                          (signed DID document, chapter 1)
├── public/
│   ├── sec_identity.md               (one plaintext file per section)
│   ├── sec_voice.md
│   └── …
├── circle/
│   ├── sec_a1b2c3.enc                (one ciphertext file per section)
│   ├── sec_9f8e7d.enc
│   └── …
├── self/
│   ├── sec_2d4f6e.enc
│   └── …
├── gamma/
│   └── gamma.jsonl.enc               (gamma log — see gamma-v0.3 draft)
└── README.txt                        (OPTIONAL, unchanged)
```

### 3.2.1′ Required entries

- `manifest.json` — REQUIRED. §3.3′.
- `did.json` — REQUIRED. Unchanged from v0.2.

### 3.2.2′ Conditional entries

- `public/<section_id>.md` — REQUIRED for every section listed in `manifest.zones.public.sections[]`. Plaintext UTF-8 markdown (no BOM, LF line endings).
- `circle/<section_id>.enc` — REQUIRED for every section listed in `manifest.zones.circle.sections[]`. XChaCha20-Poly1305 ciphertext per §3.4′.
- `self/<section_id>.enc` — REQUIRED for every section listed in `manifest.zones.self.sections[]`. XChaCha20-Poly1305 ciphertext per §3.4′.

A zone with zero sections has no subdirectory; its `manifest.zones.<name>.sections` is `[]`.

### 3.2.3′ Forbidden entries

Conformant v0.3 bundles MUST NOT include:

- `public.md`, `circle.md.enc`, `self.md.enc` (the v0.2 monolithic forms). A v0.3 bundle MUST use the per-section directory layout. Mixed bundles are rejected.
- Encrypted files (`.enc`) inside the `public/` directory, or plaintext markdown files (`.md`) inside `circle/` or `self/` (the encryption choice is fixed per zone — see §3.4.5′).
- Section files whose `<section_id>` is not listed in the manifest (orphan files).
- Symbolic links, executable code, or other non-regular ZIP entries.

### 3.2.4′ Section file naming

A section's blob file is named `<zone>/<section_id>.<ext>` where `<ext>` is `md` for the `public` zone and `enc` for `circle` and `self`. The `section_id` MUST match the corresponding entry in `manifest.zones.<zone>.sections[].section_id` exactly. Readers MUST verify this match before reading or decrypting.

### 3.2.5′ Removed: the `signatures/` directory

The v0.2.0 transition note in the current §3.2.5 already moved per-revision signatures into the gamma log. v0.3 completes the move: the `signatures/` directory is no longer part of the bundle layout. Authorship signatures for each section's mutations live in gamma (§10), keyed by `gamma_ref`. The bundle's per-section integrity is committed by the manifest signature (§3.3′ + §3.8′).

## 3.3′ The manifest (revised)

`manifest.json` remains the single source of truth for what's in the bundle. The shape changes for all three zones, which now share the v2 per-section schema.

```json
{
  "aithos": "0.3.0",
  "bundle_id": "urn:aithos:john-doe:2026.05.10-1",
  "subject_did": "did:aithos:z6Mkr…",
  "subject_handle": "john-doe",
  "display_name": "John Doe",
  "edition": {
    "version": "2026.05.10-1",
    "created_at": "2026-05-10T08:14:23Z",
    "supersedes": "urn:aithos:john-doe:2026.05.03-1",
    "prev_hash": "sha256:b47c91ad4e20f6…",
    "height": 14
  },
  "zones": {
    "public": {
      "format_version": "v2",
      "encrypted": false,
      "sections": [
        {
          "section_id": "sec_identity",
          "title": "Identity",
          "file": "public/sec_identity.md",
          "sha256_of_plaintext": "f3a8…",
          "gamma_ref": "gamma_01J…",
          "tags": ["bio"]
        },
        {
          "section_id": "sec_voice",
          "title": "Voice",
          "file": "public/sec_voice.md",
          "sha256_of_plaintext": "e4d1…",
          "gamma_ref": "gamma_01J…"
        }
      ]
    },
    "circle": {
      "format_version": "v2",
      "encrypted": true,
      "sections": [
        {
          "section_id": "sec_a1b2c3",
          "title": "Day rate",
          "file": "circle/sec_a1b2c3.enc",
          "sha256_of_plaintext": "9b12…",
          "cipher": {
            "alg": "xchacha20poly1305-ietf",
            "nonce": "bK3x…",
            "wraps": [
              {
                "recipient": "did:aithos:z6Mkr…#circle-kex",
                "alg": "x25519-hkdf-sha256-aead",
                "ephemeral_public": "z6LS…",
                "wrap_nonce": "…",
                "wrapped_key": "cP2r…"
              }
            ]
          },
          "gamma_ref": "gamma_01J…",
          "tags": ["pricing"]
        },
        {
          "section_id": "sec_9f8e7d",
          "title": "Active projects",
          "file": "circle/sec_9f8e7d.enc",
          "sha256_of_plaintext": "7a09…",
          "cipher": { "alg": "xchacha20poly1305-ietf", "nonce": "…", "wraps": [ … ] },
          "gamma_ref": "gamma_01J…"
        }
      ]
    },
    "self": {
      "format_version": "v2",
      "encrypted": true,
      "sections": [
        {
          "section_id": "sec_2d4f6e",
          "title": "Morning routine",
          "file": "self/sec_2d4f6e.enc",
          "sha256_of_plaintext": "7fe0…",
          "cipher": { "alg": "xchacha20poly1305-ietf", "nonce": "…", "wraps": [ … ] },
          "gamma_ref": "gamma_01J…"
        }
      ]
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

### 3.3.1′ `format_version` discriminator

Every zone entry carries a `format_version` field that selects the schema for the rest of that zone's manifest entry:

- `"v1"` — the v0.2 zone-monolithic shape (single `file`, optional `cipher`, optional `signature`). Permitted only via the compat read path (§3.10.2′) when reading a v0.2 bundle.
- `"v2"` — the v0.3 per-section shape (this draft). REQUIRED for all three zones in v0.3 bundles.

A v0.3 bundle MUST set `aithos: "0.3.0"` at the top level and MUST set `format_version: "v2"` for every zone in `manifest.zones`. A v0.3 reader encountering `format_version: "v1"` on any zone within a `aithos: "0.3.0"` bundle MUST reject the bundle as malformed. The v0.2 compat path applies only when the top-level `aithos` field is `"0.1.x"` or `"0.2.x"`.

### 3.3.2′ Field reference for `format_version: "v2"` zone entries

The schema is unified across `public`, `circle`, and `self`. The only zone-level discriminator is the boolean `encrypted` flag, which gates the presence of the per-section `cipher` field.

| Field | Type | Description |
|---|---|---|
| `format_version` | string | `"v2"`. REQUIRED. |
| `encrypted` | boolean | `false` for `public`, `true` for `circle` and `self`. REQUIRED. Fixed per zone identity — implementations MUST reject any other combination. |
| `sections` | array | Ordered list of section descriptors (below). REQUIRED. MAY be `[]`. |
| `sections[].section_id` | string | Stable section identifier per §2.5.1. REQUIRED. Unique within the zone. |
| `sections[].title` | string | Section title in clear. REQUIRED. Inherits the metadata-leak tradeoff of §3.7′. |
| `sections[].file` | string | Path to the section blob within the bundle, of the form `<zone>/<section_id>.md` (when zone-level `encrypted: false`) or `<zone>/<section_id>.enc` (when zone-level `encrypted: true`). REQUIRED. |
| `sections[].sha256_of_plaintext` | string | Hex SHA-256 of the section's plaintext markdown body (UTF-8, no BOM, LF line endings). For encrypted zones, computed before encryption; for `public`, computed directly over the on-disk file bytes (which are the plaintext). REQUIRED. |
| `sections[].cipher` | object | Per-section AEAD parameters (§3.4′) — `alg`, `nonce`, `wraps`. REQUIRED when zone-level `encrypted: true`. MUST be absent when zone-level `encrypted: false`. |
| `sections[].gamma_ref` | string | The gamma entry id that produced this section's current state. REQUIRED. Same semantics as §10.7. |
| `sections[].tags` | array of strings | OPTIONAL. Same shape as §2.5.1's section `tags`. |

Section ordering within `sections[]` is the canonical display order. Readers that present sections to a user SHOULD respect this order; verifiers SHOULD NOT rely on it for any chain check (gamma is the chain-of-custody record).

### 3.3.3′ Removed: per-zone signature

The v0.2 `zones.<name>.signature` field is removed. Per-section content is signed by the responsible sphere key in gamma, addressable via `gamma_ref`. The manifest's `integrity.manifest_signature` (signed by `#public`) commits to every section's `(section_id, file, sha256_of_plaintext, cipher.nonce)` via the canonical manifest hash, which is sufficient to detect bundle-layer tampering.

A future minor revision MAY add an optional `zones.<name>.zone_signature` if real-world verifiers need a zone-key attestation independent of gamma; the field is reserved but not used in v0.3.

### 3.3.4′ The edition chain

Unchanged from v0.2 §3.3.3. `edition.prev_hash` is the SHA-256 of the JCS-canonicalized form of the previous edition's manifest with `integrity.manifest_signature.value = ""`. The first edition has `prev_hash: null` and `height: 1`.

The canonicalization input expands with the v2 schema (each section's `cipher.wraps[].ephemeral_public` and `wrapped_key` are now per-section, not per-zone). Implementations MUST canonicalize by emitting the manifest object via JCS (RFC 8785) — no implementation-specific shortcuts.

## 3.4′ Encryption of sections (revised)

Each section in an **encrypted** zone (`circle`, `self`) is its own AEAD ciphertext. The construction is identical to v0.2's zone encryption (§3.4 current), applied at section grain. Sections in the `public` zone are stored as plaintext markdown files and follow §3.4.5′ instead.

### 3.4.1′ Procedure (author side, encrypted zones)

For each section `S` in an encrypted zone `Z`:

1. Produce the markdown form of the section's body: title (as `# <title>` or `## <title>` per §2.6), body, optional tags frontmatter. Canonicalize as UTF-8, no BOM, LF.
2. Generate a fresh 32-byte **per-section DEK** from a CSPRNG. **Each section gets its own DEK.**
3. Generate a fresh 24-byte **nonce** from a CSPRNG.
4. Compute:
   ```
   ciphertext = XChaCha20-Poly1305.encrypt(
     key   = section_DEK,
     nonce = nonce,
     aad   = "aithos-section-v1\0" ‖ subject_did ‖ "\0" ‖ section_id,
     plaintext = section_markdown
   )
   ```
5. For each recipient of zone `Z` (see §3.5′), wrap the section DEK using the X25519-HKDF-SHA256-AEAD construction of §3.6 (unchanged) and append a `wraps` entry to `sections[i].cipher.wraps`.
6. Write `ciphertext` to `<zone>/<section_id>.enc` inside the bundle ZIP.
7. Record `nonce` and `wraps` in `manifest.zones.<zone>.sections[i].cipher`.

### 3.4.2′ Procedure (reader side, encrypted zones)

For each section in an encrypted zone the reader is entitled to:

1. Locate `manifest.zones.<zone>.sections[i]` for the desired `section_id`.
2. Iterate `sections[i].cipher.wraps` looking for one whose `recipient` matches a DID URL fragment the reader holds the X25519 private key for.
3. Unwrap the per-section DEK using the reader's X25519 private key (§3.6 unchanged).
4. Read the ciphertext file at `sections[i].file`.
5. Decrypt with the recovered DEK, the nonce from `sections[i].cipher.nonce`, and the AAD specified in §3.4.3′.
6. Verify `sha256(plaintext) == sections[i].sha256_of_plaintext`.
7. Verify the section's authorship via gamma: dereference `sections[i].gamma_ref`, check the gamma entry's signature, and check that the entry's `payload` (`title`, `body`, `tags`) matches the decrypted plaintext.

A reader who cannot find a matching wrap MUST NOT attempt decryption of that section and MUST report the section as inaccessible. A reader MAY decrypt some sections of a zone while being unable to decrypt others — section-grain access is a design feature of v0.3.

### 3.4.3′ AAD binding

The AEAD additional data MUST be:

```
"aithos-section-v1\0" ‖ utf8(subject_did) ‖ "\0" ‖ utf8(section_id)
```

(ASCII bytes for the literal prefix, including the trailing NUL after both `v1` and `subject_did`; UTF-8 for `subject_did` and `section_id`).

This binds the ciphertext to **both** the subject (resists replay into a different subject's bundle) **and** the specific section_id (resists swapping ciphertexts between sections within the same bundle).

**Why `subject_did` and not `bundle_id`.** An earlier draft of this section bound the AAD to `bundle_id`. But `bundle_id` is *per-edition* (`urn:aithos:<handle>:<edition>`), so binding it into the AAD would force every section's ciphertext to change on every edition — re-encrypting the entire zone on each edit and defeating the per-section cost property that motivates v0.3 (it would make test B3 unsatisfiable). `subject_did` is stable across editions, so an unchanged section carries forward **byte-identical** (B3 / B14). Cross-*edition* replay resistance is not the AAD's job here: it is already provided by the signed manifest and the `edition.prev_hash` chain (§3.3.4′ / §3.8′), which commit to exactly which section ciphertext belongs to which edition. The AAD's remaining duties — cross-*subject* and cross-*section* binding — are both met by `subject_did ‖ section_id`. The v0.2 AAD `"aithos-zone-v1\0" ‖ subject_did` is replaced by this section-grained variant; the prefix label changes to `"aithos-section-v1"` to make accidental cross-version reuse fail loudly.

### 3.4.4′ Per-section DEK independence

Each section's DEK is independent. Compromise of one section's DEK exposes that section only; other sections in the same zone remain opaque. This is a strict improvement over v0.2's shared-zone DEK, where a leaked DEK exposes every section in the zone.

Authors SHOULD NOT derive section DEKs from a master zone key (no HKDF-from-zone-master construction). The per-section DEKs are independent random secrets, sealed individually to recipients. This rules out a class of "give me one DEK and I unlock all sections" attacks.

### 3.4.5′ Plaintext sections in the `public` zone

Sections in the `public` zone are not encrypted. Each section's body is written verbatim to `public/<section_id>.md` as UTF-8 markdown (no BOM, LF line endings). The file content is the canonicalized markdown form of the section per §2.6, which begins with the title heading and contains the body and optional tags frontmatter — same canonicalization as the plaintext that an encrypted-zone section would feed into XChaCha20-Poly1305 in §3.4.1′ step 1.

Author side: write the canonical markdown to `public/<section_id>.md`, compute SHA-256, record `sections[i].sha256_of_plaintext` in the manifest, omit the `cipher` field.

Reader side: read `public/<section_id>.md` directly, verify `sha256(file_bytes) == sections[i].sha256_of_plaintext`, parse the markdown.

Public sections require no AAD (no AEAD), no DEK, no wraps. The `cipher` field MUST be absent. Per-section integrity is committed by the manifest signature (which covers `sections[i].sha256_of_plaintext`) and authorship by the gamma entry at `sections[i].gamma_ref`.

The benefit of the per-section layout for `public` is purely operational: a writer modifying one public section uploads one small markdown file rather than the entire `public.md`; a reader fetching a single public section via MCP `ethos.fetch_section` retrieves one small markdown file rather than the whole zone. The threat model on the public zone is unchanged from v0.2 (everything was always public).

## 3.5′ Recipients (revised)

Recipients apply only to encrypted zones (`circle`, `self`). The `public` zone has no recipient list since its content is unencrypted.

The `wraps` array attached to **each section** in an encrypted zone lists the recipients who can decrypt that section. Each recipient is identified by a DID URL fragment whose key is X25519, exactly as in v0.2 §3.5.

### 3.5.1′ Subject as recipient

The subject MUST be a recipient of every section in their `circle` and `self` zones. For sections in `circle`, the recipient is `did:aithos:z6Mkr…#circle-kex`. For sections in `self`, it is `did:aithos:z6Mkr…#self-kex`.

This preserves the v0.2 property that the subject can re-decrypt their own bundle on a fresh install of the CLI using only their keystore.

### 3.5.2′ Agent as recipient

An agent that has been granted a recipient-conferring mandate over a zone MAY be added to the `wraps` of every section in that zone. Most mandates do NOT confer recipient status — see §4.5 (unchanged) and the companion section-level mandates draft for the v0.3 vocabulary that allows an agent to be a recipient of a **subset** of sections in a zone (e.g. only the `gmail:*` sections of `self`).

### 3.5.3′ Adding and removing recipients

Adding a recipient to all sections of a zone requires re-encrypting every section: each section's DEK is rotated, each section's wraps regenerated, each section's ciphertext re-uploaded. The cost is N × (per-section cost), which is at most the cost of v0.2's whole-zone re-encryption — and typically far less, since the per-section nonces are independent and the work parallelizes.

Adding a recipient to a **single section** (e.g. via a section-scoped mandate) requires re-encrypting just that one section. This is the use case that motivates per-section DEKs in the first place.

Removing a recipient is the same operation: a new edition with the ex-recipient omitted from the relevant sections' `wraps`. Old ciphertexts cached by the ex-recipient remain readable to them forever; this is the unavoidable forward-only nature of symmetric AEAD.

## 3.7′ Metadata leak (revised)

v0.3 increases the metadata leak surface relative to v0.2 **for the encrypted zones only**. The `public` zone's content was already public in v0.2; per-section addressing on `public` adds no privacy regression because the underlying material was never private.

For `circle` and `self`, the manifest now exposes, in clear, for every section:

1. The **section title** (already leaked in v0.2 — see v0.2 §3.7).
2. The **section count** per zone (newly visible: a v0.2 zone is one opaque blob, while a v0.3 zone announces N sections).
3. The **per-section ciphertext size** (newly visible: a v0.3 reader can size each `<zone>/<section_id>.enc`, where in v0.2 only the total zone ciphertext size was visible).
4. The **per-section recipient set** (newly visible at section grain: a v0.3 reader sees that section X is wrapped to two recipients while section Y is wrapped to one).
5. The **per-section gamma_ref** (newly visible: links each section to its most recent mutation in the gamma log).

Items 2–5 are net-new leaks for encrypted zones compared to v0.2. The author tradeoff arguments from v0.2 §3.7 still apply (server-side indexing, agent-side pre-flight decisions, counterparty visibility into the *shape* of disclosure), and now apply at section grain. Authors who want minimal metadata exposure on `circle` and `self` should:

- Continue using anodyne section titles per v0.2 advice.
- Be aware that a section's size is visible. A "very long section" or a "very short section" is itself a signal.
- Be aware that a section's recipient list is visible. Granting a delegate access to one specific section reveals that one specific section was singled out.

The v0.2 open question about an opt-in encrypted section index becomes more salient in v0.3: with section-grain metadata on encrypted zones, the case for hiding the index increases. Specification of an opt-in encrypted manifest variant for `circle` / `self` is deferred to v0.4 and tracked in §3.13′ Open questions.

## 3.8′ Integrity (revised)

A v0.3 bundle is considered **valid** iff:

1. The ZIP file extracts without error.
2. `manifest.json` parses and validates against the v0.3 JSON Schema (TBD; reference implementation pins it).
3. `did.json` parses and its root signature verifies (§1.6.2 unchanged).
4. `integrity.sha256_of_did_json` matches the actual SHA-256 of `did.json`'s bytes.
5. `integrity.manifest_signature` verifies against the `#public` sphere key, over the JCS-canonicalized form of the manifest with that `value` field blanked.
6. For every zone with `format_version: "v2"`:
   - For every section listed in `sections[]`, the file `<zone>/<section_id>.<ext>` exists in the ZIP (where `<ext>` is `md` for `public`, `enc` for `circle` / `self`).
   - For every file under `<zone>/` in the ZIP, a corresponding section is listed in `sections[]` (no orphan files).
   - For sections in the `public` zone: `sha256(file_bytes) == sections[i].sha256_of_plaintext`. Mismatch MUST FAIL verification.
   - For sections in encrypted zones, where the verifier can decrypt: `sha256(decrypted_plaintext) == sections[i].sha256_of_plaintext`.
   - For sections in encrypted zones, where the verifier cannot decrypt (no matching wrap): the section is treated as opaque-but-attested. Verification of (a) the manifest signature and (b) the file's existence at the declared path is enough to vouch for the bundle's structural integrity.
7. The **edition chain** check passes for this edition in isolation: `edition.prev_hash` is `null` iff `edition.supersedes` is `null`; `edition.height` is a positive integer.
8. If the verifier additionally has access to the predecessor edition, the SHA-256 of that predecessor's canonical manifest (with blank sig) MUST equal `edition.prev_hash` of the current edition.
9. If the verifier additionally has access to the gamma log: for every section, `sections[i].gamma_ref` resolves to a gamma entry whose `payload` reproduces the section's current state. (Cross-check between bundle snapshot and gamma chain.)

A reader MUST reject a bundle that fails any of checks 1–7. A reader MAY skip checks 8 and 9 if the predecessor edition or the gamma log is not available locally; in that case the inter-edition chain or the bundle/gamma cross-check is unverified for this hop, and the reader SHOULD record the gap.

A reader MAY cache a successfully-validated bundle.

A reader MAY validate a single section (decrypt + hash check) without validating the rest, provided check 5 (manifest signature) is performed first. **This is a v0.3 capability that v0.2 cannot offer**: the manifest signature transitively vouches for every section's `sha256_of_plaintext`, so once the manifest is valid, each section can be verified individually.

## 3.10′ Migration v0.2 → v0.3

### 3.10.1′ Versioning at the bundle level

A v0.3 bundle declares `aithos: "0.3.0"` at the manifest top level. A v0.2 bundle declares `aithos: "0.1.x"` or `"0.2.x"`. Implementations dispatch on this top-level marker before reading any zone.

### 3.10.2′ Compat read path for v0.2 bundles

A v0.3 reader MUST accept v0.2 bundles for read. Procedure:

1. Detect `aithos: "0.1.x"` or `"0.2.x"` at the manifest top level.
2. Read the public zone from the v0.2 monolithic `public.md` file. Verify hash and signature per v0.2 rules.
3. For each encrypted zone, locate `<zone>.md.enc` (v0.2 monolithic file).
4. Apply the v0.2 §3.4.2 procedure: unwrap the zone DEK from `manifest.zones.<zone>.cipher.wraps`, decrypt the whole zone, parse the markdown into sections.
5. Verify per-zone hash and signature per v0.2 §3.8.

A v0.3 reader MUST NOT treat a v0.2 bundle as authoritative for new writes — see §3.10.3′.

### 3.10.3′ One-shot migration on first write

The first author-side write against a v0.2 bundle under a v0.3 runtime triggers a **migration edition**: the runtime parses each v0.2 zone (decrypting `circle` and `self`, reading `public.md` directly), splits each into per-section blobs, generates fresh per-section DEKs for the encrypted zones, writes plaintext markdown files for the public zone, builds the v0.3 manifest with `format_version: "v2"` for all three zones, and publishes a new edition.

The migration edition:

- Carries `aithos: "0.3.0"` and per-zone `format_version: "v2"`.
- Carries `edition.supersedes` pointing to the predecessor v0.2 edition.
- Carries `edition.prev_hash` computed via the v0.3 canonicalization.
- Carries one `gamma` entry recording the migration, op `bundle.migrate.v0.3` (gamma op vocabulary update tracked separately; see gamma-v0.3 draft).

After the migration edition, all subsequent writes use the v0.3 per-section path. The v0.2 predecessor remains in the edition chain as historical record; readers walking the chain backwards transition from v0.3 reads to v0.2 reads at that hop.

A subject MAY trigger migration administratively (without an actual content change) by issuing a no-op edition. The CLI exposes this as `aithos ethos migrate-to-v0.3`. This is the recommended path for subjects who want to be on v0.3 even before the next natural edit.

### 3.10.4′ No automated bulk migration of historical editions

v0.3 does not re-encrypt past editions. A subject who has published 50 editions in v0.2 retains those 50 editions as v0.2 ciphertext in their archive. Only forward editions (post-migration) are v0.3. This avoids re-issuing 50 sphere-key signatures and respects the property that past editions are evidence of what was published when, in their original form.

A reader walking the edition chain MUST be prepared to dispatch per-edition: v0.3 for editions after the migration, v0.2 for editions before.

## 3.11′ Threat model diff from v0.2

The diff applies to all three zones for cost properties; metadata visibility changes apply to encrypted zones only (the public zone's metadata was always public).

| Property | v0.2 | v0.3 |
|---|---|---|
| Cost of editing one section (any zone) | O(zone size) | O(section size) |
| Cost of fetching one section via MCP / API (any zone) | O(zone size) | O(section size) |
| DEK leak blast radius (`circle`, `self`) | All sections of the zone | The single leaked section |
| Server visibility — section count per zone (`circle`, `self`) | Hidden (one opaque blob) | **Visible** (manifest lists sections) |
| Server visibility — per-section size (`circle`, `self`) | Hidden | **Visible** (one ciphertext file per section) |
| Server visibility — per-section recipient set (`circle`, `self`) | Identical across zone | **Visible** per section |
| Server visibility — `public` zone | Already fully visible in v0.2 | Already fully visible in v0.3 (no regression) |
| Section-grain access control (one delegate, one section) | Not expressible (zone-grain only) | **Expressible** (per-section wraps on `circle` / `self`) |
| Authorship of a section's current state | v0.2 zone signature + per-section gamma | gamma alone (zone signature removed in §3.3.3′) |
| Replay of a ciphertext into another subject's bundle | AAD binds subject_did | AAD binds subject_did **and** section_id |
| Replay of a section ciphertext into a different section_id within the same bundle | Implicitly possible (no section AAD binding) | **Prevented** (AAD includes section_id) |
| Replay of a section ciphertext across editions of the *same* subject | N/A (whole-zone re-encrypt each edition) | Permitted by design — carried-forward sections are byte-identical (B3); edition provenance is committed by the manifest signature + `prev_hash` chain, not the AAD |

Net: granular cost and granular blast radius are gained on every zone; server-side metadata visibility increases on encrypted zones only by the items listed above. The increase is documented and the mitigation (anodyne titles, opt-in encrypted manifest planned for v0.4) is explicit.

## 3.12′ Test matrix (spec-bound)

Every conformant v0.3 implementation MUST satisfy:

| Test | Assertion |
|---|---|
| B1 — v0.3 round trip, single section | Author creates a bundle with one self section; per-section DEK fresh; ciphertext at `self/<id>.enc`; manifest signature verifies; reader decrypts and checks hash. |
| B2 — v0.3 round trip, many sections | 100 sections in self; each has independent DEK and nonce; reader decrypts all; per-section AADs distinct. |
| B3 — Single-section edit cost | Modifying section 5 of 100 rewrites only `self/sec_5.enc` and updates only `manifest.zones.self.sections[4].sha256_of_plaintext`, `cipher.nonce`, `cipher.wraps`, `gamma_ref`. All other sections' ciphertexts are byte-identical to the prior edition. |
| B4 — Cross-section AAD binding | Swapping `self/sec_A.enc` and `self/sec_B.enc` (same zone, different sections) makes both fail to decrypt: AAD mismatch on `section_id`. Verify MUST FAIL. |
| B5 — Cross-subject AAD binding | Copying a section ciphertext into a **different subject's** bundle fails to decrypt: the AAD binds `subject_did`, so a re-homed ciphertext fails the AEAD tag even when the recipient wrap still resolves. (Copying a ciphertext into another *edition of the same subject* is legitimate carry-forward and MUST still decrypt — that is what B3 asserts.) |
| B6 — Manifest tampering | Any byte change to `manifest.json` invalidates the manifest signature; verify MUST FAIL. |
| B7 — Orphan ciphertext | A bundle containing `self/sec_X.enc` not listed in `manifest.zones.self.sections[]` MUST FAIL §3.8′ check 6. |
| B8 — Missing ciphertext | A manifest entry for `sec_Y` whose corresponding file is absent from the ZIP MUST FAIL §3.8′ check 6. |
| B9 — v0.2 compat read | A v0.2 bundle is opened by a v0.3 reader, all zones decrypt and verify per v0.2 rules. |
| B10 — Migration round trip | A v0.2 bundle is migrated to v0.3 via §3.10.3′; the migration edition's `edition.supersedes` and `edition.prev_hash` cross-validate; subsequent v0.3 writes succeed. |
| B11 — Section-grain partial read | A reader holding a wrap for section X but not section Y of the same zone successfully decrypts X and reports Y as inaccessible. No error on Y propagates to break X. |
| B12 — Independence of section DEKs | Compromise (or disclosure) of section X's DEK does NOT decrypt section Y. Tested by manually leaking one section's DEK and asserting other sections remain opaque. |
| B13 — Public zone v2 round trip | Author writes 5 public sections; each at `public/sec_*.md`; manifest carries `format_version: "v2"`, `encrypted: false`, no `cipher` field; reader fetches one section file directly and verifies its hash. |
| B14 — Public single-section edit | Modifying one public section rewrites only `public/<section_id>.md` and its manifest entry; other public sections' files are byte-identical to the prior edition. |
| B15 — Forbidden cipher on public | A v0.3 manifest with `zones.public.encrypted: true` or with a `cipher` field on a public section MUST FAIL §3.3.2′ schema validation. |

Implementations SHOULD publish test vectors for B1–B15 alongside their v0.3 release.

## 3.13′ Open questions

- **Encrypted manifest opt-in.** With v0.3's increased metadata leak surface (section count, per-section sizes, per-section recipients), the case for an opt-in encrypted manifest variant is stronger. A v0.4 candidate: a `manifest.outer.json` carrying only `aithos`, `bundle_id`, `subject_did`, and an encrypted `manifest.inner.enc` whose plaintext is the full v0.3 manifest. Out of scope for v0.3.
- **Per-section signatures.** §3.3.3′ removes the per-zone signature in favor of manifest signature + gamma authorship. Some verifiers may prefer an offline-from-gamma authorship check at section grain. The reserved `zones.<name>.zone_signature` slot is a placeholder; concrete shape and signing key (per-section sphere signature? per-zone aggregate signature over the section list?) is open.
- **Diff payloads in gamma `section.modify`.** §2.9 already tracks this: gamma entries currently carry the full new body. With per-section bundle ciphertexts, the gamma log is the only place where multi-MB section bodies still get re-stated in full on every edit. Diff/patch payloads in gamma become more attractive, but are independent of this draft.
- **Compaction of section ciphertexts within the ZIP.** ZIP per-entry overhead is small but not zero (~30 bytes per entry header, plus compression dictionaries). For bundles with thousands of sections, a sidecar storage format (e.g. a single `sections.dat` with offset table) MAY become preferable. Out of scope for v0.3; revisit if real-world bundle sizes warrant it.

## Sequencing of the implementation

In `packages/protocol-core` and `packages/cli`:

1. Bump the `aithos` version constant to `"0.3.0"` and add a `format_version` field to the zone-manifest TypeScript types.
2. Introduce `BundleZoneV2` type in `bundle.ts` alongside the existing v0.2 type; the encoder and decoder dispatch on `format_version`. The same v2 type is used for `public`, `circle`, and `self`, with the `encrypted` boolean gating the AEAD layer.
3. Implement a unified `writeSection(zone, section, plaintext)` and `readSection(zone, section)` whose inner branch on `zone.encrypted` chooses between (a) write/read the markdown file directly (public path) and (b) encrypt/decrypt with per-section DEK and AAD per §3.4 (encrypted path).
4. Update `buildManifest` to emit the v2 zone schema with per-section metadata for all three zones; manifest canonicalization tested against B6.
5. Update `verifyBundle` to implement §3.8′ checks 1–9; partial-decrypt path for B11; plaintext hash check on public sections per B13.
6. Implement the v0.2 → v0.3 migration in `migrate.ts`; CLI exposes `aithos ethos migrate-to-v0.3`. Migration walks all three zones, splitting the public markdown file into per-section files alongside the encrypted-zone splitting.
7. Implement the v0.2 compat read path in `decodeBundleV02.ts`; v0.3 reader MUST handle both v0.2 and v0.3 bundles.
8. Adapt the existing E2E scripts to v0.3; write B1–B15 as new E2E scripts.
9. Update `spec/03-bundle.md` to the new normative form once v0.3 is cut; archive the v0.2 chapter as `spec/drafts/bundle-v0.2-archive.md`.

Server-side coordination: the `@aithos/protocol-client` SDK and any platform implementing the bundle store MUST expose section-grain RPCs (`append_zone_section`, `update_zone_section`, `remove_zone_section`, `batch_zone_sections`) symmetrically for all three zones. The exact RPC signatures live in the platform spec, not in this protocol draft.
