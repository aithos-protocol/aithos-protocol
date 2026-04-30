# 3 · Bundle — the `.ethos` container

## 3.1 Overview

A bundle is a **ZIP archive** (PKZIP) with the `.ethos` extension. It carries one ethos edition (chapter 2), its encrypted zones, the signed DID document, and a manifest that glues them together.

The choice of ZIP is deliberate. ZIP is understood everywhere, has good tooling, preserves file structure, and is the container underlying `.docx`, `.apk`, `.epub`, and countless other established formats. A curious reader can always `unzip` a bundle to see what's inside.

## 3.2 Layout

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

The `wraps` array lists every recipient that can decrypt the zone. Each recipient is identified by a DID URL fragment whose key is X25519.

### 3.5.1 Subject as recipient

The subject MUST be listed as a recipient of their own `circle` and `self` zones. For `circle`, the recipient is `did:aithos:z6Mkr…#circle-kex`. For `self`, it is `did:aithos:z6Mkr…#self-kex`.

This is not redundant: it means the subject can re-decrypt their own bundle on a fresh install of the CLI using only their keystore, without additional mandates.

### 3.5.2 Agent as recipient

An agent that has been granted a mandate (chapter 4) over a zone is a recipient *only if* the grant was a long-lived encryption-scope mandate (§4.5). Most mandates do not confer recipient status; they confer the right to request decrypted content from a server that holds the keys. Recipient status is the strongest form — it means the agent's key material is in the bundle forever.

Authors SHOULD avoid granting recipient status liberally; the more recipients, the larger the attack surface. A typical bundle has one (the subject) or two (the subject + a known partner) recipients on `circle`, and one (the subject) on `self`.

### 3.5.3 Adding and removing recipients

Adding a recipient requires re-encrypting the zone (new DEK, new nonce, all wraps regenerated). The old bundle remains readable by the old recipient set, forever — this is the reality of giving someone ciphertext. Removing a recipient is the same operation: a new edition with the ex-recipient omitted from the wraps. An author who needs to actually revoke prior access has no cryptographic path; they must accept that the data is out.

## 3.6 Key wrapping (X25519-HKDF-SHA256-AEAD)

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
