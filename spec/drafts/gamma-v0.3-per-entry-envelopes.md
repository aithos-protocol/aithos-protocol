# Draft · Gamma v0.3 — per-entry envelopes, decoupled read/write

> **Status:** Draft. Source of truth for the v0.3 gamma format. Not yet normative. Promotion target: `spec/10-gamma.md` on release, with v0.2 content moved to `spec/drafts/gamma-v0.2-archive.md`.
>
> **Scope.** This draft replaces §10.3 and §10.5 of the current gamma spec, and amends §4 (mandates) with a new `gamma.read` scope. All other chapters are unaffected.

## Motivation

v0.2 gamma encrypts the entire JSONL log under a single data-encryption key (DEK), wrapped to recipients (sphere keys + optional delegates). This single-DEK model fails to separate two capabilities that the protocol must distinguish:

1. **Append** a new entry to the log (required for any mandate that writes the ethos: every `section.add`, `section.modify`, `section.delete` emits a gamma entry).
2. **Read** the existing log (past entries, including those authored before the mandate was issued).

Under symmetric AEAD, possession of the DEK implies both. `issueMandateWithRewrap` consequently grants every write-mandate delegate the ability to read the full gamma log, including history predating the mandate. This is a leak of subject history to any agent authorized for day-to-day writes.

v0.3 splits the two capabilities cryptographically:

- **Append** requires only (a) a valid mandate with `ethos.write.<zone>`, (b) the delegate's Ed25519 signing key, and (c) the current `manifest.gamma.head` plus the public `manifest.gamma.readers` list. No access to prior plaintext.
- **Read** requires a mandate with the new `gamma.read` scope **and** the corresponding X25519 private key. The mandate's public key is added to `manifest.gamma.readers`; every future entry seals its per-entry content key to that pubkey.

The result: a delegate authorized only for `ethos.write.*` can drive sections forward and correctly append signed gamma entries, yet the gamma log's content remains opaque to them.

## 10.3′ Storage layout (revised)

### 10.3.1′ On disk

Unchanged from v0.2:

```
~/.aithos/identities/<handle>/ethos/
├── manifest.json
├── public/public.md
├── circle/circle.md.enc
├── self/self.md.enc
└── gamma/
    └── gamma.jsonl.enc
```

### 10.3.2′ File shape

The gamma file is a JSON envelope with a version marker and a sequence of per-entry objects. The v0.2 form (single outer ciphertext) is replaced by a JSONL of per-entry sealed envelopes. A v0.3 log file MAY contain v0.2-format entries (legacy, pre-migration) and v0.3-format entries interleaved; readers MUST accept both.

```json
{
  "aithos-gamma-file": "0.3.0",
  "entries": [
    { "format": "v0.2", ... },   // legacy entry, sealed under shared DEK
    { "format": "v0.3", ... },   // per-entry envelope
    ...
  ]
}
```

A v0.3-format entry is:

```json
{
  "format": "v0.3",
  "payload_ct": "base64url(XChaCha20-Poly1305(payload, entry_key, nonce))",
  "nonce": "base64url(24 bytes)",
  "envelopes": [
    {
      "recipient": "did:aithos:z6Mkr…#public",
      "alg": "x25519-hkdf-sha256-aead",
      "ephemeral_public": "…",
      "wrap_nonce": "…",
      "wrapped_key": "base64url(seal(entry_key, recipient_x25519_pubkey))"
    },
    {
      "recipient": "urn:aithos:agent:reader-42",
      "alg": "x25519-hkdf-sha256-aead",
      ...
    }
  ],
  "public_header": {
    "aithos-gamma": "0.3.0",
    "id": "gamma_01J…",
    "at": "2026-04-22T10:12:03Z",
    "subject_did": "did:aithos:z6Mkr…",
    "zone": "circle",
    "op": "section.modify",
    "target": { "section_id": "sec_a1b2c3" },
    "prev_gamma_hash": "sha256:…",
    "prev_section_gamma": "gamma_01J…",
    "readers_hash": "sha256:…",
    "hash": "sha256:…"
  },
  "signature": {
    "alg": "ed25519",
    "key": "urn:aithos:agent:writer-17",
    "authorized_by": "mandate_01J…",
    "value": "base64url(…)"
  }
}
```

The **`public_header`** carries all fields needed for chain walk, verification, and querying without decrypting the payload. The **`payload_ct`** holds the encrypted sensitive body of the operation (op-specific; see §10.5′). The **`envelopes`** list seals the per-entry symmetric key (`entry_key`, 32 bytes) to each authorized reader's X25519 public key.

### 10.3.3′ Plaintext payload shape

The plaintext sealed in `payload_ct` is the JCS canonicalization of an object carrying exactly the op-sensitive data. For v0.2 operations:

| Op | Plaintext payload |
|---|---|
| `section.add` | `{ "title": "…", "body": "…", "tags": ["…"] }` |
| `section.modify` | `{ "title"?: "…", "body"?: "…", "tags"?: ["…"] }` |
| `section.delete` | `{ "reason"?: "…" }` |
| `section.reorder` | `{ "order": ["sec_…", …] }` |
| `section.redact` | `{ "reason": "…" }` |

Fields that belong to routing or integrity (zone, id, target, hashes, prev_hash, signature) remain in `public_header`, **not** in the payload. They are public by necessity: a reader who cannot decrypt still needs to verify chain linkage.

### 10.3.4′ readers_hash

`readers_hash = "sha256:" + hex(sha256(jcs(sorted_by_recipient([envelopes[i] without wrapped_key for all i]))))`.

This commits to the set of recipients of this entry without committing to the wrapped key material (which is inherently non-canonical because X25519 seal uses a fresh ephemeral pubkey per wrap). Including `readers_hash` in `public_header` — and therefore in the entry `hash` and signature — means the signer attests to the reader set, and tampering with the envelopes list (adding a reader, removing one) invalidates the signature.

### 10.3.5′ Manifest additions

```json
{
  ...,
  "gamma": {
    "head": "sha256:…",
    "count": 248,
    "url": "https://aithos.example/u/mathieu.gamma",
    "readers": [
      {
        "recipient": "did:aithos:z6Mkr…#public",
        "pubkey": "z6LS…",
        "added_at": "2026-04-22T08:00:00Z"
      },
      {
        "recipient": "did:aithos:z6Mkr…#circle",
        "pubkey": "z6LS…",
        "added_at": "2026-04-22T08:00:00Z"
      },
      {
        "recipient": "did:aithos:z6Mkr…#self",
        "pubkey": "z6LS…",
        "added_at": "2026-04-22T08:00:00Z"
      },
      {
        "recipient": "urn:aithos:agent:reader-42",
        "pubkey": "z6LS…",
        "via_mandate": "mandate_01J…",
        "added_at": "2026-04-22T09:30:00Z"
      }
    ]
  }
}
```

- `readers[].recipient` — the stable identifier (`did:aithos:*#sphere` for subject, `urn:aithos:agent:*` for delegates).
- `readers[].pubkey` — the X25519 public key, multibase-encoded. Writers read this list to build the `envelopes` of a new entry.
- `readers[].via_mandate` — REQUIRED for delegate readers, identifies the mandate that authorizes the wrap.
- `readers[].added_at` — informative.

The manifest signature (§3.3) covers `gamma.readers`, so a tampered reader list invalidates the manifest.

The three subject sphere X25519 pubkeys are added on identity creation. Delegate pubkeys are added by `grant` when a mandate with `gamma.read` is issued (see §10.11′).

## 10.5′ Entry schema (revised)

A v0.3 gamma entry is the outer object shown in §10.3.2′. The `public_header` fields match v0.2's entry fields with two additions (`readers_hash`) and two removals (`payload` moved out, `signature` moved to the outer object).

### 10.5.1′ Hash computation

Given a candidate entry with outer `E` and header `H = E.public_header`:

1. Set `H.hash = ""`.
2. Compute `H.readers_hash` as specified in §10.3.4′.
3. Compute `H.hash = "sha256:" + hex(sha256(jcs(payload_ct_b64url, nonce_b64url, H)))`.

The entry hash therefore commits to the ciphertext, the nonce, and the full public header (including `readers_hash`). Any modification to the envelope set, the nonce, or the payload breaks the hash.

### 10.5.2′ Signature computation

Set `E.signature.value = ""` initially, then:

1. Compute the hash as above.
2. Fill `H.hash`.
3. Sign `jcs({ hash: H.hash, authorized_by: E.signature.authorized_by || null, key: E.signature.key })` with the signing key's private half (Ed25519).
4. Set `E.signature.value`.

Note: the signature domain is intentionally narrow (just hash + mandate id + signer key). The entry hash already commits to the rest of the entry; the signature only needs to bind "I, this signer, attest to this entry hash."

### 10.5.3′ Signing key resolution

| Signer type | `signature.key` | `signature.authorized_by` | Key lookup |
|---|---|---|---|
| Subject (owner path) | `did:aithos:…#<zone>` | absent | DID document, §1 |
| Delegate (mandate path) | mandate's `grantee.id` | mandate id | Mandate's `grantee.pubkey` (Ed25519 signing) |

Subject writes continue to use the sphere Ed25519 matching the entry's `zone`. Delegate writes use the delegate's Ed25519 signing key declared in the mandate.

The mandate's signing Ed25519 is distinct from its content-decryption X25519 capability. A mandate with only `ethos.write.<zone>` binds just the Ed25519; a mandate with `gamma.read` additionally binds the X25519 to which gamma entry keys will be sealed.

## 10.11′ Append algorithm (revised)

To append an entry:

1. **Load manifest.** Read `manifest.gamma.readers` and `manifest.gamma.head`.
2. **Generate entry key.** `entry_key ← random 32 bytes` (cryptographically secure RNG). Used once, never stored.
3. **Build plaintext payload.** Op-specific, per §10.3.3′.
4. **Encrypt.** `payload_ct = XChaCha20-Poly1305(jcs(payload), entry_key, nonce)` with a fresh 24-byte nonce.
5. **Seal key to each reader.** For each `r ∈ manifest.gamma.readers`:
   ```
   envelopes.push(x25519-hkdf-sha256-aead(entry_key, r.pubkey, recipient: r.recipient))
   ```
   Use the same wrap construction as bundle zone DEKs (§3.4) for consistency.
6. **Compute `readers_hash`** per §10.3.4′.
7. **Fill `public_header`** with `prev_gamma_hash = manifest.gamma.head`, `readers_hash`, and the op-specific routing fields. Leave `hash = ""`.
8. **Hash** per §10.5.1′.
9. **Sign** per §10.5.2′ with the author's Ed25519 key.
10. **Append** the outer entry to `gamma.jsonl.enc.entries[]`.
11. **Write atomically** (temp-then-rename).
12. **Update manifest** `gamma.head` and `gamma.count`. Sign and persist the manifest edition.

**Key property:** steps 1–11 never decrypt prior entries. A delegate with `ethos.write.<zone>` but no `gamma.read` can execute the full append without read access to history.

## 10.12′ Read algorithm (revised)

To read an entry at index `i`:

1. **Load file.** Read `gamma.jsonl.enc.entries[i]`.
2. **Dispatch on format.**
   - If `entries[i].format == "v0.2"`, fall back to v0.2 read (shared DEK unwrap from outer file's `wraps`). See §10.13′ for the compat path.
   - If `entries[i].format == "v0.3"`, proceed.
3. **Verify signature.** Recompute the entry hash (§10.5.1′) and verify `signature.value` against `signature.key` using the author's Ed25519 pubkey (sphere DID doc or mandate `grantee.pubkey`, per §10.5.3′).
4. **Verify chain.** Check `prev_gamma_hash` equals `entries[i-1].public_header.hash` (or `null` for `i == 0`). Check `at` strictly exceeds prior.
5. **Verify readers_hash.** Recompute from `envelopes` and compare to `public_header.readers_hash`. If mismatch, the envelope list was tampered with and the entry MUST be rejected.
6. **Find caller's envelope.** Walk `envelopes` for an `envelope.recipient` matching the caller's DID. If absent, the caller is not authorized to read this entry: stop, return an access-denied error for this entry (chain walk may continue over subsequent entries).
7. **Unseal entry key.** Use the caller's X25519 private key to unseal `envelope.wrapped_key` → `entry_key`.
8. **Decrypt payload.** `payload = XChaCha20-Poly1305-Open(payload_ct, entry_key, nonce)` and parse as JCS JSON.

A verifier that only needs integrity (no content access) MAY execute steps 1–5 and stop: signature, chain linkage, and reader-set commitment can be checked without any decryption.

## 10.13′ Compat reader for v0.2 entries

A v0.3 implementation MUST accept logs whose `entries[]` mix v0.2 and v0.3 records. For v0.2 records:

1. The outer file carries a top-level `cipher.wraps` array (from the v0.2 format) alongside the `entries[]` list. Unwrap the shared DEK using any recipient wrap the caller has a key for.
2. The v0.2 record's structure is that of §10.3.3 of the v0.2 spec, embedded as one line of plaintext JSONL; the implementation reads the shared ciphertext from the outer file's legacy `cipher.ciphertext` field to obtain the plaintext JSONL, splits on `\n`, and serves lines at indices matching the v0.2 range of `entries[]`.
3. Verify `hash` and `signature` per v0.2 rules (§10.5 of current spec).

This path is purely for reading. **Writes always produce v0.3 entries.** No mutation of v0.2 entries is permitted.

### 10.13.1′ Migration note

The initial v0.3 release ships no migration script. An existing v0.2 log continues to work as a v0.2 file (read-only from v0.3's perspective). The first `section.add/modify/delete` under v0.3 runtime produces the first v0.3 entry in the new format; the file envelope version marker flips from `0.2.0` to `0.3.0` at that moment and all subsequent entries are v0.3.

A future release MAY ship `aithos gamma migrate` that re-encrypts v0.2 entries into v0.3 form, requiring all subject sphere seeds online. Until then, the compat reader is the stable bridge.

## 4.5′ Mandate scope vocabulary additions

Amends chapter 4 (mandates).

### New scope: `gamma.read`

```
gamma.read
```

- **Sphere binding.** Unscoped to a specific sphere. A mandate bearing `gamma.read` MAY be signed by any sphere key (`#public`, `#circle`, or `#self`); convention is `#self` since gamma is a cross-zone commitment to the subject's authorship history.
- **Capability.** Adds the mandate's `grantee.pubkey` (X25519 half) to `manifest.gamma.readers`. Every subsequent v0.3 gamma entry will include an envelope sealed to this pubkey, making its `payload_ct` decryptable by the delegate.
- **Past entries.** A `gamma.read` mandate does **not** retroactively seal past entries to the delegate. Entries appended before the mandate was granted remain sealed only to their original reader set. A delegate newly added as reader can only decrypt entries appended after their addition.
- **Revocation.** Revoking a `gamma.read` mandate removes the recipient from `manifest.gamma.readers`. Entries appended after revocation will not seal to the revoked reader; entries appended while the mandate was active remain accessible to the delegate in any copy they have (revocation is forward-only, same limitation as all symmetric-sealed data).

### Decoupling from `ethos.write.*`

The `ethos.write.<zone>` scope MUST NOT implicitly grant `gamma.read`. An `issueMandateWithRewrap` implementation for v0.3:

1. For `ethos.write.<zone>`: rewrap the zone DEK to include the delegate's X25519 pubkey (unchanged from v0.2, §4.6).
2. For `gamma.read`: add `{ recipient, pubkey, via_mandate, added_at }` to `manifest.gamma.readers`.

Both actions are independent. A mandate MAY carry any subset of `ethos.read.<zone>`, `ethos.write.<zone>`, and `gamma.read`.

### Append capability is implicit in `ethos.write.<zone>`

A delegate holding `ethos.write.<zone>` can append v0.3 gamma entries without any gamma-specific scope. The append algorithm (§10.11′) requires only the public manifest (readers list, head) and the delegate's own Ed25519 signing key. No decryption capability is exercised or checked during append.

## 10.14′ Verification tiers (revised)

### 10.14.1′ Light

Identical to v0.2. Uses `manifest.gamma.head` as an opaque anchor.

### 10.14.2′ Integrity-only (new tier)

A reader who has no gamma-read capability but wants chain integrity:

1. Fetches the log.
2. For each entry: verifies `hash`, `signature`, `readers_hash`, and chain linkage.
3. Does NOT attempt to decrypt `payload_ct`.

This confirms "the log is a coherent, signed chain authored by known keys," without learning operation payloads. Useful for a third-party auditor.

### 10.14.3′ Full

Adds payload decryption to the integrity checks. Requires the caller to be on at least one entry's envelope list (sphere key for subject, `gamma.read` pubkey for delegate reader).

## 10.15′ Threat model diff from v0.2

| Threat | v0.2 | v0.3 |
|---|---|---|
| Delegate with `ethos.write.*` reads subject's full gamma history | **Present.** Rewrap bundled automatically. | **Prevented.** Append requires no decryption; no envelope is sealed to a write-only delegate. |
| Delegate with `gamma.read` modifies past entries | Prevented (chain hash). | Prevented (chain hash + per-entry signature over readers_hash). |
| Malicious writer silently removes a reader from envelope list | Not expressible (shared DEK). | Prevented: `readers_hash` is signed; removing a reader invalidates the signature. |
| Compromised delegate X25519 private key exposes past traffic | Exposes ALL gamma history up to the delegate's wrap. | Exposes only entries appended while the key was active. Scoping is temporal, not logical. |
| Owner revokes a delegate's gamma.read | Delegate retains ability to decrypt all prior gamma via wrap list. | Same forward-only limitation, but NEW entries after revocation exclude the delegate. |

Net: the leak of past history to write-only delegates is eliminated. Revocation remains forward-only (unavoidable with local-storage copies).

## 10.16′ Test matrix (spec-bound)

Every conformant v0.3 implementation MUST satisfy:

| Test | Assertion |
|---|---|
| T1 — Owner CRUD, 3 zones | 9 v0.3 entries; each signed by the matching sphere key; chain + anchor OK. |
| T2 — Delegate write-only on public | Delegate appends `section.add/modify/delete`; `gamma show` via delegate returns `access-denied` per entry; `gamma verify` (integrity-only) PASSES. |
| T3 — Delegate read-only via `gamma.read` | Delegate calls `gamma show` and decrypts all entries appended **after** mandate issuance; entries before MUST return access-denied. |
| T4 — Delegate with both `ethos.write.*` and `gamma.read` | Same as T2 for append, plus full decryption of entries appended after mandate issuance. |
| T5 — Revoked `gamma.read` | After revocation, a new entry is appended; delegate MUST NOT be on its envelopes; pre-revocation entries remain accessible to delegate's local copy. |
| T6 — Tampered entry | Any byte change in `payload_ct`, `envelopes`, or `public_header` invalidates `hash` and/or `signature`; verify MUST FAIL with a clear error. |
| T7 — Tampered readers list | Removing an envelope invalidates `readers_hash` (signed); verify MUST FAIL. |
| T8 — Compat read of v0.2 entries | A mixed log (v0.2 + v0.3 entries) verifies end-to-end; owner decrypts both; write produces only v0.3 entries. |

Implementations SHOULD publish test vectors for T1–T8 alongside their release.

## 10.17′ Open questions

- **Envelope compression.** With N readers and M entries, the log grows as O(N·M) in envelope overhead. For a subject with 5 readers and 10k entries, that's ~50k envelopes (~10 MB). Acceptable at v0.3; chunked envelopes or reader groups may compress future versions.
- **Forward-secure reader rotation.** If a reader's X25519 key leaks, all past entries sealed to it are exposed. A ratchet-based envelope scheme (per-entry reader key derivation) would contain the blast radius. Out of scope for v0.3; noted for v0.4.
- **Public-head-only light clients.** Unchanged from v0.2 open question — Merkle commitment over `entries[]` would let a reader verify inclusion of a single entry without holding the full log.

---

**Sequencing of the implementation** (in `packages/protocol-core` and `packages/cli`):

1. Add `gamma.read` to `mandate.ts` validation (no sphere-specific constraint).
2. Extend the manifest TypeScript type with `gamma.readers`.
3. Introduce `GammaEntryV03` type and per-entry encrypt/decrypt helpers in `gamma.ts`, alongside existing v0.2 helpers.
4. Refactor `appendGammaEntryForAuthor` to dispatch on the file's version marker and write v0.3 on any append.
5. Refactor `readGammaLogForAuthor` to iterate entries, dispatching per-entry format.
6. Decouple `grant.ts`: zone rewrap only for `ethos.write.*`; readers-list addition only for `gamma.read`.
7. Wire `revoke` to remove from readers list.
8. Adapt the four existing E2E scripts per §10.16′.
9. Write T7 and T8 as new E2E scripts.
10. Bump protocol-core and CLI to v0.3.0; update README, SPEC.md, and chapter 10 of the spec.
