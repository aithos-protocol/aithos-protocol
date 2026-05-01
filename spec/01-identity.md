# 1 · Identity — the `did:aithos` method

## 1.1 Overview

A subject is identified by a **DID** (Decentralized Identifier) of method `aithos`. The identifier binds four Ed25519 public keys — one **root** and three **spheres** — into a single identity anchored in the root's public key. The DID is self-certifying: no registry or server is consulted to prove control; possession of the root private key is the proof.

The root key's sole purpose is to sign the DID document. Day-to-day signing is performed by the sphere keys. This separation lets the sphere keys rotate without changing the identifier.

## 1.2 Identifier syntax

```
did:aithos:<root-multibase>
```

- **`<root-multibase>`** is the multibase base58btc encoding of the two-byte multicodec tag `0xed 0x01` followed by the 32-byte Ed25519 root public key.

This matches exactly the encoding used by the `did:key` method for Ed25519, so any `did:key` resolver already parses the root portion correctly. A conformant `did:aithos` identifier always begins with `z6Mk` after the prefix, for that reason.

### 1.2.1 DID URL fragments

The three sphere keys are referenced as DID URL fragments of the root DID:

```
did:aithos:z6Mkr…#public
did:aithos:z6Mkr…#circle
did:aithos:z6Mkr…#self
```

The fragment identifiers are fixed: `public`, `circle`, `self`. No other fragments are reserved at v0.1.0.

### 1.2.2 Examples

```
# Valid root DID
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9

# Valid sphere DID URLs
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#public
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#circle
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#self

# Invalid — wrong fragment
did:aithos:z6Mkr…#private        # "private" is not a reserved fragment
```

### 1.2.3 ABNF

```
aithos-did       = "did:aithos:" multibase-ed25519
aithos-did-url   = aithos-did "#" sphere-fragment
sphere-fragment  = "public" / "circle" / "self"
multibase-ed25519 = "z" 1*base58btc-char     ; decodes to 0xed 0x01 ‖ 32-byte pk
```

## 1.3 Cryptographic primitives

- **All identity keys are Ed25519** (RFC 8032). Signature value is 64 bytes; public key is 32 bytes; secret key material is a 32-byte seed (libsodium stores secret key as `seed ‖ pk`, 64 bytes, for performance — implementations MAY follow either convention but MUST treat the seed as the canonical secret).
- **Key wrapping for encrypted zones** (chapter 3) uses **X25519** ECDH. Each sphere key pair has a corresponding X25519 pair derived from the same seed via [RFC 8032 §5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5) conversion (the libsodium `crypto_sign_ed25519_sk_to_curve25519` function, or its equivalent). This gives one seed per sphere that covers both signing and key agreement.

Conformant implementations SHOULD use the libsodium primitives or an audited equivalent (Noble, Monocypher, ring). Rolling your own Ed25519 is strongly discouraged.

## 1.4 Key generation

### 1.4.1 Root seed

Generate 32 cryptographically random bytes. This is the **root seed**. Derive the Ed25519 key pair from it per RFC 8032.

### 1.4.2 Sphere seeds

Generate, independently, 32 cryptographically random bytes for each sphere (`public`, `circle`, `self`). Each sphere seed produces one Ed25519 pair (for signing) and one X25519 pair (for encryption), both derived from the same seed.

The sphere seeds MUST NOT be derived from the root seed. This is intentional: deriving them would couple rotation — a change to `circle` would force a change to everything else.

### 1.4.3 Storage

Seeds are the only secrets. Everything else is public or derivable.

- The root seed is stored sealed under a passphrase using **Argon2id** (memlimit ≥ 64 MB, opslimit ≥ 3) → 32-byte key → **XChaCha20-Poly1305** of the seed. The sealed blob is the `identity.sealed.json` file in the local keystore (§1.7).
- Each sphere seed is stored the same way, with its own salt and nonce.
- The four seeds MAY share a passphrase. Most implementations will default to one passphrase for convenience; a security-conscious author may configure separate passphrases per sphere so compromise of one does not reveal others.

## 1.5 The DID document

Resolving a `did:aithos` DID yields a DID document of the following shape. The document is itself signed (§1.6).

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://aithos.dev/spec/v0.1"
  ],
  "id": "did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9",
  "verificationMethod": [
    {
      "id": "did:aithos:z6Mkr…#public",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aithos:z6Mkr…",
      "publicKeyMultibase": "z6MkpublicKeyBase58btcEncoding…"
    },
    {
      "id": "did:aithos:z6Mkr…#circle",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aithos:z6Mkr…",
      "publicKeyMultibase": "z6MkcircleKeyBase58btcEncoding…"
    },
    {
      "id": "did:aithos:z6Mkr…#self",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aithos:z6Mkr…",
      "publicKeyMultibase": "z6MkselfKeyBase58btcEncoding…"
    }
  ],
  "keyAgreement": [
    {
      "id": "did:aithos:z6Mkr…#public-kex",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:aithos:z6Mkr…",
      "publicKeyMultibase": "z6LSpublicX25519Encoding…"
    },
    { "id": "did:aithos:z6Mkr…#circle-kex", "type": "X25519KeyAgreementKey2020", "controller": "did:aithos:z6Mkr…", "publicKeyMultibase": "z6LScircleX25519Encoding…" },
    { "id": "did:aithos:z6Mkr…#self-kex",   "type": "X25519KeyAgreementKey2020", "controller": "did:aithos:z6Mkr…", "publicKeyMultibase": "z6LSselfX25519Encoding…"   }
  ],
  "service": [
    {
      "id": "did:aithos:z6Mkr…#ethos",
      "type": "EthosBundle",
      "serviceEndpoint": "https://aithos.example/u/john-doe.ethos"
    }
  ],
  "aithos": {
    "version": "0.1.0",
    "created_at": "2026-04-19T08:12:00Z",
    "rotated": []
  }
}
```

### 1.5.1 Required fields

- `@context` — MUST include `"https://www.w3.org/ns/did/v1"` and `"https://aithos.dev/spec/v0.1"` (or the URL of the spec version the document targets).
- `id` — the root DID.
- `verificationMethod` — MUST contain exactly three entries whose `id` fragments are `public`, `circle`, `self`, in that order.
- `keyAgreement` — MUST contain exactly three entries whose `id` fragments are `public-kex`, `circle-kex`, `self-kex`, referencing the X25519 half of each sphere seed.
- `aithos.version` — the spec version the document targets.
- `aithos.created_at` — RFC 3339 timestamp of document creation.
- `aithos.rotated` — array of rotation records (§1.6.3), possibly empty.

### 1.5.2 Optional fields

- `service` — zero or more service endpoints. The canonical service type is `EthosBundle`, pointing to the HTTPS URL (or other transport URL) from which the bundle can be fetched.

## 1.6 DID document signing and rotation

### 1.6.1 Signing

The DID document is signed by the root key. The signature MUST follow the rules in §5.1 (canonicalization) and §5.2 (Ed25519). The signature is attached as a JSON object named `proof` at the top level:

```json
{
  "id": "did:aithos:z6Mkr…",
  "verificationMethod": [ … ],
  "keyAgreement": [ … ],
  "aithos": { … },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-19T08:12:00Z",
    "verificationMethod": "did:aithos:z6Mkr…#root",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9…"
  }
}
```

The `verificationMethod` for the root signature uses the special fragment `#root`, which resolves to the Ed25519 public key embedded in the DID itself (the multibase after `did:aithos:`). The `#root` fragment is implicit — it is not listed in `verificationMethod` to avoid redundancy with the DID identifier.

### 1.6.2 Verification

A verifier:

1. Extracts `proof.proofValue` and `proof.verificationMethod`.
2. Resolves `#root` to the embedded Ed25519 public key (decode multibase, strip the `0xed 0x01` prefix).
3. Canonicalizes the DID document with the `proof.proofValue` field set to the empty string (§5.1.4).
4. Verifies the signature against the canonicalized bytes.

### 1.6.3 Rotation

A sphere key can be rotated by publishing a **new edition** of the DID document with the old sphere entry replaced and an entry appended to `aithos.rotated`:

```json
"rotated": [
  {
    "sphere": "circle",
    "previous_key": "z6MkoldCircleKey…",
    "rotated_at": "2026-06-01T12:00:00Z",
    "reason": "suspected_device_compromise"
  }
]
```

The new document is signed by the root key as before. Verifiers caching an older document SHOULD refresh on any observed signature that does not match a known key.

### 1.6.4 Root rotation

The root key cannot be rotated within a `did:aithos` identifier — the identifier *is* the root key. A compromised root requires moving to a new DID. The spec deliberately does not provide a recovery mechanism; see §7.5.

## 1.7 Local keystore layout (informative)

The reference CLI stores identity material under `~/.aithos/` as follows. This layout is informative; implementations are free to differ.

```
~/.aithos/
├── config.json                   # { default_handle, version }
├── identities/
│   └── john-doe/
│       ├── did.json              # signed DID document
│       ├── root.sealed.json      # sealed root seed
│       ├── public.sealed.json    # sealed public-sphere seed
│       ├── circle.sealed.json    # sealed circle-sphere seed
│       └── self.sealed.json      # sealed self-sphere seed
├── mandates/
│   ├── mandate_01JG4X7R…json
│   └── …
└── revocations/
    └── revocation_01JGM4K1…json
```

Sealed blobs use the format defined in §1.4.3.

## 1.8 Resolution (informative)

The protocol does not mandate a resolver. Two common resolver strategies are anticipated:

- **Well-known URL.** The subject publishes `did.json` at `https://<host>/.well-known/did-aithos/<handle>` and advertises the handle through social channels.
- **Companion `did:web`.** The subject publishes a `did:web` DID document that itself contains a reference to the `did:aithos`. Clients resolve `@john-doe.example.com` → `did:web:john-doe.example.com` → `did:aithos:z6Mkr…`.

Discovery is explicitly deferred to a future version of the spec.

---

Next: [chapter 2 — Ethos document](./02-ethos.md).
