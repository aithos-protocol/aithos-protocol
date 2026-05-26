# @aithos/assets-crypto

Reference cryptographic primitives for the [Aithos assets
sub-protocol](https://github.com/aithos-protocol/aithos-protocol/tree/main/spec/assets).
Implements AMK (Asset Master Key) generation, X25519-HKDF-AEAD wraps
for recipients, XChaCha20-Poly1305 byte encryption with the canonical
nonce-prefix on-disk layout, and SHA-256 content-addressing.

## Status

**Alpha** — API surface likely to shift until 0.1.0 stable. Use at
your own risk for production.

## Install

```sh
npm install @aithos/assets-crypto@alpha
```

## Quick start

```ts
import {
  generateAMK,
  wrapAMKForRecipient,
  unwrapAMK,
  encryptAssetBytes,
  decryptAssetBytes,
  generateX25519Keypair,
} from "@aithos/assets-crypto";

// 1. Generate keys
const { privateKey, publicKey } = generateX25519Keypair();
const amk = generateAMK();
const assetUrn = "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…";

// 2. Wrap the AMK for the recipient
const wrap = wrapAMKForRecipient({
  amk,
  recipientPublicKey: publicKey,
  recipientDidUrl: "did:aithos:z6Mkr…#circle-kex",
  assetUrn,
});

// 3. Encrypt the asset bytes
const plaintext = new TextEncoder().encode("My private content");
const { blob, sha256_of_plaintext_hex, size_bytes } = encryptAssetBytes({
  amk,
  assetUrn,
  plaintext,
});

// `blob` is the [nonce(24) | ciphertext+tag] ready to PUT to S3.
// `sha256_of_plaintext_hex` and `size_bytes` go into the asset metadata.

// 4. Later, decrypt
const recoveredAmk = unwrapAMK({
  wrap,
  recipientPrivateKey: privateKey,
  assetUrn,
});

const recovered = decryptAssetBytes({
  amk: recoveredAmk,
  assetUrn,
  blob,
  expectedSha256Hex: sha256_of_plaintext_hex,
});
// recovered === plaintext, byte-for-byte
```

## What's in here

The package is organized around four concerns:

- **`amk`** — AMK generation, wrap, unwrap (`spec/assets/02-key-hierarchy.md` §2.3).
- **`asset`** — Asset bytes encryption with the nonce-prefix on-disk layout
  (§2.3.2), public-regime hash verification (§2.6), and helpers.
- **`aad`** — Canonical AAD construction binding ciphertexts to
  `(asset_urn, recipient_did_url)`.
- **`types`** — Wire-format types (`AssetMetadata`, `AMKEnvelope`,
  `WrapEntry`, `AssetReference`) plus base64/hex helpers and the
  `AssetsCryptoError` class.

## Cryptographic constructions

- **AEAD**: XChaCha20-Poly1305 IETF, 24-byte nonce.
- **Key agreement**: X25519 (RFC 7748).
- **KDF**: HKDF-SHA256 (RFC 5869) with salt `"aithos-assets-amk-wrap-v1"`
  and info = recipient DID URL.
- **Content hash**: SHA-256.
- **All AADs** carry an explicit version marker (`"aithos-asset-v1\0"`,
  `"aithos-assets-amk-v1\0"`) so cross-version ciphertext substitution
  fails loudly.

## Related packages

| Package | Scope |
|---|---|
| [`@aithos/protocol-core`](https://www.npmjs.com/package/@aithos/protocol-core) | Wire-format primitives, types, canonicalization. |
| [`@aithos/data-crypto`](https://www.npmjs.com/package/@aithos/data-crypto) | Crypto primitives for the data sub-protocol (CMK/DEK/records). |
| **`@aithos/assets-crypto`** (this) | Crypto primitives for the assets sub-protocol. |
| [`@aithos/protocol-client`](https://www.npmjs.com/package/@aithos/protocol-client) | Env-agnostic client: signing, building, API access. |

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See
[LICENSE](./LICENSE).

The Aithos protocol specification (in the `spec/` directory of this
repo) is under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Contributing

Issues and pull requests are welcome at
[github.com/aithos-protocol/aithos-protocol](https://github.com/aithos-protocol/aithos-protocol).
