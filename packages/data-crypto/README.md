# @aithos/data-crypto

Reference cryptographic primitives for the Aithos **data sub-protocol** —
the PDS layer that complements the Ethos protocol for operational records
(see [`spec/data/`](../../spec/data/00-overview.md)).

> **Status:** Jalon 2 POC. Standalone primitives, no network or storage.
> Validates the construction described in
> [`spec/data/02-key-hierarchy.md`](../../spec/data/02-key-hierarchy.md) end to end.

## What this package provides

| Module | Exports |
|---|---|
| `@aithos/data-crypto/cmk` | `generateCMK`, `wrapCMKForRecipient`, `unwrapCMK` |
| `@aithos/data-crypto/dek` | `generateDEK`, `wrapDEKForCMK`, `unwrapDEKFromCMK` |
| `@aithos/data-crypto/record` | `encryptRecord`, `decryptRecord` |
| `@aithos/data-crypto/collection` | `createCollection`, `authorizeApp`, `revokeApp`, `rotateCMK` |
| `@aithos/data-crypto/types` | Shared types: `CMKEnvelope`, `WrapEntry`, `RecordPayload`, etc. |

The construction follows spec §2 exactly:

```
sphere key  ──wraps──→  CMK  ──wraps──→  DEK  ──encrypts──→  payload
```

Each `wrap` is X25519-HKDF-SHA256-AEAD; payload AEAD is XChaCha20-Poly1305
with AAD bindings to `(subject_did, collection_name, record_id)`.

## Quick start

```ts
import { generateX25519Keypair } from '@aithos/data-crypto/types';
import { createCollection, authorizeApp } from '@aithos/data-crypto/collection';
import { encryptRecord, decryptRecord } from '@aithos/data-crypto/record';

// Setup: owner key + app key
const owner = generateX25519Keypair();
const app = generateX25519Keypair();
const subjectDid = 'did:aithos:z6MkSubjectExample';
const collectionName = 'contacts';

// Owner creates a collection
const collection = createCollection({
  subjectDid,
  collectionName,
  ownerRecipientDidUrl: `${subjectDid}#data-kex`,
  ownerPublicKey: owner.publicKey,
});

// Owner authorizes an app
const updated = authorizeApp({
  collection,
  recipientDidUrl: 'did:key:z6Mk…app#kex',
  recipientPublicKey: app.publicKey,
  unwrapperPrivateKey: owner.privateKey,
  unwrapperRecipientDidUrl: `${subjectDid}#data-kex`,
});

// Owner inserts a record
const encrypted = encryptRecord({
  subjectDid,
  collectionName,
  recordId: 'record_01J9TEST',
  payload: { notes: 'Important prospect' },
  cmk: /* unwrapped from updated using owner.privateKey */,
});

// App decrypts the record
const payload = decryptRecord({
  subjectDid,
  collectionName,
  recordId: 'record_01J9TEST',
  encrypted,
  cmk: /* unwrapped from updated using app.privateKey */,
});

console.log(payload); // { notes: 'Important prospect' }
```

## Tests

```bash
npm install
npm test
```

Tests cover:

- CMK roundtrip (wrap + unwrap)
- DEK roundtrip under a CMK
- Full record encrypt/decrypt
- Owner → authorize app → app reads (O(1) authorization)
- Revoke app, with and without CMK rotation
- AAD binding enforcement (cross-collection, cross-record replay rejected)
- CMK rotation (re-wrap all DEKs under new CMK)

## Benchmark

```bash
npm run bench
```

Reports microbenchmarks of:

- CMK generation + wrap for owner
- DEK generation + wrap under CMK
- Record encryption (10 KB payload)
- Record decryption
- Authorize new app
- Rotate CMK with N records

## Notes on scope

This POC is **standalone** — no network, no storage, no scheduler.
It validates the cryptographic construction. The backend (Jalon 3)
will wrap these primitives in RPC handlers. The SDK (Jalon 4) will
expose ergonomic client APIs.

What is NOT in this POC:
- Schema validation (Jalon 5)
- Mandate verification (reused from `@aithos/protocol-core`)
- Persistence (Jalon 3)
- Gamma chain integration (Jalon 6 / threaded later)

## License

Apache-2.0 © Mathieu Colla
