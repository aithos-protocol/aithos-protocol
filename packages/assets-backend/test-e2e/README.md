# E2E tests — assets-backend

End-to-end tests for the Aithos assets PDS. These tests do **real HTTP
calls** against a deployed stack — they are NOT mocked.

## Prerequisites

1. The stack must be deployed (`npm run cdk:deploy` from the package
   root).
2. Set the environment variable `AITHOS_ASSETS_PDS_URL` to the
   `AithosAssetsPdsApiUrl` output of the stack (typically
   `https://xxx.execute-api.eu-west-3.amazonaws.com`).
3. Set `AITHOS_ASSETS_TEST_SEED_HEX` to a 64-hex-character Ed25519 seed
   that the tests will use as a `did:key:` test identity. Different
   tests share this identity to amortize setup.

## Run

```sh
AITHOS_ASSETS_PDS_URL=https://… \
AITHOS_ASSETS_TEST_SEED_HEX=$(openssl rand -hex 32) \
npm run test:e2e
```

(Add to `package.json` scripts if not present.)

## Coverage matrix

Tests in this directory cover the scenarios from
`spec/assets/09-threat-model.md` §9.6 and the API contract from
`spec/assets/05-api-primitives.md`.

| Scenario | File | Description |
|---|---|---|
| Upload public flow | `upload-public.test.ts` | init → S3 PUT → complete → get_public_asset → fetch via CDN |
| Upload private flow | `upload-private.test.ts` | AMK gen + wrap + encrypt → init → PUT → complete → get → S3 presigned GET → decrypt → SHA verify |
| Dedup intra-subject | `dedup.test.ts` | upload same plaintext twice; second returns `dedup_hit` |
| Reference lifecycle | `references.test.ts` | ref → unref → state ACTIVE→ORPHANED |
| Delete asset | `delete.test.ts` | delete refuses while referenced; succeeds after unref |
| Quota cap | `quota.test.ts` | upload past 5 GB returns AITHOS_ASSETS_QUOTA_EXCEEDED |
| Media type rejection | `media-type.test.ts` | text/html, javascript rejected |
| Size cap | `size-cap.test.ts` | declared > 100 MB rejected |
| Tampered ciphertext | `tamper.test.ts` | flipped byte in S3 → AEAD fail at client decrypt |
| AAD binding | `aad.test.ts` | substitute ciphertext between two assets → decrypt fails |
| Hash mismatch | `hash.test.ts` | declared SHA differs from actual upload → AITHOS_ASSETS_HASH_MISMATCH at complete |
| Anonymous read | `anon-public.test.ts` | get_public_asset succeeds for public; AITHOS_ASSETS_NOT_PUBLIC for private |
| Anti-replay | `replay.test.ts` | same envelope replayed → -32013 AITHOS_REPLAY_DETECTED |
| Sphere rotation | `rotate-owner-wrap.test.ts` | re-wrap AMK for new sphere; old wrap removed |

## Status

The E2E suite is **scaffolded** (files exist with `it.todo()`
placeholders) and will be filled when the stack is first deployed at
Phase 8 of the v0.1 plan. The scaffolding is preserved so contributors
have a clear inventory of what coverage to provide.
