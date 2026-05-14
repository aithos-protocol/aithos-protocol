# @aithos/data-backend — Changelog

## 0.2.0-alpha.2 — 2026-05-14

### Authentication is now real

Sub-jalon 3.2a — envelope verification + mandate verification +
anti-replay are in place. The PDS no longer accepts any operation
without a valid signed envelope.

**Anyone holding only a DID cannot read or write anything.**

### Added

- `lambda/auth/did-resolver.ts` — `did:key:…` resolution (offline, deterministic).
  Synthesizes a `DidDocument` shape compatible with `@aithos/protocol-core`.
- `lambda/auth/nonce-store.ts` — DynamoDB-backed replay cache,
  atomic `PutItem` with `attribute_not_exists`, native DDB TTL on
  `expires_at_epoch`.
- `lambda/auth/authenticate.ts` — middleware that runs the 9-step
  `verifyEnvelope` from `@aithos/protocol-core` before every handler.
  Returns a typed `Caller { subjectDid, mode, mandateId?, mandate?,
  signerPubkeyMultibase, params }`.
- `requireScope(caller, collection, action)` — enforces
  `data.<col>.<action>` (with `data.*.<action>` and admin wildcards)
  per spec §4.
- `requireSubjectMatch(caller, target)` — rejects a caller whose
  `envelope.iss` doesn't match the target subject.
- **New table** `aithos-data-pds-nonces-dev` — replay-protection store,
  TTL-managed.
- **New handlers** `update_record` and `delete_record`. Both require
  `data.<col>.write` scope. `delete_record` supports optional
  `hard_delete: true` (owner-only).
- HTTP status mapping in router: `-32010..-32013` → 401,
  `-32040..-32042` → 403, `-32020` → 404, `-32601` → 404.

### Validated end-to-end

`test-e2e/auth-flow.mjs` covers a full lifecycle on the deployed
endpoint with a real signed envelope:

| Assertion | Result |
|---|---|
| `create_collection` (owner-signed) | 200 ✓ |
| `insert_record` (owner-signed) | 200 ✓ |
| `list_records` returns 1 item | ✓ |
| `get_record` returns the record | ✓ |
| `update_record` persists changes | ✓ |
| `delete_record` (soft) | 200 ✓ |
| `get_record` after delete | 404 ✓ |
| **No envelope → 401 `AITHOS_BAD_ENVELOPE`** | ✓ |
| **Tampered signature → 401 `AITHOS_BAD_SIGNATURE`** | ✓ |
| **Method mismatch → 401 `AITHOS_BAD_ENVELOPE`** | ✓ |
| **Replayed nonce → 401 `AITHOS_REPLAY_DETECTED`** | ✓ |
| **`envelope.iss` ≠ `subject_did` → 403 `AITHOS_INSUFFICIENT_SCOPE`** | ✓ |

### Known limitations (deferred to Sub-jalon 3.2b)

- **DID method support.** Only `did:key:…` resolves locally. `did:aithos:…`
  is deferred to 3.2b (will require an HTTP fetch to the Ethos
  platform endpoint plus an in-memory cache).
- **Revocation lookup.** `findRevocation` in the envelope verifier
  context is omitted in v0.1 dev. Mandates are accepted as long as
  their signature and time window check out. Revocation handling
  arrives with the `authorize_app` / `revoke_app` handlers in 3.2b.
- **Missing handlers.** `authorize_app`, `revoke_app`, `rotate_cmk`
  remain in Sub-jalon 3.2b.
- **Schema validation** against `aithos.contacts.v1` (and other core
  schemas) — Sub-jalon 3.2c.
- **Gamma log** persistence + chain check — Sub-jalon 3.2c.

### Security note

- The replay cache uses an atomic `PutItem(condition: attribute_not_exists)`.
  A nonce is committed exactly once. A second use of the same nonce
  fails the conditional and returns `-32012`.
- Replay cache outages **fail closed** — if DynamoDB is unreachable
  for the nonce check, the request is rejected with `-32603` rather
  than allowed through.
- Envelope TTL is bounded by the protocol-core verifier to
  `[1, 300]` seconds.
- The audience check binds each envelope to the exact endpoint URL it
  was submitted to. An envelope signed for `/mcp/primitives/read`
  cannot be replayed against `/mcp/primitives/write` even within its
  TTL window.

## 0.1.0-alpha.1 — 2026-05-14

Initial MVP. See README §"What's implemented" for the initial handler
set. Auth was stubbed. Superseded by 0.2.0-alpha.2.
