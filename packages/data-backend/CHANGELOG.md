# @aithos/data-backend — Changelog

## 0.3.0-alpha.1 — 2026-05-14

### Delegate flow is now real (Sub-jalon 3.2b)

Owner can mint a mandate, authorize an app to act on their data, and
revoke that mandate. The app authenticates via its own grantee key
while presenting the subject's mandate. Scope is enforced
per-operation. Revocations are persisted and consulted on every
envelope verification.

### Added

- **Three new handlers** (`lambda/handlers/authorization.ts`):
  - `aithos.data.authorize_app` — owner adds a CMK wrap for a new
    grantee, attaches the signed mandate document, indexes the
    mandate on the collection.
  - `aithos.data.revoke_app` — owner removes the grantee's wrap,
    records the revocation in the dedicated table, optionally rotates
    the CMK and accepts re-wrapped DEKs for forward secrecy.
  - `aithos.data.rotate_cmk` — owner-driven CMK rotation independent
    of any revoke (e.g. periodic hygiene).
- **New table** `aithos-data-pds-revocations-dev` — primary key
  `mandate_id`, queried on every authenticated request whose envelope
  carries a mandate.
- `findRevocation` wired into the envelope verifier context. A
  revoked mandate now fails verification with `-32041 AITHOS_MANDATE_REVOKED`.
- DID resolver enhancement: `did:key:…` resolution exposes the
  Ed25519 key under sphere aliases (`#public`, `#circle`, `#self`) so
  Aithos mandates whose `issued_by_key` ends in `#public` verify
  against did:key issuers. Pragmatic accommodation until full
  `did:aithos:…` support arrives.

### Validated end-to-end

`test-e2e/delegate-flow.mjs` — 11 assertions, all green on the live
deployment:

| # | Step | Result |
|---|---|---|
| 1 | Owner creates collection | ✓ |
| 2 | Owner mints WRITE mandate for app A | ✓ |
| 3 | `authorize_app(mandate_A, wrap_A)` | ✓ |
| 4 | App A `insert_record` (mandate-signed envelope) | ✓ |
| 5 | App A `update_record` | ✓ |
| 6 | App A `get_record` (write implies read) | ✓ |
| 7 | Owner mints READ-only mandate for app B and `authorize_app` | ✓ |
| 8 | **App B `insert_record` → 403 `AITHOS_INSUFFICIENT_SCOPE`** | ✓ |
| 9 | App B `get_record` | ✓ |
| 10 | `revoke_app(mandate_A)` | ✓ |
| 11 | **App A `get_record` after revoke → 403 `AITHOS_MANDATE_REVOKED`** | ✓ |

Regression suite (`test-e2e/auth-flow.mjs` from 3.2a) — 14/14 still green.
**Total: 25/25 on the deployed stack.**

### Known limitations (deferred to Sub-jalon 3.2c)

- `did:aithos:…` resolution remains stubbed. did:key only.
- Schema validation of records against `aithos.contacts.v1` etc. is
  not enforced yet.
- Gamma log persistence is still a placeholder `gamma_pending_<ts>`.
- CMK rotation accepts re-wrapped DEKs but doesn't validate the wrap
  cryptographically — the platform trusts the owner client to produce
  correct wraps.
- The `actor_sphere` field of mandates uses the existing
  `public | circle | self` enum from protocol-core. The spec's
  `actor_sphere: "data"` value will need a protocol-core enum
  extension, deferred.

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
