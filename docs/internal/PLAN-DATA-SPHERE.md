# PLAN — Real `#data` sphere + did:aithos resolution (end the resolver stub)

> Status: in progress. Owner: protocol team. Started 2026-06-01.

## Goal

Make owner data/asset operations sign under the dedicated **`#data`** sphere
(spec `spec/data/02-key-hierarchy.md`), as the protocol intends — so the **root
key stays cold** (its only job is signing the DID document, `spec/01-identity.md`
§1.1) and the data key can rotate independently. Today the PDS forces `#root`
because its did:aithos resolver is a stub that collapses every sphere onto the
root key.

## Key finding (why this is smaller than it looks)

The identity **registry already exists** and already does real per-sphere
resolution server-side — we do NOT build it from scratch:

- `innoesate/aithos/platform/primitives-write` — `aithos.publish_identity`
  verifies a `did_document` (root proof) then stores it: **S3 `ethos/{did}/did.json`**
  + a **DynamoDB** row.
- `innoesate/aithos/platform/primitives-read` — `aithos.resolve_handle` /
  `aithos.get_identity` serve that did.json; `shared/src/signer-key.ts` already
  matches `vm.id === verificationMethod` to return the **correct per-sphere
  pubkey**. Exposed anonymously at **`api.aithos.be/mcp/primitives/read`**.
- The data/assets **PDS just doesn't call it** — `data-backend/lambda/auth/did-resolver.ts`
  `resolveDidAithos()` synthesizes a doc mapping all spheres to the root pubkey
  (audit MEDIUM "did:aithos resolver stubbed").

So the work is: (1) add the `#data` sphere to identities + DID doc, (2) let the
registry accept a DID doc carrying `#data`, (3) make the PDS resolve the **real**
published DID doc, (4) sign data ops under `#data` in the SDK, (5) demonstrate it
in the example app with a real did:aithos account.

## Decisions (validated)

1. **`#data` is eager for new identities, optional for legacy.** `createIdentity`
   generates a `#data` keypair from the start; the `Identity.data` field and the
   keystore/recovery `data` seed are **optional** so existing 4-key identities and
   recovery files still load. `buildDidDocument` emits the `#data` VM + `#data-kex`
   keyAgreement entry only when the identity has a `#data` sphere. (Spec note: the
   spec describes `#data` added lazily on first `create_collection`; we generalize
   to "present from creation for new identities, lazily addable for legacy" — a
   spec amendment to `spec/data/02-key-hierarchy.md` §2.2.)
2. **Keep both paths in the example app.** `did:key` (dev: single key, `#data`
   resolves via the resolver alias already added) **and** a real `did:aithos`
   account (prod: distinct `#data` key, resolved from the published DID doc).
3. **PDS resolves via HTTP**, not direct S3. The PDS Lambda calls
   `api.aithos.be` `aithos.get_identity`, verifies the DID doc's **root proof**,
   extracts the requested sphere pubkey, and **caches** it. Decoupled, no
   cross-account S3/IAM.

## Invariants to preserve

- `did.ts` `SPHERE_FRAGMENTS = [public, circle, self]` stays the **3 Ethos
  spheres** — `#data` is a separate, optional 4th key, NOT added to that tuple
  (Ethos zone logic and the DID-doc "exactly 3 Ethos VMs" shape depend on it).
- Backward compat: identities/recovery files/keystores without `#data` keep
  working (load, sign Ethos, sign data under `#root` as today).
- No wire-format change to envelopes; conformance + byte snapshots stay green.

## Phases

- **A — protocol-core.** `Identity.data?: KeyPair`; `createIdentity` generates it;
  `StoredSeed.role` gains `"data"`; `writeIdentityToDisk`/`loadIdentity` handle the
  optional 5th seed; `buildDidDocument` adds `#data` VM + `#data-kex` when present;
  relax `verifyDidDocument` to tolerate the optional `#data` entry. Tests + bump +
  `npm publish` (token in hand).
- **B — Ethos platform (innoesate).** `primitives-write` `publish_identity` (and any
  DID-doc validator in `shared`) accept the optional `#data` VM/`#data-kex`.
  Code-only → push `main` → **CD auto-deploys** (`deploy-aithos-platform`).
- **C — PDS (Aithos-protocol, data + assets backend).** Replace the stub
  `resolveDidAithos` with an HTTP fetch of `api.aithos.be` `get_identity` (verify
  root proof, extract sphere pubkey, cache). CDK env for the resolver URL +
  network. **`cdk deploy` (maintainer).**
- **D — SDK.** `StoredOwnerKeys.seedsHex.data`; owner data client signs under
  `#data` (and CMK kex = `kex(data seed)`); expose a ready-made owner data client
  from the signed-in session. Bump + publish.
- **E — example app.** A route/section owning a collection under a real signed-in
  `did:aithos` account (signs `#data`), demonstrating the correct pattern; keep a
  documented `did:key` path. Tick `aithos-app-example/TODO-did-aithos-data-sphere.md`.

## Deploy / publish ownership

- Code + commits (5 repos) + `npm publish` (@aithos/*) + Ethos platform code (via
  CD on `main`): automated.
- `terraform apply` (platform infra) + PDS `cdk deploy` (no CD on Aithos-protocol):
  maintainer. (A PDS OIDC `cdk deploy` CD workflow is a possible follow-up.)
