# 8 · Audit

## 8.1 Overview

Every state-changing operation in the assets sub-protocol emits a
signed entry in the **gamma log**. The gamma log is the same
hash-chained mutation log used by the Ethos protocol (chapter 10 of the
Ethos spec) and the data sub-protocol (chapter 08 of data). The assets
sub-protocol extends the gamma operation vocabulary with `assets.*`
ops; the chain itself is unchanged.

A subject's gamma log is a single chronological sequence per subject,
shared across all sub-protocols. An auditor reading the log sees Ethos
mutations, data mutations, and asset mutations interleaved in the order
they actually occurred — which is the natural ground truth.

## 8.2 The single-chain principle

The Ethos spec §10.2 defines the gamma log as a single chain per
subject. The data sub-protocol's chapter 08 reiterates this and adds
its own ops. The assets sub-protocol follows the same convention: there
is **one** gamma chain per `subject_did`, and asset operations append
to it.

Storage-wise, the reference implementation hosts the data and asset
gamma entries in the same DynamoDB `gamma` table that the data
sub-protocol uses (the `assets-pds-stack` deployment shares the table
with `data-pds-stack`). Entries are distinguished by their `op` field.
A subject who runs both an Ethos and asset PDS sees the Ethos gamma
entries (in their Ethos backend's table) and the data+asset gamma
entries (in the data backend's table) as two chains that need to be
**merged at read time** to reconstruct the single canonical chain.

> **Decision (revisable):** v0.1 keeps the Ethos chain and the
> data+asset chain in two distinct tables, requiring merge at read.
>
> **Rationale.** Operational separation between the Ethos backend and
> the data+asset backend was the choice in earlier sub-jalons. Merging
> chains at read is cheap (each table's entries already carry
> chronological ULIDs).
>
> **Alternative.** Unify in a single gamma service responsible for
> the chain across all sub-protocols. Cleaner conceptually; adds a
> third stack.
>
> **Pending review.** Will revisit once both backends are stable. The
> spec is written assuming the unified-view abstraction; storage is
> an implementation concern.

## 8.3 Operation vocabulary

The assets sub-protocol contributes the following operations:

| Op | When emitted | Payload (canonical fields) |
|---|---|---|
| `assets.upload_initiated` | `init_upload` returns a miss (fresh upload) | `{ urn, media_type, size_bytes, sha256_of_plaintext, attached_context }` |
| `assets.created` | `complete_upload` succeeds | `{ urn, media_type, size_bytes, sha256_of_plaintext, encrypted, recipients_count, attached_context }` |
| `assets.upload_aborted` | `abort_upload` called | `{ urn, reason? }` |
| `assets.referenced` | `ref_asset` succeeds for a new (kind, sub-id) tuple | `{ urn, reference }` |
| `assets.unreferenced` | `unref_asset` removes an entry | `{ urn, reference }` |
| `assets.orphaned` | `referenced_by[]` becomes empty | `{ urn }` |
| `assets.authorize_grantee` | `authorize_grantee` succeeds | `{ urn, recipient, mandate_id }` |
| `assets.revoke_grantee` | `revoke_grantee` succeeds | `{ urn, recipient, mandate_id, rotated: bool }` |
| `assets.amk_rotated` | `rotate_amk` succeeds | `{ urn, old_wraps_hash, new_wraps_hash, encryption_nonce_changed: true }` |
| `assets.rotate_owner_wrap` | `rotate_owner_wrap` succeeds | `{ urn, old_owner_recipient, new_owner_recipient }` |
| `assets.tombstoned` | Transition to TOMBSTONED state | `{ urn, reason: "explicit_delete" \| "retention_window_elapsed" }` |
| `assets.purged` | Transition to GONE | `{ urn }` |
| `assets.imported` | `import_asset` succeeds | `{ urn, imported_from_urn, exported_by, signature_verified: true }` |
| `assets.exported` | `export_asset` job completes | `{ urn, exported_at, include_history }` |

## 8.4 Entry shape

Every entry follows the standard gamma entry envelope (Ethos
§10.4.1):

```json
{
  "aithos": "0.2.0",
  "id": "gamma_01J…",
  "subject_did": "did:aithos:z6Mkr…",
  "at": "2026-05-10T08:14:23Z",
  "prev_gamma_hash": "sha256:…",
  "op": "assets.created",
  "payload": {
    "urn": "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…",
    "media_type": "image/png",
    "size_bytes": 184320,
    "sha256_of_plaintext": "a8b2f1ef…",
    "encrypted": true,
    "recipients_count": 1,
    "attached_context": { "kind": "ethos", "zone": "self" }
  },
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#self",
    "value": "z9V…"
  },
  "authorized_by": null
}
```

`prev_gamma_hash` is the SHA-256 of the JCS-canonical form of the
previous entry's full envelope, chaining all entries together
regardless of which sub-protocol produced them.

`signature` is over the JCS-canonical form of the envelope with
`signature.value` blanked. The signing key is the sphere key
corresponding to the attaching context (e.g. `#self` for assets
attached to the self zone, `#data` for assets attached to data
collections), or a delegate key when the entry is produced under a
mandate.

`authorized_by` carries the mandate ID when the entry is produced by
a grantee acting under a mandate; otherwise `null`.

## 8.5 Cross-protocol references in gamma payloads

Several `assets.*` entries reference state in other sub-protocols:

- `assets.referenced` and `assets.unreferenced` carry an Ethos
  edition URN or a data record URN.
- `assets.authorize_grantee` carries a mandate ID, which the auditor
  can resolve to a mandate document published by the Ethos
  sub-protocol.

A full audit walk traverses the gamma chain and resolves these
references against the relevant sub-protocols' stores. The references
are not normatively cycle-detected — a malicious construct that loops
`assets.referenced → ethos.section.modify → assets.referenced` would
be detectable by the standard "no edition referenced before its
publication" check applied to the chain.

## 8.6 Auditor procedure for an asset's life

To reconstruct the complete history of one asset:

1. Walk the gamma chain forward from the subject's genesis entry,
   filtering on `payload.urn == <target>`.
2. Verify each entry's signature against the key declared in
   `signature.key`, which must be a key valid for the subject at the
   entry's `at` timestamp (look up the DID document history).
3. Verify `prev_gamma_hash` matches the SHA-256 of the prior entry's
   canonical envelope.
4. Cross-reference each `assets.referenced` against the consuming
   sub-protocol's state at the referenced height/timestamp.

A clean audit yields an ordered list of state transitions matching the
state machine in §1.2.4, plus the recipient set's evolution over time.

The audit MAY be done locally if the subject ships their gamma log
alongside the asset metadata document (chapter 07's export
`--include-history` mode), or remotely via
`aithos.assets.list_gamma_entries` (§8.8 below).

## 8.7 Privacy of audit entries

Gamma entries are signed and chain-locked, but they are not
encrypted. Their `payload` fields are visible to anyone with access
to the gamma log.

The asset audit entries' payloads carry:

- The asset URN (which embeds the subject DID).
- The `media_type`, `size_bytes`, `sha256_of_plaintext`.
- The attached context (zone, section, collection).
- The recipient set's size (`recipients_count`).
- Mandate IDs (which embed the grantee's identity).

A subject who wants to keep audit details opaque to platform operators
has limited options at the protocol layer; the v0.3 plan for
per-section encryption in Ethos has a parallel proposal
(`gamma-v0.3-per-entry-envelopes.md`) for per-entry encryption of
gamma payloads. Once that lands, assets gamma payloads will benefit
from the same opacity. v0.1 of assets does not introduce its own gamma
encryption.

The threat model (chapter 09 §9.3) treats the audit log as
platform-visible by default.

## 8.8 Read primitive

### 8.8.1 `aithos.assets.list_gamma_entries`

List gamma entries filtered to the assets sub-protocol's ops.

Input:

```ts
interface ListGammaEntriesInput {
  subject_did: string;
  op_prefix?: string;           // e.g. "assets." or "assets.amk_"
  urn?: string;                 // restrict to entries for one asset
  since?: string;               // RFC 3339 timestamp
  until?: string;
  limit?: number;
  cursor?: string;
  verify?: boolean;             // if true, server returns per-entry signature verification result
}
```

Output: `Page<GammaEntry>` (per §8.4) with optional `verification`
field on each entry when `verify: true` was passed.

The platform MAY require authentication for non-public subjects;
asset gamma entries are typically considered audit-private even when
the asset itself is public, because the audit reveals the subject's
activity timing.

## 8.9 Sanity invariants

A conformant implementation MUST satisfy these invariants:

- For every `assets.created`, there is no prior `assets.created` for
  the same URN (URN uniqueness within the chain).
- For every `assets.referenced`, the `(urn, reference)` tuple is
  unique within the open-reference window (no double-ref without an
  intervening unref).
- The recipient counts implied by `assets.authorize_grantee` and
  `assets.revoke_grantee` events match the materialized
  `amk_envelope.wraps.length` at any point.
- A `assets.tombstoned` is the last entry for that URN before any
  `assets.purged`; no other `assets.*` entries appear for that URN
  after `assets.purged`.

Audit tooling that processes the chain MAY use these invariants as
checksums; a violation is evidence of corruption or tampering and
MUST be surfaced.

---

Next: [chapter 09 — Threat model](./09-threat-model.md).
