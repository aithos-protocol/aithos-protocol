# 9 · Local store — owned and tracked identities

## 9.1 Overview

The preceding chapters define the wire formats: the DID document (ch. 1), the ethos document (ch. 2), the `.ethos` bundle (ch. 3), mandates (ch. 4), signatures (ch. 5). This chapter defines the **on-disk layout of a local Aithos CLI keystore** and the semantics of operations against it.

Two classes of identity live side-by-side in a keystore:

- **Owned identities.** The keystore holds the sphere seed files and can therefore sign, decrypt, and issue mandates.
- **Tracked identities.** The keystore holds only the public artifacts of another subject's identity — their DID document and (optionally) a received ethos bundle. The user can read the public zone, verify signatures, and, when holding the right mandates, read further zones or author gamma entries (§10) via delegate keys.

A tracked identity is indistinguishable from an owned one on the wire. The distinction exists entirely at the storage layer: presence or absence of sealed seed files.

## 9.2 Filesystem layout

```
$AITHOS_HOME/                 (default: ~/.aithos)
├── config.json
├── identities/
│   ├── <owned-handle>/
│   │   ├── did.json
│   │   ├── root.sealed.json
│   │   ├── public.sealed.json
│   │   ├── circle.sealed.json
│   │   ├── self.sealed.json
│   │   └── ethos/
│   │       ├── manifest.json
│   │       ├── public/public.md
│   │       ├── circle/circle.md.enc
│   │       ├── self/self.md.enc
│   │       ├── signatures/<sec_id>.json
│   │       └── history/
│   └── <tracked-handle>/
│       ├── did.json
│       └── ethos/
│           ├── manifest.json
│           ├── public/public.md
│           ├── circle/circle.md.enc
│           ├── self/self.md.enc
│           └── signatures/<sec_id>.json
├── mandates/<mandate_id>.json
└── revocations/<revocation_id>.json
```

Two things to note.

First, the **native `ethos/` subtree has the same shape for owned and tracked identities.** This is deliberate: every ethos-manipulating command (`list`, `show`, `verify`, and for tracked-with-write-mandate, `add-section` / `add-revision`) reads the same layout regardless of whether the identity is owned. The only difference is whether sealed seed files are present, and therefore whether signing / decryption with a sphere key is possible.

Second, **an unpacked bundle is NOT the native layout.** The bundle (ch. 3) is flat: `manifest.json`, `public.md`, `circle.md.enc`, etc. at the bundle root. The native layout nests them under `ethos/<zone>/`. An explicit **install** step (§9.3) transforms one into the other.

## 9.3 Install — converting a received bundle into a tracked identity

```
aithos ethos install <path> [--as <handle>] [--verify-only] [--force]
```

Input: `<path>` is either a `.ethos` zip file or a directory containing an already-unpacked bundle (layout per ch. 3).

Behavior:

1. Parse the bundle's `manifest.json` and `did.json`.
2. Run the stateless verify algorithm (§9.4) over the bundle. If it fails, the install aborts and no files are written under `identities/`.
3. Determine the target handle: `--as <handle>` if provided, otherwise `manifest.subject_handle`. If an identity with that handle already exists, abort unless `--force` is passed.
4. Under `identities/<handle>/`, write:
   - `did.json` (copied from the bundle)
   - `ethos/manifest.json` (copied)
   - `ethos/public/public.md` (copied, LF line endings preserved)
   - `ethos/circle/circle.md.enc` if the bundle has one
   - `ethos/self/self.md.enc` if the bundle has one
   - `ethos/signatures/<sec_id>.json` for each entry under the bundle's `signatures/`
   - `ethos/history/` (empty — tracked identities do not keep local per-edition history; the manifest's edition chain is the reference)
5. The bundle source is not mutated. It may be deleted by the caller after install.

With `--verify-only`, steps 1–2 run and the result is reported; step 3–4 are skipped.

After install, the identity is listable via `list identities`, introspectable via `show <handle>`, and usable with every `ethos` subcommand. The identity is marked tracked because no `*.sealed.json` files are written.

## 9.4 Stateless verify — `ethos verify --path`

```
aithos ethos verify --path <dir|ethos-zip> [--no-decrypt]
```

The existing `ethos verify --handle <h>` operates on an installed identity. This sibling form operates on a bundle directly, without touching the keystore. It runs the integrity checks from §3.8 (steps 1–8) against the bundle, returning a structured result.

Step 9 (inter-edition link verification against a predecessor) is **not** performed by `verify --path` because the predecessor lives in the keystore, not the bundle. Verifiers that want edition-chain walking after install can use `verify --handle <h>` once the bundle is installed.

Scope of stateless verification. The zone signatures of §3.3.1 and the section chain signatures of §2.5.4.2 are computed over **plaintext**. Without a key to decrypt `circle.md.enc` / `self.md.enc`, a stateless verifier cannot verify those signatures. `verify --path` performs the checks that do not require plaintext:

- §3.8 check 1 — ZIP extracts, required entries present, forbidden entries absent.
- §3.8 check 2 — manifest parses and validates against the schema.
- §3.8 check 3 — `did.json` root signature verifies.
- §3.8 check 4 — `sha256_of_did_json` matches the bundle's `did.json` bytes.
- §3.8 check 6 — `integrity.manifest_signature` verifies against the subject's `#public` sphere key. This is the subject's cryptographic commitment to the manifest — including each encrypted zone's `sha256_of_plaintext`, section titles, and wraps. A valid manifest signature means every value in the manifest was endorsed by the subject; it does not prove that the ciphertext decrypts to a plaintext whose hash equals that commitment.
- §3.8 check 8 — edition self-consistency.
- §3.8 check 5 and check 7 — **fully** for the `public` zone (plaintext available); **not** for encrypted zones.

For encrypted zones, the stateless report enumerates each zone's declared `section_titles` and wrap recipients, marks content checks as `skipped (encrypted; no decryption key)`, and records the manifest signature as the anchor of trust for those zones' declarations.

Explicit `--no-decrypt` is accepted as a no-op: stateless verify is always no-decrypt.

Exit codes:

- `0` — bundle valid.
- `1` — bundle invalid (one or more integrity checks failed).
- `2` — bundle unparseable (not a zip, malformed manifest, missing required entries).

## 9.5 Mandate intake — `aithos mandate add`

```
aithos mandate add <path>  [--handle <h>]
aithos mandate remove <id>
```

Mandates arrive in three ways:

- **Owned-issued.** You generated the mandate yourself via `aithos grant`. The CLI already stored it under `~/.aithos/mandates/`.
- **Bundled.** The mandate was shipped inside a `.ethos` bundle under a `mandates/` directory (see §9.8). On `install`, the bundle's mandates are evaluated and copied into `~/.aithos/mandates/` if they are destined to you.
- **Out-of-band.** The mandate was delivered to you separately (email, message, USB key, HTTP endpoint). You receive a single JSON file, the mandate document of §4.2.

`mandate add` handles the third case. It takes a path to a mandate JSON file and performs the following:

1. Parse the JSON as a mandate document (ch. 4).
2. Resolve the issuer's DID (from `mandate.issuer`). If the issuer is already installed as a tracked or owned identity in the keystore, use the local `did.json`. Otherwise the command requires the issuer's DID document to be already available; we do not fetch from the network at v0.1.0.
3. Verify `mandate.issued_by_key` is a sphere key of the issuer and matches `mandate.actor_sphere`.
4. Verify the mandate's Ed25519 signature over its canonical form (§5.1.2).
5. Verify the mandate's time window: `not_before < not_after`; if `--at T` is passed, additionally require `T ≤ not_after`.
6. Verify that the mandate names **us** as grantee. Matching rules:
   - If `grantee.id` is a `did:aithos:…` DID, it must match one of our owned identities' root DIDs (or, if `--handle <h>` is passed, specifically that identity's root DID).
   - If `grantee.id` is `urn:aithos:agent:<name>@<host>` and `grantee.pubkey` is set, we match if we hold the corresponding delegate keyfile locally (see §9.6).
   - If neither matches, abort: the mandate is not for us, and silently storing someone else's mandate would be misleading.
7. Check that `mandate.id` is not already present locally. If so, abort unless the on-disk copy and the new one are byte-identical (idempotent re-add is allowed).
8. Check the local revocations directory for a matching revocation. If revoked, report and abort; the operator may pass `--allow-revoked` to store the mandate as inert history (rare; useful for audit trails).
9. Write the mandate to `~/.aithos/mandates/<mandate_id>.json` with mode 0600.

On success, print a summary: issuer DID, grantee id, actor sphere, scopes, TTL, and the local storage path.

`mandate remove <id>` is the symmetric operation for the recipient: it deletes the local copy of a mandate from `~/.aithos/mandates/`. It does NOT issue a revocation — revocation is a distinct operation reserved for the mandate's issuer (ch. 4). Removal is purely local bookkeeping; any counterparty still holding the mandate remains capable of presenting it.

## 9.6 Capability resolution

Every ethos operation against an identity `H` resolves capabilities in this order:

1. **Owned-key path.** If `identities/<H>/` contains all sealed seed files, the identity is owned and every operation proceeds with full authority.
2. **Tracked-with-mandate path.** If the identity is tracked, the CLI searches `~/.aithos/mandates/` for a mandate with:
   - `issuer` matching `did` of identity `H`,
   - scopes matching the operation being attempted,
   - time window covering the current wall-clock time,
   - not revoked per `~/.aithos/revocations/`.

   When a matching mandate is found, it is used. For **read** operations on circle or self, the mandate's grantee must additionally be a recipient of the zone's AEAD wraps (§3.5); otherwise the mandate grants read *intent* but not *capability*, and the operation is reported as "authorized but ciphertext unavailable to this agent". For **write** operations (add-section, add-revision), `grantee.pubkey` must be set and a local delegate keyfile matching that public key must be resolvable (§9.7); the revision is signed with that key per §4.5.4.

3. **Public-only path.** If neither of the above applies, the public zone is readable by anyone and all operations scoped to public succeed without a mandate. Operations on circle/self return a clear "no access key for <zone> zone" error.

The resolver chooses mandates deterministically: if multiple mandates match, the longest-lived covering the operation is preferred, ties broken by most-recently-issued. The user may force a specific mandate with `--mandate <id>` on any command that accepts it.

## 9.7 Delegate keyfiles

A delegate keyfile binds a local Ed25519 private key to an agent identifier (matching `grantee.id` in a mandate). The existing `aithos delegate-key --out <path>` command produces such files with shape:

```json
{
  "aithos-delegate-key": "0.1.0",
  "id": "urn:aithos:agent:laptop@mac-john-doe",
  "public_multibase": "z6Mk…",
  "seed_hex": "…",
  "created_at": "2026-04-19T08:14:23Z"
}
```

Keyfiles are passed explicitly to write-scoped commands via `--agent-key <path>`. The CLI does not index keyfiles in a global registry at v0.1.0 — the operator is expected to keep track of which keyfile corresponds to which agent.

A future version (§9.10) may add a `delegate-keys/` subdirectory under `$AITHOS_HOME` with an index for automatic resolution. For v0.1.0, explicit paths are the contract.

## 9.8 Bundled mandates (bundle extension)

The `.ethos` bundle layout (ch. 3) is extended with an OPTIONAL `mandates/` directory:

```
<subject>.ethos
├── manifest.json
├── did.json
├── public.md
├── circle.md.enc
├── self.md.enc
├── signatures/
├── mandates/                         ← OPTIONAL, added in v0.2 of the bundle layout
│   └── <mandate_id>.json
└── README.txt
```

Bundled mandates are mandates the subject issued to the bundle's recipient, packaged with the bundle so the recipient gets both the data and the capability in one artifact.

On `aithos ethos install`, each file under `mandates/` is evaluated per the `mandate add` rules (§9.5). Mandates where the grantee is **us** are copied into `~/.aithos/mandates/`. Mandates whose grantee is someone else are ignored (they are not errors — they may have been included for context — but they are not stored).

Bundles without a `mandates/` directory are backwards-compatible with v0.1.0 readers: the directory is purely additive.

## 9.9 Effective capability display

`aithos show <handle>` is extended to report, after the existing identity metadata, the effective per-zone capabilities of the current keystore against that identity:

```
Capabilities (resolved now, 2026-04-20T07:30:00Z):
  public  read ✓    write ✗                  (public is world-readable; no write mandate)
  circle  read ✓    write ✓  (via m_01JG4X…) (delegate key urn:aithos:agent:laptop@…)
  self    read ✗    write ✗                  (no mandate, no key recipient)
```

The display is derived entirely from the resolver of §9.6. For owned identities it collapses to `read ✓ write ✓` on every zone with the annotation `(owned)`.

`--json` emits the same information in machine-readable form.

## 9.10 Deferred

The following items are identified but deferred past v0.1.0:

- **Delegate-key index.** §9.7's manual `--agent-key` path is serviceable; an index under `$AITHOS_HOME/delegate-keys/` with lookup by `grantee.id` would eliminate the need to pass paths explicitly.
- **Network DID resolution.** `mandate add` currently requires the issuer's DID document to be already local. A `did:aithos` resolver that fetches from a subject's canonical URL or service endpoint would complete the flow.
- **Revocation list freshness.** The resolver of §9.6 consults `~/.aithos/revocations/` as a static snapshot. For time-sensitive operations, a freshness check (refresh the list from the issuer's revocation endpoint before binding actions) is expected, tracked in §4.10.
