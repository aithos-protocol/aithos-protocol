# @aithos/cli

Reference CLI for the Aithos protocol (v0.2.0).

This tool creates and manages Aithos identities, issues and revokes mandates, and verifies signed artifacts. It is a **reference implementation** — small, readable, pinned to the v0.2.0 spec. It is not hardened for production: seeds are stored as plaintext JSON files on disk, protected only by Unix permissions. See the security note at the bottom.

## Install

Requires Node.js ≥ 20.

```bash
cd cli
npm install
npm run build
npm link          # optional; exposes `aithos` on your PATH
```

Or run directly without linking:

```bash
node dist/index.js <command> …
```

## The thirty-second tour

```bash
# 1. Create an identity (root + three sphere keys + signed DID document)
#    AND its live ethos in one step. Pass --no-ethos for headless/service
#    identities that will only sign mandates.
aithos init --handle mathieu --display-name "Mathieu Colla"

# 2. Inspect.
aithos show
aithos list identities

# 3. Grant a weekly read+reply mandate to a local Gmail agent.
aithos grant urn:aithos:agent:gmail-agent@macbook-mathieu \
  --sphere circle \
  --scope ethos.read.public,ethos.read.circle,email.reply \
  --ttl 7d \
  --label "Personal Gmail agent"

# 4. Mint a delegate key, then issue a write mandate for a secondary device.
aithos delegate-key --out ~/phone.aithos.key --id urn:aithos:agent:phone@pixel
aithos grant urn:aithos:agent:phone@pixel \
  --sphere circle \
  --scope ethos.write.circle \
  --pubkey <multibase-from-previous-step> \
  --ttl 90d

# 5. List what you've issued.
aithos list mandates

# 6. Verify a mandate.
aithos verify ~/.aithos/mandates/mandate_01JG….json

# 7. Revoke one.
aithos revoke mandate_01JG… --reason device_sold

# 8. Or revoke them all (preview first, confirm with --yes).
aithos revoke --all --reason incident
aithos revoke --all --reason incident --yes

# 9. Nuclear option: rotate a sphere key.
aithos rotate --sphere circle --reason key_compromise --yes
```

## Commands

| Command | Purpose |
|---|---|
| `init` | Create a new Aithos identity **and** initialize its ethos. Pass `--no-ethos` to skip the ethos init (headless/service identities). |
| `show` | Print identity metadata (DID, sphere keys, X25519 keys). |
| `show-mandate <id>` | Pretty-print a mandate with derived status (`active` / `expired` / `revoked`). |
| `list <kind>` | List local identities, mandates, or revocations. |
| `grant` | Issue a signed mandate. |
| `delegate-key` | Generate a fresh Ed25519 keypair for a write mandate's delegate. |
| `revoke` | Revoke a previously-issued mandate (or `--all` to revoke every local mandate, filterable by sphere/agent). |
| `rotate` | Rotate a sphere key — the kill-switch. Invalidates every mandate signed by the old key, including any you could not enumerate. |
| `verify` | Verify a mandate, revocation, or action artifact. |
| `sign-action` | Emit or counter-sign an action artifact (agent-side / subject-side). |
| `ethos <sub>` | Manage the live ethos document — `init` (only needed after `init --no-ethos` or to reset), `add-section`, `modify-section`, `delete-section`, `show`, `list`, `verify`, `pack`, `unpack`, `install`. |
| `gamma <sub>` | Walk and verify the signed mutation log — `show`, `verify`. Every add/modify/delete is a signed entry here; the live ethos holds only the current state. |

Run `aithos <cmd> --help` for per-command flags.

## Storage layout

```
~/.aithos/
├── config.json
├── identities/
│   └── mathieu/
│       ├── did.json
│       ├── root.sealed.json
│       ├── public.sealed.json
│       ├── circle.sealed.json
│       └── self.sealed.json
├── mandates/
│   └── mandate_01JG….json
└── revocations/
    └── revocation_01JG….json
```

`AITHOS_HOME` overrides `~/.aithos`. Every JSON file is written with mode `0600`; directories with `0700`.

## Tracked identities (read-only)

An identity directory that contains `did.json` and an `ethos/` folder but **no** `*.sealed.json` files is a **tracked** identity. You hold someone else's public material — enough to read their public zone and verify every signature they ever emitted — but you hold none of their private sphere keys, so you cannot decrypt the encrypted zones, sign mandates on their behalf, or record mutations to their ethos. This is the intended mode for subscribing to someone's published ethos.

The CLI and the MCP server both auto-detect this state via `isTrackedIdentity(handle)` and downgrade gracefully rather than crashing when a sealed-seed file is missing:

```
$ aithos list identities
HANDLE       DID                                                                 DEFAULT
alice        did:aithos:z6Mki3B3WV4g42PpB6NfPfqFDNufSm2KxPAMraouw9U1FJjV  [tracked]

$ aithos show alice
Handle:         alice  [tracked — public data only]
…

$ aithos ethos list --handle alice
[handle=alice] [tracked] Ethos sections
ZONE    │ ID               │ GAMMA_REF                        │ UPDATED                  │ TITLE
────────┼──────────────────┼──────────────────────────────────┼──────────────────────────┼─────
public  │ sec_9ae63416bf2a │ gamma_01JG4X7R…                  │ 2026-04-19T11:11:10.864Z │ Public Bio

  (circle: encrypted — no sphere key (identity is tracked-only))
  (self: encrypted — no sphere key (identity is tracked-only))

$ aithos ethos verify --handle alice
[handle=alice] [tracked — public-only verify] ethos: OK
  warning: zone circle: skipped content checks (encrypted, no sphere key available) — manifest declares 1 section(s)
  warning: zone self: skipped content checks (encrypted, no sphere key available) — manifest declares 1 section(s)
```

Write operations (`ethos add-section`, `ethos modify-section`, `ethos delete-section`, `grant`, `rotate`, `revoke`, `sign-action`) refuse cleanly with a `TrackedIdentityError` that lists exactly which sealed seed files are missing. The encryption boundary is enforced by the protocol, not by the CLI: even if you manipulate the on-disk state, you cannot read circle/self ciphertext without the sphere's X25519 private key.

## Write mandates

`ethos.write.{public,circle,self}` scopes authorize a **delegate key** — a separate Ed25519 keypair generated with `aithos delegate-key` — to record mutations to the named zone on the subject's behalf. The sphere key never leaves the primary device; it signs the mandate once, and the delegate key does the day-to-day signing of gamma entries. Revoking the mandate with the sphere key terminates the delegate's authority. Past gamma entries remain in the chain (append-only), but the subject MAY publish a follow-up gamma entry (a new modify-section or delete-section) if they wish to repudiate.

See [spec §4.5.4](../../spec/04-mandates.md#454-write-mandate-delegated-authoring) and [§10](../../spec/10-gamma.md) for the full protocol semantics.

### Revocation is prospective

Revoking a mandate terminates its authority going forward. Gamma entries that were signed *while the mandate was still valid* remain valid forever — the log is append-only, and the integrity check treats those entries as sound. `ethos verify` and `gamma verify` will emit an informational **warning** identifying entries signed by a since-revoked mandate, but will not mark the ethos as failed. Conversely, an entry whose timestamp falls **on or after** the revocation timestamp — or outside the mandate's `not_before`/`not_after` window — is rejected by both the write path and the verifiers, because it violates the protocol invariant.

If a subject wants to repudiate what a revoked mandate wrote, they publish a follow-up gamma entry (modify-section or delete-section) signed by their sphere key. The log is never rewritten.

## Security note (v0.2.0)

This CLI stores sphere-key seeds as **plaintext JSON** under `~/.aithos/`, protected only by filesystem permissions. That is acceptable for a developer preview on a trusted device. It is **not** acceptable for production.

A subsequent minor release MUST add passphrase-sealed seeds using Argon2id + XChaCha20-Poly1305 as specified in §1.4.3 of the protocol. Until then, treat `~/.aithos/` as you would an SSH key directory: do not back it up to untrusted services, do not copy it across machines without a secure channel, and do not run this CLI on shared infrastructure. Note that the gamma log itself is already sealed at rest under the self sphere key.

## License

Apache-2.0. See [../LICENSE](../LICENSE).
