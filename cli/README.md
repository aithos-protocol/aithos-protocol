# @aithos/cli

Reference CLI for the Aithos protocol (v0.1.0).

This tool creates and manages Aithos identities, issues and revokes mandates, and verifies signed artifacts. It is a **reference implementation** — small, readable, pinned to the v0.1.0 spec. It is not hardened for production: seeds are stored as plaintext JSON files on disk, protected only by Unix permissions. See the security note at the bottom.

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
| `ethos <sub>` | Manage the live ethos document — `init` (only needed after `init --no-ethos` or to reset), `add-section`, `add-revision`, `show`, `list`, `verify`, `pack`, `unpack`. |

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

## Write mandates

`ethos.write.{public,circle,self}` scopes authorize a **delegate key** — a separate Ed25519 keypair generated with `aithos delegate-key` — to append revisions to the named zone on the subject's behalf. The sphere key never leaves the primary device; it signs the mandate once, and the delegate key does the day-to-day signing. Revoking the mandate with the sphere key terminates the delegate's authority. Past revisions remain in the chain (append-only), but the subject MAY publish a redaction revision naming them by hash if they wish to repudiate.

See [spec §4.5.4](../spec/04-mandates.md#454-write-mandate-delegated-authoring) and [§2.5.4](../spec/02-ethos.md#254-revisions--the-per-section-hash-chain) for the full protocol semantics.

### Revocation is prospective

Revoking a mandate terminates its authority going forward. Revisions that were signed *while the mandate was still valid* remain valid forever — the hash chain is append-only, and the integrity check treats those revisions as sound. `ethos verify` will emit an informational **warning** identifying revisions signed by a since-revoked mandate, but will not mark the ethos as failed. Conversely, a revision whose timestamp falls **on or after** the revocation timestamp — or outside the mandate's `not_before`/`not_after` window — is rejected by both the write path and `ethos verify`, because it violates the protocol invariant.

If a subject wants to repudiate what a revoked mandate wrote, they publish a follow-up redaction revision signed by their sphere key. The history is never rewritten.

## Security note (v0.1.0)

This CLI stores seeds as **plaintext JSON** under `~/.aithos/`, protected only by filesystem permissions. That is acceptable for a developer preview on a trusted device. It is **not** acceptable for production.

A v0.1.1 follow-up MUST add passphrase-sealed seeds using Argon2id + XChaCha20-Poly1305 as specified in §1.4.3 of the protocol. Until then, treat `~/.aithos/` as you would an SSH key directory: do not back it up to untrusted services, do not copy it across machines without a secure channel, and do not run this CLI on shared infrastructure.

## License

Apache-2.0. See [../LICENSE](../LICENSE).
