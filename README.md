<a href="https://www.aithos.be"><img src="./assets/logo.svg" alt="" align="right" width="64" height="64"></a>

# Aithos Protocol

> **An open protocol for portable digital ethos.**
> One human. One digital incarnation. Owned by no platform.

Project home: <https://www.aithos.be>

Aithos lets a person publish a signed, versioned, zone-partitioned description of themselves — their *ethos* — that any AI agent can read, under rules the person sets. The person can grant a time-bounded, scoped mandate to a specific agent and revoke it. The agent's actions, when taken under that mandate, are cryptographically attributable.

**Status: v0.2.1.** Spec is stabilizing. CLI is a working reference implementation. v0.2.0 promoted the signed **gamma log** (append-only, hash-chained, Ed25519-signed, sealed under the self sphere) to the sole authority on section mutation history — the per-section `revisions[]` chain from v0.1.x is gone. v0.2.1 closes the loop on **delegated writes against a tracked identity**: a delegate produces a fully verifiable edition (signed manifest, signed gamma entries, sealed zones) without ever holding the owner's sphere seeds, and the owner pulls that edition back in with `aithos ethos install --force`. Nothing is frozen yet.

## Start here

- **[WHITEPAPER.md](./WHITEPAPER.md)** — the founding text. Read this first if you want the *why*.
- **[SPEC.md](./SPEC.md)** — normative protocol specification (index).
- **[cli/](./cli/)** — the `aithos` CLI reference implementation.
- **[ROADMAP.md](./ROADMAP.md)** — what's next, what's not, and how the pieces fit.
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — how to engage if you want to help.

## Currently in design

The protocol is still evolving and several proposals are in active design. They are versioned under [`spec/drafts/`](./spec/drafts/) and open for review:

- **[Bundle v0.3 — per-section encryption](./spec/drafts/bundle-v0.3-per-section-encryption.md)** — split each zone into per-section blobs (one ciphertext file per section in `circle` and `self`, one plaintext markdown file per section in `public`). Editing one section costs O(section size) instead of O(zone size). Symmetric across all three zones.
- **[Gamma v0.3 — per-entry envelopes](./spec/drafts/gamma-v0.3-per-entry-envelopes.md)** — split append capability from read capability in the gamma log, so a write-delegate no longer gets retroactive read access to the subject's history. Adds a new `gamma.read` scope.
- **Section-level mandates** *(companion draft, in design)* — extend the mandate scope grammar to address individual sections (`ethos.write.self#gmail:*`). Builds on per-section encryption.

See [`spec/drafts/README.md`](./spec/drafts/README.md) for the full draft index and lifecycle, and [`ROADMAP.md`](./ROADMAP.md) for how these fit into the broader trajectory toward v1.0.

Comments, critique, and pull requests are welcome on every draft. Open an issue to start a discussion or propose changes directly on a draft.

## In a paragraph

An **ethos** is a versioned document describing a person in three zones: `public` (readable by anyone), `circle` (encrypted, readable by anyone holding a mandate you granted), and `self` (encrypted under your own key). Identity is a **DID** of method `did:aithos`, deriving three sphere keys — one per zone — from independent Ed25519 seeds. A **mandate** is a signed, time-bounded capability token authorizing a specific agent to read certain zones and take certain classes of action. Agents that act under a mandate emit signed **action artifacts** that make the chain of authority verifiable end-to-end.

## The CLI in thirty seconds

```bash
# Generate a new Aithos identity (three sphere keys → ~/.aithos/)
aithos init --handle john-doe

# Inspect
aithos show
# did:aithos:z6Mkr…
#   #public  z6Mk…
#   #circle  z6Mk…
#   #self    z6Mk…

# Grant a mandate to an agent
aithos grant gmail-agent \
  --sphere circle \
  --scope ethos.read.public,ethos.read.circle,email.reply \
  --ttl 7d
# mandate_01JG4X7RABCDXYZ123  (saved to ~/.aithos/mandates/)

# List mandates
aithos mandates

# Revoke
aithos revoke mandate_01JG4X7RABCDXYZ123 --reason device_lost

# Used by agents: sign an action under the current valid mandate
cat reply.json | aithos sign --as-mandate mandate_01JG4X7RABCDXYZ123 > reply.signed.json

# Verify any signed artifact (mandate, revocation, action)
aithos verify reply.signed.json
```

See [`cli/README.md`](./cli/README.md) for the full command reference.

## Repository layout

```
Aithos-protocol/
├── WHITEPAPER.md          # the founding text (public, shareable)
├── SPEC.md                # normative spec — index page
├── spec/
│   ├── 00-introduction.md
│   ├── 01-identity.md     # did:aithos method, sphere keys, DID document
│   ├── 02-ethos.md        # ethos document model, zones, editions
│   ├── 03-bundle.md       # .ethos bundle container (zip format)
│   ├── 04-mandates.md     # grants, scopes, TTL, revocation
│   ├── 05-signing.md      # canonical form, signature format, action artifacts
│   ├── 06-transport.md    # MCP + HTTP
│   ├── 07-threat-model.md
│   ├── 08-glossary.md
│   └── 09-local-store.md  # owned vs tracked, install, verify --path, mandate add
├── cli/                   # reference CLI (Node.js, TypeScript)
│   ├── README.md
│   ├── package.json
│   └── src/
├── examples/              # sample mandates, action artifacts, etc.
├── ROADMAP.md
└── LICENSE                # Apache-2.0 (software) · CC BY 4.0 (documentation)
```

## Relationship to the POC editor

The `.ethos` bundle format — the zip container, the free-section markdown model, the manifest shape — is the one that emerged from the v0.2 Ethos proof-of-concept editor at [`../Ethos-poc/`](../Ethos-poc/). This repository formalizes that format and adds the identity, mandate, and action layers that the editor does not implement.

The editor stays useful as the simplest possible way to author a bundle by hand in a browser, single-file HTML, no backend. The protocol here is the lingua franca that makes the resulting bundle interoperable with any agent.

## Relationship to `aithos/` (the product repo)

The repository at `mnt/aithos/` is the Aithos product workspace — it holds the SaaS backend (`apps/mvp-backend`), the SaaS frontend (`apps/mvp-frontend`), a Node SDK, a Python SDK, and an earlier draft of the spec. This `Aithos-protocol` repository supersedes that draft and becomes the canonical specification source; the product repo will align to this spec over the next editions.

## License

**Software** in `packages/protocol-core`, `packages/cli`, and `packages/mcp` is under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See [LICENSE](./LICENSE)
and each package’s `LICENSE` file.

**Documentation** in `spec/`, `SPEC.md`, and `WHITEPAPER.md` is under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Governance & future versions

The `0.x` line — the current evolving wire format — will remain under Apache-2.0
forever; the grant is irrevocable. Reaching `1.0` will likely involve breaking
changes to the wire format, and the project reserves the right to publish major
versions (`1.0+`) under a different license at the maintainers’ discretion. Any
such change will be telegraphed in advance and will not affect prior releases.

External contributions are accepted under a Contributor License Agreement (CLA)
that grants the project the right to relicense future versions; see
[CONTRIBUTING.md](./CONTRIBUTING.md).

## The name

*Aithos* = **AI** + **Ethos**. Deliberate portmanteau; the roots are Greek, the word is invented. Pronounced **AY-toss**. See the appendix in [WHITEPAPER.md](./WHITEPAPER.md#appendix-a--a-note-on-the-name).
