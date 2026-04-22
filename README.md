# Aithos Protocol

> **An open protocol for portable digital ethos.**
> One human. One digital incarnation. Owned by no platform.

Aithos lets a person publish a signed, versioned, zone-partitioned description of themselves — their *ethos* — that any AI agent can read, under rules the person sets. The person can grant a time-bounded, scoped mandate to a specific agent and revoke it. The agent's actions, when taken under that mandate, are cryptographically attributable.

**Status: v0.2.1.** Spec is stabilizing. CLI is a working reference implementation. v0.2.0 promoted the signed **gamma log** (append-only, hash-chained, Ed25519-signed, sealed under the self sphere) to the sole authority on section mutation history — the per-section `revisions[]` chain from v0.1.x is gone. v0.2.1 closes the loop on **delegated writes against a tracked identity**: a delegate produces a fully verifiable edition (signed manifest, signed gamma entries, sealed zones) without ever holding the owner's sphere seeds, and the owner pulls that edition back in with `aithos ethos install --force`. Nothing is frozen yet.

## Start here

- **[WHITEPAPER.md](./WHITEPAPER.md)** — the founding text. Read this first if you want the *why*.
- **[SPEC.md](./SPEC.md)** — normative protocol specification (index).
- **[cli/](./cli/)** — the `aithos` CLI reference implementation.
- **[ROADMAP.md](./ROADMAP.md)** — what's next.

## In a paragraph

An **ethos** is a versioned document describing a person in three zones: `public` (readable by anyone), `circle` (encrypted, readable by anyone holding a mandate you granted), and `self` (encrypted under your own key). Identity is a **DID** of method `did:aithos`, deriving three sphere keys — one per zone — from independent Ed25519 seeds. A **mandate** is a signed, time-bounded capability token authorizing a specific agent to read certain zones and take certain classes of action. Agents that act under a mandate emit signed **action artifacts** that make the chain of authority verifiable end-to-end.

## The CLI in thirty seconds

```bash
# Generate a new Aithos identity (three sphere keys → ~/.aithos/)
aithos init --handle mathieu

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
└── LICENSE                # Apache-2.0
```

## Relationship to the POC editor

The `.ethos` bundle format — the zip container, the free-section markdown model, the manifest shape — is the one that emerged from the v0.2 Ethos proof-of-concept editor at [`../Ethos-poc/`](../Ethos-poc/). This repository formalizes that format and adds the identity, mandate, and action layers that the editor does not implement.

The editor stays useful as the simplest possible way to author a bundle by hand in a browser, single-file HTML, no backend. The protocol here is the lingua franca that makes the resulting bundle interoperable with any agent.

## Relationship to `aithos/` (the product repo)

The repository at `mnt/aithos/` is the Aithos product workspace — it holds the SaaS backend (`apps/mvp-backend`), the SaaS frontend (`apps/mvp-frontend`), a Node SDK, a Python SDK, and an earlier draft of the spec. This `Aithos-protocol` repository supersedes that draft and becomes the canonical specification source; the product repo will align to this spec over the next editions.

## License

Apache License 2.0 — see [LICENSE](./LICENSE).

## The name

*Aithos* = **AI** + **Ethos**. Deliberate portmanteau; the roots are Greek, the word is invented. Pronounced **AY-toss**. See the appendix in [WHITEPAPER.md](./WHITEPAPER.md#appendix-a--a-note-on-the-name).
