# Aithos — A Protocol for Portable Digital Ethos

**Version 0.1 (draft) · April 2026**
*Mathieu Colla — mathieu.colla.pro@gmail.com*

---

## Abstract

For the first time in history, machines speak in our voice. They draft our emails, answer our messages, schedule our days, take small decisions in our name. We have accepted this without asking the most consequential question: **whose voice is it, exactly?**

Today the answer is uncomfortable. Each platform — OpenAI, Google, Microsoft, Apple, the next entrant — keeps a fragment of who we are. None of them holds the whole. None of them is portable. None of them is signed. None of them is ours.

Aithos is a protocol that makes a person's *ethos* — their character, voice, values, and consent — a first-class artifact: written, versioned, signed, and owned by the person, in three explicit zones of disclosure (public, circle, self). Any AI agent, on any platform, can read it under the rules the person sets. The person can grant a time-bounded mandate to a specific agent, and revoke it. The agent's actions, when taken under that mandate, are cryptographically attributable.

This document presents the motivation, the model, the cryptographic design, and the path to adoption. The companion [SPEC](./SPEC.md) is normative; this paper is its argument.

---

## 1. The problem we are solving

### 1.1 Identity, fragmented

Every conversation a person has with an AI assistant builds a sliver of representation: a few preferences inferred, a tone learned, a routine remembered. That sliver is captured in private memory inside the assistant's vendor. The user cannot see it, cannot edit it directly, cannot export it cleanly, and cannot move it to a competitor.

The result is a fragmented digital self. The Claude that drafts your emails knows one version of you. The ChatGPT that helps with your code knows another. The Gemini in your inbox knows a third. None of them agrees with the others. None of them is signed by you. All of them disappear the day you delete an account.

### 1.2 Speech, unmandated

When an AI speaks for you — replies to a client, posts to your timeline, accepts a meeting — it does so without an explicit, verifiable mandate. There is no analogue to a power of attorney. There is no chain of authority that a counterparty can verify. There is no way for *you* to demonstrate, after the fact, exactly which actions were taken in your name and which were not.

This is not a niche concern. It is the operational architecture of the next decade of communication.

### 1.3 The asymmetry of memory

Platforms see your behavior continuously and remember it permanently. You see their representation of you intermittently and edit it with difficulty. The asymmetry is structural: it favors the side that operates the pipes.

Aithos exists to invert that asymmetry. The author of an ethos is the person, not the platform. The cryptographic root of trust is held by the person, not licensed by them.

---

## 2. The model

### 2.1 An ethos, in one sentence

An **ethos** is a versioned, signed, structured description of a person, partitioned into three zones of disclosure, addressable by a stable identifier, readable by any conformant AI agent, and entirely owned by its subject.

### 2.2 The three zones

Humans already live in zones. The face we present in public is not the face we share with close friends, and neither is the face we wear when we are alone. An ethos that pretends otherwise is a lie about how persons work.

- **Public.** What anyone — any agent, any stranger — is allowed to know. Positioning, declared values, preferred forms of address. Plaintext. Hashed for integrity.
- **Circle.** What you share with the people close enough to deserve it. Personal context, ongoing projects, the texture of how you work. Encrypted. Readable only by holders of a credential you have granted.
- **Self.** What is yours alone. Reflections, doubts, the unfiltered self. Encrypted under a key only you possess. No third party — no platform, no agent vendor, not the Aithos project — can read it.

The zones are not a UX gimmick. They are the architecture of being a person in public.

### 2.3 Editions and the history spine

An ethos is not a stream of edits. It is a **sequence of immutable editions**, each signed at a moment in time and linked to the one before it by a SHA-256 hash. The chain is not metaphorical — it is the cryptographic guarantee that nobody, not even the author, can silently rewrite what was said yesterday.

Inside each edition, every section's content is itself an **append-only log** of dated revisions. You want to change how you describe your voice? You add a new dated revision; the old one stays. You want to update your availability window? New revision, old one preserved. Each revision carries the SHA-256 of the revision before it and is signed by the sphere key whose zone it lives in. Altering a past revision breaks the chain: the next revision's `prev_hash` no longer matches, subsequent signatures fail to verify, the whole section is visibly corrupted.

The result is a double spine: **per-edition chain** from one bundle version to the next, and **per-section chain** within each section's own history. Together they enforce a simple property: **the past is recorded, signed, and provable.**

This is not a blockchain. There is no consensus, no distributed ledger, no mining, no token. It is the *integrity* property of a blockchain applied to a deeply personal artifact: a verifiable append-only record of how a person has evolved.

Why this matters:

- An agent reading "the subject prefers short paragraphs" can see **when** that was said and whether it has since been amended.
- A counterparty who has two readings of your ethos taken six months apart can verify both are authentic snapshots of your evolution.
- A court, someday, may need to know exactly what you said on a specific date. The chain provides that.

The cost is that bundles grow over time. A subject who wants a fresh start — after a root-key compromise, after a major personal reinvention — produces a **genesis edition** with no predecessor. The break is visible and deliberate.

Redaction is possible and public. An author who wants to erase a past revision issues a signed, dated **redaction revision** that marks the old body as withdrawn. The chain is preserved; the redaction is logged; the act is visible to anyone verifying the chain. The tension between immutability for third parties and the right-to-forget for the author is resolved by making erasure a first-class, public, signed act — not a silent rewrite.

### 2.4 Mandates

A **mandate** is a signed capability token that authorizes a specific AI agent to read certain zones, take certain classes of action, and bind those actions to your identity, for a specific period.

```
aithos grant gmail-agent --scope=ethos.read.circle,email.reply --ttl=7d
```

The agent receives a signed JSON object proving it may act. When it acts, it produces a signed action artifact that names the mandate it operated under. Anyone — you, the recipient, an audit log, a court — can verify the chain.

A mandate is **revocable**. The revocation is a second signed object that supersedes the first. Conformant agents and verifiers refresh their mandate state before acting on consequential operations.

This single mechanism — granted, scoped, time-bounded, revocable, cryptographically verifiable mandates — is what turns "an AI helping me with email" into "an AI authorized to speak in a part of my voice, for a defined purpose, for a defined time, accountable to me alone."

---

## 3. Identity: `did:aithos`

### 3.1 Why a DID

A subject's identity in Aithos is a **Decentralized Identifier (DID)**, following the [W3C DID Core](https://www.w3.org/TR/did-core/) specification. This is deliberate:

- **No central registry.** No single authority can revoke your name.
- **Self-certifying.** The DID is derived directly from a public key; possession of the corresponding private key is the only proof of control needed.
- **Resolver-agnostic.** A DID can be resolved through DNS, the filesystem, a decentralized ledger, or simply a well-known URL — the protocol does not impose one.

### 3.2 The `did:aithos` method

A subject is represented by a single **root DID**. From the root, three **sphere keys** are derived — one per zone — each with its own DID URL fragment.

```
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#public
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#circle
did:aithos:z6MkrJVnaZkeFzdQyMZu1cmd3Mh1jGhxqfekzMC8TdZeTwj9#self
```

The identifier portion (`z6Mk…`) is a [multibase](https://github.com/multiformats/multibase) base58btc encoding of a [multicodec](https://github.com/multiformats/multicodec) byte (`0xed` for Ed25519) prepended to the 32-byte Ed25519 root public key. This is the same encoding used by the well-established `did:key` method, deliberately, so that any `did:key` resolver can already parse the root portion of a `did:aithos` identifier.

The three sphere keys are each independent Ed25519 key pairs. They are not hierarchically derived from the root: each is generated from its own random seed and bound to the root through a signed **DID document**. The reason is simple: zone keys must be independently rotatable. If your `circle` key is compromised — say a recipient's device is breached — you must be able to roll it without disturbing your `public` posture or your `self` archive.

### 3.3 The DID document

Resolving a `did:aithos` returns a DID document of the shape:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://aithos.dev/spec/v0.1"],
  "id": "did:aithos:z6Mkr…",
  "verificationMethod": [
    { "id": "did:aithos:z6Mkr…#public", "type": "Ed25519VerificationKey2020", "controller": "did:aithos:z6Mkr…", "publicKeyMultibase": "z6Mk…" },
    { "id": "did:aithos:z6Mkr…#circle", "type": "Ed25519VerificationKey2020", "controller": "did:aithos:z6Mkr…", "publicKeyMultibase": "z6Mk…" },
    { "id": "did:aithos:z6Mkr…#self",   "type": "Ed25519VerificationKey2020", "controller": "did:aithos:z6Mkr…", "publicKeyMultibase": "z6Mk…" }
  ],
  "service": [
    { "id": "#ethos", "type": "EthosBundle", "serviceEndpoint": "https://aithos.example/u/mathieu.ethos" }
  ]
}
```

The DID document is itself signed by the root key. A verifier resolves the document, checks the root signature, then trusts each sphere key to sign within its scope.

---

## 4. The ethos bundle

### 4.1 Container

A published ethos is a `.ethos` file: a ZIP archive carrying the ethos document, the encrypted zones, and the manifest. The format is deliberately ordinary — same shape as `.docx`, `.apk`, `.epub` — so any tool can inspect it.

```
mathieu.ethos
├── manifest.json     (metadata, key references, salt, hashes, section index)
├── public.md         (plaintext markdown, frontmatter + free-form sections)
├── circle.md.enc     (XChaCha20-Poly1305 ciphertext over markdown)
├── self.md.enc       (XChaCha20-Poly1305 ciphertext over markdown)
├── did.json          (signed DID document)
└── README.txt        (human-readable explanation, for the curious)
```

The proof-of-concept editor at `Ethos-poc/` already produces a v0.2 bundle in this shape. The protocol formalizes it.

### 4.2 Free sections, optional autocomplete

The bundle does not impose a rigid schema on what a person should say about themselves. Each zone is a markdown file with an explicit list of named sections (`# Identity`, `# Voice`, `# Refusals`, `# Tech stack`, `# Morning routine`, `# Anything else`). The protocol provides a non-normative list of canonical section titles — *Identity, Voice, Positioning, Refusals, Availability, Pricing, Voice (intimate), Refusals (intimate)* — but the author may invent their own. The point is that an LLM is good at adapting; we should not over-constrain the human.

What we do constrain is *the manifest*. The manifest carries, for each zone, the list of section titles that exist in that zone. This lets a reader who does not have the passphrase still know that "there is a section titled `Negotiation preferences` in your circle zone" — without seeing the content. Whether this metadata leak is acceptable is part of the threat model (§7).

### 4.3 Crypto profile

| Component | Choice | Rationale |
|---|---|---|
| Signature | Ed25519 (RFC 8032) | Fast, ubiquitous, no parameter choices to mis-make. |
| Sphere key derivation | Independent random seeds | So zones can rotate independently. |
| Symmetric AEAD | XChaCha20-Poly1305 (libsodium / RFC 8439 variant) | 24-byte nonce → safe to randomize without coordination. |
| Zone key wrapping | X25519 ECDH + HKDF + AEAD | Standard envelope encryption; one wrap per recipient. |
| Passphrase KDF | Argon2id (memlimit=64 MB, opslimit=3) | Memory-hard, current best practice. |
| Canonicalization | RFC 8785 JCS | Deterministic JSON, signature-stable. |
| Hash | SHA-256 | Used for content integrity, not key derivation. |

For the v0.2 proof-of-concept editor (see `Ethos-poc/`), PBKDF2-SHA256 (100 000 iterations) and AES-GCM-256 are used in lieu of Argon2id and XChaCha20 to keep the editor implementable purely in browser `crypto.subtle` without WASM. The protocol normatively specifies the libsodium primitives; the POC documents its substitution.

---

## 5. Mandates

### 5.1 Anatomy

A mandate is a JSON object signed by one of the subject's sphere keys. It declares:

- **Who** is being granted (`grantee`): a DID, a stable agent identifier, or a named software install.
- **Which sphere** they may act under (`actor_sphere`): `public`, `circle`, or `self`.
- **What scopes** they may use (`scopes`): a list of capability strings drawn from a controlled vocabulary (`ethos.read.public`, `ethos.read.circle`, `email.reply`, `calendar.respond`, `linkedin.post`, …).
- **When** the mandate is valid (`not_before`, `not_after`).
- **A unique id** (`id`): a ULID for time-orderable, sortable identification.

```json
{
  "aithos-mandate": "0.1.0",
  "id": "mandate_01JG4X7RABCDXYZ123",
  "issuer": "did:aithos:z6Mkr…",
  "issued_by_key": "did:aithos:z6Mkr…#circle",
  "grantee": {
    "id": "urn:aithos:agent:gmail-agent@local",
    "label": "Personal Gmail agent (local install on macbook-mathieu)"
  },
  "actor_sphere": "circle",
  "scopes": ["ethos.read.public", "ethos.read.circle", "email.reply"],
  "not_before": "2026-04-19T00:00:00Z",
  "not_after":  "2026-04-26T00:00:00Z",
  "issued_at":  "2026-04-19T08:14:23Z",
  "nonce":      "rNlx4L9k3q",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#circle",
    "value": "mF7p2x…"
  }
}
```

### 5.2 Revocation

A revocation is itself a signed object that names the mandate id and a reason. Conformant agents fetching their own mandate state before any consequential action MUST honor revocations published in the issuer's revocation list. Revocations are not retroactive — actions taken before the revocation timestamp remain attributable, but the agent loses authority to take new ones.

```json
{
  "aithos-revocation": "0.1.0",
  "mandate_id": "mandate_01JG4X7RABCDXYZ123",
  "issuer": "did:aithos:z6Mkr…",
  "revoked_at": "2026-04-22T12:01:00Z",
  "reason": "device_lost",
  "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#circle", "value": "…" }
}
```

### 5.3 Signed actions

When an agent acts under a mandate, it emits an **action artifact** — a JSON object that names the mandate, describes the action, and is signed both by the agent's own key and (optionally, for high-stakes operations) counter-signed by the mandated sphere key. This makes the chain of authority verifiable end-to-end:

```
gmail-agent --sign-as=aithos
  ├─ resolves the live mandate from ~/.aithos/mandates/
  ├─ checks not_after, refreshes revocation list
  ├─ takes the action (drafts the reply)
  ├─ canonicalizes the action payload (RFC 8785)
  ├─ signs with its own agent key
  └─ writes the action artifact alongside the action,
     and (for actions that scope-flag "binding") prompts
     the human to counter-sign with the mandated sphere key
```

This is what makes "the AI replied for me" a verifiable claim instead of an opaque assertion.

### 5.4 Delegated authoring

Mandates also cover the act of **editing the ethos itself**. A subject can issue a write mandate (`ethos.write.public`, `ethos.write.circle`, `ethos.write.self`) that names a freshly-generated **delegate key** — an Ed25519 key pair living on a secondary device, an editing tool, or an AI assistant. Revisions signed by that delegate key are valid as long as the mandate is valid. The sphere key — the "official" key — never leaves the primary device; it signs the mandate once and goes back to sleep.

This solves a concrete operational problem: how do you let a phone, a tablet, or an AI assistant amend your ethos without copying your sphere key around. The answer is the same one classical capability systems have given for fifty years: issue a narrow, time-bounded, revocable token, and let the day-to-day signing happen with disposable keys.

If the delegate device is lost, stolen, or misbehaves, the subject revokes the mandate with the sphere key. Past revisions remain in the chain — the protocol is append-only — but the delegate's authority to write new ones ends immediately. If the past writes themselves are repudiated, the subject publishes a redaction revision that names them by hash.

---

## 6. Transport

The protocol does not mandate one transport; it specifies two in detail and leaves room for more.

- **MCP (Model Context Protocol).** A `.ethos` bundle can be served to any MCP-compatible agent (Claude Desktop, Cursor, Zed, Continue, ChatGPT Desktop, …) through a stdio or HTTP-streamable MCP server. The reference implementation lives at `Ethos-poc/mcp/`. Resources expose the zones; tools expose targeted reads (`ethos_search`, `ethos_list_sections`); a prompt (`write_as`) bundles the available zones into a system message that instructs the agent to write in the subject's voice.
- **HTTP.** A canonical URL (`GET /ethos/{handle}`) returns the public zone unconditionally, the circle zone on presentation of a valid mandate, and refuses the self zone to anyone who is not the subject themselves.

Both transports are normatively specified in the [transport spec](./spec/06-transport.md).

---

## 7. Threat model

We design against the following adversaries.

### 7.1 The honest-but-curious platform

The default adversary. A platform that hosts your bundle, your agent, or your account, and does not actively attack you, but cannot resist looking. The defense is mathematical: encrypted zones reveal nothing to the platform. The metadata leak (section titles in the manifest) is an acknowledged tradeoff and is documented per-bundle so a paranoid author can choose to encrypt the section index too.

### 7.2 The compromised recipient

A circle member's device is compromised. The attacker can read your circle zone for as long as your circle key remains valid. Defense: rotate the circle sphere key. All currently-live circle mandates are invalidated, and a new edition of the bundle re-encrypts the circle zone for the remaining recipients only.

### 7.3 The misbehaving agent

An agent acts beyond the scope of its mandate (replies to messages it should not, posts content it should not). Defense: every action carries a signed artifact naming the mandate. A counterparty who receives a reply they suspect is unauthorized can request the artifact and verify the chain. The author can revoke the mandate and publish a public statement repudiating actions that lack a valid artifact.

### 7.4 Stale mandates and replay

An agent caches a mandate that has since been revoked. Defense: agents MUST refresh the issuer's revocation list before any action whose scope is flagged `binding`. Each mandate carries a `nonce` so an attacker who replays a captured mandate cannot use it past its `not_after`.

### 7.5 Key compromise

The root sphere key is compromised. This is the worst case. Defense: the root signs only the DID document; ordinary operations use sphere keys. A compromised sphere key triggers a key-rotation edition signed by the root, listing the old key as revoked-from-timestamp-T. A compromised root key requires moving to a new DID — there is no recovery path that preserves the identifier. We document this loudly: lose your root, you lose your name.

---

## 8. What Aithos is not

- Not a model. We do not train, serve, or fine-tune anything.
- Not a memory layer. Aithos is what agents *read*, not how they *remember*.
- Not an identity provider in the OAuth sense. There is no Aithos sign-in button. Authentication between you and an agent is done via your sphere keys, on your hardware.
- Not a legal framework. A mandate is cryptographically verifiable but not legally binding by virtue of being signed. The legal weight of a digital mandate is jurisdictional and is the job of policy, not of this protocol. The protocol provides the substrate; the law catches up.
- Not a walled garden. The normative spec and this paper are **CC BY 4.0**; the reference TypeScript (CLI, library, MCP) is **BUSL-1.1** with automatic conversion to **Apache-2.0** on 2030-12-31 — see [LICENSE](./LICENSE). The bundle format remains a zip you can extract with `unzip`.

---

## 9. Why now

Three trends converge.

1. **Agents become first-class.** OpenAI, Anthropic, Google, and a long tail of startups are shipping agentic experiences that take real actions: draft emails, schedule meetings, fill forms, post to social. The question of mandate is no longer hypothetical.
2. **MCP standardizes context.** The Model Context Protocol gives us, for the first time, a common way to feed structured context into any AI agent. An ethos bundle that speaks MCP works in Claude, in Cursor, in Zed, in Continue, in ChatGPT Desktop — without per-vendor integration work.
3. **Users want sovereignty.** The cohort of users who prefer to host their own data, run their own models, and own their own identity is small but loud and growing. They are the early adopters of any successful identity protocol. They are also the people most likely to experiment with agents.

Aithos is the artifact that lets these three trends compose: an identity I own, a mandate I can grant, a context any agent can read.

---

## 10. Roadmap

The protocol is being developed in public, in three concurrent tracks.

- **Track A — Specification.** This document and the normative [SPEC](./SPEC.md). v0.1 stabilizes the bundle format, the DID method, the mandate format, and the MCP transport. v0.2 adds the HTTP transport and the discovery story (`did:web` companion). v1.0 freezes the wire formats and commits to backward-compatible evolution.
- **Track B — Reference implementations.** The Aithos CLI in `cli/`, the Ethos editor at `Ethos-poc/`, the MCP server at `Ethos-poc/mcp/`. Node SDK first; Python SDK to follow.
- **Track C — A SaaS demonstrator.** A hosted ethos plus a single-purpose agent (Gmail triage and reply drafting) to prove the protocol works end-to-end against real-world tools. The SaaS lives in a separate, private repository; the protocol it speaks is the one published here.

---

## 11. Closing

A protocol succeeds when it disappears into the substrate of how things work. People do not think about HTTP when they read a web page; they will not think about Aithos when an AI replies in their voice. They will simply notice that the AI got it right — that it sounded like them, knew what they refuse, knew what they cost, knew when they sleep — and that no platform was needed in between to certify any of it.

That is the goal. **One human, one digital incarnation, owned by no platform.**

---

## Appendix A — A note on the name

*Aithos* is a deliberate portmanteau: **AI** + **Ethos**. The Greek roots are real; the word is invented.

**Ethos** (ἦθος): character, moral disposition, the credibility of the one who speaks. In Aristotle's *Rhetoric* it is one of the three pillars of persuasion, alongside *pathos* (emotion) and *logos* (reason). To let another speak on your behalf is, above all, a question of ethos.

**Aithēr** (αἰθήρ): the upper air, the medium that carries light, the bridge between mortals and gods.

**Aithō** (αἴθω): to burn, to ignite — the spark.

A character to be represented. A medium that carries it. A spark that sets it in motion. Pronounced **AY-toss**.

---

## Appendix B — Acknowledgments and prior art

Aithos stands on the shoulders of work done elsewhere. We borrow shamelessly and we cite gratefully.

- **W3C Decentralized Identifiers** for the model of self-sovereign identity.
- **The `did:key` method** for the elegant encoding of a public key as an identifier, which we extend rather than replace.
- **libsodium** and the **Noble cryptography** family for primitives a non-cryptographer can use without footguns.
- **The Model Context Protocol (MCP)** for the agent-side standardization that makes a portable ethos worth publishing.
- **RFC 8785 JCS** for canonical JSON.
- **The capability-security tradition** (Mark S. Miller, ocaps) for the model of unforgeable authority that informs our mandate design.
- **The `.docx`, `.apk`, `.epub` family of zip-based containers** for the precedent of "boring archive that any tool can inspect."

Aithos is its own thing, but it is built out of pieces other people made well.

---

*This white paper is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and may be redistributed, quoted, and built upon with attribution. The latest version is at [getaithos.org](https://getaithos.org) (forthcoming).*
