# 4 · Mandates

## 4.1 Overview

A **mandate** is a signed capability token that grants a specific software agent the authority to read certain zones of an ethos and take certain classes of action under the subject's identity, within a time window. Mandates are the core of what turns "an AI helping me" into "an AI acting for me, with a defined scope, accountable to me."

A mandate is:

- **Issued** by the subject, signing with a sphere key appropriate to the mandated scope.
- **Time-bounded** by explicit `not_before` and `not_after` fields.
- **Scoped** to a list of capability strings drawn from a controlled vocabulary (§4.3).
- **Revocable** at any time by the issuer.
- **Verifiable** by any party holding the subject's DID document.

This chapter defines the mandate format, the scope vocabulary, the revocation format, and the verifier's algorithm. Chapter 5 defines the signed **action artifacts** an agent emits when operating under a mandate.

## 4.2 Mandate document

### 4.2.1 Example

```json
{
  "aithos-mandate": "0.1.0",
  "id": "mandate_01JG4X7RABCDXYZ123",
  "issuer": "did:aithos:z6Mkr…",
  "issued_by_key": "did:aithos:z6Mkr…#circle",
  "grantee": {
    "id": "urn:aithos:agent:gmail-agent@macbook-john-doe",
    "label": "Personal Gmail agent (local install on macbook-john-doe)",
    "pubkey": "z6MkageEd25519KeyIfAgentHasOne…"
  },
  "actor_sphere": "circle",
  "scopes": ["ethos.read.public", "ethos.read.circle", "email.reply"],
  "constraints": {
    "domains": ["*"],
    "rate_limit": { "replies_per_hour": 20 },
    "require_counter_sign": ["email.send_binding"]
  },
  "not_before": "2026-04-19T00:00:00Z",
  "not_after":  "2026-04-26T00:00:00Z",
  "issued_at":  "2026-04-19T08:14:23Z",
  "nonce":      "rNlx4L9k3qBp",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#circle",
    "value": "mF7p2x9kLQ…"
  }
}
```

### 4.2.2 Required fields

| Field | Type | Description |
|---|---|---|
| `aithos-mandate` | string | Schema version. `"0.1.0"` for this draft. |
| `id` | string | Unique mandate identifier (§4.2.3). |
| `issuer` | string | Subject's root DID. |
| `issued_by_key` | string | The sphere DID URL that signed this mandate. MUST be a sphere key of `issuer`. |
| `grantee` | object | The agent being granted; §4.2.4. |
| `actor_sphere` | string | One of `public`, `circle`, `self`. The sphere the agent is authorized to speak within. |
| `scopes` | array of strings | One or more scope strings from §4.3. |
| `not_before` | string (RFC 3339) | Start of validity window. |
| `not_after` | string (RFC 3339) | End of validity window. MUST be strictly greater than `not_before`. |
| `issued_at` | string (RFC 3339) | Creation time. |
| `nonce` | string | At least 48 bits of entropy, base64url-encoded or similar. Protects against replay of captured mandates. |
| `signature` | object | Ed25519 signature over the canonical form (§5.1.2) with `signature.value` replaced by `""`. |

### 4.2.3 Mandate IDs

Mandate IDs are of the form:

```
mandate_<ULID>
```

where `<ULID>` is a [ULID](https://github.com/ulid/spec) — a 26-character Crockford-base32 string encoding a 48-bit timestamp and 80 bits of randomness, lexicographically sortable by time. IDs are unique per issuer; collisions are vanishingly unlikely but MUST be checked by the issuer before issuing.

### 4.2.4 Grantee

The `grantee` object identifies who is being granted. Fields:

- `id` — REQUIRED. A stable identifier for the agent. Conventional forms:
  - `urn:aithos:agent:<name>@<host>` — a named software install on a known host.
  - `did:aithos:z6Mk…` — another Aithos subject (cross-subject mandates).
  - `did:key:z6Mk…` — any `did:key` identifier.
  - `did:web:<domain>` — an agent identified by its website.
- `label` — OPTIONAL. Human-readable description.
- `pubkey` — OPTIONAL. If the grantee has a stable Ed25519 public key, it MAY be recorded here; this lets the issuer bind the mandate to a specific agent key pair, so that only holders of that key can emit valid action artifacts under this mandate. If omitted, any agent presenting the mandate is considered eligible (less secure; useful only for tightly-scoped read-only mandates).

### 4.2.5 Constraints

The `constraints` object is optional and carries non-normative hints that narrow the mandate further than the scope list. Recognized keys at v0.1.0:

- `domains` — array of domain names or wildcards (`["example.com", "*.acme.com"]`). Restricts which external domains the agent may communicate with. A `["*"]` value means no domain restriction.
- `rate_limit` — object of rate caps. Keys are scope-specific; values are integers. Example: `{ "replies_per_hour": 20 }`.
- `require_counter_sign` — array of scope strings that require a counter-signature from the mandated sphere key at action time (§5.4). Actions under scopes listed here are "binding" and MUST NOT be taken without the subject's live participation.

Readers MUST NOT reject a mandate for carrying unrecognized constraint keys, but MAY refuse to honor the mandate if they cannot enforce a constraint the issuer clearly intended.

## 4.3 Scope vocabulary

Scopes are stringly-typed capabilities drawn from a controlled vocabulary. v0.1.0 defines the following. Future versions MAY add scopes; implementations MUST ignore scopes they do not recognize (but SHOULD log them).

### 4.3.1 Ethos reading

| Scope | Meaning |
|---|---|
| `ethos.read.public` | Read the `public` zone. |
| `ethos.read.circle` | Read the `circle` zone. |
| `ethos.read.self` | Read the `self` zone. (Only granted to the subject's own agents.) |
| `ethos.read.all` | Shorthand for all three read scopes. |
| `ethos.write.public` | Author gamma entries affecting the `public` zone (§10, delegated authoring §4.5.4). |
| `ethos.write.circle` | Author gamma entries affecting the `circle` zone. |
| `ethos.write.self` | Author gamma entries affecting the `self` zone. RECOMMENDED to carry `require_counter_sign`. |

### 4.3.2 Email

| Scope | Meaning |
|---|---|
| `email.read` | Read the user's inbox. |
| `email.draft` | Prepare draft replies without sending. |
| `email.reply` | Send non-binding replies (RSVP, acknowledgment, small talk). |
| `email.send_binding` | Send emails that constitute a commitment (contracts, agreements, money). Requires `require_counter_sign`. |

### 4.3.3 Calendar

| Scope | Meaning |
|---|---|
| `calendar.read` | Read the user's calendar. |
| `calendar.respond` | Accept/decline invitations. |
| `calendar.create` | Create new events on the user's calendar. |

### 4.3.4 Messaging

| Scope | Meaning |
|---|---|
| `chat.read` | Read chat messages. |
| `chat.reply` | Respond to messages. |

### 4.3.5 Social

| Scope | Meaning |
|---|---|
| `social.post.linkedin` | Post to LinkedIn on behalf of the subject. Binding. |
| `social.post.x` | Post to X on behalf of the subject. Binding. |
| `social.post.draft` | Prepare posts without publishing. |

### 4.3.6 Filesystem and data

| Scope | Meaning |
|---|---|
| `files.read` | Read files the subject owns. |
| `files.write` | Write files the subject owns. |

### 4.3.7 Sphere policy

A mandate's `scopes` MUST be consistent with its `actor_sphere`:

- `public` sphere mandates MAY carry read scopes for the `public` zone only, and the `ethos.write.public` scope. No other action scopes.
- `circle` sphere mandates MAY carry `ethos.read.public`, `ethos.read.circle`, `ethos.write.public`, `ethos.write.circle`, and any non-sphere action scope.
- `self` sphere mandates MAY carry all read scopes, all write scopes, and any action scope, but are strongly RECOMMENDED to be issued only to agents running on hardware the subject controls.

A write scope `ethos.write.<zone>` MUST be carried only by a mandate whose `actor_sphere == <zone>` — i.e. a write mandate for the `circle` zone MUST itself be signed by the `#circle` sphere key. The reason is accountability: the sphere key that "speaks for" a zone is also the one that delegates authoring within it.

## 4.4 Issuing key

The sphere key used to sign a mandate MUST match `actor_sphere`. A mandate whose `actor_sphere` is `circle` MUST be signed by the `#circle` sphere key. This is enforced: a reader who finds `issued_by_key` ≠ `did:aithos:…#<actor_sphere>` MUST reject the mandate.

The reason is accountability: the sphere key is what attests to "this is me speaking as my public/circle/self self." A mandate issued by the wrong sphere key is ill-formed.

## 4.5 Types of mandate

The protocol distinguishes three mandate flavors informally. All three use the same format; the flavor is determined by which scopes are present.

### 4.5.1 Read-only mandate

A mandate whose scopes are all of the form `<x>.read.<y>`. Grants the agent the right to fetch zones / data; no authority to act. The simplest and safest grant.

### 4.5.2 Action mandate

A mandate that carries at least one non-read scope (e.g. `email.reply`). Grants the agent the authority to emit action artifacts under this mandate. The agent still needs to possess the mandate id and, if `grantee.pubkey` is set, the corresponding private key.

### 4.5.3 Key-bearing mandate

A read-only mandate in which the agent is additionally listed as a zone recipient (§3.5.2) so that the agent's key material is embedded in the bundle and the agent can decrypt the zone offline. The mandate itself is just the read grant; the key-bearing property is a consequence of the bundle, not of the mandate document. Most agents should not receive key-bearing mandates.

### 4.5.4 Write mandate (delegated authoring)

A **write mandate** authorizes an agent to author gamma entries (§10) affecting a zone of the subject's ethos *without* holding the subject's sphere key. This is how a subject equips a secondary device, an editing tool, or an AI agent with the ability to amend their ethos while keeping the sphere key offline on the primary device.

The mandate is an ordinary mandate per §4.2 with these additional requirements:

- `scopes` MUST contain at least one of `ethos.write.public`, `ethos.write.circle`, `ethos.write.self`.
- `actor_sphere` MUST equal the zone being written (see §4.3.7).
- `grantee.pubkey` MUST be set. It is the multibase Ed25519 public key of the **delegate key** generated by the subject for this specific agent/device. Every gamma entry signed under this mandate MUST be signed by that exact key.
- `constraints` MAY include additional keys specific to writing:
  - `sections: ["sec_a1b2c3", "sec_9f8e7d"]` — restrict the delegate to authoring gamma entries targeting only these section IDs. Omitted ⇒ any section in the authorized zone.
  - `max_mutations_per_day: N` — rate-limit on the number of gamma entries the delegate may commit per UTC day.
  - `max_body_bytes: N` — cap on the byte length of any single `section.add` / `section.modify` `payload.body` field.
  - `require_counter_sign: ["ethos.write.<zone>"]` — every gamma entry authored by the delegate MUST carry a subject counter-signature to be considered valid. Turns the delegate into a drafting assistant rather than an autonomous author. RECOMMENDED for `self`.

When a delegate signs a gamma entry, the entry's `authorized_by` field is set to `"<mandate_id>"` and `signature.key` is the delegate's multibase Ed25519 public key — not a sphere DID URL. Verification is the combined procedure of §10.5 (gamma entry hash/signature) and §4.7 (mandate).

#### 4.5.4.1 Generating a delegate keypair

The subject generates an Ed25519 keypair whose seed is stored on the delegate device. The reference CLI does this via `aithos delegate-key --out <path>`; the subject then issues a write mandate whose `grantee.pubkey` matches the generated public key and provisions the keyfile onto the delegate device.

The delegate key is not added to the subject's DID document. It is a **capability-bearing** key whose authority lives entirely in the mandate; its lifetime and reach are exactly those of the mandate, and revoking the mandate (§4.6) terminates the delegate's authority.

#### 4.5.4.2 Revocation semantics for write mandates

Revocation of a write mandate is forward-only, like any other mandate (§4.6.3):

- Gamma entries with `G.at < revoked_at` remain valid and attributable.
- Gamma entries with `G.at ≥ revoked_at` are unauthorized regardless of the mandate's TTL.

If the subject believes a delegate key was compromised and wishes to **repudiate** past gamma entries authored by it, the subject issues a `section.redact` gamma entry (§10.8) referencing those entries by id. The redaction is signed directly by the sphere key, leaves the original entries in the chain, and makes the repudiation public and dated.

#### 4.5.4.3 Why this is safe

The sphere key — the "official key" — never leaves the subject's primary device. The write mandate is signed by it once, then the sphere key goes back to sleep. The delegate key does all the day-to-day signing. If the delegate device is lost, stolen, or compromised, the subject revokes with the sphere key and all future writes are blocked. Past writes remain evidence of what was said when, in the spirit of §2.8.

This mirrors how signed capabilities work in classical capability systems: a single long-lived root authority (the sphere key) issues short-lived, narrow capabilities (write mandates) that circulate freely and can be torn up at any time.

## 4.6 Revocation

### 4.6.1 Revocation document

```json
{
  "aithos-revocation": "0.1.0",
  "mandate_id": "mandate_01JG4X7RABCDXYZ123",
  "issuer": "did:aithos:z6Mkr…",
  "issued_by_key": "did:aithos:z6Mkr…#circle",
  "revoked_at": "2026-04-22T12:01:00Z",
  "reason": "device_lost",
  "signature": {
    "alg": "ed25519",
    "key": "did:aithos:z6Mkr…#circle",
    "value": "v9K…"
  }
}
```

### 4.6.2 Fields

| Field | Description |
|---|---|
| `aithos-revocation` | Schema version. |
| `mandate_id` | The mandate being revoked. |
| `issuer` | Subject root DID. MUST match the mandate's issuer. |
| `issued_by_key` | Sphere DID URL that signs this revocation. MUST match the mandate's `issued_by_key` (a mandate may only be revoked by the key that issued it). |
| `revoked_at` | RFC 3339 time after which the mandate is invalid. |
| `reason` | Short free-form string. Recognized values: `device_lost`, `device_sold`, `agent_retired`, `superseded`, `policy_change`, `user_request`, `incident`, `other`. Implementations MUST NOT act on the reason programmatically — it is informative. |
| `signature` | Ed25519 signature, same canonicalization rules as mandates (§5.1.2). |

### 4.6.3 Effect of revocation

After `revoked_at`:

- The mandate is invalid. Agents MUST NOT act under it.
- Action artifacts dated **before** `revoked_at` remain attributable. Revocation is not retroactive.
- Action artifacts dated **after** `revoked_at` MUST be treated as invalid by verifiers, even if the artifact itself is well-formed.

### 4.6.4 Revocation list publication

A subject MAY publish their current set of active revocations as a signed **revocation list**:

```json
{
  "aithos-revocations-list": "0.1.0",
  "issuer": "did:aithos:z6Mkr…",
  "issued_at": "2026-04-22T12:05:00Z",
  "revocations": [
    { "mandate_id": "mandate_01JG…", "revoked_at": "2026-04-22T12:01:00Z" },
    …
  ],
  "signature": { "alg": "ed25519", "key": "did:aithos:z6Mkr…#public", "value": "…" }
}
```

The revocation list is signed by the `#public` sphere key so that any party — even one without any relationship to the subject — can check whether a mandate has been revoked. The list is typically published at `<canonical_url>/revocations.json` or advertised through the DID document's service endpoints.

Agents that hold action-class mandates MUST refresh the revocation list before any action whose scope triggers `require_counter_sign` or otherwise before binding actions (§4.2.5, §5.4).

## 4.7 Verifier algorithm

To verify that an agent is authorized to perform scope `S` on subject `DID` at time `T`:

1. Resolve the subject's DID document (chapter 1). Verify its root signature.
2. Fetch the mandate the agent presents. Validate its JSON shape.
3. Check `issuer == DID` and `issued_by_key.fragment == actor_sphere`.
4. Resolve `issued_by_key` in the DID document. Verify the mandate's Ed25519 signature.
5. Check `not_before ≤ T ≤ not_after`.
6. Fetch the current revocation list. Check that `id` is not revoked at time `T`.
7. Check `S ∈ scopes`.
8. If the mandate has `grantee.pubkey`, check that the presenter can prove possession of the corresponding private key (challenge-response; §5.5).
9. Honor the mandate's `constraints` where applicable.

If any step fails, reject.

## 4.8 Storage and transport

Mandates are JSON objects. They can be transported in any medium: as part of an MCP request, in an HTTP header, on a USB key handed to a physical device. The reference CLI stores issued mandates under `~/.aithos/mandates/` and issued revocations under `~/.aithos/revocations/` as one file per document.

A subject who issues a mandate to an external agent MUST transmit it to the agent through a secure channel. The mandate is not secret in the cryptographic sense — its signature is what matters — but its existence reveals which agents a subject has trusted, which is itself information.

## 4.9 Example lifecycle

```
# 1. Alice, did:aithos:z6MkAlice…, issues a mandate for her Gmail agent.
aithos grant gmail-agent \
  --sphere circle \
  --scope ethos.read.public,ethos.read.circle,email.reply \
  --ttl 7d
# → writes ~/.aithos/mandates/mandate_01JG4X7R…json
# → prints the mandate id and the path

# 2. The agent is bootstrapped with the mandate.
cp ~/.aithos/mandates/mandate_01JG4X7R…json /opt/gmail-agent/etc/mandate.json

# 3. The agent receives an incoming email. It decides to reply.
gmail-agent reply --to msg-42 --draft-file reply.json
# internally: agent canonicalizes reply.json, signs under its own key,
# emits an action artifact referencing mandate_01JG4X7R…

# 4. Bob's agent receives the reply. It fetches alice's DID document,
#    fetches her revocation list, and validates the chain.
# If everything checks out, Bob's UI shows "reply is attributable to Alice's
# circle sphere, via agent gmail-agent@macbook-john-doe".

# 5. A week later the TTL expires. The mandate is no longer valid.
#    Alice may or may not choose to re-issue.

# 6. Meanwhile, Alice suspects her macbook was briefly accessed by
#    someone else. She revokes proactively:
aithos revoke mandate_01JG4X7R… --reason device_suspect
# → writes ~/.aithos/revocations/revocation_01JGMaN…json
# → updates ~/.aithos/revocations.list.json
```

## 4.10 Open questions

- **Delegation chains.** Can a delegate holding a write mandate issue *sub-mandates* to other agents? (Mark S. Miller-style chained caps.) Not permitted at v0.1.0 — only the sphere key can issue mandates. A future version may add a `can_subdelegate: true` capability in the scope vocabulary if real usage demands it.
- **Offline verification.** The verifier algorithm currently requires online access to the revocation list. For offline verifiers, short-TTL mandates are the only safe answer. A signed revocation-list expiry window could make offline use more robust; deferred.
- **Legal binding.** Whether a mandate has legal weight is a separate question entirely. The protocol provides the substrate; jurisdiction-specific frameworks can decide what to do with it.

---

Next: [chapter 5 — Signing](./05-signing.md).
