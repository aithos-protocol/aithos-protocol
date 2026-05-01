# 5 · Signing

## 5.1 Canonicalization

All signatures in Aithos are computed over a **canonical** byte representation of a JSON value, produced according to [RFC 8785 — JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785). JCS gives a deterministic byte sequence for any JSON value, so different implementations produce identical signatures over identical content.

### 5.1.1 What gets canonicalized

To sign a JSON object `O` carrying its own signature in field `sig`:

1. Take `O` and replace `O.sig.value` (the actual signature bytes) with the empty string `""`.
2. Run the resulting object through JCS.
3. Sign the resulting byte string.

To verify, perform the same substitution and recanonicalization, then verify the signature against the substituted bytes.

The signature object's `key`, `alg`, `created` (etc.) fields **are** included in the canonicalized bytes — they are part of what's signed. Only the `value` field is blanked.

### 5.1.2 Mandate canonicalization

For a mandate document (chapter 4):

1. Set `signature.value = ""`.
2. JCS-canonicalize the entire document.
3. Sign / verify the resulting bytes.

### 5.1.3 Zone signature canonicalization

A zone signature in a bundle manifest (chapter 3) is computed not over the encrypted ciphertext but over a **zone document** — the projection of the ethos document (§2.2) restricted to that one zone.

The zone document is:

```json
{
  "aithos": "0.1.0",
  "subject_did": "did:aithos:z6Mkr…",
  "subject_handle": "john-doe",
  "edition": { "version": "2026.04.19-1", "created_at": "…", "supersedes": "…" },
  "zone": "circle",
  "sections": [ … ]
}
```

This object is JCS-canonicalized and signed by the corresponding sphere key. The signature is then placed in `manifest.zones.<zone>.signature`.

The reason signatures are over the *plaintext* zone document, not over ciphertext: a recipient who decrypts a zone wants to verify the author, not the encryption. Signing the plaintext also means the author can re-encrypt (different DEK, different recipients) without re-signing.

### 5.1.4 DID document canonicalization

For the DID document (chapter 1):

1. Set `proof.proofValue = ""`.
2. JCS-canonicalize.
3. Sign with the root key.

### 5.1.5 Action artifact canonicalization

For an action artifact (§5.4):

1. Set `signature.value = ""` (and `counter_signature.value = ""` if present).
2. JCS-canonicalize.
3. Sign / verify in two passes if there are two signatures.

## 5.2 Signature primitive

All signatures in v0.1.0 use **Ed25519** as defined in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). The signature value is 64 bytes; encoded in JSON as base64url without padding.

The protocol's `alg` string for Ed25519 is `"ed25519"`. The DID-Core `type` for the verification method is `"Ed25519VerificationKey2020"` and the proof type for proof objects is `"Ed25519Signature2020"`.

A future version of the protocol MAY add post-quantum primitives (Dilithium, Falcon). When it does, mandates and bundles will carry an `alg` string accordingly, and verifiers will negotiate by capability declaration.

## 5.3 Domain separation (informative)

Aithos does not currently use domain-separator strings inside signed payloads. The substituted-value canonical form (§5.1.1) provides domain separation by structure: a mandate can never be confused with a zone document or an action artifact because the JSON shape differs.

Implementations that want belt-and-braces domain separation MAY pre-pend a fixed byte string before signing (`"aithos-mandate-v0.1\0" ‖ canonical_bytes`). If they do, they MUST do it consistently on both signing and verifying ends. The reference implementation does NOT do this, to keep the protocol simple.

## 5.4 Action artifacts

When an agent acts under a mandate (chapter 4), it MUST emit an **action artifact** — a signed JSON object that names the mandate, describes the action taken, and is signed by the agent's own key.

### 5.4.1 Anatomy

```json
{
  "aithos-action": "0.1.0",
  "id": "action_01JG5YQ3K8BPDRABCD",
  "mandate_id": "mandate_01JG4X7RABCDXYZ123",
  "issued_at": "2026-04-19T14:22:11Z",
  "actor": {
    "id": "urn:aithos:agent:gmail-agent@macbook-john-doe",
    "pubkey": "z6MkAgentEdKey…"
  },
  "action": {
    "verb": "email.reply",
    "target": {
      "kind": "email",
      "message_id": "<CABc1234@mail.gmail.com>",
      "thread_id": "thread-987",
      "to": ["alice@acme.com"]
    },
    "content_hash": "sha256:f3a8c9…",
    "summary": "Confirmed availability for Tuesday afternoon."
  },
  "signature": {
    "alg": "ed25519",
    "key": "z6MkAgentEdKey…",
    "value": "p8R…"
  },
  "counter_signature": null
}
```

### 5.4.2 Required fields

| Field | Description |
|---|---|
| `aithos-action` | Schema version. |
| `id` | ULID-based unique id of this action: `action_<ULID>`. |
| `mandate_id` | The mandate under which this action is taken. |
| `issued_at` | RFC 3339 timestamp at which the action was emitted. |
| `actor.id` | The agent's stable identifier. MUST match `mandate.grantee.id`. |
| `actor.pubkey` | The agent's Ed25519 public key. If `mandate.grantee.pubkey` is set, MUST match it. |
| `action.verb` | A scope string (§4.3) describing what was done. MUST appear in the mandate's `scopes`. |
| `action.target` | An object describing the target of the action. Schema is verb-specific (§5.4.4). |
| `action.content_hash` | `sha256:` followed by the hex SHA-256 of the action's payload (the email body, the calendar event, the post text, …). The payload itself is not in the artifact — only its hash. |
| `action.summary` | Short human-readable summary, ≤ 280 characters. |
| `signature` | Ed25519 signature by the agent's own key, computed per §5.1.5. |
| `counter_signature` | Either `null`, or an Ed25519 signature by the mandated sphere key. REQUIRED when the action's verb is in the mandate's `constraints.require_counter_sign` list. |

### 5.4.3 Counter-signing for binding actions

A mandate's `constraints.require_counter_sign` list (§4.2.5) names scopes considered binding. When the agent intends to take such an action, it MUST:

1. Prepare the action artifact with `counter_signature: null`.
2. Present the artifact (or a UX projection of it) to the subject.
3. Receive a signature from the subject's mandated sphere key over the canonical form.
4. Attach the signature as `counter_signature` and emit.

This mechanism guarantees that the most consequential class of actions cannot be taken by the agent unilaterally — the human has signed at the moment of the action, with a key only they hold.

### 5.4.4 Target schemas (informative)

The shape of `action.target` is verb-specific. Recommended shapes for v0.1.0 verbs:

```jsonc
// email.reply, email.draft, email.send_binding
{
  "kind": "email",
  "message_id": "<rfc822-message-id>",
  "thread_id": "string",
  "to":  ["addr@example.com"],
  "cc":  [],
  "bcc": []
}

// calendar.respond
{
  "kind": "calendar.invitation",
  "event_id": "string",
  "calendar_url": "https://...",
  "response": "accepted" | "declined" | "tentative"
}

// social.post.linkedin / social.post.x
{
  "kind": "social.post",
  "platform": "linkedin" | "x",
  "thread_target": "url-or-id-or-null"
}
```

Verifiers SHOULD treat unknown shapes as opaque and validate only the structural fields they recognize.

### 5.4.5 Verifier algorithm

To verify an action artifact `A` claims to be authorized:

1. Resolve `A.mandate_id` to the mandate document. (May be presented alongside the artifact, or fetched from the issuer's published mandate set.)
2. Verify the mandate per §4.7 *as of time `A.issued_at`*. The revocation check uses `A.issued_at`, not "now", so an action taken before revocation remains attributable.
3. Check `A.action.verb ∈ mandate.scopes`.
4. Check `A.actor.id == mandate.grantee.id`.
5. If `mandate.grantee.pubkey` is set, check `A.actor.pubkey == mandate.grantee.pubkey`.
6. Verify `A.signature` against `A.actor.pubkey` over the canonical form.
7. If `A.action.verb ∈ mandate.constraints.require_counter_sign`, verify `A.counter_signature` against the mandated sphere key.

If any check fails, the action is **unattributable**. The artifact is not a forgery in the narrow sense — its bytes are real — but it does not constitute proof that the subject authorized the action.

## 5.5 Challenge-response (informative)

Some transports (notably the HTTP API in chapter 6) require an agent to prove possession of `mandate.grantee.pubkey`'s private key without revealing it. The standard pattern is:

1. The server returns a `nonce` (32 random bytes) along with the request that triggered the requirement.
2. The agent signs `"aithos-challenge-v1\0" ‖ nonce` with its private key.
3. The server verifies the signature against `mandate.grantee.pubkey`.

The exact wire encoding (header, body, query parameter) is left to the transport spec.

## 5.6 Implementation notes

- **JCS is unforgiving.** Two implementations of JCS that disagree on Unicode escapes or number formatting will disagree on canonical bytes and break verification. Use a tested library; the reference CLI uses a JCS implementation pinned to a specific commit and tested against the W3C VC test vectors.
- **Sign over bytes, not strings.** After canonicalization you have UTF-8 bytes. Do not let your signature library re-encode them. Pass the raw bytes.
- **Constant-time comparisons.** When verifying a signature value, use a constant-time comparison. Most Ed25519 libraries do this internally; if you implement comparison yourself, be careful.
- **Clock skew.** Verifiers SHOULD accept a small leeway (typically 30 s) on `not_before` to allow for clock skew between issuer and agent. They MUST NOT accept any leeway on `not_after`, since that would allow expired mandates to be honored.

---

Next: [chapter 6 — Transport](./06-transport.md).
