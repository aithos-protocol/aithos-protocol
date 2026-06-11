# 6 · Transport

## 6.1 Overview

The protocol is transport-agnostic in principle — a bundle is a zip file and a mandate is a JSON object; both can travel by email attachment, USB stick, HTTP, MCP, or carrier pigeon. In practice two transports matter for v0.1.0 and are specified normatively:

- **MCP (Model Context Protocol).** The primary transport for letting an AI agent consume an ethos. Most agent hosts (Claude Desktop, Cursor, Zed, Continue, ChatGPT Desktop, …) speak MCP, so a single MCP server lets an ethos reach any of them without per-vendor integration work.
- **HTTP.** The transport for publishing an ethos at a public URL and for agent-to-server interactions when MCP is not available.

This chapter specifies both, identifies the points where mandates (chapter 4) are presented, and leaves a deliberately small surface area for extensions.

## 6.2 MCP bridge

### 6.2.1 Server shape

The reference server is `@aithos/mcp` (`aithos-mcp`, packages/mcp). It speaks
MCP over stdio (default) or Streamable HTTP, reads the local keystore at
`$AITHOS_HOME` through the `AithosStorage` abstraction, and serves the
canonical tool catalogue of `@aithos/agent-tools` (tool names, schemas, and
normative descriptions are defined THERE, not here).

Two launch shapes:

**Owner shape** — `aithos-mcp` on the subject's machine: full authority over
the local identities, all tools exposed, writes are transactional by default
(staged until `ethos_commit`; `--auto-commit` restores per-write editions).

**Delegated shape (mandate pack)** — `aithos-mcp --mandate-pack <path>`. The
pack is ONE JSON file the subject hands to an agent host:

```json
{
  "aithos-mandate-pack": "1",
  "mandate":   { /* the signed mandate, §4 */ },
  "agent_key": { "seed_hex": "…", "pubkey_multibase": "z…" },
  "options":   { "auto_commit": false, "expose_tools": ["…"] }
}
```

A server booted under a pack MUST:

- expose only the tools the mandate's scopes allow (`tools/list` filtering),
- sign writes with the pack's delegate key by default (no per-call `mandate`
  / `agent_key` arguments needed),
- refuse a pack whose `agent_key.pubkey_multibase` does not match
  `mandate.grantee.pubkey`,
- re-check the mandate's validity window and revocation status BEFORE
  anything persists — at stage time and again at commit. An expired or
  revoked mandate never writes.

Sessions may introspect their own authority via `mandate_describe` (the
mandate document, live status, and the EXACT served tool set) and
`ethos_preflight_write` (authorized + reason, without executing).

### 6.2.2 Resources

The reference server exposes the following resources (absent when
inapplicable). URIs are subject-addressed — one server can serve several
identities:

| URI | Condition | Content |
|---|---|---|
| `aithos://identities` | always | JSON. Index of every identity the host serves (handle, DID, tracked flag). |
| `aithos://ethos/{handle}/manifest` | always | JSON. The current signed manifest (edition, zone digests, gamma anchor). |
| `aithos://ethos/{handle}/voice` | always | The subject's presentation guidance (§12.3): an authored PUBLIC section tagged `voice` (or `guidance`) served verbatim (JSON §12.3.2, or prose), else the §12.3.4 default with `{handle}` substituted. JSON when authored-as-JSON or default; markdown when authored prose. |
| `aithos://ethos/{handle}/public` | always | Markdown, UTF-8. The public zone (re-rendered per-section on v0.3 stores). |
| `aithos://ethos/{handle}/circle` · `…/self` | server holds the zone key | Markdown, UTF-8, decrypted in memory. |
| `aithos://ethos/{handle}/manifest-path` | filesystem hosts only | Plain text. Absolute on-disk manifest path (diagnostic). |

A server that cannot decrypt a zone resource MUST NOT fail the read: it
degrades — the raw ciphertext envelope (v0.2 single-blob stores), or an
explanatory text pointing the agent at the per-section read tools (v0.3) —
or returns a structured error clients can recognize
(`AITHOS_ZONE_INACCESSIBLE`, code `-32001`). Clients MUST handle all three.

### 6.2.3 Tools

The tool surface is defined ONCE, in the canonical catalogue
`@aithos/agent-tools` (decision D1): names, argument schemas, and normative
descriptions live there and are served verbatim by every host (the parity
tests T10 / T10-proxy pin this). This section does not duplicate the
catalogue; normatively:

- A conformant server MUST serve at least the public read family —
  `ethos_list_sections`, `ethos_read_section`, `ethos_read_sections`,
  `ethos_search` — with the catalogue's exact specs.
- `tools/list` MUST be filtered by the session mandate's scopes
  (`toolsForScopes`), and per-call zone enforcement MUST remain at dispatch
  time (defense in depth — a forced out-of-scope call never reads or
  writes).
- Writes are transactional by default (staged until `ethos_commit`;
  per-write editions only under `auto_commit`).
- The narration tools (`ethos_introduce`) are public-only STRUCTURALLY:
  they never read circle/self whatever the mandate (§4 narration rule;
  §12 is their behavioral reference).
- `agent_briefing` composes `mandate_describe` + the voice profile (§12.3)
  + `ethos_context_pack` in one call; servers SHOULD serve it wherever the
  read family is served.

### 6.2.4 Prompts (retired)

Earlier drafts specified a `write_as` prompt bundling whole zones into a
system message. It was never implemented and is RETIRED: budgeted, scoped
grounding belongs to the `ethos_context_pack` / `agent_briefing` tools, and
the subject's voice to the `aithos://ethos/{handle}/voice` resource (§12.3).
Servers MUST NOT rely on MCP prompts for conformance.

### 6.2.5 Handshake and capabilities

An Aithos MCP server declares, in its `initialize` response:

```json
{
  "serverInfo": { "name": "aithos-mcp", "version": "0.1.0" },
  "capabilities": { "resources": {}, "tools": {} }
}
```

The `aithos-mcp` name is reserved for conformant servers. Third-party implementations MUST use a distinct name; they MAY additionally advertise support for this spec via a `capabilities.experimental.aithos` entry:

```json
{ "capabilities": { "experimental": { "aithos": { "version": "0.1.0" } } } }
```

### 6.2.6 Mandate presentation over MCP

MCP as of its 2024-11-05 revision does not define a standard `Authorization`-style header for tool calls. Until it does, Aithos MCP servers accept mandates in one of two ways:

1. **Launch-time mandate.** The server is launched with a `--mandate <path>` argument. The mandate is loaded, validated, and its scopes control which resources and tools respond. Simple, static, enough for the common case.
2. **Inline mandate.** Tools that require authorization take an optional `mandate` argument — a JSON object — and validate it per §4.7 before acting. This enables a richer agent loop where different tools may hold different mandates.

Servers MUST implement (1). Servers MAY implement (2).

## 6.3 HTTP API

### 6.3.1 Endpoints

```
GET   {base}/ethos/{handle}                           — fetch the public zone
GET   {base}/ethos/{handle}?zones=public,circle       — fetch multiple zones
GET   {base}/ethos/{handle}/did.json                  — fetch the DID document
GET   {base}/ethos/{handle}/revocations.json          — fetch the revocation list
POST  {base}/ethos/{handle}/challenge                 — request a nonce for challenge-response
```

The `{handle}` path segment is URL-encoded from the subject's handle.

### 6.3.2 Response bodies

`GET /ethos/{handle}` returns a JSON object of the shape:

```json
{
  "aithos": "0.1.0",
  "manifest": { …bundle manifest… },
  "did": { …DID document… },
  "zones": {
    "public": { "cleartext": "# Identity\n…" },
    "circle": { "wire": { …ciphertext envelope… } },    // only if authorized
    "self":   { "wire": { …ciphertext envelope… } }     // only if authorized
  }
}
```

The server MUST strip any zone the requester is not authorized to receive. Authorization flow:

1. No `Authorization` header → only `public` is returned.
2. `Authorization: Aithos <mandate-token>` where `<mandate-token>` is a compact-encoded mandate (§6.3.4) → the zones listed in the mandate's scopes are returned in encrypted form (the requester then decrypts client-side using their own key material, referenced by the mandate).
3. A signed challenge-response is provided (§6.3.5) tying the mandate to the current request.

### 6.3.3 Caching

All Aithos HTTP responses SHOULD carry:

- `ETag: "<bundle_id>"` — the immutable bundle URN, since an edition never changes after publication.
- `Cache-Control: public, max-age=300` on the public zone; `private, no-cache` on the circle/self zones.
- `Content-Type: application/json`.

### 6.3.4 Compact mandate encoding

For HTTP `Authorization` headers, a mandate may be sent as a JCS-canonicalized JSON object, base64url-encoded:

```
Authorization: Aithos <base64url(canonical_mandate)>
```

Clients MUST include the full mandate, not just its id — the server may not have the mandate cached.

### 6.3.5 Challenge-response

To prove possession of `mandate.grantee.pubkey`'s private key, the client may:

1. `POST /ethos/{handle}/challenge` → receives `{ nonce: "<base64url(32 random bytes)>", valid_for: 60 }`.
2. Sign `"aithos-challenge-v1\0" ‖ base64url_decode(nonce)` with its private key.
3. Retry the protected request with both headers:
   ```
   Authorization: Aithos <base64url(mandate)>
   Aithos-Challenge: <nonce>:<base64url(signature)>
   ```
4. Server verifies the signature against `mandate.grantee.pubkey`, then serves.

Challenges are one-shot and expire after `valid_for` seconds.

### 6.3.6 Errors

The HTTP API uses conventional status codes plus an optional `application/problem+json` body per [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807):

- `200` — OK.
- `401` — no or invalid mandate.
- `403` — valid mandate but insufficient scope.
- `404` — unknown handle.
- `410` — edition withdrawn.
- `429` — rate-limited.

Aithos-specific problem types:

- `https://aithos.dev/problems/mandate-expired`
- `https://aithos.dev/problems/mandate-revoked`
- `https://aithos.dev/problems/scope-insufficient`
- `https://aithos.dev/problems/zone-inaccessible`

## 6.4 Discovery (informative, v0.2-bound)

Discovery — resolving a short handle to a `did:aithos` identifier — is explicitly deferred to v0.2. Anticipated patterns include:

- **DNS TXT.** `_aithos.example.com IN TXT "did:aithos:z6Mkr…"`.
- **`.well-known`.** `GET https://example.com/.well-known/did-aithos/<handle>`.
- **Companion `did:web`.** The subject maintains a `did:web` DID whose document references the `did:aithos`; any `did:web` resolver can find Aithos through it.

Until v0.2 lands, implementations MUST hardcode or out-of-band communicate the mapping.

## 6.5 Other transports (non-normative)

Nothing in the protocol prevents an implementation from transporting an ethos via:

- **Email attachment.** A `.ethos` file delivered as an email attachment is a perfectly valid way to give a counterparty an offline copy.
- **USB / removable media.** Useful for self-sovereign authors who prefer to hand a bundle rather than host it.
- **IPFS / content-addressed storage.** The bundle is immutable and signed; content addressing is natural.
- **ActivityPub / fediverse.** A subject's fediverse actor could advertise a `did:aithos` in its profile metadata, and deliver bundle URLs through ActivityPub messages.

These are possible today. Future drafts may standardize the binding if usage warrants it.

---

Next: [chapter 7 — Threat model](./07-threat-model.md).
