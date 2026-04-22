# 12 · Platform MCP — converse

> **Status at spec v0.2.0 — DEFERRED.** The converse endpoint is specified
> but **not scheduled for the current hosting MVP**. The MVP ships only the
> primitives endpoints of §10 (read + write) and the CLI-equivalent cockpit.
> Converse is a parallel surface that can be layered on top later without
> touching §10 semantics; it is kept in the spec as the canonical design so
> implementers do not re-invent it when they get there. Treat every "MUST"
> in this chapter as *"MUST when this endpoint is offered"*, not as an MVP
> requirement.

## 12.1 Overview

Chapter 10 specifies a **primitives** endpoint: sharp, technical tools that
return raw protocol objects (DID documents, manifests, zone ciphertexts,
mandates). That endpoint is for backends and developer tooling.

This chapter specifies a parallel **converse** endpoint intended for
LLM agents that talk to a human end user about a subject. The tools are the
same primitives underneath, but their tool descriptions, return shapes, and
accompanying `presentation_guidance` fields are designed so that the calling
agent, without any additional prompting from the integrator, produces a
conversation that reads as if the subject were speaking.

### 12.1.1 Design principle: zero server-side inference

The converse endpoint consumes **zero LLM tokens on the server**. It is a
declarative MCP surface — the entire conversational quality comes from (a)
the calling agent's own language abilities and (b) the `presentation_guidance`
that the subject authored and signed into their ethos. The platform composes
the guidance from the ethos on the fly, adds per-tool instructions, and
returns — no generation, no paraphrasing, no server-side model.

This keeps the marginal cost identical to the primitives endpoint, makes
scaling trivial, eliminates an inference bill, and — most importantly —
keeps the subject's words as the only human-authored text in the response.

### 12.1.2 Boundary with primitives

The converse endpoint is **read-only** in this spec revision. Any write
operation flows through §10.6. A subject authoring their own `presentation_guidance`
does so by publishing an ethos edition through `aithos.publish_ethos_edition`
like any other section.

## 12.2 Transport

### 12.2.1 Endpoint

```
POST {base}/mcp/converse
```

Single path, JSON-RPC over Streamable HTTP per §10.2.1.

### 12.2.2 Capabilities

```json
{
  "serverInfo": { "name": "aithos-platform", "version": "0.1.0" },
  "capabilities": {
    "tools": {},
    "experimental": { "aithos": { "spec": "0.1.0", "role": "converse" } }
  }
}
```

### 12.2.3 Authentication

Anonymous. Rate limits per §10.7 read path.

A mandate MAY be presented as `params.mandate` (full §4.2 object) to unlock
`circle`-scoped content; the server verifies it per §4.7 before producing
decrypted guidance. `self`-scoped content is not served by the converse
endpoint under any circumstance — by design, the `self` zone stays inward-
facing and is not mediated to third parties through narration.

## 12.3 `presentation_guidance` — the format

### 12.3.1 Purpose

`presentation_guidance` is a bundle of machine-readable instructions the
subject writes once, signs into their ethos, and that the platform embeds in
every converse response. It tells the calling agent — in tool-description
space, not at runtime — how to narrate the subject's content: voice, tone,
refusals, pinned framing.

It is authored as a single JSON object published in the subject's **public**
zone under a reserved section id `sec_presentation_guidance`. A subject
without one is served with a conservative default (§12.3.4).

### 12.3.2 Schema

```ts
interface PresentationGuidance {
  "aithos-guidance": "0.1.0";

  voice: {
    person: "first" | "third";          // "first" = speak as the subject
    languages: string[];                 // BCP-47, ordered by preference
    tone: string[];                      // free-form list: "direct", "warm", "curious", …
    formality: "casual" | "neutral" | "formal";
    verbosity: "short" | "medium" | "long";
    style_notes?: string;                // ≤ 500 chars; prose guidance to the agent
  };

  rendering: {
    preamble?: string;                   // optional verbatim opening line
    pinned_sections: string[];           // section ids, in order of salience
    topic_hints?: string[];              // ≤ 10 short phrases the subject cares about
    transition_style: "natural" | "headings" | "bullets";
    close?: string;                      // optional verbatim closing line
  };

  disclosure: {
    ai_disclosure: "always" | "on_request" | "never";
    disclosure_text?: string;            // what to say when disclosing
    scope_limits?: string[];             // topics the subject declines to speak to
  };

  refusal_template?: string;              // used when disclosure.scope_limits triggers
}
```

### 12.3.3 Field semantics

- **`voice.person`.** `"first"` means the agent narrates as if it were the
  subject ("I am Alice, I work on ..."). `"third"` means the agent narrates
  about the subject ("Alice is a designer who ..."). First-person is the
  default Aithos experience; third-person is for directory-style hosts.
- **`voice.languages`.** The agent SHOULD reply in the first language it
  shares with the end user. If none matches, it uses `languages[0]`.
- **`voice.verbosity`.** Upper-bound signal for the agent. `short` = one
  short paragraph; `medium` = 3–5 sentences; `long` = unconstrained.
- **`rendering.preamble` / `rendering.close`.** Verbatim strings the agent
  MUST include, exactly as written, around its response. These are the
  subject's own words; the agent does not paraphrase them.
- **`rendering.pinned_sections`.** Section ids (see §2.4) the agent SHOULD
  surface before others when a generic intro is requested.
- **`disclosure.ai_disclosure = "always"`.** The agent MUST state, at the
  start of every response, that it is narrating from an Aithos ethos and is
  not the subject themselves. The exact text is `disclosure.disclosure_text`
  if set, else a server-supplied default.
- **`disclosure.scope_limits`.** Topics outside the subject's consented
  scope. The agent MUST refuse to speculate on these topics and SHOULD use
  `refusal_template` (or a server default) as its refusal response.

### 12.3.4 Default guidance

When the subject's ethos does not carry `sec_presentation_guidance`, the
server returns this default alongside any converse response:

```json
{
  "aithos-guidance": "0.1.0",
  "voice": {
    "person": "first",
    "languages": ["en"],
    "tone": ["neutral", "factual"],
    "formality": "neutral",
    "verbosity": "short"
  },
  "rendering": {
    "pinned_sections": [],
    "transition_style": "natural"
  },
  "disclosure": {
    "ai_disclosure": "always",
    "disclosure_text": "You are speaking with an agent narrating from {handle}'s Aithos ethos, not with {handle} directly.",
    "scope_limits": [
      "private feelings, intentions, or decisions not stated in the ethos",
      "speculation about events not described in the ethos",
      "commitments or promises on behalf of the subject"
    ]
  },
  "refusal_template": "That is outside what {handle} has recorded in their ethos, so I cannot answer on their behalf."
}
```

`{handle}` is a template placeholder the server resolves per response.
Clients MUST perform the substitution verbatim; no other placeholders are
currently defined.

### 12.3.5 Authored guidance — required invariants

A subject-authored `presentation_guidance` MUST:

1. Be published in the **public** zone (guidance is never private — agents
   need it to decide what they can and cannot say).
2. Parse as valid JSON of the §12.3.2 schema.
3. Include a `disclosure.ai_disclosure` field. If omitted, the server
   treats the guidance as malformed and falls back to default.

The ethos renderer (`@aithos/protocol-core/ethos.renderZoneMarkdown`) writes
the guidance into the zone markdown as a fenced `json` block with a comment
header so it remains human-readable inside the `.ethos` bundle.

## 12.4 Tools

All tools in §12.4 are exposed on `POST {base}/mcp/converse`. Every response
is wrapped in:

```ts
interface ConverseResponse<T> {
  data: T;
  presentation_guidance: PresentationGuidance;
  subject: {
    did: string;
    handle: string;
    display_name?: string;
    canonical_url: string;
  };
  source: {
    bundle_id: string;
    edition_height: number;
    sections: { zone: string; id: string }[];  // which sections were surfaced
  };
  generated_at: string;
}
```

### 12.4.1 `aithos.converse.introduce`

"Introduce this subject to the caller as if speaking for them."

Input: `{ "did": DidRef, "mandate"?: Mandate }`.

Output: `ConverseResponse<IntroductionData>`:

```ts
interface IntroductionData {
  headline?: string;                      // from a section tagged "intro" if any
  pinned: { id: string; title: string; body: string }[];
  topics: string[];                        // presentation_guidance.rendering.topic_hints
}
```

Tool description (embedded in the MCP tools list and sent to the calling
agent verbatim):

> Speak in the voice specified by `presentation_guidance.voice`. Open
> with `rendering.preamble` if present. Introduce the subject using the
> `pinned` sections in order, without paraphrasing — quote the subject's
> own phrasing where practical. Do not invent facts absent from the
> returned sections. Close with `rendering.close` if present. Apply
> `disclosure.ai_disclosure` and honor `disclosure.scope_limits`.

### 12.4.2 `aithos.converse.answer_about`

"Answer a question about this subject using their ethos as source."

Input:

```json
{
  "did": "did:aithos:…",
  "question": "What do they think about remote work?",
  "zones": ["public", "circle"],
  "mandate": null
}
```

The server performs a substring / keyword match against the requested zones
(circle only if a valid mandate with `ethos.read.circle` is presented) and
returns the most relevant sections.

Output: `ConverseResponse<AnswerData>`:

```ts
interface AnswerData {
  matches: {
    zone: "public" | "circle";
    section_id: string;
    title: string;
    body: string;
    score: number;     // 0..1; opaque ranking signal
  }[];
  no_match_guidance?: string; // server-rendered refusal text when matches is empty
}
```

Tool description:

> If `matches` is non-empty, speak in the subject's voice using their
> words, citing the sections by title when natural. If `matches` is
> empty, use `no_match_guidance` as the basis of your reply — the
> subject has not spoken to this topic, so neither do you. Never fabricate
> an answer beyond the returned sections.

### 12.4.3 `aithos.converse.voice_profile`

"Return the subject's `presentation_guidance` alone, without fetching
content."

Input: `{ "did": DidRef }`.

Output: `ConverseResponse<null>` where `data` is `null` and the guidance
is the subject's full (or default) `presentation_guidance`. Useful for an
agent that wants to adapt its whole system prompt to the subject's voice
before making further calls.

### 12.4.4 `aithos.converse.list_topics`

"What does the subject want to discuss?"

Input: `{ "did": DidRef }`.

Output: `ConverseResponse<TopicList>`:

```ts
interface TopicList {
  topics: { label: string; hint?: string; sections: string[] }[];
}
```

Topics are derived from `presentation_guidance.rendering.topic_hints`
cross-referenced with the public zone's sections. The server does no NLP —
a topic appears if a hint matches a section title substring.

### 12.4.5 `aithos.converse.quote_section`

"Return a specific section, framed to be quoted in the subject's voice."

Input: `{ "did": DidRef, "section_id": string, "mandate"?: Mandate }`.

Output: `ConverseResponse<QuotedSection>`:

```ts
interface QuotedSection {
  zone: "public" | "circle";
  section_id: string;
  title: string;
  body: string;
  revision_height: number;
  updated_at: string;
}
```

Circle sections require a mandate with `ethos.read.circle`. Self sections
are never exposed by this endpoint.

Tool description:

> Quote the section body verbatim or near-verbatim. If the `voice.person`
> is `"first"`, speak as the subject; if `"third"`, attribute the quote.

## 12.5 Conformance

A conformant converse endpoint MUST implement §12.4.1, §12.4.2, §12.4.3.

SHOULD implement §12.4.4, §12.4.5.

MAY add additional `aithos.converse.x_*` tools.

Every response MUST include `presentation_guidance` — either the subject's
authored value or the server default (§12.3.4).

## 12.6 Refusal behavior

The server itself does not generate refusals — no LLM runs here. When a
subject's `disclosure.scope_limits` would apply, the server surfaces a
`refusal_template` in `presentation_guidance`; it is the calling agent's
responsibility to (a) detect an out-of-scope question and (b) apply the
template.

The server MUST, however, hard-refuse at the transport layer:

- `self` zone access via converse: HTTP 403, `AITHOS_ZONE_INACCESSIBLE`.
- `circle` zone access without a valid mandate: `AITHOS_INSUFFICIENT_SCOPE`.
- Tombstoned identity: `AITHOS_IDENTITY_TOMBSTONED` with the full
  `tombstoned_at` and `reason` from §10.6.6.

## 12.7 Caching

Converse responses are derived from immutable editions plus a stable
`presentation_guidance`. They are cacheable:

- `Cache-Control: public, max-age=60, stale-while-revalidate=300` for
  anonymous introduces/quotes.
- `Cache-Control: private, no-cache` when a `mandate` is presented
  (response contents vary by mandate).

The cache key MUST include `did`, `tool`, canonicalized input, and
`latest_edition_height`. A new edition invalidates the cache by virtue of
the height bump.

## 12.8 Authoring guidance (non-normative)

A subject onboarding through the web app is prompted to fill a short
`presentation_guidance` form in step 5 (PLATFORM-DESIGN §Parcours
d'onboarding). The form defaults to the §12.3.4 values and lets the subject
override voice, tone, pinned sections, and disclosure behavior. The form
writes a new section `sec_presentation_guidance` in the public zone on save.

Hosts MAY provide richer authoring UIs (live preview, example agent
transcript, tone sliders) but the on-wire representation is always the
§12.3.2 JSON.
