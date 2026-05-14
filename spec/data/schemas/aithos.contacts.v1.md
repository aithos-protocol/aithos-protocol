# `aithos.contacts.v1` — Contact schema

> **Status:** Normative for `aithos.data.v0.1`. First core schema
> published under the data sub-protocol.

## Purpose

A schema for natural-person contact records — prospects, customers,
partners, address book entries. Designed for CRM-like workflows but
intentionally minimal so the same record format serves both a
freelance CRM and a contact-book PWA.

## Identification

| Field | Value |
|---|---|
| `aithos:schema` | `aithos.contacts.v1` |
| Current version | `0.1.0` |
| Canonical URL | `https://schemas.aithos.dev/aithos.contacts.v1.json` |
| Published | 2026-05-14 |

## Field summary

| Field | Visibility | Required | Notes |
|---|---|---|---|
| `name` | indexable (clear) | **yes** | Free-form display name |
| `email` | indexable (clear) | no | Exact-match lookup |
| `phone_hash` | indexable (clear) | no | `blake3:<hex>` of normalized phone |
| `status` | indexable (clear) | no | enum: lead/contact/opportunity/won/lost/archived |
| `tags` | indexable (clear) | no | Array of free-form labels, max 32, unique |
| `source` | indexable (clear) | no | How the contact entered the pipeline |
| `created_at` | indexable (clear) | server-set | `aithos:auto: on_insert` |
| `modified_at` | indexable (clear) | server-set | `aithos:auto: on_modify` |
| `last_contacted_at` | indexable (clear) | no | Client-set |
| `phone` | **encrypted** | no | PII; clear phone in payload |
| `notes` | **encrypted** | no | Free-form journal |
| `conversation_log` | **encrypted** | no | Append-only structured log |
| `form_responses` | **encrypted** | no | Form data |
| `custom_fields` | **encrypted** | no | User-defined |

## What the server can see

Per the data sub-protocol's threat model (`spec/data/09-threat-model.md`
§9.4.3), the platform sees every field marked `aithos:indexable`. For
contacts that means:

- The contact's name, email, status, tags, source, timestamps.
- The hash of the phone number (not the number itself).
- The fact that the record exists and its size.
- Who is authorized to read it (the wraps list on the collection).

The platform **cannot** see:

- The phone number in clear.
- Notes, conversation logs, form responses, custom fields.

Subjects who consider names sensitive (e.g. journalists protecting
sources) should NOT use this schema — use a more restrictive variant
that moves `name` into the encrypted payload.

## Designed-for invariants

- **Append-only conversation_log.** The schema does not enforce this
  at validation time (an array field can be replaced wholesale), but
  applications writing to this field SHOULD only append. Tools may
  add hash-chain invariants in a future minor revision.
- **Status transitions.** Not enforced by the schema. Applications are
  expected to manage the workflow (`lead → contact → opportunity →
  won/lost`) according to their own logic.
- **One record per real contact.** The schema does not enforce
  uniqueness. Deduplication is the application's responsibility, with
  `email` and `phone_hash` providing indexable keys for lookup.

## Validation rules at insert / update

The platform applies these rules on every `insert_record` /
`update_record` against this schema:

1. The supplied `metadata` object contains only the indexable fields.
   Unknown fields rejected with `-32072 AITHOS_DATA_RECORD_INVALID`.
2. Required fields present (`name`).
3. Type checks per JSON Schema 2020-12.
4. Fields marked `aithos:auto: on_insert` / `on_modify`:
   - Client-supplied values are silently overridden (or rejected
     with `-32072` depending on implementation choice — see
     `aithos.data.v0.1` §3.5.1).
5. `additionalProperties: false` — no fields outside the schema are
   accepted in `metadata`. The encrypted payload is opaque to the
   platform so it isn't validated server-side at the schema level.

## Querying

Common query patterns supported by the platform's GSI1:

- "All my leads, newest first" → `list_records({ filter: { equals: { field: "status", value: "lead" } }, order: "newest" })`.
- "Find the contact with this email" → `list_records({ filter: { equals: { field: "email", value: "jane@example.com" } } })`.
- "Find the contact with this phone" → compute `blake3:<hex>` of the
  normalized phone client-side, then
  `list_records({ filter: { equals: { field: "phone_hash", value: "blake3:..." } } })`.
- "Contacts last touched in the last 7 days" → `list_records({ filter: { range: { field: "last_contacted_at", gte: "<iso>" } } })`.

## Backward compatibility commitments

The protocol guarantees that any subsequent minor version of this schema
(`0.1.1`, `0.2.0`, …) will be a strict superset of v0.1.0 within the
major version `aithos.contacts.v1`:

- Existing fields keep the same types and `aithos:indexable` /
  `aithos:encrypted` annotations.
- New fields may be added (always optional).
- The enum on `status` may add values, never remove.

A breaking change (rename, removal, type narrowing, indexable→encrypted
flip) requires a new major version `aithos.contacts.v2`.

## License

Apache-2.0 — same as the rest of the Aithos protocol.
