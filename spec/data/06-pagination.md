# 6 · Pagination

## 6.1 Overview

The data sub-protocol uses **cursor-based pagination** aligned with the
Ethos sub-protocol's `Page<T>` convention (Ethos §10.4.4). This chapter
specifies:

- The `Page<T>` wire shape.
- How cursors are formed and consumed.
- The semantics of pagination under concurrent mutation.
- How filters interact with pagination.
- The boundaries of what a paginated query may and may not do.

## 6.2 `Page<T>` shape

Every paginated read primitive returns:

```ts
interface Page<T> {
  items: T[];
  next_cursor?: string;      // absent when no further pages
  total_estimate?: number;   // best-effort, may be absent
}
```

- `items` — the records (or briefs, depending on the call) for this
  page. May be empty if no record matches the query.
- `next_cursor` — opaque token to pass as `cursor` on the next call.
  ABSENT (not `null`) when the page is the last one.
- `total_estimate` — best-effort estimate of total items matching the
  query, useful for "page X of N" UIs. MAY be absent. MUST NOT be used
  as a precise count — for that, use `aithos.data.count_records`.

The `next_cursor` is **opaque to clients**. A client MUST treat it as
an arbitrary string, MUST NOT parse, derive, or modify it. The platform
is free to change the cursor encoding between versions.

## 6.3 Cursor construction

A cursor encodes the position in the iteration as a tuple of:

- The collection URN.
- The current sort order (`newest` or `oldest`).
- The filter, in a canonicalized form.
- The position in the result stream (typically the last `record_id`
  emitted, plus any secondary sort key).
- An issued-at timestamp (for cursor expiry).

A reference encoding (the platform MAY choose differently):

```json
{
  "v": 1,
  "c": "urn:aithos:collection:did:aithos:z6Mkr…:contacts",
  "o": "newest",
  "f": "<canonical-json of filter>",
  "p": "record_01J…",
  "iat": "2026-05-14T12:00:00Z"
}
```

Serialized as base64url, optionally MACed with a server secret to
prevent tampering. The MAC is not strictly required (a tampered cursor
either still works or fails clearly), but defends against denial of
service via crafted cursors.

## 6.4 Cursor stability

A cursor remains valid for **at least 1 hour** from issuance. Beyond
that, the platform MAY refuse with `AITHOS_DATA_CURSOR_EXPIRED` and the
client MUST start a fresh query.

The cursor's stability under collection mutation is bounded:

- **A new record inserted at the top of the sort order while paginating
  newest-first** does NOT appear in the iteration — the cursor anchors
  on the position at the time it was issued.
- **A record deleted while paginating** disappears from subsequent
  pages. The total count drops accordingly.
- **A record updated while paginating** stays in the iteration if it
  still matches the filter post-update; falls out if it no longer
  matches.
- **The collection's CMK rotated mid-pagination** — the cursor remains
  valid (the cursor doesn't carry crypto state), but the client may
  need to refetch the collection metadata if it has cached the CMK
  envelope.

These semantics match the "snapshot-at-cursor-issuance" approximation
that DynamoDB-style pagination naturally provides. They are NOT a
strong-consistency snapshot — concurrent writers can produce a final
iteration that misses or duplicates records depending on timing.
Clients sensitive to this MUST use `expected_modified_at` for write
operations or take an export-side snapshot for analytical reads.

## 6.5 Default ordering

When `order` is not specified, the platform returns records in **ULID
descending order** (newest first). Rationale:

- Matches typical UI expectations (most recent first).
- Lexicographic on ULIDs == reverse-chronological without needing a
  separate timestamp comparison.
- Predictable across implementations.

`order: "oldest"` reverses the iteration to ULID-ascending. Other
orderings (e.g. by a custom field) require sorting client-side after
fetching, or future minor versions of the protocol.

## 6.6 Page size

Each pagination call accepts a `limit` parameter:

| Parameter | Default | Maximum |
|---|---|---|
| `list_records` | 20 | 100 |
| `list_collections` | 20 | 100 |
| `list_schemas` | 50 | 200 |
| `list_public_collections` | 20 | 100 |

A platform MAY return fewer items than `limit` requests, in which case
`next_cursor` still reflects whether more pages exist. Returning fewer
items than requested is common when the platform's pagination granularity
(e.g. DynamoDB's 1 MB page limit) is hit before the logical limit.

Conversely, a platform MUST NOT return more items than `limit` requests.
A client iterating with `limit: 100` MUST NEVER receive `items.length > 100`.

## 6.7 Pagination with filters

The `filter` parameter (§5.3.5) is part of the iteration's identity.
A cursor issued for one filter cannot be used with a different filter:

```ts
// Page 1
const page1 = await client.data.contacts.list({
  filter: { equals: { field: 'status', value: 'lead' } },
  limit: 20,
});

// Page 2 — same filter, pass cursor
const page2 = await client.data.contacts.list({
  filter: { equals: { field: 'status', value: 'lead' } },
  cursor: page1.next_cursor,
});
```

If the second call had a different filter or omitted it, the platform
returns `AITHOS_DATA_CURSOR_FILTER_MISMATCH`. The client MUST start a
new iteration from scratch.

For interactive UIs where the user changes the filter mid-flow, the
client SHOULD discard the cursor and issue a fresh query. The cursor
mismatch error is a development-time correctness signal, not a
user-facing recovery path.

## 6.8 Composing pagination with mandate filters

When the caller's mandate carries a filter (§4.3), that filter is
applied **in addition to** the caller's query filter. The effective
result set is:

```
records_returned = records_matching(mandate_filter) ∩ records_matching(query_filter)
```

A cursor issued under a mandate filter is bound to that mandate — if
the mandate is revoked, the cursor becomes invalid. The platform MAY
return `AITHOS_MANDATE_REVOKED` rather than silently truncating.

The mandate filter is opaque to the caller (the platform doesn't expose
it explicitly in the cursor). A caller can detect a mandate filter is
in effect by comparing returned record counts: if `count_records` for
the same query yields a higher number than the actual iteration
produces, the difference is records hidden by the mandate filter.

## 6.9 Empty pages and end-of-stream

A pagination call returns:

- `items: []` and `next_cursor: undefined` when there are no records
  at all matching the filter.
- `items: [...non-empty]` and `next_cursor: "..."` while iteration
  continues.
- `items: [...possibly-empty]` and `next_cursor: undefined` on the
  last page. The last page MAY be empty if the page boundary aligns
  exactly with a deletion.

A client iterates by checking `next_cursor` truthy/falsy:

```ts
let cursor: string | undefined = undefined;
do {
  const page = await client.data.contacts.list({ cursor });
  for (const record of page.items) {
    yield record;
  }
  cursor = page.next_cursor;
} while (cursor !== undefined);
```

## 6.10 What is NOT supported

For clarity, the following are out of scope for v0.1:

- **Random-access pagination** (jumping to page N). Cursors are
  sequential; you must walk pages in order.
- **Backward pagination** (going from a cursor back to the previous
  page). Cursors are forward-only.
- **Multi-field ordering.** A query orders by ULID (creation time) only.
  To order by a custom field (e.g. `last_contact_at`), filter to a
  manageable set and sort client-side.
- **`OFFSET`-style pagination.** Considered and rejected — offset
  becomes incorrect under concurrent inserts/deletes, and DynamoDB-style
  cursors are strictly better for most use cases.

A future minor version MAY add backward pagination and multi-field
sort as optional capabilities behind a `experimental.aithos.data`
capability flag.

---

Next: [chapter 07 — Portability](./07-portability.md).
