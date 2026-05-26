# 6 · Pagination

## 6.1 Overview

The assets sub-protocol uses the same opaque-cursor pagination model as
the data sub-protocol (data §6). This chapter specifies the asset-side
particulars: which methods paginate, the page envelope shape, cursor
semantics, and behaviour under concurrent mutation.

## 6.2 Paginated methods

The methods that return paginated results:

- `aithos.assets.list_assets` (§5.3.3)
- `aithos.assets.list_references` (§5.3.4)

No other read primitive paginates. Single-asset reads return one
document; recipient lists are bounded by the wrap count (typically <
10) and are returned in full.

## 6.3 Page envelope

The generic shape of a paginated response:

```ts
interface Page<T> {
  items: T[];
  next_cursor?: string;
  // OPTIONAL — platform-dependent
  total_count_estimate?: number;
  total_count_exact?: number;
}
```

| Field | Description |
|---|---|
| `items` | The current page's entries. Always present, possibly empty. |
| `next_cursor` | An opaque string the caller passes to the next request to receive the following page. Absent when the current page is the last one. |
| `total_count_estimate` | OPTIONAL. An approximate total count, e.g. for UI display. The platform MAY emit this when an exact count would be expensive. |
| `total_count_exact` | OPTIONAL. Present only when the platform can produce an exact count cheaply (typically for small collections or with maintained counters). |

The caller MUST NOT decode or modify `next_cursor`. Its contents are
platform-private and may carry timestamps, paged DynamoDB keys,
GSI offsets, or anything else the platform needs.

## 6.4 Cursor semantics

### 6.4.1 Stable ordering

Each paginated method declares its **ordering field** and the
ordering direction. `list_assets` orders by `created_at` (newest
first by default; oldest first with `order: "oldest"`). `list_references`
orders by `since_height` (Ethos-bound references) or `since`
timestamp (data-bound references), descending by default.

Within a stable order, the page sequence is deterministic: pages
returned for the same `(filter, order, limit)` triple in the absence
of intervening mutations cover all items exactly once, in the declared
order, with no overlaps and no gaps.

### 6.4.2 Behaviour under concurrent mutation

The asset list is not a static dataset. New assets may be uploaded,
others deleted or orphaned between consecutive page requests. The
protocol does NOT guarantee a stable snapshot across pages.

The platform's behaviour:

- **New assets created after page 1 was returned** — appear on a later
  page in the natural order. A consumer iterating "newest first" may
  miss assets created between two page reads if those assets sort
  *before* the cursor's recorded position; the consumer SHOULD restart
  iteration if a strict snapshot is required.
- **Existing assets deleted between pages** — disappear silently. The
  consumer MUST be tolerant of "page N has 18 items instead of the
  expected 20" without treating it as an error.
- **Assets transitioning between ACTIVE / ORPHANED / TOMBSTONED** —
  visibility depends on the `include_orphaned` / `include_tombstoned`
  flags passed at request time. A transition during iteration may make
  an asset appear or disappear; the consumer SHOULD treat the result
  as eventually-consistent.

A consumer that needs a perfectly consistent view SHOULD use the
portability export (chapter 07) which captures a snapshot.

### 6.4.3 Cursor expiration

A cursor MAY embed a timestamp and expire after some platform-defined
window (default: 1 hour). A request with an expired cursor returns
`AITHOS_CURSOR_EXPIRED` (code -32040), and the caller SHOULD restart
iteration from the beginning.

This protects the platform from clients holding cursors indefinitely
and using them to perform deep enumeration outside of normal session
boundaries.

## 6.5 Limits

| Method | Default `limit` | Maximum `limit` |
|---|---|---|
| `aithos.assets.list_assets` | 20 | 100 |
| `aithos.assets.list_references` | 50 | 200 |

`limit` is the **maximum** number of items in the page. The platform
MAY return fewer if filter-eliminated rows are common in the underlying
storage. A page smaller than the requested limit does NOT imply the
iteration is complete; the `next_cursor` field is the only
authoritative end-of-stream signal.

## 6.6 No offset-based pagination

The protocol deliberately does NOT support offset/limit pagination.
Reasons:

- Offsets on a mutable dataset produce duplicate or skipped items
  under concurrent insertion/deletion.
- Offset pagination requires O(offset) work to skip past prior pages
  in many storage engines; opaque cursors are O(1).
- Asset lists are append-mostly; cursor-based forward iteration
  matches the usage pattern.

A future revision MAY add reverse iteration (a `prev_cursor` field)
if real-world usage shows a need.

---

Next: [chapter 07 — Portability](./07-portability.md).
