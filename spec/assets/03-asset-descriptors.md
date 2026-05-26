# 3 · Asset descriptors and referencing

## 3.1 Overview

An asset, on its own, is a blob with metadata. It becomes useful only
when **referenced** from a consuming context — an Ethos section, a data
record, or some future container. This chapter specifies:

- How a section or record declares its outgoing references (§3.2).
- The URI scheme used to embed references in markdown bodies (§3.3).
- Constraints on supported media types and integrity verification
  (§3.4).
- The interaction between asset references and the Ethos bundle
  manifest signature (§3.5).

Chapter 04 covers the authorization side (who can read an asset);
this chapter covers the descriptive side (what an asset is and how it
is named in context).

## 3.2 Referencing from an Ethos section

### 3.2.1 The `assets[]` slot on a section

> **Spec coordination note.** The `assets[]` slot specified here is a
> coordinated extension to the Ethos bundle manifest (Ethos spec §3.3).
> v0.1 of this assets sub-protocol introduces the slot. A future
> revision of the bundle spec MUST promote this slot into its normative
> field reference; until then, an Ethos manifest implementing the
> assets sub-protocol carries an unrecognized field that the v0.2
> manifest validator MUST tolerate (Ethos §2.2.2 already allows
> `x-`-prefixed extensions; we therefore record the slot as `x-assets`
> in v0.1 implementations, to be renamed `assets` once the bundle spec
> formally adopts it).

A section that references one or more assets carries an `x-assets`
array at the section level (Ethos v0.3, when sections gain explicit
manifest entries) or at the zone level (Ethos v0.2 fallback). The
v0.3-shaped slot is the canonical form; the v0.2 shape is a transient
compatibility layer.

**v0.3 shape (section-level):**

```json
{
  "section_id": "sec_identity",
  "title": "Identity",
  "file": "public/sec_identity.md",
  "sha256_of_plaintext": "f3a8…",
  "gamma_ref": "gamma_01J…",
  "x-assets": [
    {
      "urn": "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…",
      "role": "inline",
      "media_type": "image/png",
      "size_bytes": 184320,
      "sha256_of_plaintext": "a8b2f1ef…",
      "caption": "Profile photograph",
      "alt_text": "John Doe smiling at the camera"
    }
  ]
}
```

**v0.2 shape (zone-level fallback):**

```json
{
  "file": "public.md",
  "encrypted": false,
  "sha256_of_plaintext": "…",
  "section_titles": ["…"],
  "signature": { … },
  "x-assets": [
    {
      "urn": "urn:aithos:asset:did:aithos:z6Mkr…:asset_01J…",
      "in_section": "sec_identity",
      "role": "inline",
      "media_type": "image/png",
      "size_bytes": 184320,
      "sha256_of_plaintext": "a8b2f1ef…",
      "caption": "Profile photograph",
      "alt_text": "John Doe smiling at the camera"
    }
  ]
}
```

The v0.2 shape carries an explicit `in_section` field so that consumers
can still attribute the asset to its section even though Ethos v0.2
does not list sections in the manifest. The same `sec_…` IDs the
markdown body uses (via the `<!-- sec_… · gamma_… -->` comment) are
used here.

### 3.2.2 Field reference for asset descriptor entries

| Field | Type | Description |
|---|---|---|
| `urn` | string | Canonical asset URN per §1.2.1. REQUIRED. |
| `role` | string | One of `"inline"`, `"attachment"`, `"thumbnail"`. REQUIRED. See §3.2.3. |
| `in_section` | string | Section ID this reference belongs to. REQUIRED at zone-level (v0.2); MUST be absent at section-level (v0.3). |
| `media_type` | string | IANA media type per RFC 6838. REQUIRED. Must match the asset metadata's `media_type` exactly. |
| `size_bytes` | integer | Plaintext byte count. REQUIRED. Must match the asset metadata. |
| `sha256_of_plaintext` | string (hex) | Plaintext SHA-256. REQUIRED. Must match the asset metadata. The duplication into the bundle manifest is intentional — it lets a counterparty verify content integrity without needing to call the asset PDS RPC. |
| `caption` | string | OPTIONAL. Display caption shown alongside the asset when rendered. 0–200 characters. |
| `alt_text` | string | OPTIONAL. Accessibility text used when the asset is an image or other visual. 0–300 characters. |

The fields beyond `urn` are denormalized copies of the asset's own
metadata. The duplication is deliberate: the bundle manifest is the
**signed** carrier, and embedding the asset's identifying fields in
the manifest binds the asset's identity to the subject's signature.
A platform that returns a different `media_type` or
`sha256_of_plaintext` than what the manifest declares is detectable as
inconsistent without trusting the platform.

### 3.2.3 Role semantics

- **`"inline"`** — the asset is intended to be rendered within the
  section's text flow at the position indicated by the markdown
  reference (§3.3). For images, this is an `<img>` in HTML; for audio,
  an `<audio>` element; for documents, an embedded viewer or download
  link. The renderer chooses.
- **`"attachment"`** — the asset is associated with the section but
  not rendered inline. Typical use: a CV PDF attached to a section
  describing a person's professional background, displayed as a
  download chip below the section's prose.
- **`"thumbnail"`** — a small representation of another asset. Such an
  entry MAY carry an additional `for_urn` field pointing to the
  primary asset. The thumbnail can be public even when the primary is
  private, giving recipients without the AMK a preview placeholder.

The role does NOT affect the asset's underlying storage or encryption
— it is purely a hint to the renderer.

## 3.3 The `aithos-asset:` URI scheme

Section bodies are markdown. An inline asset is referenced by an
`aithos-asset:` URI placed in the standard markdown image or link
syntax:

```markdown
# Identity

A bit about me: I work primarily in the Mediterranean rim, in venues
where the line between architecture and ritual is thin.

![Profile photograph](aithos-asset:urn:aithos:asset:did:aithos:z6Mkr…:asset_01J9YB2X7Q1K3P4R5S6T7U8V9W "Profile, 2026")
```

The scheme:

```
aithos-asset:<asset_urn>
```

is a "URI scheme" in the loose sense — it has no DNS authority, no
path, no query. The whole right-hand side is the asset URN as
specified in §1.2.1. A markdown renderer that does not understand the
scheme falls back to showing the alt text and the title; a renderer
that understands it resolves the URN through the assets RPC and
renders the bytes.

### 3.3.1 Resolution

To resolve an `aithos-asset:<urn>` reference:

1. Parse the URN to extract `subject_did` and `asset_id`.
2. Discover the asset PDS endpoint for `subject_did` via the standard
   Aithos resolver (Ethos spec §6) — typically a well-known endpoint
   at `https://api.<subject-domain>/mcp/assets/`.
3. Call `aithos.assets.get_asset` for the URN (chapter 05 §5.3.1).
4. For private assets: unwrap the AMK with the caller's key; fetch the
   ciphertext via the returned presigned URL; decrypt; verify SHA-256.
5. For public assets: fetch directly via the returned stable URL;
   verify SHA-256.
6. Render the plaintext bytes according to the media type and role
   declared in the manifest entry (§3.2.1).

A renderer that lacks the credentials to unwrap a private asset MUST
display a placeholder (the alt text, a generic icon, or a "locked
asset" indicator) and MUST NOT silently fail.

### 3.3.2 Why not a normal HTTPS URL?

A direct HTTPS URL embedded in markdown — `![](https://...)` — has two
problems for Aithos use:

- **Mutability.** An HTTPS URL points to wherever the host wants it to
  point. The bundle's signature does not cover the bytes the URL
  resolves to, only the URL string. A host can change the bytes at any
  time and the signature still verifies.
- **Indirection.** The URL embeds the asset's hosting location, which
  is a platform-specific artifact. A subject migrating from one PDS
  to another would have to rewrite every URL in their Ethos.

The `aithos-asset:` scheme avoids both: the URN binds to content
(through `sha256_of_plaintext` in the manifest descriptor), and it
binds to identity (through `subject_did`), not to a hosting location.

A renderer MAY, as a UX optimization, resolve the URN to a CloudFront
URL once and cache that resolution for the duration of a render — but
the bundle's reference itself never carries the CloudFront URL.

### 3.3.3 Linking versus embedding

A non-image asset (e.g. a PDF) is typically referenced as a markdown
link rather than an image:

```markdown
My current CV: [download (PDF)](aithos-asset:urn:aithos:asset:did:aithos:z6Mkr…:asset_01K…)
```

The renderer chooses how to present the link (a download chip, an
embedded viewer if the role is `inline` and the runtime supports it).
The protocol does not prescribe.

## 3.4 Media types and integrity

### 3.4.1 Allow-list

The platform MUST maintain a configurable allow-list of media types
that may be uploaded. The recommended baseline for v0.1:

| Category | Media types |
|---|---|
| Images | `image/png`, `image/jpeg`, `image/webp`, `image/gif`, `image/svg+xml`, `image/avif` |
| Documents | `application/pdf`, `application/vnd.openxmlformats-officedocument.*`, `application/msword`, `text/markdown`, `text/plain` |
| Audio | `audio/mpeg`, `audio/wav`, `audio/ogg`, `audio/flac`, `audio/aac` |
| Video | `video/mp4`, `video/webm`, `video/quicktime` |
| Archives | `application/zip` (with sniffing for `.ethos` rejection — see below) |

The platform MUST refuse media types that would cause active code
execution in a typical browser:

- `text/html`
- `application/javascript`, `text/javascript`
- `application/xhtml+xml`
- `application/x-shockwave-flash`
- Any `*/*+xml` that the renderer cannot guarantee is inert

`image/svg+xml` is borderline (SVG can carry script). Implementations
that allow SVG MUST serve it with `Content-Disposition: attachment` or
with a strict CSP that disables script execution, and SHOULD prefer
rasterized derivatives for inline rendering.

### 3.4.2 Magic-byte sniffing

The platform MAY perform magic-byte sniffing at `complete_upload` to
verify the declared media type matches the bytes' magic prefix. Mismatch
SHOULD warn the caller but is not, in v0.1, normatively a hard reject —
some legitimate cases (encrypted-then-magic-byte-stripped content,
custom formats) do not have meaningful magic bytes.

Sniffing for `.ethos` archive lookalikes inside `application/zip` is
RECOMMENDED to avoid users accidentally smuggling Ethos bundles in
asset form.

### 3.4.3 Integrity verification

Three integrity checks operate on every asset fetch:

1. **AEAD authenticity** (private assets only). The Poly1305 tag
   verifies that the ciphertext was produced under the AMK and
   matches the AAD-bound `asset_urn`. Failure indicates tampering or
   key mismatch.
2. **SHA-256 of plaintext** (always). The fetched plaintext (decrypted
   for private, raw for public) is hashed and compared to the
   `sha256_of_plaintext` declared in the asset's metadata document.
   Failure indicates corruption or substitution.
3. **Manifest cross-check** (when fetching via an Ethos reference). The
   asset's `sha256_of_plaintext` (returned by the asset PDS) must
   equal the `sha256_of_plaintext` declared in the referring section's
   `x-assets[]` descriptor. Failure indicates a discrepancy between
   what the Ethos author signed and what the asset PDS currently
   serves — possibly a substitution by a compromised PDS.

A client MUST treat any failure of check 1, 2, or 3 as fatal for that
asset. The Ethos manifest signature anchors the chain of trust: the
manifest is signed by `#public` (which the subject controls), and the
manifest commits to the asset's content via `sha256_of_plaintext`. As
long as that hash matches the bytes the client decrypted, the client
has evidence that the bytes are those the subject signed off on.

## 3.5 Manifest-level versus PDS-level metadata

The same asset's metadata is described in two places that can drift
if implementations are sloppy:

| Field | Recorded in Ethos manifest | Recorded in asset PDS metadata |
|---|---|---|
| `urn` | yes (descriptor) | yes |
| `media_type` | yes | yes |
| `size_bytes` | yes | yes |
| `sha256_of_plaintext` | yes | yes |
| `caption`, `alt_text`, `role` | yes (descriptor) | no — purely Ethos-level |
| `encrypted`, `amk_envelope` | no | yes |
| `referenced_by[]` | no — implicit (the manifest is one reference) | yes — explicit |
| `created_at`, `modified_at` | no | yes |

The Ethos manifest's view is the **signed**, edition-bound view. The
asset PDS's view is the **live** view. They MUST agree on the
denormalized fields (`media_type`, `size_bytes`, `sha256_of_plaintext`);
they MAY differ on the others (the PDS sees that the same asset is also
referenced by a data record, for example, which the Ethos manifest does
not).

When a client reads an asset via an Ethos section reference, it MUST
verify the agreement: the PDS-returned `sha256_of_plaintext` must equal
the manifest-declared one. Disagreement MUST be treated as integrity
failure (§3.4.3 check 3).

## 3.6 Future: section-level asset role inheritance

Once Ethos v0.3 lands and sections carry explicit per-section
manifest entries with their own `wraps[]`, the asset descriptor MAY
inherit the section's recipient set automatically at upload time (the
RecipientResolver, §1.5, already encodes this dependency). A future
revision MAY add an `inherit_recipients_from: "section" | "explicit"`
flag to the descriptor to express:

- `"section"`: the asset's wraps[] follows the section's wraps[]
  whenever the section's recipient set changes (the SDK keeps them in
  sync via `assets.sync_recipients`).
- `"explicit"`: the asset's wraps[] is managed independently by the
  owner.

v0.1 supports only the `"explicit"` behaviour; the SDK does not
auto-sync recipients. The owner uses `authorize_grantee` and
`revoke_grantee` explicitly per asset. See §10.7 for the locked
decision.

## 3.7 SDK-level integration with data records

> **Forward reference.** This section anticipates the
> `aithos-asset-ref/v1` schema fragment introduced in v0.2 of the data
> sub-protocol. The behaviour described here is the locked decision
> from §10.14; the schema fragment ships in v0.2 data.

When a data record's schema declares a field as
`{ "$ref": "aithos://schemas/asset-ref/v1" }`, the SDK MUST detect
references to assets at write time and trigger the corresponding
reference-lifecycle calls transparently:

- On `insert` that introduces a URN in such a field → call
  `aithos.assets.ref_asset` with the new record's URN as the
  attaching context.
- On `update` that changes the URN → call `aithos.assets.unref_asset`
  on the old value, then `aithos.assets.ref_asset` on the new.
- On `delete`, or on `update` that clears the field → call
  `aithos.assets.unref_asset`.

The default placement of such a field is **encrypted** (the schema
declares `x-aithos-encrypted: true`); the URN therefore lives in the
record's encrypted payload and is invisible to the platform's server-
side query layer. Schemas that explicitly need the URN indexable MAY
opt out by declaring `x-aithos-indexable: true`.

---

Next: [chapter 04 — Mandates](./04-mandates.md).
