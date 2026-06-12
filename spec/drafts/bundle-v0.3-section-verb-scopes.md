# Section verb-scopes (v0.3 companion) (Draft)

> **Status:** **Draft.** Targets **§4** (mandate scope grammar), **§3.5′** (per-section recipient derivation), and **§3.8′ / §11** (write enforcement — informative for the bundle layer, normative for a provider). Companion to and **refinement of** [`bundle-v0.3-section-level-mandates.md`](./bundle-v0.3-section-level-mandates.md): it generalises that draft's single top-level `section_scope` into a **per-scope selector**, and introduces a **verb vocabulary** so that a delegate's *read* perimeter, its *write* perimeter, and the *operations* it may perform are expressed **independently, in one mandate**.
>
> **Dependency.** Cryptographic substrate is [`bundle-v0.3-per-section-encryption.md`](./bundle-v0.3-per-section-encryption.md) (per-section DEKs, per-section recipient lists, per-section `title_cipher`).
>
> **Additive.** Bumps `aithos-mandate` **0.4.0 → 0.5.0**. Every mandate issued before this draft keeps its exact meaning (§4.8.5′). `scopes` stays a `string[]`; the selector rides in the scope string, so the signed canonical bytes (§4.4) do not change shape.

## Motivation

The promoted `section_scope` (§4.7′) is a **single top-level field** applied uniformly to every ethos scope in the mandate. Two limits block real agent grants:

1. **One perimeter for all verbs.** It cannot say "read the *whole* zone but edit only section `X`" — read and write are narrowed to the same set.
2. **No verb beyond read/write.** A section-bounded `write` carries the same power as a whole-zone `write` (create + edit + delete). The provider today enforces only `ethos.write.<zone>` at the **zone** level; per-section write enforcement is explicitly deferred (§4.7.5′).

Real delegations need **three independent dials**: *which* sections may be read, *which* may be written, and *what* may be done to them (edit-only vs may-create vs may-delete). This draft makes each scope string carry its own **perimeter** and **verb**.

## 4.8′ Per-scope section selector (supersedes the top-level §4.7′ form)

An ethos scope MAY carry a selector suffix:

```
ethos.<verb>.<zone>[#<selector>]

selector := id=<section_id>
          | prefix=<id_prefix>
          | tag=<tag>
```

- **no suffix** → the **whole zone** (existing behaviour, §4.7′ back-compat).
- `#id=<section_id>` → exactly that section.
- `#prefix=<p>` → every section whose `id` begins with `p` (e.g. `prefix=gmail:` — the README's `gmail:*` sketch, without the glob star).
- `#tag=<t>` → every section carrying tag `t` (§2.5.1 section `tags`).

Multiple selectors are expressed as **multiple scope strings**; a section is covered by a verb iff **any** scope string of that verb matches it (union). The selector is part of the signed scope string (§4.4 canonical bytes), so a perimeter **cannot be widened or forged** after issuance.

The top-level `section_scope: { ids, tags }` (§4.7′) **remains valid** and is now *defined* as shorthand for "apply this selector to every `ethos.read.*` / `ethos.write.*` scope in the mandate." A mandate that needs **distinct verbs** or **distinct read/write perimeters** MUST use the per-scope suffix form; the two forms SHOULD NOT be combined in one mandate (if they are, the union of all resulting (verb, perimeter) grants applies).

### 4.8.1′ Matching

```
match(S, ⟨no suffix⟩) := true                       (whole zone)
match(S, "id=x")       := S.id == x
match(S, "prefix=p")   := S.id starts with p
match(S, "tag=t")      := t ∈ S.tags
```

A selector matching **no** current section is valid (forward-looking, §4.7′): when a matching section is later authored it falls under the grant automatically.

## 4.8.2′ Verb vocabulary

Each verb names the operations granted **on that scope's perimeter** (the section set selected per §4.8′):

| Verb | Operations on the perimeter |
|---|---|
| `read` | decrypt + read a section's title/body (be a recipient). |
| `edit` | modify the body/title of an **existing** section. **No create, no delete.** |
| `append` | **create** a new section, and `edit` sections within the perimeter. **No delete.** |
| `delete` | remove an existing section. |
| `write` | full CRUD on the perimeter = `append` + `edit` + `delete`. |

Rules:

- **Mutation implies readership.** `edit` / `append` / `write` on a perimeter each imply `read` (recipient) on that perimeter — you must decrypt a section to rewrite it. So `ethos.edit.self#id=X` also makes the delegate a recipient of `X` (§3.5.7′). (`delete` alone does **not** imply readership — removing a section needs only its clear id; see Open Questions.)
- **Subsumption.** `write ⊇ {append, edit, delete}`; `append ⊇ edit` within the perimeter.
- **Owner is unconstrained.** Verbs and perimeters apply to **delegates only**. The subject acting with its own sphere keys may read/append/edit/delete any section of any zone, targeting one or several sections (the v0.3 per-section mechanism) — there is no mandate in that path.

These map the agreed cases exactly:

- whole-zone `write` (`ethos.write.self`) → add / edit / delete **any** section of `self`.
- section `edit` (`ethos.edit.self#id=X`) → edit **only** `X`; cannot delete it, cannot add another.
- section `write` (`ethos.write.self#id=X`) → edit **and delete** `X` (its *create* facet is moot for a fixed id — use `prefix=` when create power is intended).
- `append` (`ethos.append.self#prefix=gmail:`) → create `gmail:*` **and** edit what falls under the prefix.

### 4.8.3′ Operation → required grant (provider enforcement)

On a **delegate-signed** publish, the provider computes, per zone, the per-section diff against the predecessor edition, keyed by **clear section id** and **section content hash** (both present in the clear manifest):

```
added(S)   := id ∈ new,  id ∉ prev                  → needs  append | write   covering S
edited(S)  := id ∈ both, sha(new) ≠ sha(prev)        → needs  edit | append | write   covering S
deleted(S) := id ∉ new,  id ∈ prev                  → needs  delete | write   covering S
```

The publish is authorised iff **every** diffed section has a covering grant whose `(verb, zone, selector)` matches; otherwise the provider returns `-32014 insufficient_scope`, naming the first offending `section_id` and the missing verb. This **replaces** the binary zone-level `zoneChanged` check of §4.7.5′ / the current `ethos.write.<zone>` gate.

### 4.8.4′ Enforceability from the clear manifest (normative constraint)

A provider enforces writes from the **clear manifest only** — it holds no decryption key. Therefore:

- `id=` and `prefix=` selectors are **hard-enforceable for writes in every zone**: section ids are clear (they are the blob file names `<zone>/<id>.md` | `.enc`).
- `tag=` selectors are enforceable for writes **only where the section index is clear** — `public` and `circle`. In `self` the tags live inside the encrypted per-section `title_cipher` (§3.3.2′), so the provider cannot read them. A `tag=` **write** scope on `self` is therefore **advisory** until gamma-v0.3 authorship (§3.8′ #9) supplies an authenticated per-section tag/author record.

**Consequence (normative):** a write/edit/append/delete perimeter on `self` MUST be expressed with `id=` / `prefix=` to be hard-enforced. `tag=` stays fully valid for **read** perimeters in all zones — recipient derivation is performed by the **owner** at authoring time, with plaintext tags in hand (§3.5.7′).

### 4.8.5′ Back-compatibility

- A scope with **no suffix** = whole zone — every existing `ethos.read.<zone>` / `ethos.write.<zone>` keeps its current meaning.
- A `0.4.0` mandate carrying a top-level `section_scope` keeps read-scoping every ethos scope uniformly (§4.8′).
- New verbs (`edit` / `append` / `delete`) are additional scope strings; a verifier that does not recognise a verb MUST treat the scope as granting **nothing** (fail-closed), never as a whole-zone `write`.

## 3.5.7′ Per-section recipient derivation (revised for per-scope verbs)

When the **owner** authors an encrypted zone `Z` (§3.4.1′), a delegate `D` is a recipient of section `S` iff `D` holds **any** read-bearing verb on `Z` whose selector matches `S`:

```
recipients(S) :=
    { subject #Z-kex }                                            (always — §3.5.1′)
  ∪ { D : ∃ scope ∈ D.scopes,
          verb(scope) ∈ { read, edit, append, write }
          ∧ zone(scope) = Z
          ∧ match(S, selector(scope)) }
```

This generalises §3.5.4′ (which read the single top-level `section_scope`) to the **union of per-scope selectors**. A whole-zone read/edit/write (no suffix) matches every section, reproducing v0.3 exactly. The recipient-set-change ⇒ re-encryption rule (§3.5.6′) is unchanged: granting or narrowing a delegate re-encrypts only the sections whose recipient set actually changes; all others carry forward byte-identical.

A **delegate** author (§3.8′ #5) does not re-derive other delegates' grants — adding/removing section-scoped delegates is an **owner** operation (the owner re-authors the affected sections). Unchanged from §3.5.4′.

## 3.5.7″ Sealed-selector read gate: wrap-as-capability (normative)

§4.8.4′ established that the provider enforces from the **clear manifest only**. On the read side this leaves exactly one hole: a **read-bearing `tag=` perimeter on a sealed-index zone** (`self` — tags live inside `title_cipher`). The strict per-section read gate cannot evaluate the selector there and would fail closed — even though §3.5.7′ already made the **author** evaluate it, with plaintext tags in hand, when it wrapped the section DEK to the delegate.

**Rule.** For a delegate read of section `S` in zone `Z` whose strict scope evaluation failed, the provider MUST serve `S` iff **all** of:

1. the envelope's mandate is **active** — signature, validity window, revocation and revocation-epoch checks all pass (these run upstream of the gate, so the residual wrap of a revoked or expired mandate is never honored);
2. the mandate holds a **read-bearing** verb (`read`/`edit`/`append`/`write`) on `Z` with a **`tag=` selector**, and `Z` has a **sealed index** (today: `self` only);
3. the **stored** section carries a DEK wrap whose recipient label is the delegate's (`granteeId#pubkeyMultibase`) — v0.3: the descriptor's `cipher.wraps`; v0.4: the zone's `extra_wraps` entry for `S`.

**Why this is sound.** The wrap is the author's recorded authorization decision, made where the tags were readable; only authoring identities can place wraps (owner publishes, or a mandate-bounded delegate publish whose ExtraWraps changes are tied to authorized ops — Partie II N6.4). And the gate releases only **ciphertext the delegate can already decrypt** — the wrap *is* the DEK — so honoring it grants nothing the cryptography has not already granted. The marginal protection lost is ciphertext-exfiltration resistance for exactly the sections the owner sealed to that delegate.

**Non-rescue (normative).** The fallback applies to **no other case**: `id=`/`prefix=` selectors and clear-index `tag=` (public/circle) remain strictly server-evaluated — an explicit mismatch is **never** rescued by a wrap; `delete` is not read-bearing and never opens the fallback; an inactive mandate never reaches it.

## Worked examples

```jsonc
// 1. Read all of self, but edit only X and Y (one mandate, two perimeters)
"scopes": ["ethos.read.self", "ethos.edit.self#id=X", "ethos.edit.self#id=Y"]

// 2. Gmail capture-agent: create + amend gmail:* in self, see nothing else
"scopes": ["ethos.append.self#prefix=gmail:"]
//   ⇒ recipient of gmail:* only; never learns the subject's other self titles (§3.5.5′)

// 3. Whole-zone manager (current behaviour, unchanged)
"scopes": ["ethos.write.self"]

// 4. Reviewer: read all of circle, edit one section
"scopes": ["ethos.read.circle", "ethos.edit.circle#id=bio"]
```

## 3.12.2′ Test matrix (verb-scopes)

| Test | Assertion |
|---|---|
| V1 — edit is edit-only | `ethos.edit.self#id=X` edits `X`; a publish that **deletes** `X` is rejected `-32014` (needs `delete`/`write`). |
| V2 — edit cannot create | `ethos.edit.self#id=X`; a publish that **adds** a new section is rejected (needs `append`/`write`). |
| V3 — section write = edit + delete | `ethos.write.self#id=X` edits and deletes `X`; adding `Z ∉ {X}` is rejected (create out of perimeter). |
| V4 — append (prefix) | `ethos.append.self#prefix=gmail:` adds `gmail:123` (ok), edits `gmail:123` (ok), is rejected on **deleting** `gmail:123`, and rejected on adding `notes:1`. |
| V5 — split perimeters | `["ethos.read.self", "ethos.edit.self#id=X"]`: delegate decrypts **every** self section but may edit **only** `X`. |
| V6 — top-level back-compat | A `0.4.0` mandate with `section_scope:{ids:[X]}` still read-scopes every ethos scope uniformly. |
| V7 — no-suffix back-compat | A bare `ethos.write.self` (no suffix) = whole-zone CRUD; existing mandates unchanged. |
| V8 — self tag-write is advisory | `ethos.append.self#tag=gmail` does **not** hard-enforce at the provider (documented); `ethos.edit.public#tag=…` **does** (clear index). |
| V9 — recipient derivation | `ethos.edit.self#id=X` makes `D` a recipient of `X` but **not** `Y`. |
| V10 — unknown verb fails closed | A scope `ethos.frobnicate.self` grants nothing; it is never read as whole-zone write. |

## Open questions

- **`delete` ⇒ recipient?** Default: **no** — deleting a section needs only its clear id, not its plaintext. Revisit if a "delete-with-audit" mode needs to prove the deleter could read what it removed.
- **"Edit strictly own."** `append` here grants edit on **every** section in its perimeter, not only the ones this delegate authored. Restricting to self-authored sections needs the gamma per-section authorship record (§3.8′ #9); until then `append = create + edit-within-perimeter`, which is sufficient for the prefix-namespaced capture-agent case.
- **`tag=` write on `self`.** Hard enforcement is deferred to gamma-v0.3 authorship; documented as advisory in §4.8.4′.
- **Selector richness.** Only `id` / `prefix` / `tag`. Full globbing beyond a single prefix is out of scope.
- **Version gating.** `aithos-mandate` → `0.5.0`. Whether a provider should also advertise/enforce a minimum mandate version on the publish envelope is left to §11 deployment policy.
