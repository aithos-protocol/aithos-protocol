# 9 · Threat model

## 9.1 Overview

This chapter enumerates the attackers the assets sub-protocol's
security guarantees must defend against, the information each can
observe, the actions each can attempt, and the mitigations in place. It
follows the same template as Ethos §7 and data sub-protocol §09.

The threat model is **explicit about what is NOT protected** as much
as about what is. Where the protocol accepts a leak as part of its
operational design (§9.2), the leak is named, its impact bounded, and
the mitigation (where one exists) referenced.

## 9.2 Information visibility by actor

### 9.2.1 Platform operator

The platform (the PDS operator: an AWS account holder, a self-hosted
deployment owner, a future managed-service provider) sees:

| Visible | Hidden |
|---|---|
| Subject DIDs and asset URNs | Asset bytes for private assets (AEAD-encrypted) |
| Asset `media_type`, `size_bytes`, `sha256_of_plaintext` | Asset plaintext content |
| AMK envelope structure (number of wraps, recipient DID URLs) | AMK in cleartext (wraps are encrypted to recipients) |
| `referenced_by[]` (full set, since the platform updates it) | The narrative content of referring sections / records (those are in other sub-protocols' encrypted stores) |
| Upload, fetch, authorize, revoke timestamps | Why an upload happened (no semantic content) |
| Mandate IDs and grantee DID URLs in the wrap list | Mandate scope details and grantee identity (those are in the mandate document, which the platform also sees) |
| Gamma log entries' payloads (per §8.7) | (Same — gamma is plaintext in v0.1) |
| The full S3 ciphertext blobs | (Same — encrypted under AMK the platform does not hold) |

The platform sees a great deal of **metadata**. It cannot read the
bytes of private assets but it can observe their size, their
frequency of upload, their pattern of access (when each grantee
fetches), and the topology of the recipient graph (which grantees
share which assets).

### 9.2.2 Authorized grantee

An application holding a mandate with the appropriate scope sees:

| Visible | Hidden |
|---|---|
| The assets the mandate covers (full metadata + bytes) | Assets outside the mandate scope (existence and metadata both filtered) |
| Their own wrap entry in `amk_envelope` | Other recipients' wraps |
| The `referenced_by[]` entries pointing at contexts the grantee is also authorized for | Other `referenced_by[]` entries |

### 9.2.3 Anonymous reader

An anonymous reader (e.g. a public web viewer of a public Ethos)
sees:

| Visible | Hidden |
|---|---|
| Public assets (full bytes via CloudFront URL) | Private assets (existence is not exposed via anonymous endpoints) |
| `media_type`, `size_bytes`, `sha256_of_plaintext` of public assets | All metadata for private assets |
| Whatever public Ethos editions reveal | Private context |

The platform MUST NOT, via any anonymous endpoint, leak the existence
of private assets to an unauthenticated caller. A request for a
private asset URN by an anonymous caller MUST receive
`AITHOS_NOT_FOUND`, not `AITHOS_INSUFFICIENT_SCOPE`.

## 9.3 Attacker models and mitigations

### 9.3.1 Honest-but-curious platform operator

**Capability.** The operator runs the PDS infrastructure with full
access to S3 ciphertexts, DynamoDB metadata, gamma log entries, and
all in-flight RPC traffic. They follow the protocol but record every
observable for later analysis.

**Capability boundary.** They DO NOT have access to subject sphere
keys, grantee X25519 keys, or AMKs.

**What they can learn:**

- The set of subjects active on the platform, their relative activity
  rates, and the times and sizes of their uploads.
- The pattern of access to each asset over time, including which
  grantee fetches which asset at what cadence.
- The bytes of all public assets (they are public by design).
- The size distribution and media type distribution of private
  assets (visible in metadata).

**Mitigations:**

- AEAD encryption of private asset bytes under AMKs the operator does
  not hold (§2.3).
- AAD binding to `asset_urn` prevents the operator from substituting a
  different ciphertext under the same metadata (the substitution would
  fail AEAD verification at the client).
- SHA-256 cross-check at the client (§3.4.3 check 2) detects byte
  corruption or substitution.
- Manifest cross-check (§3.4.3 check 3) detects discrepancies between
  what the subject signed in the Ethos manifest and what the
  operator currently serves.

**Residual leakage accepted as design:**

- The metadata visibility listed in §9.2.1 is unmitigated. A subject
  with strong unlinkability needs additional layers (e.g.
  application-level padding to obscure asset sizes; access via Tor or
  similar to obscure timing). v0.1 does not provide these layers.

### 9.3.2 Compromised platform operator

**Capability.** The operator's infrastructure has been breached. The
attacker has all the platform's secrets, all stored data, and the
ability to mint arbitrary platform responses.

**What they can learn:**

- Everything the honest-but-curious operator could learn.
- Live RPC traffic for all subjects.

**What they can do that the honest operator cannot:**

- Forge platform-side responses to clients (e.g. lie about which
  recipients are authorized on an asset).
- Substitute one ciphertext for another in S3.
- Drop or alter gamma log entries.

**Mitigations:**

- Manifest signature in Ethos: a tampered asset descriptor in a
  signed manifest fails signature verification. The attacker cannot
  forge a section that references their substituted asset without
  also forging the subject's `#public` key.
- Gamma chain hash linking: a forged `assets.referenced` entry would
  break the chain at the prior hash, detectable by audit.
- AEAD failure on byte substitution: a different ciphertext at the
  same S3 key fails to decrypt under the legitimate AMK (the AAD
  binds to `asset_urn`, not to a content hash that the operator
  could re-compute).
- Cross-verification with a recent backup or with the user's own
  records of recent state.

**Residual risk accepted as inherent:**

- The operator can DELETE assets they cannot read. A compromised
  operator can effectively erase a subject's data. The mitigation is
  out-of-platform: the subject's own backup of exported assets
  (chapter 07). v0.1 does not provide platform-side cryptographic
  guarantees against deletion.
- The operator can refuse to serve. Denial-of-service is not
  cryptographically prevented; the user's recourse is to migrate
  PDSes (chapter 07).

### 9.3.3 Compromised grantee

**Capability.** A grantee whose private key has been stolen, or who
has been turned (an application provider acting maliciously after
having been granted access).

**What they can do:**

- Decrypt every asset their mandate covers, including any cached AMK
  from prior reads.
- Continue to do so until the mandate is revoked AND the AMK is
  rotated.

**Mitigations:**

- Mandate revocation via Ethos §4.6 prevents future RPC access.
- AMK rotation (§2.5.2) closes the door on assets they had cached.
- The retention of past ciphertexts (which the revoked grantee may
  have downloaded) is unavoidable; this is the standard limitation of
  symmetric encryption.

**Forward-secrecy strict mode** (§2.3.8) requires AMK rotation at
revoke time, paying the cost of re-encryption to deny the revoked
grantee access to all *new* versions of the asset bytes. For assets
that are immutable (per §1.2.5, asset bytes never change), the
"forward secrecy" property is largely vacuous — the grantee already
has what bytes there are. The owner who wants stricter control must
treat the asset as superseded: upload a new asset, dereference the
old, and trust that the platform purges the old's bytes per the
retention window. Once the old bytes are purged, no further leakage
is possible regardless of grantee retention of the old AMK.

### 9.3.4 Subject with a leaked sphere key

**Capability.** The subject's `#circle`, `#self`, or `#data` private
key has been stolen.

**What the attacker can do:**

- Unwrap every AMK on every asset attached to the corresponding
  context.
- Decrypt every asset's bytes.
- Issue arbitrary mandates appearing to come from the subject.

**Mitigations:**

- Subject sphere rotation flow (Ethos §1.6), which generates a new
  key and updates the DID document.
- Re-wrap every affected asset's AMK for the new sphere key
  (§2.5.3).
- Once the old sphere key is invalidated in the DID document, the
  platform's signature verification on envelopes signed by the old
  key fails.

**Residual:**

- Bytes already decrypted by the attacker are lost; rotation cannot
  un-leak past content.
- A long-running attack window between the leak and the rotation is
  catastrophic. The subject's own monitoring of unusual activity is
  the first defense.

### 9.3.5 Network adversary

**Capability.** A passive or active attacker on the network between
the client and the PDS, or between the client and S3/CloudFront.

**What they can do (passive):**

- Observe TLS metadata (sizes, destinations, timings).
- Observe public asset bytes (since CloudFront URLs are not
  authenticated and the bytes are not encrypted).

**What they can do (active):**

- Attempt to MitM TLS (defeated by PKI + HSTS).
- Replay a presigned URL within its TTL (if intercepted).

**Mitigations:**

- TLS on all RPC paths and S3/CloudFront paths.
- Short presigned URL TTL (default 15 min) bounds replay windows.
- Envelope nonces and `iat`/`exp` fields in JSON-RPC envelopes
  prevent replay of RPC calls (Ethos §11.5).
- AEAD authentication tag on the ciphertext bytes prevents undetected
  byte mutation in transit.

A network adversary fundamentally cannot decrypt a private asset
without one of the wraps; the AMK never traverses the network
unencrypted.

### 9.3.6 Inter-subject inference

**Capability.** The platform — or an external adversary with access
to the platform's metadata — wants to determine whether two distinct
subjects share knowledge of the same file (e.g. "subject A and
subject B both have this whistleblower document").

**Why this matters.** Cross-subject deduplication, if it existed,
would expose this information trivially. The protocol's refusal
(§1.4.3) closes that channel.

**What the attacker can still infer in v0.1:**

- If subjects A and B both have assets of the same `size_bytes`,
  that's a (weak) signal.
- If those assets share `sha256_of_plaintext` (declared in metadata),
  that's a strong signal. The platform sees both subjects' metadata
  and can correlate.

**Mitigation:** The protocol stores the SHA-256 in plaintext in the
metadata document for legitimate purposes (intra-subject deduplication
§1.4, integrity verification §3.4). A subject who wants to deny this
inference channel must either (a) avoid the asset PDS for that
content, (b) pre-pad the plaintext with a per-subject random nonce
before uploading, changing the hash, or (c) host on an
unlinked PDS instance.

A future revision MAY add an optional "salt" field that obscures the
SHA from the platform's view; out of scope for v0.1.

## 9.4 Why cross-subject deduplication is excluded

The decision is normative in §1.4.3 and §0.6. Rationale recapped here
for completeness.

**Convergent encryption** (`AMK = HKDF(plaintext, fixed_salt)`) makes
the ciphertext deterministic in the plaintext. Two subjects uploading
the same plaintext produce identical ciphertexts. The platform can:

1. Observe a duplicate ciphertext across subjects → conclude they
   share the underlying file.
2. Mount a dictionary attack: encrypt a known file under the
   convergent scheme, search S3 for matching ciphertexts, identify
   which subjects hold it.

For a system whose first principle is "the server sees only what must
leak for it to function" (P2), this is unacceptable. The cost (no
cross-subject dedup, slightly more S3 storage in the rare cases of
genuinely shared content) is paid for the benefit (no cross-subject
inference channel through the encryption layer itself).

Intra-subject dedup remains safe: the subject already knows what
content they uploaded; the platform learning "subject A has two
references to the same SHA" is not new information about A relative
to anyone else.

## 9.5 What is explicitly out of scope for v0.1

The protocol does NOT defend against:

- **Side-channel attacks** on the cryptographic primitives. The
  protocol assumes the underlying X25519 / HKDF / XChaCha20-Poly1305
  implementations are constant-time and side-channel-resistant. A
  side-channel on a grantee's machine that extracts the AMK is out
  of the protocol's purview; the grantee is trusted with the AMK by
  the design of the wrap construction.
- **Endpoint device compromise.** A subject whose laptop is
  compromised loses their sphere keys. No protocol can defend against
  this; the subject's keystore protection (sealed with Argon2id, per
  Ethos §1.4.3) is the line of defense.
- **Coercion.** A subject who is forced to surrender keys cannot be
  helped by the protocol. The mitigation is plausible deniability
  layers (e.g. multiple identities, separate PDSes) outside the
  protocol scope.
- **Long-term archival cryptography.** v0.1 uses XChaCha20-Poly1305
  and Ed25519, which are conjecturally safe against today's adversaries
  for the foreseeable future. A "store now, decrypt later" attacker
  with a future quantum computer could break the X25519 wraps. v0.1
  does not provide post-quantum cryptography; the protocol's
  versioned `alg` fields allow a future migration.

## 9.6 Test scenarios

A conformant implementation SHOULD have test cases for:

- Tampered ciphertext at S3 → client AEAD failure at fetch.
- Tampered metadata at DynamoDB → client SHA mismatch or wrap
  verification failure.
- Forged gamma entry → chain hash mismatch.
- Authorized grantee fetching after revocation → RPC denial; if
  bytes already cached, only mitigated by AMK rotation.
- Anonymous fetch of private asset → `AITHOS_NOT_FOUND` (NOT
  `AITHOS_INSUFFICIENT_SCOPE`).
- Asset substitution between contexts (a malicious section pointing
  at another subject's asset URN) → AEAD AAD mismatch.
- Race between mandate revocation and presigned URL TTL expiry →
  worst-case 15 min residual access window for the revoked grantee.

These scenarios live as integration tests in
`packages/assets-backend/test-e2e/` once the reference implementation
ships.

---

Next: [chapter 10 — Open questions](./10-open-questions.md).
