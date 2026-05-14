# 9 · Threat model

## 9.1 Overview

This chapter enumerates the threats the data sub-protocol is designed
to defend against, the threats it explicitly does not, and the residual
trust assumptions. The framing follows Ethos §7 (threat model for the
Ethos protocol) and inherits its actor model.

## 9.2 Actors

- **Subject.** The Aithos identity that owns one or more data
  collections. Holds sphere keys including `#data`.
- **Application (grantee).** An identity holding a mandate signed by
  the subject. Identified by Ed25519 + X25519 keypairs.
- **Platform.** The PDS implementation (this protocol's reference) that
  stores ciphertexts and metadata, serves the RPC primitives, enforces
  mandates and rate limits. May or may not be operated by the subject.
- **Outsider.** Any party with no key material — no subject key, no
  grantee key, no platform admin access. Observes only public network
  traffic and unauthenticated endpoints.

## 9.3 What the protocol protects against

### 9.3.1 Outsider eavesdropping

**Threat.** An attacker on the network between client and platform
intercepts traffic.

**Defense.** Transport is HTTPS. The AEAD payload is independently
encrypted; even an attacker breaking TLS sees only ciphertext.

**Result.** Network attacker cannot read record payloads. They CAN see
metadata clear (record counts, statuses, tags, timestamps) if they
observe the transport — which is why HTTPS is non-optional, not
because of payload secrecy but because of metadata privacy.

### 9.3.2 Platform read of payload contents

**Threat.** An adversarial platform operator wants to read record
payloads without the subject's consent.

**Defense.** Payloads are AEAD-encrypted with per-record DEKs wrapped
under a CMK the platform never sees in cleartext. The platform stores
ciphertext and wrap envelopes — it has the cryptographic ingredients
necessary to deny access without the subject's private keys, but
cannot extract content without breaking AEAD (~2¹²⁸ work).

**Result.** Platform-side read of payloads is computationally infeasible.

### 9.3.3 Tampered ciphertext

**Threat.** An attacker (platform, network, malicious app) modifies the
stored ciphertext in an attempt to inject or alter content.

**Defense.** XChaCha20-Poly1305 is authenticated encryption: any change
to the ciphertext breaks the 16-byte Poly1305 tag, causing decryption
to fail. The AAD binds the ciphertext to `(subject_did,
collection_name, record_id)`, so cross-record or cross-collection
replay also fails.

**Result.** Tampering is detected; decryption returns an error rather
than corrupted plaintext.

### 9.3.4 Replay of past records

**Threat.** A revoked grantee (or external attacker) holds an older
copy of a record and presents it as current.

**Defense.** Each record's gamma entry chain commits to the record's
state at each point in time. A reader who follows the gamma chain
detects out-of-date hashes. For real-time freshness, clients SHOULD
use `expected_modified_at` (optimistic concurrency) on updates and
the `modified_at` metadata for read-time freshness checks.

**Limit.** A revoked grantee with cached ciphertext still holds a valid
copy of the data at the time of revocation. There is no way to "uncopy"
data. The forward-secrecy mode `strict` (§4.6) protects future
ciphertexts but not past ones.

### 9.3.5 Unauthorized writes

**Threat.** A non-authorized application attempts to write to a
collection.

**Defense.** Every write requires a signed envelope (Ethos §11) with a
valid mandate (Ethos §4). The platform verifies signature, scope,
window, revocation status. Without a valid mandate the call is
rejected before touching storage.

### 9.3.6 Mandate replay

**Threat.** An attacker captures a signed envelope from the network and
replays it.

**Defense.** Envelopes carry `nonce`, `iat`, `exp`. The platform
maintains a replay cache (per Ethos §11.5) and rejects envelopes whose
nonce is already seen or whose `exp` is in the past.

### 9.3.7 CMK theft via memory dump

**Threat.** An attacker compromises a client device and dumps the
client's RAM, recovering an in-memory CMK.

**Defense (partial).** The CMK is held in client memory only for the
duration of operations. Clients SHOULD zero CMK bytes after use
(`Uint8Array.fill(0)` on the holding buffer). Long-running clients
SHOULD re-unwrap from the wrapped CMK envelope for each operation
rather than caching indefinitely.

**Result.** Memory-dump risk reduces to the time the CMK is actively
in use, not the full session length. Cannot be fully eliminated without
hardware TEE.

### 9.3.8 Mandate exfiltration

**Threat.** An attacker steals a grantee's Ed25519 + X25519 keypairs
plus a valid mandate, then impersonates the application.

**Defense (partial).** The protocol cannot distinguish between the
legitimate grantee and an attacker holding the same keys — that's the
fundamental property of public-key authentication. The subject must
revoke the mandate (§4.6) once the compromise is suspected.

**Mitigations.**
- Keep mandate windows short (`not_after - not_before`) for high-value
  scopes.
- Use `require_counter_sign` (§4.4) for destructive operations
  (`delete_record`, `rotate_cmk`).
- Implement device-bound key storage (hardware-backed keychain on
  mobile, Secure Enclave on Apple, Android Keystore) wherever possible.

## 9.4 What the protocol does NOT protect against

### 9.4.1 Subject's own key compromise

If the subject's `#data` sphere key is exposed, the attacker can:

- Unwrap any of the subject's CMKs.
- Issue mandates in the subject's name.
- Rotate sphere keys (if they also hold `#root` — see Ethos §1.6).

Recovery is via the subject's `.recovery` file (Ethos §1.7) if backed
up, and via sphere rotation. The protocol provides no defense against
total key compromise other than the standard rotation flow.

### 9.4.2 Platform refusal of service

The platform can deny service: refuse to serve reads, refuse to accept
writes, refuse to serve gamma entries. The protocol cannot force a
platform to operate. The subject's recourse is to:

- Maintain backups of `.data` exports.
- Migrate to another conformant platform (chapter 07).
- For regulated jurisdictions, exercise legal data-portability rights.

### 9.4.3 Metadata leakage to the platform

By design (P2 of chapter 00), the platform SEES the metadata clear of
every record. This includes:

- Field values declared `aithos:indexable` (status, tags, emails,
  hashed phones, timestamps).
- The total record count per collection.
- The frequency and timing of operations.
- The mandate-grantee mapping (the platform sees which grantees access
  which collections, even though it doesn't see what they read).

A subject whose threat model includes "the platform must be blind to
ALL information about my data" SHOULD NOT use this sub-protocol; the
Ethos sub-protocol's encrypted zones provide better metadata hiding at
the cost of indexing and pagination.

Mitigations within the sub-protocol:

- Schema design: minimize indexable fields. Hashed forms
  (`phone_hash` rather than `phone`) reduce leak surface.
- Collection partitioning: use multiple collections to scope
  what each application's mandate exposes.

### 9.4.4 Side-channel attacks

Cache timing, electromagnetic emanation, power analysis, and similar
side-channels are out of scope. The reference implementation uses
constant-time AEAD (libsodium / WebCrypto), but the protocol does not
mandate side-channel-hardened deployment.

### 9.4.5 Quantum attacks

The X25519 + Ed25519 primitives are classical. A sufficiently large
quantum computer could break them. The protocol does NOT currently
include post-quantum primitives.

**Mitigation path.** When PQ primitives (CRYSTALS-Kyber for KEM,
CRYSTALS-Dilithium for signatures) standardize, the protocol can be
extended via algorithm identifier registration (chapter 02 §2.6).
Existing data remains decryptable as long as the underlying classical
crypto stays unbroken — but future readers will use PQ wraps.

### 9.4.6 Cryptanalytic break of AEAD

If XChaCha20-Poly1305 is broken (no known attack today), all
ciphertexts are compromised. The protocol's defense is the choice of
primitive: XChaCha20-Poly1305 is one of the most studied modern AEADs,
deployed by libsodium, WireGuard, Signal, age, and others. A future
break of this primitive is a catastrophic event for the entire field,
not specific to this protocol.

## 9.5 Trust assumptions

The protocol assumes:

1. **The subject's key custody is the subject's responsibility.**
   Loss of all keys without recovery file == loss of access. The
   protocol does not implement key escrow.
2. **The platform implements the protocol faithfully for
   verifiable properties.** A platform that lies about CMK wraps
   (e.g. returns a fake wrap with platform-known keys) is detectable
   by the subject's client: the wrap verifies against the platform's
   declared recipient public key, which the platform cannot replace
   without the subject's DID document update.
3. **Mandates are issued thoughtfully.** A subject who grants
   `data.*.admin` to a malicious app gets what they granted. The
   protocol enables informed authorization (clear scope vocabulary)
   but does not assess application trustworthiness.
4. **DID resolution is honest.** The chain of trust starts at the
   subject's DID document. If the DID resolution returns a tampered
   document, every downstream verification is corrupted. The Ethos
   sub-protocol's DID rotation chain (Ethos §1.6) mitigates this in
   the case of compromised-then-rotated keys.

## 9.6 Comparison with related models

For reference, here is how the data sub-protocol's threat model
compares with adjacent designs:

| Property | Aithos data v0.1 | Bluesky AT Protocol PDS | Standard Notes | Encrypted DDB BYOK |
|---|---|---|---|---|
| Payload encryption | Client-side AEAD | None (public records) | Client-side AEAD | Server-side (KMS BYOK) |
| Metadata visibility | Indexable fields only | All record content | None (E2E full) | Configurable |
| O(1) authorization | Yes (CMK) | Yes (handle-scoped) | N/A (single user) | N/A |
| Mandate revocation | Yes (revoke + optional CMK rotation) | App tokens | N/A | KMS key disable |
| Audit log | Gamma chain | Repo CIDs (Merkle) | None | CloudTrail |
| Portability | `.data` artifact | PDS migration | `.protected` export | None |
| Server can read | Metadata only | All | Nothing | Yes (decrypts on auth) |
| Threat model | Hostile platform tolerated for payloads, trusted for metadata enforcement (mandate filters) | Public-by-default; private records deferred | Adversarial platform tolerated | Trusted platform assumed |

The closest comparable in spirit is Bluesky AT Protocol's PDS model,
augmented with end-to-end encryption for payloads and finer-grained
authorization (per-collection mandate filters).

## 9.7 Open threats (acknowledged)

The following are recognized residual threats that v0.1 does NOT
resolve, deferred to future revisions:

- **Mandate filter cryptographic enforcement.** As stated in §4.3.1,
  filter mandates are platform-enforced, not cryptographically. A
  hostile platform could bypass filter checks. Cryptographic filter
  enforcement requires sub-collection keys (deferred to v0.2+).
- **Forward secrecy on cached ciphertexts.** A revoked grantee retains
  cleartext for data they previously decrypted. There is no protocol
  primitive to "unread" past data.
- **Anonymity of grantee identity.** The wrap list reveals which
  grantees are authorized on a collection. A privacy-aware
  implementation would obfuscate this; v0.1 doesn't.
- **Quantum resistance.** As §9.4.5.

These are tracked in [chapter 10 — Open questions](./10-open-questions.md).

---

Next: [chapter 10 — Open questions](./10-open-questions.md).
