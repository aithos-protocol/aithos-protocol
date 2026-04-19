# 7 · Threat model

## 7.1 Scope

This chapter documents the adversaries the protocol defends against, the trust assumptions it makes, the leaks it accepts by construction, and the open problems the current version does not solve.

A protocol's threat model is a forcing function: anything not listed here should be assumed **not** defended against. Implementers who need stronger properties than what is described below should extend the protocol at their own cost and document the delta.

## 7.2 Adversaries

### 7.2.1 The honest-but-curious platform

*A platform that hosts your bundle, your agent, or your account, and will not actively attack you, but cannot resist looking.*

**Defense.** Zone encryption (chapter 3) makes the circle and self zones opaque to any party without the matching key material. The subject is always a recipient of their own circle and self zones (§3.5.1); no additional keys are left with the server.

**Residual leak.** The manifest exposes section titles even for encrypted zones (§3.7). A subject who does not want their server to know "there is a section titled `Burnout notes` in your self zone" must use anodyne titles like `Private notes` for sensitive material, or wait for the v0.2 opt-in encrypted section index.

### 7.2.2 The compromised recipient

*A circle member's device is breached. The attacker can read your circle zone for as long as your circle key material remains valid on that device.*

**Defense.** Key rotation (§1.6.3). Rotate the `circle` sphere key, issue a new edition with the circle zone re-encrypted for the remaining recipient set, and publish the revocation of any circle-scoped mandates tied to the compromised device. All prior ciphertext the attacker captured remains readable — that is an unavoidable consequence of having given them ciphertext — but no new edition is.

**Residual leak.** The attacker retains a copy of the old circle zone content. Plan your disclosures accordingly.

### 7.2.3 The misbehaving agent

*An agent acts beyond the scope of its mandate — replies to messages it should not, posts content it should not, speaks in the subject's voice without authority.*

**Defense.** Action artifacts (§5.4) attribute each action to a mandate. A counterparty who receives a message they suspect is unauthorized can request the artifact, verify it against the subject's DID document and revocation list, and reject if the chain fails. The subject can revoke the mandate and publicly repudiate any message lacking a valid artifact.

**Residual risk.** An agent that simply ignores the mandate machinery and sends a message without an artifact leaves the counterparty no cryptographic way to know the message is unauthorized. This is a **social** problem, not a protocol problem — adoption has to precede attribution. Until counterparties routinely check artifacts, the defense is procedural: subjects should keep the set of action-scope mandates small and well-known.

### 7.2.4 The replay attacker

*An adversary captures a mandate in transit and replays it after it has been revoked or has expired.*

**Defense.** Each mandate carries a `nonce` and a strict `not_after`. Verifiers MUST reject mandates past `not_after` without leeway (§5.6). The revocation list (§4.6.4) is signed and must be refreshed before binding actions.

**Residual risk.** An agent that holds an unexpired mandate and has been revoked but fails to refresh its revocation list can still act, and a naive verifier who does not check the revocation list will accept. Both sides must do their job. This is a **liveness** requirement, not a correctness one.

### 7.2.5 The metadata-only attacker

*An adversary who cannot decrypt the circle or self zones but can observe which bundles exist, who's fetching them, and when.*

**Defense.** None, at the protocol level. A public bundle URL reveals its existence and access patterns to anyone observing the hosting server's logs or the network path. Authors who want stronger metadata hygiene should host bundles on privacy-respecting infrastructure (Tor hidden services, private CDNs) and accept the cost.

### 7.2.6 The coerced subject

*A physical adversary compels the subject to reveal passphrases or sign documents under duress.*

**Defense.** None. This is the domain of operational security, not protocol design. Aithos has no duress password, no panic revocation-on-next-heartbeat, no plausible-deniability features. Explicit non-goal.

### 7.2.7 The state actor with subpoena power

*An actor legally compels the hosting provider to turn over bundles and access logs.*

**Defense.** Zone encryption protects the content of the circle and self zones: even under subpoena, a hosting provider cannot produce plaintext it never held. The `public` zone is by definition accessible. Metadata (who fetched what, when) is whatever the hosting provider's logs say, and is outside the protocol's defense scope.

## 7.3 Trust assumptions

The protocol assumes the following. Violations of these assumptions render the defenses void.

- **CSPRNG.** The environment in which keys and nonces are generated provides a cryptographically secure random source. On modern OSes (`getrandom(2)`, `/dev/urandom`, `BCryptGenRandom`), this is given. On embedded devices, implementations must verify.
- **Key storage.** Passphrase-sealed seeds in `~/.aithos/` are only as safe as the passphrase and the device's filesystem isolation. A subject with a weak passphrase on a shared machine is exposed.
- **Clock.** Signature verification depends on time comparisons (`not_before`, `not_after`, `revoked_at`). A compromised clock on a verifier or issuer produces incorrect results. Use NTP or a trusted time source.
- **JCS correctness.** Canonicalization (§5.1) must match across implementations. A JCS library with an encoding bug will produce incompatible signatures. The reference implementation pins a tested library; third parties SHOULD do the same.
- **Ed25519 implementation.** Implementations MUST use a well-reviewed library (libsodium, Noble, ring). Rolling one's own Ed25519 is a known-bad idea.

## 7.4 Accepted leaks

By construction, the protocol leaks:

1. **Section titles** in encrypted zones (§3.7). Documented; mitigation available via anodyne titles; opt-in encryption planned for v0.2.
2. **Bundle size** — an encrypted bundle's size gives a rough signal about the size of its private content. Traffic padding is out of scope.
3. **Mandate existence** — a subject's set of issued mandates, if published, reveals which agents they have trusted. A paranoid subject can keep mandates unpublished and transmit them out-of-band to agents, but at the cost of making revocation-list verification impossible for third parties.
4. **Recipient set on the circle zone** — the manifest lists every recipient of an encrypted zone by DID URL. A bundle is a record of who the subject considers "circle" at this edition. A subject who does not want to publish their circle should keep the bundle private.
5. **Superseded-chain** — the `edition.supersedes` chain is public in every edition, so the history of edition IDs is visible. The content of superseded editions may not be available, but the fact that they existed is.

Subjects who need stronger privacy than this should not publish bundles at all.

## 7.5 Key compromise scenarios

### 7.5.1 Compromised sphere key

Rotate the sphere key (§1.6.3), reissue the DID document with the new key, re-encrypt the affected zone(s), publish a new edition, revoke any mandates issued under the old key.

### 7.5.2 Compromised root key

**There is no recovery.** The root key is the subject's name. Losing it means moving to a new DID, rebuilding recognition from zero. This is deliberate — a recovery mechanism that allows you to replace the root key while keeping the identifier is, by construction, a backdoor that any attacker can use.

A t-of-n social recovery layer — where a quorum of designated trustees can co-sign a root-key replacement — is under consideration for v0.2 but is not yet specified.

### 7.5.3 Lost passphrase

The sealed seed cannot be recovered. If the subject has a written-down copy of the raw seed in a safe place (the reference CLI prompts for this at `init` time), they can re-seal it with a new passphrase. If they have neither the passphrase nor the raw seed, the keys are gone.

## 7.6 What the protocol does not address

### 7.6.1 Legal authority

A mandate is cryptographic, not legal. Whether a mandate constitutes a valid power of attorney, a binding commercial authorization, or a lawful delegation of speech is a question for jurisdictions to answer. The protocol provides a verifiable substrate on which such frameworks can build; it does not presume that any particular jurisdiction has yet built them.

Until a jurisdiction has blessed mandates as legally binding, counterparties who receive an action artifact should treat it as evidence of authorization but not as legal proof.

### 7.6.2 Content authenticity

A bundle proves "the subject signed this content." It does not prove "this content is true." A subject can sign a bundle full of lies; that is their right. Counterparties verify who said it, not whether what they said is accurate. Truth is downstream.

### 7.6.3 Deepfakes and voice cloning

The protocol does not defend against an adversary who produces AI-generated content that *sounds* like the subject without being signed. The defense is cultural — counterparties must learn to insist on artifact-backed claims for anything consequential — not cryptographic.

## 7.7 Hardening recommendations (informative)

For production deployments:

- Use hardware key storage where possible. The sphere seeds map cleanly to a YubiKey or similar; `libsodium` sealing is a software fallback.
- Enforce `require_counter_sign` on any scope that results in a commitment, money movement, or public statement.
- Keep TTLs short. A mandate that lives for 7 days is much safer than one that lives for 90.
- Limit `grantee.pubkey` unset mandates to strictly read-only scopes. Write mandates should always bind a specific agent key.
- Publish revocation lists on at least two mirrored locations, signed identically. A subject who loses control of their primary host should have a fallback path.

---

Next: [chapter 8 — Glossary](./08-glossary.md).
