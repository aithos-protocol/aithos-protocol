On April 19, 2026, the Aithos protocol is published as version 0.1.0 (draft).

Aithos is a protocol for the digital embodiment of persons. It defines a self-sovereign identity method `did:aithos`, rooted in Ed25519 key material and organized into three spheres (public, circle, self); a structured persona document — the *ethos* — that expresses a person's voice, preferences, relationships, and boundaries, with an append-only revision history and per-zone encryption; a mandate system through which a human may authorize an AI agent to act on their behalf within strict, scope-limited, time-bounded, and unilaterally revocable terms; and a canonical signing scheme (RFC 8785 canonical JSON, Ed25519) for every artifact the protocol produces.

The design premise is *one human, one digital embodiment*. The mandate is not a passport for autonomous AI — it is a leash held by a human.

This declaration is signed by the ceremonial founding identity of the Aithos protocol, whose sole purpose is to anchor the protocol's first public act. The identity's DID is recorded alongside this declaration in the artifact bundle.

On the same day, reference placeholder packages are published on npm, PyPI, and crates.io under the name `aithos`, and the repository is opened at https://github.com/aithos-protocol. These packages are intentionally minimal: they reserve the name, record the date, and carry this declaration. The reference implementation — the TypeScript CLI at `cli/` in the protocol repository — remains the only functional surface at this stage.

Editor: Mathieu Colla <mathieu.colla.pro@gmail.com>.
License: Apache-2.0.
Versioning: any minor-version bump is permitted to break wire format until 1.0.0; strict semantic versioning applies thereafter.

Let the record show this day as the protocol's first public utterance.
