# aithos

Rust reference implementation of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) — **placeholder, not yet functional**.

## Status

This crate was published on **2026-04-19** to reserve the name `aithos` on crates.io on the day the protocol was first released as version `0.1.0` (draft). It is intentionally minimal: it exposes the protocol version as a `const`, a stub API that returns `Error::NotImplemented`, and carries the signed birth artifacts of the protocol at the crate root (`birth/`). The only functional reference implementation at this stage is the [TypeScript CLI](https://github.com/aithos-protocol/aithos-protocol/tree/main/cli).

A real Rust implementation will land here incrementally — DID resolution first, then ethos parsing, then mandate verification, then write paths. Track progress on the [issue tracker](https://github.com/aithos-protocol/aithos-protocol/issues).

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*. It defines a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf within strict, scope-limited, time-bounded, and unilaterally revocable terms. Read the [whitepaper](https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md) and the [spec](https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md).

## Usage today

```rust
assert_eq!(aithos::PROTOCOL_VERSION, "0.1.0");
assert_eq!(aithos::PACKAGE_VERSION, "0.0.1");

let err = aithos::verify_bundle("some.ethos").unwrap_err();
assert!(matches!(err, aithos::Error::NotImplemented { .. }));
```

## License

[Apache-2.0](./LICENSE).
