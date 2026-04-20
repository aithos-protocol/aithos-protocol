# aithos

Python reference implementation of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) — **placeholder, not yet functional**.

## Status

This package was published on **2026-04-19** to reserve the name `aithos` on PyPI on the day the protocol was first released as version `0.1.0` (draft). It is intentionally minimal: it exposes the protocol version and carries the signed birth artifacts of the protocol. The only functional reference implementation at this stage is the [TypeScript CLI](https://github.com/aithos-protocol/aithos-protocol/tree/main/cli).

A real Python implementation will land here incrementally — DID resolution first, then ethos parsing, then mandate verification, then write paths. Track progress on the [issue tracker](https://github.com/aithos-protocol/aithos-protocol/issues).

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*. It defines a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf within strict, scope-limited, time-bounded, and unilaterally revocable terms. Read the [whitepaper](https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md) and the [spec](https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md).

## Usage today

```python
import aithos

aithos.PROTOCOL_VERSION
# '0.1.0'

aithos.BIRTH_DIR
# PosixPath('.../site-packages/aithos/birth')
# Contains: birth.json, birth-declaration.md, aithos-birth.ethos, did.json

aithos.verify_bundle("some.ethos")
# NotImplementedError: Python reference implementation not yet available. …
```

## License

[Apache-2.0](./LICENSE).
