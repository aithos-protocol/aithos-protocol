# aithos

Go reference implementation of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) — **placeholder, not yet functional**.

```
go get github.com/aithos-protocol/aithos@latest
```

## Status

This module was published on **2026-04-19** to reserve the import path `github.com/aithos-protocol/aithos` on the day the protocol was first released as version `0.1.0` (draft). It is intentionally minimal: it exposes the protocol version as a `const`, a stub API that returns `ErrNotImplemented`, and embeds (via `//go:embed`) the signed birth artifacts of the protocol. The only functional reference implementation at this stage is the [TypeScript CLI](https://github.com/aithos-protocol/aithos-protocol/tree/main/cli).

A real Go implementation will land here incrementally — DID resolution first, then ethos parsing, then mandate verification, then write paths. Track progress on the [issue tracker](https://github.com/aithos-protocol/aithos-protocol/issues).

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*. It defines a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf within strict, scope-limited, time-bounded, and unilaterally revocable terms. Read the [whitepaper](https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md) and the [spec](https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md).

## Usage today

```go
package main

import (
    "fmt"
    "io/fs"

    "github.com/aithos-protocol/aithos"
)

func main() {
    fmt.Println(aithos.ProtocolVersion) // 0.1.0
    fmt.Println(aithos.PackageVersion)  // 0.0.1

    // Read the embedded birth artifacts.
    data, _ := fs.ReadFile(aithos.BirthFS(), "birth.json")
    fmt.Println(string(data))

    // Stub API returns ErrNotImplemented.
    if err := aithos.VerifyBundle("some.ethos"); err != nil {
        fmt.Println(err)
    }
}
```

## License

[Apache-2.0](./LICENSE).
