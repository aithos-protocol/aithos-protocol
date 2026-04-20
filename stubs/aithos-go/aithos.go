// Package aithos is the Go reference implementation of the Aithos protocol.
//
// This package was published on 2026-04-19 to reserve the import path
// github.com/aithos-protocol/aithos on the day the protocol was first
// released as version 0.1.0 (draft). It is intentionally minimal: it exposes
// the protocol version, a stub API that returns ErrNotImplemented, and
// embeds the signed birth artifacts of the protocol under the embedded FS
// returned by [BirthFS].
//
// The only functional reference implementation at this stage is the
// TypeScript CLI at https://github.com/aithos-protocol/aithos-protocol/tree/main/cli.
//
// A real Go implementation will land here incrementally. Track progress on
// the issue tracker: https://github.com/aithos-protocol/aithos-protocol/issues.
package aithos

import (
	"embed"
	"errors"
	"io/fs"
)

// ProtocolVersion is the Aithos protocol version this module targets.
const ProtocolVersion = "0.1.0"

// PackageVersion is the version of this Go module itself. Intentionally
// decoupled from [ProtocolVersion] so the module can iterate without
// implying a protocol change.
const PackageVersion = "0.0.1"

// CeremonialDID is the DID of the ceremonial founding identity that signed
// the protocol's birth artifacts on 2026-04-19. Its only purpose was to
// sign the first ethos bundle of the protocol; it holds no ongoing authority.
const CeremonialDID = "did:aithos:z6Mkeu1UTXwL4djF9JmH5idEAF5t7g3bHjvJTBGeWqX5qPpA"

// ErrNotImplemented is returned by every fallible operation in this
// placeholder release. Use the TypeScript reference CLI at
// https://github.com/aithos-protocol/aithos-protocol/tree/main/cli for
// actual functionality.
var ErrNotImplemented = errors.New(
	"aithos: not yet implemented in Go; use the TypeScript reference CLI " +
		"at https://github.com/aithos-protocol/aithos-protocol/tree/main/cli",
)

//go:embed birth
var birthFS embed.FS

// BirthFS returns a filesystem rooted at birth/ containing the signed birth
// artifacts of the Aithos protocol:
//
//   - birth.json              — protocol-native birth record.
//   - birth-declaration.md    — human-readable declaration.
//   - aithos-birth.ethos      — signed ethos bundle (spec §3), conformant and
//     verifiable with `aithos ethos verify` from the TypeScript CLI.
//   - did.json                — DID document of the ceremonial identity.
func BirthFS() fs.FS {
	sub, err := fs.Sub(birthFS, "birth")
	if err != nil {
		// Unreachable: the embed directive guarantees the subtree exists.
		panic(err)
	}
	return sub
}

// VerifyBundle verifies the signatures, hash chains, and manifest of a
// .ethos bundle. Not yet implemented in Go: returns [ErrNotImplemented].
func VerifyBundle(path string) error {
	return ErrNotImplemented
}

// ResolveDID resolves a did:aithos:... identifier to its DID document.
// Not yet implemented in Go: returns [ErrNotImplemented].
func ResolveDID(did string) error {
	return ErrNotImplemented
}
