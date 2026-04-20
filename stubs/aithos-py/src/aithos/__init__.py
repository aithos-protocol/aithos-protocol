"""Aithos — Python reference implementation (placeholder).

This package reserves the name ``aithos`` on PyPI on 2026-04-19, the day the
Aithos protocol was published as version 0.1.0 (draft). It is intentionally
minimal: it exposes the protocol version string, a ``NotImplementedError``
stub for the read API, and the signed birth artifacts bundled under
``aithos.birth``.

The only functional reference implementation at this stage is the TypeScript
CLI at https://github.com/aithos-protocol/aithos-protocol/tree/main/cli.

A real Python implementation will land here incrementally. Track progress
at https://github.com/aithos-protocol/aithos-protocol/issues.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "PROTOCOL_VERSION",
    "PACKAGE_VERSION",
    "BIRTH_DIR",
    "verify_bundle",
    "resolve_did",
]

#: The Aithos protocol version this package targets.
PROTOCOL_VERSION: str = "0.1.0"

#: The version of this Python package itself. Intentionally decoupled from
#: the protocol version so the package can iterate without implying a
#: protocol change.
PACKAGE_VERSION: str = "0.0.1"

#: Path to the bundled birth artifacts (declaration, signed .ethos bundle,
#: DID document, and birth.json metadata). See ``aithos.birth/birth.json``.
BIRTH_DIR: Path = Path(__file__).parent / "birth"


def verify_bundle(path: str | Path) -> None:
    """Verify the signatures, hash chains, and manifest of a ``.ethos`` bundle.

    Not yet implemented in Python. For now, use the TypeScript reference CLI:

        aithos ethos verify --handle <handle>

    or unpack the bundle and inspect ``manifest.json`` manually. Tracking
    issue: https://github.com/aithos-protocol/aithos-protocol/issues
    """
    raise NotImplementedError(
        "Python reference implementation not yet available. "
        f"Install the TypeScript CLI to verify {path!s}, or subscribe to "
        "https://github.com/aithos-protocol/aithos-protocol for updates."
    )


def resolve_did(did: str) -> None:
    """Resolve a ``did:aithos:…`` identifier to its DID document.

    Not yet implemented. See ``verify_bundle`` above.
    """
    raise NotImplementedError(
        f"DID resolution not yet available in Python for {did!r}."
    )
