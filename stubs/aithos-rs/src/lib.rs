//! # Aithos — Rust reference implementation (placeholder)
//!
//! This crate reserves the name `aithos` on crates.io on 2026-04-19, the day
//! the [Aithos protocol] was published as version `0.1.0` (draft). It is
//! intentionally minimal: it exposes the protocol version string, a stub for
//! the read API that returns [`Error::NotImplemented`], and the signed birth
//! artifacts bundled at the crate root (`birth/`).
//!
//! The only functional reference implementation at this stage is the
//! TypeScript CLI in the [protocol repository].
//!
//! A real Rust implementation will land here incrementally. Track progress on
//! the [issue tracker].
//!
//! [Aithos protocol]: https://github.com/aithos-protocol/aithos-protocol
//! [protocol repository]: https://github.com/aithos-protocol/aithos-protocol/tree/main/cli
//! [issue tracker]: https://github.com/aithos-protocol/aithos-protocol/issues
//!
//! ## Usage today
//!
//! ```
//! assert_eq!(aithos::PROTOCOL_VERSION, "0.1.0");
//! assert_eq!(aithos::PACKAGE_VERSION, "0.0.1");
//!
//! let err = aithos::verify_bundle("some.ethos").unwrap_err();
//! assert!(matches!(err, aithos::Error::NotImplemented { .. }));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;
use std::path::Path;

/// The Aithos protocol version this crate targets.
pub const PROTOCOL_VERSION: &str = "0.1.0";

/// The version of this crate itself. Intentionally decoupled from
/// [`PROTOCOL_VERSION`] so the crate can iterate without implying a protocol
/// change.
pub const PACKAGE_VERSION: &str = "0.0.1";

/// DID of the ceremonial founding identity that signed the protocol's birth
/// artifacts on 2026-04-19.
pub const CEREMONIAL_DID: &str =
    "did:aithos:z6Mkeu1UTXwL4djF9JmH5idEAF5t7g3bHjvJTBGeWqX5qPpA";

/// Errors returned by this crate. For the v0.0.1 placeholder release,
/// effectively every fallible operation returns [`Error::NotImplemented`].
#[derive(Debug)]
pub enum Error {
    /// The requested operation is not yet implemented in Rust. Use the
    /// TypeScript reference CLI at
    /// <https://github.com/aithos-protocol/aithos-protocol/tree/main/cli>.
    NotImplemented {
        /// Short description of what was asked.
        what: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotImplemented { what } => write!(
                f,
                "aithos: {what} is not yet implemented in Rust. \
                 Use the TypeScript reference CLI: \
                 https://github.com/aithos-protocol/aithos-protocol/tree/main/cli"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Verify the signatures, hash chains, and manifest of a `.ethos` bundle.
///
/// Not yet implemented in Rust. Returns [`Error::NotImplemented`].
pub fn verify_bundle<P: AsRef<Path>>(_path: P) -> Result<(), Error> {
    Err(Error::NotImplemented {
        what: "verify_bundle",
    })
}

/// Resolve a `did:aithos:…` identifier to its DID document.
///
/// Not yet implemented in Rust. Returns [`Error::NotImplemented`].
pub fn resolve_did(_did: &str) -> Result<(), Error> {
    Err(Error::NotImplemented { what: "resolve_did" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_expected() {
        assert_eq!(PROTOCOL_VERSION, "0.1.0");
    }

    #[test]
    fn package_version_is_expected() {
        assert_eq!(PACKAGE_VERSION, "0.0.1");
    }

    #[test]
    fn ceremonial_did_is_did_aithos() {
        assert!(CEREMONIAL_DID.starts_with("did:aithos:"));
    }

    #[test]
    fn verify_bundle_returns_not_implemented() {
        let err = verify_bundle("does-not-matter.ethos").unwrap_err();
        assert!(matches!(err, Error::NotImplemented { what: "verify_bundle" }));
    }

    #[test]
    fn resolve_did_returns_not_implemented() {
        let err = resolve_did(CEREMONIAL_DID).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { what: "resolve_did" }));
    }
}
