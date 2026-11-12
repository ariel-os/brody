//! Error type for brody's envelope parsing, key loading, and signing operations.

use std::fmt;

/// Errors that can occur while signing a SUIT envelope.
#[derive(Debug)]
pub enum Error {
    /// The input bytes are not a well-formed `SUIT_Envelope` CBOR map.
    InvalidEnvelope(String),
    /// The `SUIT_Digest` in the envelope does not match the manifest at key 3.
    DigestMismatch(String),
    /// The supplied key could not be parsed or doesn't match the requested algorithm.
    InvalidKey(String),
    /// Reading or writing a file failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidEnvelope(msg) => write!(f, "invalid envelope: {msg}"),
            Error::DigestMismatch(msg) => write!(f, "digest mismatch: {msg}"),
            Error::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            Error::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
