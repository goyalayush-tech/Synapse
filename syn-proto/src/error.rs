//! Protocol-specific error types.

use thiserror::Error;

/// Maximum size, in bytes, of a single wire message accepted for Rkyv
/// validation/deserialization.
///
/// This is a defense-in-depth ceiling: `PacketHeader::payload_len` is a `u32`
/// (nominally supporting payloads up to ~4 GiB), but no legitimate message in
/// this system approaches that size, and accepting an unbounded byte slice
/// straight into `rkyv` validation/deserialization is an easy resource
/// exhaustion vector (a hostile or corrupt peer could claim an enormous
/// buffer). 16 MiB comfortably covers real workloads while still bounding
/// worst-case memory/CPU spent validating a single message.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Errors that can occur during protocol operations.
#[derive(Error, Debug)]
pub enum ProtoError {
    /// Failed to serialize a message.
    #[error("Serialization failed: {0}")]
    Serialization(String),

    /// Failed to deserialize a message.
    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    /// Message validation failed (e.g., Rkyv checksum mismatch).
    #[error("Validation failed: {0}")]
    Validation(String),

    /// Message exceeds maximum allowed size.
    #[error("Message too large: {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge {
        /// The actual size of the message in bytes.
        size: usize,
        /// The maximum allowed size in bytes.
        max: usize,
    },

    /// Unknown message type or version.
    #[error("Unknown message type: {0}")]
    UnknownType(String),
}

/// Result type for protocol operations.
pub type ProtoResult<T> = Result<T, ProtoError>;

impl From<serde_json::Error> for ProtoError {
    fn from(err: serde_json::Error) -> Self {
        if err.is_io() {
            Self::Serialization(err.to_string())
        } else {
            Self::Deserialization(err.to_string())
        }
    }
}
