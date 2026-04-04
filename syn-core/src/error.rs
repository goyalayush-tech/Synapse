//! Centralized error handling for the Synapse ecosystem.
//!
//! Rust's error handling ecosystem distinguishes between:
//! - **Libraries**: Define precise, enumerable errors with `thiserror`
//! - **Applications**: Consume and report errors with `anyhow`
//!
//! `syn-core` is a library, so we define a unified [`SynapseError`] enum.
//! This allows consumers (CLI, proxy) to:
//! - Match on specific variants for recovery logic
//! - Provide helpful user-facing messages
//! - Chain context as errors propagate

use thiserror::Error;

/// The unified error type for all Synapse operations.
///
/// This enum covers all failure modes across the system, allowing
/// precise error handling and informative diagnostics.
#[derive(Error, Debug)]
pub enum SynapseError {
    /// Configuration file is invalid or missing required fields.
    #[error("Configuration invalid: {0}")]
    Config(String),

    /// Network I/O operation failed.
    #[error("Network I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// Wire protocol violation (malformed packets, invalid checksums).
    #[error("Protocol violation: {0}")]
    Protocol(String),

    /// A required system resource is unavailable.
    ///
    /// This could be a socket, file descriptor, or OS primitive.
    #[error("System resource unavailable: {0}")]
    SystemUnavailable(String),

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The requested operation timed out.
    #[error("Operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// An internal invariant was violated.
    ///
    /// This indicates a bug in Synapse, not user error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Identity verification failed.
    #[error("Identity verification failed: {0}")]
    IdentityVerification(String),

    /// The operation was cancelled.
    #[error("Operation cancelled")]
    Cancelled,
}

/// A convenient Result type alias for Synapse operations.
pub type Result<T> = std::result::Result<T, SynapseError>;

impl SynapseError {
    /// Creates a configuration error with the given message.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Creates a protocol error with the given message.
    #[must_use]
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Creates a serialization error with the given message.
    #[must_use]
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    /// Creates an internal error with the given message.
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Returns `true` if this error is recoverable.
    ///
    /// Recoverable errors may succeed if retried (e.g., transient network issues).
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::Timeout(_) | Self::SystemUnavailable(_)
        )
    }

    /// Returns `true` if this error indicates a bug in Synapse.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let syn_err: SynapseError = io_err.into();
        assert!(matches!(syn_err, SynapseError::Io(_)));
        assert!(syn_err.is_recoverable());
    }

    #[test]
    fn config_error_not_recoverable() {
        let err = SynapseError::config("missing field 'port'");
        assert!(!err.is_recoverable());
        assert!(!err.is_internal());
    }

    #[test]
    fn internal_error_flagged() {
        let err = SynapseError::internal("invariant violation");
        assert!(err.is_internal());
    }
}
