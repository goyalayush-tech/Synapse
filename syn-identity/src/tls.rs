//! TLS configuration using SPIFFE identities.
//!
//! This module provides utilities for creating TLS configurations from
//! SPIFFE identities, enabling mutual TLS authentication.

use crate::spiffe::{SpiffeError, SpiffeIdentity, SpiffeResult};
use thiserror::Error;

/// Errors that can occur during TLS configuration.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Failed to load certificate.
    #[error("Failed to load certificate: {0}")]
    CertificateLoad(String),

    /// Failed to load private key.
    #[error("Failed to load private key: {0}")]
    PrivateKeyLoad(String),

    /// Failed to create TLS configuration.
    #[error("Failed to create TLS configuration: {0}")]
    ConfigCreation(String),

    /// Real TLS/mTLS wiring is not implemented by this crate.
    #[error("TLS/mTLS is not implemented in syn-identity: {0}")]
    NotImplemented(String),

    /// SPIFFE error.
    #[error("SPIFFE error: {0}")]
    Spiffe(#[from] SpiffeError),
}

/// TLS configuration for client or server.
///
/// # This does not build real TLS
///
/// This struct is a **placeholder data holder only**. It stores a
/// [`SpiffeIdentity`] and an `is_client` flag, but it never builds a real
/// `rustls::ClientConfig`/`ServerConfig`, never parses/validates the
/// certificate chain, and never installs a certificate verifier. It cannot
/// be used to actually establish a TLS or mTLS connection.
///
/// Because a struct named `TlsConfig` could easily be mistaken for a working
/// TLS configuration, every public constructor (`new`, `client`, `server`)
/// and the [`ToTlsConfig`] extension trait always return
/// `Err(TlsError::NotImplemented)`. Real TLS/mTLS wiring (e.g. via `rustls`)
/// is out of scope for this crate today.
#[cfg(feature = "spiffe")]
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// SPIFFE identity used for this configuration.
    pub identity: SpiffeIdentity,
    /// Whether this is a client or server configuration.
    pub is_client: bool,
}

#[cfg(feature = "spiffe")]
impl TlsConfig {
    /// Attempts to create a new TLS configuration from a SPIFFE identity.
    ///
    /// # Errors
    ///
    /// **Always returns an error.** Real TLS/mTLS configuration (a
    /// `rustls::ClientConfig`/`ServerConfig` backed by the SPIFFE identity's
    /// certificate and a real certificate verifier) is not implemented in
    /// this crate. This function exists only as a documented placeholder so
    /// callers get an explicit, unmistakable failure instead of a
    /// TLS-shaped struct that cannot actually perform TLS.
    pub fn new(identity: SpiffeIdentity, is_client: bool) -> TlsResult<Self> {
        // Validate that identity is not expired
        if identity.is_expired() {
            return Err(TlsError::ConfigCreation(
                "SPIFFE identity is expired".to_string(),
            ));
        }

        let _ = is_client; // reserved for a real implementation

        Err(TlsError::NotImplemented(
            "TlsConfig does not build a real TLS/mTLS configuration (no rustls::ClientConfig \
             / ServerConfig is constructed and no certificate verifier is installed). Wire up \
             rustls (or another TLS library) directly for real TLS/mTLS; this crate does not \
             yet do so."
                .to_string(),
        ))
    }

    /// Attempts to create a client TLS configuration.
    ///
    /// # Errors
    ///
    /// Always returns `Err(TlsError::NotImplemented)` — see [`TlsConfig::new`].
    pub fn client(identity: SpiffeIdentity) -> TlsResult<Self> {
        Self::new(identity, true)
    }

    /// Attempts to create a server TLS configuration.
    ///
    /// # Errors
    ///
    /// Always returns `Err(TlsError::NotImplemented)` — see [`TlsConfig::new`].
    pub fn server(identity: SpiffeIdentity) -> TlsResult<Self> {
        Self::new(identity, false)
    }

    /// Returns the SPIFFE ID associated with this configuration.
    #[must_use]
    pub fn spiffe_id(&self) -> &str {
        &self.identity.spiffe_id
    }
}

/// Result type for TLS operations.
pub type TlsResult<T> = Result<T, TlsError>;

/// Extension trait for converting SPIFFE identities to TLS configurations.
#[cfg(feature = "spiffe")]
pub trait ToTlsConfig {
    /// Attempts to convert the identity to a TLS configuration.
    ///
    /// # Errors
    ///
    /// **Always returns `Err(TlsError::NotImplemented)`.** Real TLS/mTLS
    /// wiring is not implemented in this crate — see [`TlsConfig`] for
    /// details. Do not rely on this method for real security in any
    /// environment.
    fn to_tls_config(&self, is_client: bool) -> TlsResult<TlsConfig>;
}

#[cfg(feature = "spiffe")]
impl ToTlsConfig for SpiffeIdentity {
    fn to_tls_config(&self, is_client: bool) -> TlsResult<TlsConfig> {
        TlsConfig::new(self.clone(), is_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe::SpiffeIdentity;
    use std::time::{Duration, SystemTime};

    fn create_test_identity() -> SpiffeIdentity {
        SpiffeIdentity::new(
            "spiffe://example.org/workload/test".to_string(),
            vec![], // Empty for test
            vec![], // Empty for test
            vec![],
            SystemTime::now() + Duration::from_secs(3600),
        )
    }

    #[test]
    fn tls_config_creation_is_not_implemented() {
        // TlsConfig does not build real TLS/mTLS material, so construction
        // must always fail explicitly rather than silently succeed with a
        // TLS-shaped-but-inert struct.
        let identity = create_test_identity();
        let result = TlsConfig::client(identity);
        assert!(matches!(result, Err(TlsError::NotImplemented(_))));
    }

    #[test]
    fn to_tls_config_is_not_implemented() {
        let identity = create_test_identity();
        let result = identity.to_tls_config(true);
        assert!(matches!(result, Err(TlsError::NotImplemented(_))));
    }

    #[test]
    fn tls_config_expired_identity() {
        let identity = SpiffeIdentity::new(
            "spiffe://example.org/workload/test".to_string(),
            vec![],
            vec![],
            vec![],
            SystemTime::now() - Duration::from_secs(1), // Expired
        );

        // Still an error (expiry is checked before the NotImplemented gate).
        assert!(matches!(
            TlsConfig::client(identity),
            Err(TlsError::ConfigCreation(_))
        ));
    }
}
