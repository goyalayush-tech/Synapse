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

    /// SPIFFE error.
    #[error("SPIFFE error: {0}")]
    Spiffe(#[from] SpiffeError),
}

/// TLS configuration for client or server.
///
/// This is a simplified abstraction. In production, you would use
/// rustls or native-tls to create actual TLS configurations.
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
    /// Creates a new TLS configuration from a SPIFFE identity.
    ///
    /// # Arguments
    ///
    /// * `identity` - SPIFFE identity to use for TLS.
    /// * `is_client` - Whether this is a client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS configuration cannot be created.
    pub fn new(identity: SpiffeIdentity, is_client: bool) -> TlsResult<Self> {
        // Validate that identity is not expired
        if identity.is_expired() {
            return Err(TlsError::ConfigCreation(
                "SPIFFE identity is expired".to_string(),
            ));
        }

        Ok(Self {
            identity,
            is_client,
        })
    }

    /// Creates a client TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created.
    pub fn client(identity: SpiffeIdentity) -> TlsResult<Self> {
        Self::new(identity, true)
    }

    /// Creates a server TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be created.
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
    /// Converts the identity to a TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the conversion fails.
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
    fn tls_config_creation() {
        let identity = create_test_identity();
        let config = TlsConfig::client(identity).unwrap();
        assert!(config.is_client);
        assert_eq!(config.spiffe_id(), "spiffe://example.org/workload/test");
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

        assert!(TlsConfig::client(identity).is_err());
    }
}

