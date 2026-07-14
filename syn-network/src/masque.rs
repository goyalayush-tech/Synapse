//! MASQUE (Multiplexed Application Substrate over QUIC Encryption) tunnel support.
//!
//! MASQUE enables secure proxy tunnels over QUIC, allowing agents to
//! establish encrypted connections through intermediaries.

use crate::quic::{QuicConnection, QuicError, QuicResult};
use thiserror::Error;

/// Errors that can occur during MASQUE operations.
#[derive(Debug, Error)]
pub enum MasqueError {
    /// Failed to create MASQUE tunnel.
    #[error("Failed to create MASQUE tunnel: {0}")]
    TunnelCreationFailed(String),

    /// Failed to connect through proxy.
    #[error("Failed to connect through proxy: {0}")]
    ProxyConnectionFailed(String),

    /// Tunnel closed.
    #[error("Tunnel closed")]
    TunnelClosed,

    /// Invalid target address.
    #[error("Invalid target address: {0}")]
    InvalidTarget(String),

    /// QUIC error.
    #[error("QUIC error: {0}")]
    Quic(#[from] QuicError),

    /// Operation not yet implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// MASQUE tunnel for proxying connections.
///
/// A MASQUE tunnel establishes a QUIC connection to a proxy server,
/// which then forwards traffic to the target destination.
#[cfg(feature = "masque")]
pub struct MasqueTunnel {
    /// Proxy connection.
    #[allow(dead_code)] // populated once real MASQUE negotiation is implemented
    proxy_connection: QuicConnection,
    /// Target address.
    target: String,
}

#[cfg(feature = "masque")]
impl MasqueTunnel {
    /// Creates a new MASQUE tunnel through a proxy.
    ///
    /// # Arguments
    ///
    /// * `proxy_addr` - Address of the MASQUE proxy server.
    /// * `target` - Target address to connect to through the proxy.
    ///
    /// # Errors
    ///
    /// A real MASQUE CONNECT-UDP tunnel exchange is not implemented yet.
    /// This always returns [`MasqueError::NotImplemented`] rather than
    /// silently returning a tunnel that isn't actually established.
    pub async fn new(
        proxy_addr: std::net::SocketAddr,
        target: impl Into<String>,
    ) -> MasqueResult<Self> {
        // A real implementation would:
        // 1. Establish a QUIC connection to the proxy (e.g. via
        //    `QuicClient::connect`)
        // 2. Send a MASQUE CONNECT-UDP request with the target
        // 3. Wait for the proxy to establish the connection
        // 4. Return the tunnel
        //
        // None of that is implemented yet, so rather than pretend a tunnel
        // was established we report it honestly.
        let _ = proxy_addr;
        let _ = target.into();

        Err(MasqueError::NotImplemented(
            "MASQUE tunnel establishment not yet implemented".to_string(),
        ))
    }

    /// Returns the target address.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Closes the tunnel.
    ///
    /// # Errors
    ///
    /// Graceful tunnel teardown is not implemented yet; this always
    /// returns [`MasqueError::NotImplemented`].
    pub async fn close(self) -> MasqueResult<()> {
        Err(MasqueError::NotImplemented(
            "MASQUE tunnel teardown not yet implemented".to_string(),
        ))
    }
}

/// Result type for MASQUE operations.
pub type MasqueResult<T> = Result<T, MasqueError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn masque_tunnel_creation_not_implemented() {
        // Real MASQUE CONNECT-UDP negotiation isn't implemented yet, so
        // `MasqueTunnel::new` must report that honestly instead of
        // pretending to establish a working tunnel. Since it never touches
        // the network, this doesn't require a live QUIC server.
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = MasqueTunnel::new(addr, "example.com:443").await;

        assert!(matches!(result, Err(MasqueError::NotImplemented(_))));
    }
}
