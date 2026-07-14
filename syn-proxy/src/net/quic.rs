//! QUIC network provider implementation.
//!
//! This module provides a QUIC-based NetProvider implementation using
//! the syn-network crate for high-performance, multiplexed connections.

use super::{ConnectionListener, ConnectionStream, NetProvider};
use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;

#[cfg(feature = "quic")]
use syn_network::quic::{QuicConfig, QuicServer as NetworkQuicListener, TlsCerts};

/// QUIC-based network provider.
///
/// Uses QUIC transport for both control and data sockets, providing
/// built-in encryption, multiplexing, and head-of-line blocking prevention.
#[cfg(feature = "quic")]
pub struct QuicNetProvider {
    certs: TlsCerts,
    config: QuicConfig,
}

#[cfg(feature = "quic")]
impl QuicNetProvider {
    /// Creates a new QUIC network provider using the given TLS certificates
    /// and configuration.
    #[must_use]
    pub fn new(certs: TlsCerts, config: QuicConfig) -> Self {
        Self { certs, config }
    }
}

#[cfg(feature = "quic")]
#[async_trait]
impl NetProvider for QuicNetProvider {
    async fn bind_control_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let listener =
            NetworkQuicListener::bind(socket_addr, self.certs.clone(), self.config.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(Box::new(QuicListenerAdapter { listener }))
    }

    async fn bind_data_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        // Data socket uses the same QUIC mechanism
        self.bind_control_socket(addr).await
    }

    fn description(&self) -> &'static str {
        "QuicNetProvider (QUIC transport)"
    }
}

/// Adapter that wraps syn-network's `QuicServer` to implement `ConnectionListener`.
#[cfg(feature = "quic")]
struct QuicListenerAdapter {
    listener: NetworkQuicListener,
}

#[cfg(feature = "quic")]
#[async_trait]
impl ConnectionListener for QuicListenerAdapter {
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>> {
        // A real implementation would:
        // 1. Accept a QUIC connection (`self.listener.accept()`)
        // 2. Open/accept a stream on the connection
        // 3. Return a stream adapter wrapping it
        //
        // That plumbing (turning a multiplexed QUIC connection into a
        // single `ConnectionStream`) isn't implemented yet, so report it
        // honestly instead of hanging or fabricating a stream.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QUIC stream adapter not yet implemented",
        ))
    }

    fn local_addr(&self) -> io::Result<String> {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "QUIC listener has no bound local address",
                )
            })
    }
}
