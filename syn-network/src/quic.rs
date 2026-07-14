//! QUIC transport implementation using Quinn.
//!
//! QUIC (Quick UDP Internet Connections) provides:
//! - Built-in encryption (TLS 1.3)
//! - Connection multiplexing (multiple streams)
//! - Head-of-line blocking prevention
//! - Fast connection establishment (0-RTT)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      QUIC Transport Layer                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
//! │  │ QuicServer  │  │ QuicClient  │  │   ConnectionPool        │ │
//! │  │  (accept)   │  │  (connect)  │  │  (reuse connections)    │ │
//! │  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
//! │         │                │                     │               │
//! │         └────────────────┼─────────────────────┘               │
//! │                          │                                      │
//! │                    ┌─────┴──────┐                               │
//! │                    │QuicConnection│                             │
//! │                    └─────┬──────┘                               │
//! │         ┌────────────────┼─────────────────┐                   │
//! │         │                │                 │                   │
//! │   ┌─────┴─────┐   ┌─────┴─────┐   ┌──────┴──────┐             │
//! │   │BiStream   │   │SendStream │   │RecvStream   │             │
//! │   │(read/write)│   │(write)    │   │(read)       │             │
//! │   └───────────┘   └───────────┘   └─────────────┘             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Why Quinn?
//!
//! Quinn is the most mature Rust QUIC implementation with:
//! - Excellent async/await support via tokio
//! - Proper TLS 1.3 integration via rustls
//! - Active maintenance and community
//! - Production-ready performance
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "quic")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use syn_network::quic::{QuicClient, QuicConfig};
//!
//! let client = QuicClient::insecure(QuicConfig::development())?;
//! let conn = client.connect("127.0.0.1:4433".parse()?, "localhost").await?;
//!
//! let mut stream = conn.open_bi().await?;
//! stream.write_all(b"Hello, QUIC!").await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

#[cfg(feature = "quic")]
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};

/// Errors that can occur during QUIC operations.
#[derive(Debug, Error)]
pub enum QuicError {
    /// Failed to create QUIC endpoint.
    #[error("Failed to create QUIC endpoint: {0}")]
    EndpointCreation(String),

    /// Failed to bind to address.
    #[error("Failed to bind to address {addr}: {reason}")]
    BindFailed {
        /// Address that failed to bind.
        addr: SocketAddr,
        /// Error reason.
        reason: String,
    },

    /// Failed to accept connection.
    #[error("Failed to accept connection: {0}")]
    AcceptFailed(String),

    /// Failed to connect to remote.
    #[error("Failed to connect to {addr}: {reason}")]
    ConnectFailed {
        /// Address that failed to connect.
        addr: SocketAddr,
        /// Error reason.
        reason: String,
    },

    /// Connection closed.
    #[error("Connection closed: {0}")]
    ConnectionClosed(String),

    /// Stream error.
    #[error("Stream error: {0}")]
    StreamError(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// TLS error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for QuicError {
    fn from(err: std::io::Error) -> Self {
        QuicError::IoError(err.to_string())
    }
}

/// Result type for QUIC operations.
pub type QuicResult<T> = Result<T, QuicError>;

/// QUIC connection configuration.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Maximum number of concurrent bidirectional streams.
    pub max_concurrent_bidi_streams: u64,
    /// Maximum number of concurrent unidirectional streams.
    pub max_concurrent_uni_streams: u64,
    /// Initial stream receive window size in bytes.
    pub stream_receive_window: u64,
    /// Initial connection receive window size in bytes.
    pub receive_window: u64,
    /// Idle timeout in milliseconds (0 = no timeout).
    pub idle_timeout_ms: u64,
    /// Keep-alive interval in milliseconds (0 = disabled).
    pub keep_alive_interval_ms: u64,
    /// Whether to allow self-signed certificates (for development).
    pub allow_insecure: bool,
    /// Server name for SNI (client only).
    pub server_name: Option<String>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            stream_receive_window: 1024 * 1024, // 1 MB per stream
            receive_window: 10 * 1024 * 1024,   // 10 MB per connection
            idle_timeout_ms: 30_000,            // 30 seconds
            keep_alive_interval_ms: 10_000,     // 10 seconds
            allow_insecure: false,
            server_name: None,
        }
    }
}

impl QuicConfig {
    /// Creates a development configuration with relaxed security.
    ///
    /// WARNING: This allows insecure connections. Do not use in production.
    #[must_use]
    pub fn development() -> Self {
        Self {
            allow_insecure: true,
            ..Default::default()
        }
    }

    /// Sets the server name for SNI verification.
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Builds a Quinn TransportConfig from this configuration.
    #[cfg(feature = "quic")]
    fn build_transport_config(&self) -> TransportConfig {
        let mut transport = TransportConfig::default();

        if let Ok(val) = VarInt::from_u64(self.max_concurrent_bidi_streams) {
            transport.max_concurrent_bidi_streams(val);
        }
        if let Ok(val) = VarInt::from_u64(self.max_concurrent_uni_streams) {
            transport.max_concurrent_uni_streams(val);
        }
        if let Ok(val) = VarInt::from_u64(self.stream_receive_window) {
            transport.stream_receive_window(val);
        }
        if let Ok(val) = VarInt::from_u64(self.receive_window) {
            transport.receive_window(val);
        }

        if self.idle_timeout_ms > 0 {
            if let Ok(timeout) = std::time::Duration::from_millis(self.idle_timeout_ms).try_into() {
                transport.max_idle_timeout(Some(timeout));
            }
        }

        if self.keep_alive_interval_ms > 0 {
            transport.keep_alive_interval(Some(std::time::Duration::from_millis(
                self.keep_alive_interval_ms,
            )));
        }

        transport
    }
}

/// TLS certificate configuration for QUIC.
#[derive(Clone)]
pub struct TlsCerts {
    /// DER-encoded certificate chain.
    pub cert_chain: Vec<Vec<u8>>,
    /// DER-encoded private key.
    pub private_key: Vec<u8>,
}

impl TlsCerts {
    /// Creates TLS certs from DER-encoded data.
    #[must_use]
    pub fn from_der(cert_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        Self {
            cert_chain,
            private_key,
        }
    }
}

/// QUIC server endpoint for accepting incoming connections.
#[cfg(feature = "quic")]
pub struct QuicServer {
    endpoint: Endpoint,
    config: QuicConfig,
}

#[cfg(feature = "quic")]
impl QuicServer {
    /// Creates a new QUIC server bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails or TLS configuration is invalid.
    pub fn bind(addr: SocketAddr, certs: TlsCerts, config: QuicConfig) -> QuicResult<Self> {
        // Build rustls server config
        let cert_chain: Vec<_> = certs
            .cert_chain
            .iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.clone()))
            .collect();

        let private_key = rustls::pki_types::PrivateKeyDer::try_from(certs.private_key)
            .map_err(|e| QuicError::TlsError(format!("Invalid private key: {e}")))?;

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| QuicError::TlsError(format!("TLS config error: {e}")))?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| QuicError::TlsError(format!("QUIC crypto config error: {e}")))?,
        ));
        server_config.transport_config(Arc::new(config.build_transport_config()));

        let endpoint =
            Endpoint::server(server_config, addr).map_err(|e| QuicError::BindFailed {
                addr,
                reason: e.to_string(),
            })?;

        tracing::info!("QUIC server listening on {}", addr);

        Ok(Self { endpoint, config })
    }

    /// Accepts a new incoming connection.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept(&self) -> QuicResult<QuicConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| QuicError::AcceptFailed("Endpoint closed".to_string()))?;

        let connection = incoming
            .await
            .map_err(|e| QuicError::AcceptFailed(e.to_string()))?;

        let remote_addr = connection.remote_address();
        tracing::debug!("Accepted QUIC connection from {}", remote_addr);

        Ok(QuicConnection {
            inner: connection,
            config: self.config.clone(),
        })
    }

    /// Returns the local address the server is bound to.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr().ok()
    }

    /// Gracefully shuts down the server.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"server shutdown");
        tracing::info!("QUIC server shut down");
    }
}

/// QUIC client endpoint for outgoing connections.
#[cfg(feature = "quic")]
pub struct QuicClient {
    endpoint: Endpoint,
    config: QuicConfig,
}

#[cfg(feature = "quic")]
impl QuicClient {
    /// Creates a new QUIC client with custom root certificates.
    ///
    /// # Arguments
    ///
    /// * `root_certs` - DER-encoded root CA certificates for server verification.
    /// * `config` - QUIC configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if client creation fails.
    pub fn with_root_certs(root_certs: Vec<Vec<u8>>, config: QuicConfig) -> QuicResult<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
            .map_err(|e| QuicError::EndpointCreation(e.to_string()))?;

        let mut roots = rustls::RootCertStore::empty();
        for cert in root_certs {
            let cert_der = rustls::pki_types::CertificateDer::from(cert);
            roots
                .add(cert_der)
                .map_err(|e| QuicError::TlsError(format!("Invalid root certificate: {e}")))?;
        }

        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut client_cfg = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::TlsError(format!("QUIC crypto error: {e}")))?,
        ));
        client_cfg.transport_config(Arc::new(config.build_transport_config()));
        endpoint.set_default_client_config(client_cfg);

        Ok(Self { endpoint, config })
    }

    /// Creates a new QUIC client that skips certificate verification.
    ///
    /// # Safety
    ///
    /// This should ONLY be used for development/testing. It disables
    /// all TLS certificate verification.
    ///
    /// # Errors
    ///
    /// Returns an error if client creation fails.
    pub fn insecure(config: QuicConfig) -> QuicResult<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
            .map_err(|e| QuicError::EndpointCreation(e.to_string()))?;

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_cfg = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::TlsError(format!("QUIC crypto error: {e}")))?,
        ));
        client_cfg.transport_config(Arc::new(config.build_transport_config()));
        endpoint.set_default_client_config(client_cfg);

        tracing::warn!("Created insecure QUIC client - DO NOT USE IN PRODUCTION");

        Ok(Self { endpoint, config })
    }

    /// Connects to a remote QUIC server.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> QuicResult<QuicConnection> {
        let connection = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| QuicError::ConnectFailed {
                addr,
                reason: e.to_string(),
            })?
            .await
            .map_err(|e| QuicError::ConnectFailed {
                addr,
                reason: e.to_string(),
            })?;

        tracing::debug!("Connected to QUIC server at {}", addr);

        Ok(QuicConnection {
            inner: connection,
            config: self.config.clone(),
        })
    }

    /// Closes the client endpoint.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"client closed");
    }
}

// =============================================================================
// Connection Pool
// =============================================================================

/// Pooled connection entry
#[cfg(feature = "quic")]
struct PooledConnection {
    connection: Connection,
    server_name: String,
    created_at: Instant,
    last_used: Instant,
}

/// Connection pool for reusing QUIC connections.
///
/// QUIC connections are expensive to establish (TLS handshake), so pooling
/// connections can significantly improve performance for applications that
/// make many requests to the same servers.
#[cfg(feature = "quic")]
pub struct ConnectionPool {
    client: QuicClient,
    connections: Arc<RwLock<HashMap<SocketAddr, PooledConnection>>>,
    max_idle_time: Duration,
    max_connections: usize,
}

#[cfg(feature = "quic")]
impl ConnectionPool {
    /// Creates a new connection pool.
    pub fn new(client: QuicClient) -> Self {
        Self {
            client,
            connections: Arc::new(RwLock::new(HashMap::new())),
            max_idle_time: Duration::from_secs(60),
            max_connections: 100,
        }
    }

    /// Sets the maximum idle time before a connection is closed.
    #[must_use]
    pub fn with_max_idle_time(mut self, duration: Duration) -> Self {
        self.max_idle_time = duration;
        self
    }

    /// Sets the maximum number of pooled connections.
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Gets a connection to the specified address, reusing an existing one if available.
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails.
    pub async fn get(&self, addr: SocketAddr, server_name: &str) -> QuicResult<QuicConnection> {
        // Check for existing connection
        {
            let mut conns = self.connections.write().await;

            if let Some(pooled) = conns.get_mut(&addr) {
                // Check if connection is still valid
                if pooled.last_used.elapsed() < self.max_idle_time {
                    pooled.last_used = Instant::now();

                    // Return a wrapped connection
                    return Ok(QuicConnection {
                        inner: pooled.connection.clone(),
                        config: self.client.config.clone(),
                    });
                } else {
                    // Connection expired, remove it
                    conns.remove(&addr);
                }
            }
        }

        // Create new connection
        let conn = self.client.connect(addr, server_name).await?;

        // Store in pool
        {
            let mut conns = self.connections.write().await;

            // Evict old connections if at capacity
            if conns.len() >= self.max_connections {
                self.evict_oldest(&mut conns);
            }

            conns.insert(
                addr,
                PooledConnection {
                    connection: conn.inner.clone(),
                    server_name: server_name.to_string(),
                    created_at: Instant::now(),
                    last_used: Instant::now(),
                },
            );
        }

        Ok(conn)
    }

    /// Evicts the oldest connection from the pool.
    fn evict_oldest(&self, conns: &mut HashMap<SocketAddr, PooledConnection>) {
        if let Some((oldest_addr, _)) = conns
            .iter()
            .min_by_key(|(_, c)| c.last_used)
            .map(|(a, c)| (*a, c.last_used))
        {
            if let Some(conn) = conns.remove(&oldest_addr) {
                conn.connection.close(VarInt::from_u32(0), b"evicted");
            }
        }
    }

    /// Removes and closes a connection from the pool.
    pub async fn remove(&self, addr: &SocketAddr) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(addr) {
            conn.connection.close(VarInt::from_u32(0), b"removed");
        }
    }

    /// Removes all expired connections from the pool.
    pub async fn cleanup(&self) {
        let mut conns = self.connections.write().await;
        let expired: Vec<_> = conns
            .iter()
            .filter(|(_, c)| c.last_used.elapsed() > self.max_idle_time)
            .map(|(a, _)| *a)
            .collect();

        for addr in expired {
            if let Some(conn) = conns.remove(&addr) {
                conn.connection.close(VarInt::from_u32(0), b"expired");
            }
        }
    }

    /// Returns statistics about the pool.
    pub async fn stats(&self) -> PoolStats {
        let conns = self.connections.read().await;

        let active = conns
            .values()
            .filter(|c| c.last_used.elapsed() < self.max_idle_time)
            .count();

        let oldest_age = conns
            .values()
            .map(|c| c.created_at.elapsed())
            .max()
            .unwrap_or(Duration::ZERO);

        PoolStats {
            total_connections: conns.len(),
            active_connections: active,
            max_connections: self.max_connections,
            oldest_connection_age: oldest_age,
        }
    }

    /// Closes all connections and clears the pool.
    pub async fn close_all(&self) {
        let mut conns = self.connections.write().await;
        for (_, conn) in conns.drain() {
            conn.connection.close(VarInt::from_u32(0), b"pool closed");
        }
    }
}

/// Statistics about a connection pool.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total number of connections in the pool.
    pub total_connections: usize,
    /// Number of active (non-expired) connections.
    pub active_connections: usize,
    /// Maximum number of connections allowed.
    pub max_connections: usize,
    /// Age of the oldest connection.
    pub oldest_connection_age: Duration,
}

/// Skip server certificate verification (DEVELOPMENT ONLY).
#[cfg(feature = "quic")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "quic")]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// QUIC connection wrapper.
///
/// Represents an established QUIC connection with support for
/// multiple bidirectional and unidirectional streams.
#[cfg(feature = "quic")]
pub struct QuicConnection {
    inner: Connection,
    config: QuicConfig,
}

#[cfg(feature = "quic")]
impl QuicConnection {
    /// Opens a new bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error if opening the stream fails.
    pub async fn open_bi(&self) -> QuicResult<QuicBiStream> {
        let (send, recv) = self.inner.open_bi().await.map_err(|e| {
            QuicError::StreamError(format!("Failed to open bidirectional stream: {e}"))
        })?;

        Ok(QuicBiStream { send, recv })
    }

    /// Opens a new unidirectional stream (send only).
    ///
    /// # Errors
    ///
    /// Returns an error if opening the stream fails.
    pub async fn open_uni(&self) -> QuicResult<QuicSendStream> {
        let send = self.inner.open_uni().await.map_err(|e| {
            QuicError::StreamError(format!("Failed to open unidirectional stream: {e}"))
        })?;

        Ok(QuicSendStream { inner: send })
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept_bi(&self) -> QuicResult<QuicBiStream> {
        let (send, recv) = self.inner.accept_bi().await.map_err(|e| {
            QuicError::StreamError(format!("Failed to accept bidirectional stream: {e}"))
        })?;

        Ok(QuicBiStream { send, recv })
    }

    /// Accepts an incoming unidirectional stream (receive only).
    ///
    /// # Errors
    ///
    /// Returns an error if accepting fails.
    pub async fn accept_uni(&self) -> QuicResult<QuicRecvStream> {
        let recv = self.inner.accept_uni().await.map_err(|e| {
            QuicError::StreamError(format!("Failed to accept unidirectional stream: {e}"))
        })?;

        Ok(QuicRecvStream { inner: recv })
    }

    /// Returns the remote address.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Returns the connection's stable ID.
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Closes the connection gracefully.
    pub fn close(&self, reason: &str) {
        self.inner.close(VarInt::from_u32(0), reason.as_bytes());
    }

    /// Waits for the connection to be closed.
    pub async fn closed(&self) -> QuicError {
        let err = self.inner.closed().await;
        QuicError::ConnectionClosed(err.to_string())
    }
}

/// Bidirectional QUIC stream.
#[cfg(feature = "quic")]
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
}

#[cfg(feature = "quic")]
impl QuicBiStream {
    /// Splits the stream into separate send and receive halves.
    #[must_use]
    pub fn split(self) -> (QuicSendStream, QuicRecvStream) {
        (
            QuicSendStream { inner: self.send },
            QuicRecvStream { inner: self.recv },
        )
    }

    /// Writes data to the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub async fn write_all(&mut self, buf: &[u8]) -> QuicResult<()> {
        self.send
            .write_all(buf)
            .await
            .map_err(|e| QuicError::StreamError(format!("Write failed: {e}")))
    }

    /// Reads data from the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub async fn read(&mut self, buf: &mut [u8]) -> QuicResult<Option<usize>> {
        self.recv
            .read(buf)
            .await
            .map_err(|e| QuicError::StreamError(format!("Read failed: {e}")))
    }

    /// Reads all data until the stream ends.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub async fn read_to_end(&mut self, max_size: usize) -> QuicResult<Vec<u8>> {
        self.recv
            .read_to_end(max_size)
            .await
            .map_err(|e| QuicError::StreamError(format!("Read to end failed: {e}")))
    }

    /// Finishes the send side of the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if finishing fails.
    pub fn finish(&mut self) -> QuicResult<()> {
        self.send
            .finish()
            .map_err(|e| QuicError::StreamError(format!("Finish failed: {e}")))
    }
}

/// Send-only QUIC stream.
#[cfg(feature = "quic")]
pub struct QuicSendStream {
    inner: SendStream,
}

#[cfg(feature = "quic")]
impl QuicSendStream {
    /// Writes data to the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub async fn write_all(&mut self, buf: &[u8]) -> QuicResult<()> {
        self.inner
            .write_all(buf)
            .await
            .map_err(|e| QuicError::StreamError(format!("Write failed: {e}")))
    }

    /// Finishes the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if finishing fails.
    pub fn finish(&mut self) -> QuicResult<()> {
        self.inner
            .finish()
            .map_err(|e| QuicError::StreamError(format!("Finish failed: {e}")))
    }
}

/// Receive-only QUIC stream.
#[cfg(feature = "quic")]
pub struct QuicRecvStream {
    inner: RecvStream,
}

#[cfg(feature = "quic")]
impl QuicRecvStream {
    /// Reads data from the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub async fn read(&mut self, buf: &mut [u8]) -> QuicResult<Option<usize>> {
        self.inner
            .read(buf)
            .await
            .map_err(|e| QuicError::StreamError(format!("Read failed: {e}")))
    }

    /// Reads all data until the stream ends.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub async fn read_to_end(&mut self, max_size: usize) -> QuicResult<Vec<u8>> {
        self.inner
            .read_to_end(max_size)
            .await
            .map_err(|e| QuicError::StreamError(format!("Read to end failed: {e}")))
    }
}

// =============================================================================
// Non-feature-gated types for API compatibility
// =============================================================================

/// QUIC server (stub when feature disabled).
#[cfg(not(feature = "quic"))]
pub struct QuicServer {
    addr: SocketAddr,
    config: QuicConfig,
}

#[cfg(not(feature = "quic"))]
impl QuicServer {
    /// Creates a new QUIC server (stub).
    ///
    /// # Errors
    ///
    /// Always returns an error when the quic feature is disabled.
    pub fn bind(addr: SocketAddr, _certs: TlsCerts, _config: QuicConfig) -> QuicResult<Self> {
        Err(QuicError::InvalidConfig(
            "QUIC feature not enabled. Rebuild with --features quic".to_string(),
        ))
    }
}

/// QUIC client (stub when feature disabled).
#[cfg(not(feature = "quic"))]
pub struct QuicClient {
    config: QuicConfig,
}

#[cfg(not(feature = "quic"))]
impl QuicClient {
    /// Creates a new insecure QUIC client (stub).
    ///
    /// # Errors
    ///
    /// Always returns an error when the quic feature is disabled.
    pub fn insecure(_config: QuicConfig) -> QuicResult<Self> {
        Err(QuicError::InvalidConfig(
            "QUIC feature not enabled. Rebuild with --features quic".to_string(),
        ))
    }
}

/// Legacy compatibility: QUIC connection (stub when feature disabled).
#[cfg(not(feature = "quic"))]
pub struct QuicConnection {
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Legacy compatibility: QUIC stream (stub when feature disabled).
#[cfg(not(feature = "quic"))]
pub struct QuicStream {
    stream_id: u64,
}

#[cfg(not(feature = "quic"))]
impl QuicStream {
    /// Creates a new QUIC stream stub.
    #[must_use]
    pub fn new(stream_id: u64) -> Self {
        Self { stream_id }
    }

    /// Returns the stream ID.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_config_default() {
        let config = QuicConfig::default();
        assert_eq!(config.max_concurrent_bidi_streams, 100);
        assert_eq!(config.idle_timeout_ms, 30_000);
    }

    #[test]
    fn quic_config_development() {
        let config = QuicConfig::development();
        assert!(config.allow_insecure);
    }

    #[test]
    fn quic_config_with_server_name() {
        let config = QuicConfig::default().with_server_name("localhost");
        assert_eq!(config.server_name, Some("localhost".to_string()));
    }

    #[test]
    fn tls_certs_from_der() {
        let certs = TlsCerts::from_der(vec![vec![1, 2, 3]], vec![4, 5, 6]);
        assert_eq!(certs.cert_chain.len(), 1);
        assert_eq!(certs.private_key, vec![4, 5, 6]);
    }
}
