//! Network abstraction layer (Ports & Adapters pattern).
//!
//! This module defines the `NetProvider` trait - the "Port" in hexagonal
//! architecture terminology. By depending on this interface rather than
//! concrete OS implementations, the proxy logic remains testable and portable.
//!
//! ## Key Abstractions
//!
//! - [`NetProvider`]: Factory for network resources (sockets, pipes)
//! - [`ConnectionListener`]: Accepts incoming connections
//! - [`ConnectionStream`]: Bidirectional byte stream (read/write)
//!
//! ## Implementations
//!
//! - [`real::RealNetProvider`]: Uses actual OS primitives
//! - [`super::windows::mock::WindowsMockProvider`]: In-memory simulation

pub mod real;

use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

/// A trait object representing a generic bidirectional byte stream.
///
/// This abstracts over concrete stream types:
/// - `TcpStream`
/// - `UnixStream`  
/// - `NamedPipeServer` (Windows)
/// - `DuplexStream` (mock)
///
/// Requirements:
/// - `AsyncRead + AsyncWrite`: Tokio async I/O
/// - `Unpin`: Can be moved while I/O is pending
/// - `Send`: Can be sent across threads
pub trait ConnectionStream: AsyncRead + AsyncWrite + Unpin + Send {}

// Blanket implementation for all compatible types
impl<T> ConnectionStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Abstract listener that produces connection streams.
///
/// Implementations wrap platform-specific listeners:
/// - `TcpListener`
/// - `UnixListener`
/// - `NamedPipeServer`
#[async_trait]
pub trait ConnectionListener: Send + Sync {
    /// Accepts a new incoming connection.
    ///
    /// This method is cancel-safe - dropping the future will not lose connections.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accepting fails.
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>>;

    /// Returns the local address this listener is bound to.
    fn local_addr(&self) -> io::Result<String>;
}

/// The "Provider" trait: An abstract factory for network resources.
///
/// This is the central abstraction point for platform portability.
/// The proxy server receives a `Box<dyn NetProvider>` and uses it
/// to create listeners without knowing the underlying implementation.
///
/// ## Example
///
/// ```ignore
/// let provider: Box<dyn NetProvider> = if cfg!(feature = "mock-windows") {
///     Box::new(WindowsMockProvider::new())
/// } else {
///     Box::new(RealNetProvider)
/// };
///
/// let listener = provider.bind_control_socket("synapse_ctl").await?;
/// ```
#[async_trait]
pub trait NetProvider: Send + Sync {
    /// Binds a control socket for CLI communication.
    ///
    /// The address format is platform-dependent:
    /// - **Windows**: Named Pipe name (e.g., `synapse_ctl` → `\\.\pipe\synapse_ctl`)
    /// - **Unix**: Socket path (e.g., `/tmp/synapse_ctl.sock`)
    /// - **Mock**: Ignored (uses in-memory channels)
    ///
    /// # Errors
    ///
    /// Returns an I/O error if binding fails (address in use, permissions, etc.)
    async fn bind_control_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>>;

    /// Binds a data socket for high-throughput agent traffic.
    ///
    /// Separate from control to allow different network configurations
    /// (e.g., control on localhost, data on public interface).
    async fn bind_data_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>>;

    /// Returns a human-readable description of this provider.
    fn description(&self) -> &'static str;
}

#[cfg(feature = "quic")]
pub mod quic;

/// Selects the appropriate network provider based on configuration.
///
/// Priority:
/// 1. `SYNAPSE_MOCK` environment variable → MockProvider
/// 2. `mock-windows` feature flag → MockProvider  
/// 3. Default → RealNetProvider
pub fn select_provider() -> Box<dyn NetProvider> {
    let use_mock = std::env::var("SYNAPSE_MOCK").is_ok() || cfg!(feature = "mock-windows");

    if use_mock {
        tracing::warn!("Using MOCK network provider - not for production!");
        Box::new(crate::windows::mock::WindowsMockProvider::new())
    } else {
        tracing::info!("Using real network provider");
        Box::new(real::RealNetProvider)
    }
}
