//! Mock Windows Named Pipe provider for cross-platform development.
//!
//! This module enables **Hermetic Testing** - integration tests that verify
//! the entire application lifecycle without touching the actual network stack.
//! This eliminates "flaky" tests caused by port conflicts, permissions, or
//! OS restrictions.
//!
//! ## How It Works
//!
//! The mock provider uses `tokio::io::duplex` to create in-memory connected
//! stream pairs. One end goes to the server (which thinks it's a real client),
//! the other stays in the test harness to simulate traffic.
//!
//! ```text
//! ┌─────────────────┐        tokio::io::duplex        ┌─────────────────┐
//! │   Test Harness  │ ◄──────────────────────────────► │   ProxyServer   │
//! │                 │      (in-memory channel)        │                 │
//! │ client_stream   │                                 │ server sees as  │
//! │                 │                                 │ real connection │
//! └─────────────────┘                                 └─────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! let mock = WindowsMockProvider::new();
//!
//! // Get a fake client connection
//! let mut client = mock.connect_mock_client().await;
//!
//! // The server will receive this when it calls accept()
//! client.write_all(b"hello").await.unwrap();
//! ```

use crate::net::{ConnectionListener, ConnectionStream, NetProvider};
use async_trait::async_trait;
use std::io;
use std::sync::Arc;
use tokio::io::DuplexStream;
use tokio::sync::Mutex;

/// Mock provider simulating Windows Named Pipe IPC.
///
/// Thread-safe and clonable - the same provider can be shared between
/// the server and test harness.
#[derive(Clone)]
pub struct WindowsMockProvider {
    /// Queue of "pending" connections that tests can populate.
    pending_connections: Arc<Mutex<Vec<DuplexStream>>>,
}

impl WindowsMockProvider {
    /// Creates a new mock provider with an empty connection queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_connections: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Creates a mock client connection.
    ///
    /// Returns the "client" end of a duplex stream. The "server" end is
    /// queued and will be returned by the next `accept()` call.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mock = WindowsMockProvider::new();
    /// let mut client = mock.connect_mock_client().await;
    ///
    /// // Send a command
    /// let cmd = ControlCommand::Ping;
    /// client.write_all(&cmd.to_json().unwrap()).await.unwrap();
    /// ```
    pub async fn connect_mock_client(&self) -> DuplexStream {
        // 4KB buffer should be enough for control messages
        let (client, server) = tokio::io::duplex(4096);
        self.pending_connections.lock().await.push(server);
        client
    }

    /// Returns the number of pending connections waiting to be accepted.
    pub async fn pending_count(&self) -> usize {
        self.pending_connections.lock().await.len()
    }
}

impl Default for WindowsMockProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock listener that returns connections from the provider's queue.
pub struct MockListener {
    pending: Arc<Mutex<Vec<DuplexStream>>>,
    addr: String,
}

#[async_trait]
impl ConnectionListener for MockListener {
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>> {
        // Poll the queue until a connection appears
        // In production, you might use a channel with proper blocking
        loop {
            {
                let mut guard = self.pending.lock().await;
                if let Some(stream) = guard.pop() {
                    tracing::debug!(addr = %self.addr, "(MOCK) Accepted connection");
                    return Ok(Box::new(stream));
                }
            }
            // Yield to allow other tasks to run and populate the queue
            tokio::task::yield_now().await;
        }
    }

    fn local_addr(&self) -> io::Result<String> {
        Ok(format!("mock://{}", self.addr))
    }
}

#[async_trait]
impl NetProvider for WindowsMockProvider {
    async fn bind_control_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        tracing::warn!(addr = %addr, "(MOCK) Binding virtual Windows Named Pipe");
        Ok(Box::new(MockListener {
            pending: self.pending_connections.clone(),
            addr: addr.to_string(),
        }))
    }

    async fn bind_data_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        tracing::warn!(addr = %addr, "(MOCK) Binding virtual data socket");
        Ok(Box::new(MockListener {
            pending: self.pending_connections.clone(),
            addr: addr.to_string(),
        }))
    }

    fn description(&self) -> &'static str {
        "WindowsMockProvider (in-memory simulation)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn mock_roundtrip() {
        let mock = WindowsMockProvider::new();

        // Spawn a "server" that accepts one connection
        let mock_clone = mock.clone();
        let server_handle = tokio::spawn(async move {
            let mut listener = mock_clone
                .bind_control_socket("test")
                .await
                .expect("bind");

            let mut stream = listener.accept().await.expect("accept");

            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello");

            stream.write_all(b"world").await.expect("write");
        });

        // Give the server a moment to start listening
        tokio::task::yield_now().await;

        // Connect a mock client
        let mut client = mock.connect_mock_client().await;
        client.write_all(b"hello").await.expect("write");

        let mut response = [0u8; 5];
        client.read_exact(&mut response).await.expect("read");
        assert_eq!(&response, b"world");

        server_handle.await.expect("server task");
    }
}
