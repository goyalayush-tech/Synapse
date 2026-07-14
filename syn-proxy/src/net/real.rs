//! Real network provider using OS primitives.
//!
//! This module contains `#[cfg]`-guarded code that compiles only on
//! the target platform. A developer on Linux won't get Windows
//! compilation errors and vice versa.

use super::{ConnectionListener, ConnectionStream, NetProvider};
use async_trait::async_trait;
use std::io;

/// Network provider using actual OS networking primitives.
///
/// - **Windows**: Named Pipes via `tokio::net::windows::named_pipe`
/// - **Unix**: Unix Domain Sockets via `tokio::net::UnixListener`
pub struct RealNetProvider;

#[async_trait]
impl NetProvider for RealNetProvider {
    async fn bind_control_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        bind_control_impl(addr).await
    }

    async fn bind_data_socket(&self, addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
        // For now, data and control use the same mechanism
        // In production, data might use TCP or QUIC
        bind_control_impl(addr).await
    }

    fn description(&self) -> &'static str {
        if cfg!(windows) {
            "RealNetProvider (Windows Named Pipes)"
        } else if cfg!(unix) {
            "RealNetProvider (Unix Domain Sockets)"
        } else {
            "RealNetProvider (TCP fallback)"
        }
    }
}

// =============================================================================
// Windows Implementation
// =============================================================================

#[cfg(windows)]
async fn bind_control_impl(addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

    let pipe_name = format!(r"\\.\pipe\{}", addr);
    tracing::debug!(pipe = %pipe_name, "Binding Windows Named Pipe");

    // Create the first pipe instance
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .pipe_mode(PipeMode::Message)
        .create(&pipe_name)?;

    Ok(Box::new(WindowsPipeListener {
        pipe_name,
        current_server: Some(server),
    }))
}

#[cfg(windows)]
struct WindowsPipeListener {
    pipe_name: String,
    current_server: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

#[cfg(windows)]
#[async_trait]
impl ConnectionListener for WindowsPipeListener {
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>> {
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

        // Borrow (don't remove) the current server instance and wait for a
        // client to connect. `NamedPipeServer::connect` takes `&self`, so we
        // never need to take `current_server` out of the `Option` just to
        // await the connection.
        //
        // This matters for the documented cancel-safety contract
        // (`ConnectionListener::accept`, net/mod.rs): if this future is
        // dropped while the `.await` below is still pending (e.g. cancelled
        // by a `tokio::select!` elsewhere), or if `connect()` returns an
        // error, `self.current_server` still holds a valid, connectable pipe
        // instance for the next `accept()` call instead of being left `None`
        // forever.
        {
            let server = self
                .current_server
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Listener closed"))?;

            server.connect().await?;
        }

        // A client is now connected to the instance in `current_server`.
        // Create a fresh instance to listen for the *next* client and swap
        // it in, handing back the now-connected instance to the caller.
        // Only once the replacement instance is successfully created do we
        // remove the connected one from `current_server` - so a failure here
        // still leaves a connected (if unconsumed) instance in place rather
        // than losing pipe state.
        let new_server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .create(&self.pipe_name)?;

        let connected_server = self
            .current_server
            .replace(new_server)
            .expect("current_server was Some when accept() started and was not mutated since");

        Ok(Box::new(connected_server))
    }

    fn local_addr(&self) -> io::Result<String> {
        Ok(self.pipe_name.clone())
    }
}

// =============================================================================
// Unix Implementation
// =============================================================================

#[cfg(unix)]
async fn bind_control_impl(addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
    use tokio::net::UnixListener;

    let socket_path = format!("/tmp/{}.sock", addr);

    // Remove existing socket file if present
    let _ = std::fs::remove_file(&socket_path);

    tracing::debug!(path = %socket_path, "Binding Unix Domain Socket");

    let listener = UnixListener::bind(&socket_path)?;
    Ok(Box::new(UnixSocketListener {
        listener,
        path: socket_path,
    }))
}

#[cfg(unix)]
struct UnixSocketListener {
    listener: tokio::net::UnixListener,
    path: String,
}

#[cfg(unix)]
#[async_trait]
impl ConnectionListener for UnixSocketListener {
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Box::new(stream))
    }

    fn local_addr(&self) -> io::Result<String> {
        Ok(self.path.clone())
    }
}

#[cfg(unix)]
impl Drop for UnixSocketListener {
    fn drop(&mut self) {
        // Clean up the socket file
        let _ = std::fs::remove_file(&self.path);
    }
}

// =============================================================================
// Fallback for unsupported platforms
// =============================================================================

#[cfg(not(any(windows, unix)))]
async fn bind_control_impl(addr: &str) -> io::Result<Box<dyn ConnectionListener>> {
    // Fallback to TCP on localhost for unsupported platforms
    use tokio::net::TcpListener;

    let bind_addr = format!("127.0.0.1:{}", addr);
    tracing::warn!(
        addr = %bind_addr,
        "Platform lacks native IPC, falling back to TCP"
    );

    let listener = TcpListener::bind(&bind_addr).await?;
    Ok(Box::new(TcpFallbackListener { listener }))
}

#[cfg(not(any(windows, unix)))]
struct TcpFallbackListener {
    listener: tokio::net::TcpListener,
}

#[cfg(not(any(windows, unix)))]
#[async_trait]
impl ConnectionListener for TcpFallbackListener {
    async fn accept(&mut self) -> io::Result<Box<dyn ConnectionStream>> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(Box::new(stream))
    }

    fn local_addr(&self) -> io::Result<String> {
        self.listener.local_addr().map(|a| a.to_string())
    }
}
