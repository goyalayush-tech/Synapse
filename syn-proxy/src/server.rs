//! Proxy server implementation.
//!
//! The `ProxyServer` orchestrates the entire proxy lifecycle:
//! 1. Binds control and data sockets via `NetProvider`
//! 2. Accepts incoming connections
//! 3. Dispatches to appropriate handlers
//! 4. Manages graceful shutdown

use crate::net::{self, NetProvider};
use anyhow::{Context, Result};
use std::sync::Arc;
use syn_proto::{ControlCommand, ControlResponse, ProxyStatus};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, RwLock};

#[cfg(feature = "memory")]
use syn_memory::{Event, EventStore, InMemoryEventStore};

/// The Synapse proxy server.
///
/// Owns the network provider and manages connection lifecycle.
pub struct ProxyServer {
    provider: Box<dyn NetProvider>,
    state: Arc<RwLock<ServerState>>,
    #[cfg(feature = "memory")]
    event_store: Arc<RwLock<Box<dyn EventStore>>>,
}

/// Shared mutable state for the server.
struct ServerState {
    active_connections: u64,
    total_connections: u64,
    accepting: bool,
    start_time: std::time::Instant,
}

impl ProxyServer {
    /// Creates a new proxy server with the default network provider.
    ///
    /// Provider selection is based on:
    /// 1. `SYNAPSE_MOCK` environment variable
    /// 2. `mock-windows` feature flag
    /// 3. Default to real OS primitives
    #[must_use]
    pub fn new() -> Self {
        Self::with_provider(net::select_provider())
    }

    /// Creates a proxy server with a specific network provider.
    ///
    /// Useful for testing with mock providers.
    #[must_use]
    pub fn with_provider(provider: Box<dyn NetProvider>) -> Self {
        tracing::info!(provider = provider.description(), "Creating ProxyServer");
        Self {
            provider,
            state: Arc::new(RwLock::new(ServerState {
                active_connections: 0,
                total_connections: 0,
                accepting: true,
                start_time: std::time::Instant::now(),
            })),
            #[cfg(feature = "memory")]
            event_store: Arc::new(RwLock::new(Box::new(InMemoryEventStore::new()))),
        }
    }

    /// Emits an event to the event store (if enabled).
    #[cfg(feature = "memory")]
    async fn emit_event(&self, event_type: &str, payload: serde_json::Value) {
        let event = Event::new(0, event_type, payload);
        if let Err(e) = self.event_store.write().await.append(event).await {
            tracing::warn!(error = %e, "Failed to emit event");
        }
    }

    /// Runs the proxy server event loop.
    ///
    /// This method blocks until shutdown is requested via a control command
    /// or the process receives a termination signal.
    ///
    /// # Errors
    ///
    /// Returns an error if binding sockets fails.
    pub async fn run(&self) -> Result<()> {
        // Bind the control socket
        let mut control_listener = self
            .provider
            .bind_control_socket("synapse_ctl")
            .await
            .context("Failed to bind control socket")?;

        let control_addr = control_listener
            .local_addr()
            .unwrap_or_else(|_| "unknown".to_string());
        tracing::info!(addr = %control_addr, "Control plane listening");

        // Shutdown signal channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Accept loop
        loop {
            tokio::select! {
                // Accept new control connections
                result = control_listener.accept() => {
                    match result {
                        Ok(stream) => {
                            let state = self.state.clone();
                            let mut shutdown_rx = shutdown_tx.subscribe();
                            
                            // Update connection counters
                            let conn_id = {
                                let mut s = state.write().await;
                                s.active_connections += 1;
                                s.total_connections += 1;
                                s.total_connections
                            };
                            
                            tracing::debug!(conn_id, "Accepted control connection");
                            
                            // Emit connection event
                            #[cfg(feature = "memory")]
                            {
                                let server = self;
                                let event_payload = serde_json::json!({
                                    "connection_id": conn_id,
                                    "type": "control"
                                });
                                server.emit_event("connection.accepted", event_payload).await;
                            }
                            
                            // Handle the connection in a separate task
                            #[cfg(feature = "memory")]
                            let event_store_clone = Some(self.event_store.clone());
                            
                            tokio::spawn(async move {
                                #[cfg(feature = "memory")]
                                let result = handle_control_connection(
                                    stream, 
                                    state.clone(), 
                                    &mut shutdown_rx,
                                    event_store_clone,
                                ).await;
                                #[cfg(not(feature = "memory"))]
                                let result = handle_control_connection(
                                    stream, 
                                    state.clone(), 
                                    &mut shutdown_rx,
                                ).await;
                                
                                // Decrement active connections
                                state.write().await.active_connections -= 1;
                                
                                if let Err(e) = result {
                                    tracing::warn!(conn_id, error = %e, "Control connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Accept failed");
                        }
                    }
                }
                
                // Handle shutdown signal (Ctrl+C)
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal");
                    let _ = shutdown_tx.send(());
                    break;
                }
            }

            // Check if we should stop accepting
            if !self.state.read().await.accepting {
                tracing::info!("Server no longer accepting connections");
                break;
            }
        }

        // Graceful shutdown: wait for active connections to drain
        let drain_timeout = std::time::Duration::from_secs(30);
        let drain_start = std::time::Instant::now();

        while self.state.read().await.active_connections > 0 {
            if drain_start.elapsed() > drain_timeout {
                tracing::warn!("Drain timeout reached, forcing shutdown");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }
}

impl Default for ProxyServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Handles a single control connection.
async fn handle_control_connection(
    stream: Box<dyn crate::net::ConnectionStream>,
    state: Arc<RwLock<ServerState>>,
    shutdown_rx: &mut broadcast::Receiver<()>,
    #[cfg(feature = "memory")]
    event_store: Option<Arc<RwLock<Box<dyn EventStore>>>>,
) -> Result<()> {
    // Split into read/write halves
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();

        tokio::select! {
            // Read a command (newline-delimited JSON)
            result = reader.read_line(&mut line) => {
                let bytes_read = result.context("Read failed")?;
                if bytes_read == 0 {
                    // EOF - client disconnected
                    break;
                }

                // Parse and handle the command
                let response = match ControlCommand::from_json(line.trim().as_bytes()) {
                    Ok(cmd) => {
                        // Emit command event
                        #[cfg(feature = "memory")]
                        {
                            if let Some(ref store) = event_store {
                                let event = Event::new(
                                    0,
                                    "command.received",
                                    serde_json::json!({
                                        "command": format!("{:?}", cmd)
                                    }),
                                );
                                let _ = store.write().await.append(event).await;
                            }
                        }
                        
                        handle_command(cmd, &state).await
                    }
                    Err(e) => ControlResponse::Error {
                        message: format!("Invalid command: {e}"),
                    },
                };

                // Send response
                let mut response_bytes = response.to_json().context("Serialize response")?;
                response_bytes.push(b'\n');
                writer.write_all(&response_bytes).await.context("Write response")?;
                writer.flush().await?;

                // If shutdown was requested, signal and exit
                if matches!(response, ControlResponse::Ok) && line.contains("shutdown") {
                    state.write().await.accepting = false;
                    break;
                }
            }

            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                tracing::debug!("Connection received shutdown signal");
                break;
            }
        }
    }

    Ok(())
}

/// Processes a control command and returns the appropriate response.
async fn handle_command(cmd: ControlCommand, state: &RwLock<ServerState>) -> ControlResponse {
    tracing::debug!(?cmd, "Processing control command");

    match cmd {
        ControlCommand::Ping => ControlResponse::Pong,

        ControlCommand::GetStatus => {
            let s = state.read().await;
            ControlResponse::Status(ProxyStatus {
                uptime_secs: s.start_time.elapsed().as_secs(),
                active_connections: s.active_connections,
                total_connections: s.total_connections,
                accepting: s.accepting,
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
        }

        ControlCommand::Reload => {
            tracing::info!("Configuration reload requested");
            // TODO: Implement actual config reload
            ControlResponse::Ok
        }

        ControlCommand::Shutdown => {
            tracing::info!("Graceful shutdown requested");
            state.write().await.accepting = false;
            ControlResponse::Ok
        }

        ControlCommand::GetMetrics => {
            // TODO: Implement Prometheus metrics
            ControlResponse::Error {
                message: "Metrics not implemented yet".to_string(),
            }
        }
    }
}
