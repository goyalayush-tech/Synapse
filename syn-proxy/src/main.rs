//! Entry point for the Synapse proxy daemon.

use anyhow::Result;
use syn_core::telemetry;
use syn_proxy::ProxyServer;

/// Main entry point.
///
/// Initializes telemetry, creates the proxy server with the appropriate
/// network provider, and enters the main event loop.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging first
    telemetry::init().map_err(|e| anyhow::anyhow!("Telemetry init failed: {e}"))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Initializing Synapse Proxy..."
    );

    // Instantiate the server with the appropriate network provider
    // Provider selection is based on feature flags and environment variables
    let server = ProxyServer::new();

    tracing::info!("Synapse Proxy starting event loop");

    // Enter the main event loop
    server.run().await?;

    tracing::info!("Synapse Proxy shutdown complete");
    Ok(())
}
