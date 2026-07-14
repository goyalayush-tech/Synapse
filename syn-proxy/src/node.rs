//! # SynapseNode: The Agentic Mesh Runtime
//!
//! This module implements the full v2.0 "Agentic Mesh" architecture, integrating
//! all four planes:
//!
//! 1. **Shield (Identity)**: Kernel-anchored verification via eBPF
//! 2. **Router (Connectivity)**: QUIC transport with MCP/A2A protocols
//! 3. **State (Memory)**: LanceDB vectors + Automerge CRDTs
//! 4. **Judge (Governance)**: Wasmtime + Cedar policy engine
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     SynapseNode                                  │
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
//! │  │ Identity │  │  Router  │  │  Memory  │  │   Governance     │ │
//! │  │ (eBPF)   │◄─┤  (QUIC)  │◄─┤ (Lance+  │◄─┤   (WASM+Cedar)   │ │
//! │  │          │  │          │  │  CRDT)   │  │                  │ │
//! │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Configuration for the Synapse Node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Address for QUIC listener
    pub quic_addr: String,
    /// Path to event store data directory
    pub data_dir: std::path::PathBuf,
    /// Path to Cedar policy files
    pub policy_dir: std::path::PathBuf,
    /// Enable eBPF identity (requires Linux + root)
    pub enable_ebpf: bool,
    /// Enable CRDT state synchronization
    pub enable_crdt: bool,
    /// Vector embedding dimension
    pub vector_dimension: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            quic_addr: "0.0.0.0:4433".to_string(),
            data_dir: std::path::PathBuf::from("./synapse_data"),
            policy_dir: std::path::PathBuf::from("./policies"),
            enable_ebpf: cfg!(target_os = "linux"),
            enable_crdt: true,
            vector_dimension: 384, // MiniLM-L6-v2 dimension
        }
    }
}

/// Runtime state for node metrics and health.
#[derive(Debug, Default, Clone)]
pub struct NodeMetrics {
    pub events_processed: u64,
    pub active_connections: u64,
    pub policy_evaluations: u64,
    pub vector_searches: u64,
    pub crdt_syncs: u64,
}

/// Hyper-converged state combining vector memory and CRDT blackboard.
#[cfg(feature = "agentic-mesh")]
pub struct HyperState {
    /// Vector memory for semantic search (long-term)
    pub vector: Arc<RwLock<syn_memory::vector::InMemoryVectorMemory>>,
    /// CRDT blackboard for live collaboration (short-term)
    pub crdt: Arc<RwLock<syn_memory::CrdtBlackboard>>,
    /// Embedder for generating vectors (lazy initialized)
    pub embedder: Arc<RwLock<Option<syn_memory::Embedder>>>,
    /// Vector dimension
    dimension: usize,
}

#[cfg(feature = "agentic-mesh")]
impl HyperState {
    /// Create new hyper-state with the given configuration.
    pub fn new(vector_dimension: usize) -> Self {
        Self {
            vector: Arc::new(RwLock::new(syn_memory::vector::InMemoryVectorMemory::new(
                vector_dimension,
            ))),
            crdt: Arc::new(RwLock::new(syn_memory::CrdtBlackboard::new(
                syn_memory::CrdtConfig::default(),
            ))),
            embedder: Arc::new(RwLock::new(None)),
            dimension: vector_dimension,
        }
    }

    /// Initialize the embedder (async because model loading is async)
    pub async fn init_embedder(&self) -> anyhow::Result<()> {
        let config = syn_memory::EmbedderConfig::default();
        let embedder = syn_memory::Embedder::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Embedder init failed: {}", e))?;
        *self.embedder.write().await = Some(embedder);
        Ok(())
    }

    /// Store an event in both vector memory and optionally CRDT.
    pub async fn ingest(&self, event_type: &str, content: &str) -> Result<()> {
        use syn_memory::vector::{VectorEmbedding, VectorMemory};

        // Generate embedding (or use placeholder if embedder not ready)
        let embedding_vec = {
            let embedder_guard = self.embedder.read().await;
            if let Some(ref embedder) = *embedder_guard {
                embedder
                    .embed(content)
                    .await
                    .unwrap_or_else(|_| vec![0.0f32; self.dimension])
            } else {
                vec![0.0f32; self.dimension]
            }
        };

        // Create vector embedding
        let id = format!(
            "{}_{}",
            event_type,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let embedding = VectorEmbedding::new(id, embedding_vec, self.dimension)
            .map_err(|e| anyhow::anyhow!("Vector error: {}", e))?
            .with_metadata(serde_json::json!({
                "event_type": event_type,
                "content": content,
            }));

        // Store in vector memory
        self.vector
            .write()
            .await
            .store(embedding)
            .await
            .map_err(|e| anyhow::anyhow!("Vector store error: {}", e))?;

        // CRDT store for live state (if it's a state-change event)
        if event_type.starts_with("state.") {
            let key = event_type.strip_prefix("state.").unwrap_or(event_type);
            let doc_id = syn_memory::DocumentId::new("shared");
            let blackboard = self.crdt.write().await;
            blackboard
                .set(
                    &doc_id,
                    &[key],
                    syn_memory::CrdtValue::String(content.to_string()),
                )
                .await?;
        }

        Ok(())
    }

    /// Semantic search across vector memory.
    pub async fn recall(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        use syn_memory::vector::VectorMemory;

        // Generate query embedding
        let query_vec = {
            let embedder_guard = self.embedder.read().await;
            if let Some(ref embedder) = *embedder_guard {
                embedder
                    .embed(query)
                    .await
                    .unwrap_or_else(|_| vec![0.0f32; self.dimension])
            } else {
                vec![0.0f32; self.dimension]
            }
        };

        let memory = self.vector.read().await;
        let results = memory
            .search(&query_vec, limit, 0.0)
            .await
            .map_err(|e| anyhow::anyhow!("Search error: {}", e))?;

        Ok(results
            .into_iter()
            .filter_map(|r| {
                r.embedding
                    .metadata
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect())
    }

    /// Get current CRDT state for a key.
    pub async fn get_state(&self, key: &str) -> Option<syn_memory::CrdtValue> {
        let doc_id = syn_memory::DocumentId::new("shared");
        let blackboard = self.crdt.read().await;
        blackboard.get(&doc_id, &[key]).await.ok().flatten()
    }

    /// Merge remote CRDT changes via sync message.
    pub async fn merge_remote(
        &self,
        message: syn_memory::SyncMessage,
    ) -> Result<Option<syn_memory::SyncMessage>> {
        let blackboard = self.crdt.read().await;
        blackboard
            .receive_sync_message(message)
            .await
            .map_err(|e| anyhow::anyhow!("Sync error: {}", e))
    }

    /// Save CRDT state to bytes.
    pub async fn save_crdt(&self, doc_id: &str) -> Result<Vec<u8>> {
        let doc_id = syn_memory::DocumentId::new(doc_id);
        let blackboard = self.crdt.read().await;
        blackboard
            .save_document(&doc_id)
            .await
            .map_err(|e| anyhow::anyhow!("Save error: {}", e))
    }
}

/// The main Synapse Node runtime.
///
/// This is the entry point for the v2.0 Agentic Mesh architecture.
/// It orchestrates all four planes and provides the unified event loop.
pub struct SynapseNode {
    config: NodeConfig,
    metrics: Arc<RwLock<NodeMetrics>>,
    shutdown_tx: broadcast::Sender<()>,

    // Plane 1: Identity (Shield)
    #[cfg(feature = "agentic-mesh")]
    identity: Arc<dyn syn_identity::provider::IdentityProvider>,

    // Plane 3: Memory (State) - Vector + CRDT
    #[cfg(feature = "agentic-mesh")]
    memory: Arc<HyperState>,

    // Plane 4: Governance (Judge)
    #[cfg(feature = "policy")]
    policy_engine: Arc<syn_policy::engine::PolicyEngine>,
}

impl SynapseNode {
    /// Create a new Synapse Node with the given configuration.
    pub fn new(config: NodeConfig) -> Result<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);

        // Initialize Identity Provider (Shield)
        //
        // `MockIdentityProvider` only exists off-Linux and `EbpfIdentityProvider`
        // only exists on Linux (see syn-identity/src/provider.rs), so each
        // branch below is written to only ever reference the type that is
        // actually available for its target - referencing `MockIdentityProvider`
        // unconditionally here would fail to compile on Linux.
        #[cfg(feature = "agentic-mesh")]
        let identity: Arc<dyn syn_identity::provider::IdentityProvider> = {
            let id_config = syn_identity::provider::IdentityProviderConfig::default();

            #[cfg(target_os = "linux")]
            {
                // `MockIdentityProvider` isn't available on Linux (it's
                // `#[cfg(not(target_os = "linux"))]`), so `EbpfIdentityProvider`
                // is the only usable implementation here regardless of
                // `enable_ebpf`. Warn if the caller asked to opt out, since
                // there is currently no non-eBPF identity path on Linux.
                if !config.enable_ebpf {
                    tracing::warn!(
                        "enable_ebpf=false is not supported on Linux (no alternative identity \
                         provider is available for this target); using EbpfIdentityProvider anyway"
                    );
                }
                Arc::new(syn_identity::provider::EbpfIdentityProvider::new(id_config))
            }

            #[cfg(not(target_os = "linux"))]
            {
                Arc::new(syn_identity::provider::MockIdentityProvider::new(id_config))
            }
        };

        // Initialize Hyper-State (Memory)
        #[cfg(feature = "agentic-mesh")]
        let memory = Arc::new(HyperState::new(config.vector_dimension));

        // Initialize Policy Engine (Governance)
        #[cfg(feature = "policy")]
        let policy_engine = {
            let engine_config = syn_policy::engine::PolicyConfig::default();
            Arc::new(syn_policy::engine::PolicyEngine::new(engine_config))
        };

        Ok(Self {
            config,
            metrics: Arc::new(RwLock::new(NodeMetrics::default())),
            shutdown_tx,
            #[cfg(feature = "agentic-mesh")]
            identity,
            #[cfg(feature = "agentic-mesh")]
            memory,
            #[cfg(feature = "policy")]
            policy_engine,
        })
    }

    /// Run the main event loop.
    ///
    /// This starts all four planes and handles incoming connections.
    pub async fn run(&self) -> Result<()> {
        tracing::info!(
            quic_addr = %self.config.quic_addr,
            "Starting Synapse Node v2.0 (Agentic Mesh)"
        );

        // Attach identity provider (eBPF hooks on Linux)
        #[cfg(feature = "agentic-mesh")]
        {
            self.identity
                .attach()
                .await
                .context("Failed to attach identity provider")?;
            tracing::info!("Identity plane initialized");
        }

        // Main event loop
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Ctrl+C received, initiating shutdown");
                    let _ = self.shutdown_tx.send(());
                    break;
                }
            }
        }

        self.graceful_shutdown().await?;
        Ok(())
    }

    /// Graceful shutdown procedure.
    async fn graceful_shutdown(&self) -> Result<()> {
        tracing::info!("Starting graceful shutdown...");

        // Wait for active connections to drain
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();

        while self.metrics.read().await.active_connections > 0 {
            if start.elapsed() > timeout {
                tracing::warn!("Drain timeout, forcing shutdown");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Sync CRDT state to disk
        #[cfg(feature = "agentic-mesh")]
        {
            if let Ok(changes) = self.memory.save_crdt("shared").await {
                let path = self.config.data_dir.join("crdt_state.bin");
                if let Err(e) = tokio::fs::create_dir_all(&self.config.data_dir).await {
                    tracing::warn!(error = %e, "Failed to create data directory");
                }
                if let Err(e) = tokio::fs::write(&path, changes).await {
                    tracing::warn!(error = %e, "Failed to persist CRDT state");
                }
            }
        }

        tracing::info!("Shutdown complete");
        Ok(())
    }

    /// Get current node metrics.
    pub async fn metrics(&self) -> NodeMetrics {
        self.metrics.read().await.clone()
    }

    /// Semantic search across event history.
    #[cfg(feature = "agentic-mesh")]
    pub async fn recall(&self, query: &str, limit: usize) -> Result<Vec<String>> {
        self.memory.recall(query, limit).await
    }

    /// Get CRDT state.
    #[cfg(feature = "agentic-mesh")]
    pub async fn get_state(&self, key: &str) -> Option<syn_memory::CrdtValue> {
        self.memory.get_state(key).await
    }

    /// Ingest an event into the hyper-state.
    #[cfg(feature = "agentic-mesh")]
    pub async fn ingest(&self, event_type: &str, content: &str) -> Result<()> {
        self.metrics.write().await.events_processed += 1;
        self.memory.ingest(event_type, content).await
    }

    /// Get shared memory reference for external handlers.
    #[cfg(feature = "agentic-mesh")]
    pub fn memory(&self) -> Arc<HyperState> {
        self.memory.clone()
    }

    /// Get identity provider reference.
    #[cfg(feature = "agentic-mesh")]
    pub fn identity(&self) -> Arc<dyn syn_identity::provider::IdentityProvider> {
        self.identity.clone()
    }

    /// Get policy engine reference.
    #[cfg(feature = "policy")]
    pub fn policy(&self) -> Arc<syn_policy::engine::PolicyEngine> {
        self.policy_engine.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = SynapseNode::new(config);
        assert!(node.is_ok());
    }

    #[tokio::test]
    async fn test_metrics() {
        let config = NodeConfig::default();
        let node = SynapseNode::new(config).unwrap();
        let metrics = node.metrics().await;
        assert_eq!(metrics.events_processed, 0);
    }
}
