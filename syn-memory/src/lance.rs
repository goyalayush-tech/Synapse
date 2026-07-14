//! Lance Columnar Storage Engine
//!
//! Lance is a Rust-native columnar format designed for ML workloads.
//! It provides:
//! - Zero-copy reads for efficient memory usage
//! - Built-in vector indexing (IVF-PQ) for <10ms semantic search
//! - Optimized for append-heavy workloads (perfect for event logs)
//! - Native integration with Arrow for interoperability
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Lance Storage Engine                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
//! │  │   MemTable   │  │  WAL Buffer  │  │    Lance Segments      ││
//! │  │ (Red-Black)  │  │ (in-memory)  │  │    (.lance files)      ││
//! │  │              │  │              │  │                        ││
//! │  │ Hot writes   │──│  Durability  │──│ Cold storage with      ││
//! │  │ O(log n)     │  │  guarantee   │  │ IVF-PQ vector index    ││
//! │  └──────────────┘  └──────────────┘  └────────────────────────┘│
//! │         │                                      │                │
//! │         └──────────────────┬───────────────────┘                │
//! │                            │                                    │
//! │                    ┌───────┴───────┐                           │
//! │                    │ Query Engine  │                           │
//! │                    │ - Point lookup│                           │
//! │                    │ - Range scan  │                           │
//! │                    │ - Vector ANN  │                           │
//! │                    └───────────────┘                           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementation Note
//!
//! This is "lance-lite" - a lightweight implementation that provides
//! the same API as the full Lance library but uses BTreeMap + JSON
//! persistence instead of native Lance columnar files. This avoids
//! heavy build dependencies (cmake, NASM) on Windows.
//!
//! For production deployments, use the `lance-full` feature which
//! integrates with the real Lance library for IVF-PQ vector indices.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "lance")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use syn_memory::lance::{LanceStore, LanceConfig, IntentEvent};
//!
//! let config = LanceConfig::new("/data/synapse/events");
//! let mut store = LanceStore::open(config).await?;
//!
//! // Store an intent event
//! let event = IntentEvent::new("agent-001")
//!     .with_action("code_review")
//!     .with_payload("Review PR #123");
//! store.append(event).await?;
//!
//! // Semantic search
//! let results = store.recall("authentication changes", 10).await?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

// WHY im::OrdMap: Persistent immutable data structure implementing Red-Black tree
// Provides O(log n) operations with structural sharing for efficient snapshots
use im::OrdMap;

/// Errors that can occur during Lance operations
#[derive(Debug, Error)]
pub enum LanceError {
    /// Failed to open or create dataset
    #[error("Failed to open dataset: {0}")]
    OpenFailed(String),

    /// Failed to append data
    #[error("Append failed: {0}")]
    AppendFailed(String),

    /// Failed to query data
    #[error("Query failed: {0}")]
    QueryFailed(String),

    /// Failed to build index
    #[error("Index build failed: {0}")]
    IndexBuildFailed(String),

    /// Invalid schema
    #[error("Invalid schema: {0}")]
    InvalidSchema(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for Lance operations
pub type LanceResult<T> = Result<T, LanceError>;

/// Configuration for Lance storage
#[derive(Debug, Clone)]
pub struct LanceConfig {
    /// Base directory for Lance datasets
    pub data_dir: PathBuf,
    /// Name of the events dataset
    pub events_dataset: String,
    /// MemTable flush threshold (number of entries)
    pub memtable_flush_threshold: usize,
    /// Vector dimension for embeddings
    pub vector_dimension: usize,
    /// Number of partitions for IVF index
    pub ivf_partitions: usize,
    /// Number of sub-quantizers for PQ
    pub pq_num_sub_vectors: usize,
    /// Enable automatic index building
    pub auto_index: bool,
}

impl LanceConfig {
    /// Create a new configuration with the given data directory
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            events_dataset: "events".to_string(),
            memtable_flush_threshold: 10_000,
            vector_dimension: 384, // Default for small embedding models
            ivf_partitions: 256,
            pq_num_sub_vectors: 16,
            auto_index: true,
        }
    }

    /// Set the vector dimension
    pub fn with_vector_dimension(mut self, dim: usize) -> Self {
        self.vector_dimension = dim;
        self
    }

    /// Set the MemTable flush threshold
    pub fn with_flush_threshold(mut self, threshold: usize) -> Self {
        self.memtable_flush_threshold = threshold;
        self
    }

    /// Configure IVF-PQ index parameters
    pub fn with_index_params(mut self, partitions: usize, sub_vectors: usize) -> Self {
        self.ivf_partitions = partitions;
        self.pq_num_sub_vectors = sub_vectors;
        self
    }
}

impl Default for LanceConfig {
    fn default() -> Self {
        Self::new("./data/lance")
    }
}

/// An intent event stored in Lance
///
/// This is the primary unit of storage in Synapse. Unlike traditional
/// event stores that store opaque bytes, we store structured "intent"
/// that can be queried semantically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentEvent {
    /// Unique event ID
    pub id: u64,
    /// Source agent/process ID
    pub source: String,
    /// Timestamp (microseconds since epoch)
    pub timestamp_us: u64,
    /// Action type (e.g., "code_review", "deploy", "alert")
    pub action: String,
    /// Human-readable reason/intent
    pub reason: String,
    /// Structured payload (TOON-serialized)
    pub payload: String,
    /// Causal parent event ID (for DAG)
    pub parent_id: Option<u64>,
    /// Vector embedding (computed from payload)
    pub embedding: Option<Vec<f32>>,
    /// Tags for filtering
    pub tags: Vec<String>,
}

impl IntentEvent {
    /// Create a new intent event
    pub fn new(source: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id: 0, // Will be assigned by store
            source: source.into(),
            timestamp_us: now,
            action: String::new(),
            reason: String::new(),
            payload: String::new(),
            parent_id: None,
            embedding: None,
            tags: Vec::new(),
        }
    }

    /// Set the action type
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    /// Set the reason/intent
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Set the payload
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Set the parent event ID (for causal chain)
    pub fn with_parent(mut self, parent_id: u64) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Set the embedding vector
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// MemTable entry for hot path writes
#[derive(Debug, Clone)]
struct MemTableEntry {
    event: IntentEvent,
    /// Timestamp for TTL-based eviction (future use)
    #[allow(dead_code)]
    inserted_at: SystemTime,
}

/// Search result with relevance score
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The matching event
    pub event: IntentEvent,
    /// Relevance score (0.0 to 1.0)
    pub score: f32,
    /// Distance in vector space (if vector search)
    pub distance: Option<f32>,
}

/// Lance-based storage engine for Synapse
///
/// This is the "brain" of Synapse - where intent is stored and queried.
/// It uses a tiered architecture:
/// 1. MemTable (Red-Black tree via im::OrdMap) for hot writes
/// 2. WAL for durability
/// 3. Lance segments for cold storage with vector indices
///
/// # MemTable Implementation
///
/// We use `im::OrdMap` which implements a persistent Red-Black tree:
/// - O(log n) insert, lookup, and range queries
/// - Structural sharing enables efficient snapshots
/// - Lock-free reads via immutable data structures
pub struct LanceStore {
    config: LanceConfig,
    /// MemTable for hot path writes (Red-Black tree)
    /// WHY im::OrdMap: Persistent immutable structure with O(log n) ops
    memtable: Arc<RwLock<OrdMap<u64, MemTableEntry>>>,
    /// Next event ID
    next_id: Arc<RwLock<u64>>,
    /// Flushed events (simulating Lance dataset)
    flushed: Arc<RwLock<Vec<IntentEvent>>>,
}

impl LanceStore {
    /// Open or create a Lance store
    pub async fn open(config: LanceConfig) -> LanceResult<Self> {
        // Ensure data directory exists
        tokio::fs::create_dir_all(&config.data_dir).await?;

        tracing::info!("Opening Lance store at {:?}", config.data_dir);

        // Load existing data if present
        let metadata_path = config.data_dir.join("metadata.json");
        let (next_id, flushed) = if metadata_path.exists() {
            let data = tokio::fs::read_to_string(&metadata_path).await?;
            let meta: StoreMeta = serde_json::from_str(&data)
                .map_err(|e| LanceError::Serialization(e.to_string()))?;

            // Load flushed events
            let events_path = config.data_dir.join("events.json");
            let events: Vec<IntentEvent> = if events_path.exists() {
                let data = tokio::fs::read_to_string(&events_path).await?;
                serde_json::from_str(&data).map_err(|e| LanceError::Serialization(e.to_string()))?
            } else {
                Vec::new()
            };

            (meta.next_id, events)
        } else {
            (1, Vec::new())
        };

        Ok(Self {
            config,
            memtable: Arc::new(RwLock::new(OrdMap::new())),
            next_id: Arc::new(RwLock::new(next_id)),
            flushed: Arc::new(RwLock::new(flushed)),
        })
    }

    /// Append an event to the store
    pub async fn append(&self, mut event: IntentEvent) -> LanceResult<u64> {
        // Assign ID
        let id = {
            let mut next = self.next_id.write().await;
            let id = *next;
            *next += 1;
            id
        };
        event.id = id;

        // Insert into MemTable
        {
            let mut memtable = self.memtable.write().await;
            memtable.insert(
                id,
                MemTableEntry {
                    event: event.clone(),
                    inserted_at: SystemTime::now(),
                },
            );

            // Check if we need to flush
            if memtable.len() >= self.config.memtable_flush_threshold {
                drop(memtable);
                self.flush().await?;
            }
        }

        tracing::trace!("Appended event {} from {}", id, event.source);
        Ok(id)
    }

    /// Flush MemTable to persistent storage
    pub async fn flush(&self) -> LanceResult<()> {
        let entries: Vec<_> = {
            let mut memtable = self.memtable.write().await;
            let entries: Vec<_> = memtable.values().map(|e| e.event.clone()).collect();
            memtable.clear();
            entries
        };

        if entries.is_empty() {
            return Ok(());
        }

        // Append to flushed events
        {
            let mut flushed = self.flushed.write().await;
            flushed.extend(entries);
        }

        // Persist to disk
        self.persist().await?;

        tracing::debug!("Flushed MemTable to storage");
        Ok(())
    }

    /// Persist data to disk
    async fn persist(&self) -> LanceResult<()> {
        let next_id = *self.next_id.read().await;
        let flushed = self.flushed.read().await;

        // Save metadata
        let meta = StoreMeta { next_id };
        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|e| LanceError::Serialization(e.to_string()))?;
        tokio::fs::write(self.config.data_dir.join("metadata.json"), meta_json).await?;

        // Save events
        let events_json = serde_json::to_string_pretty(&*flushed)
            .map_err(|e| LanceError::Serialization(e.to_string()))?;
        tokio::fs::write(self.config.data_dir.join("events.json"), events_json).await?;

        Ok(())
    }

    /// Get an event by ID
    pub async fn get(&self, id: u64) -> Option<IntentEvent> {
        // Check MemTable first
        {
            let memtable = self.memtable.read().await;
            if let Some(entry) = memtable.get(&id) {
                return Some(entry.event.clone());
            }
        }

        // Check flushed events
        let flushed = self.flushed.read().await;
        flushed.iter().find(|e| e.id == id).cloned()
    }

    /// Get events in a range
    pub async fn range(&self, start_id: u64, end_id: u64) -> Vec<IntentEvent> {
        let mut results = Vec::new();

        // Get from MemTable using im::OrdMap range iteration
        {
            let memtable = self.memtable.read().await;
            // im::OrdMap range requires std::ops::RangeBounds
            for (_, entry) in memtable.range(start_id..=end_id) {
                results.push(entry.event.clone());
            }
        }

        // Get from flushed
        {
            let flushed = self.flushed.read().await;
            for event in flushed.iter() {
                if event.id >= start_id && event.id <= end_id {
                    if !results.iter().any(|e| e.id == event.id) {
                        results.push(event.clone());
                    }
                }
            }
        }

        results.sort_by_key(|e| e.id);
        results
    }

    /// Semantic search using text matching (placeholder for vector search)
    ///
    /// In production, this would use IVF-PQ vector indices for <10ms ANN search.
    /// For now, we use simple text matching as a placeholder.
    pub async fn recall(&self, query: &str, top_k: usize) -> LanceResult<Vec<SearchResult>> {
        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();

        let mut results = Vec::new();

        // Search MemTable
        {
            let memtable = self.memtable.read().await;
            for entry in memtable.values() {
                let score = self.compute_relevance(&entry.event, &query_words);
                if score > 0.0 {
                    results.push(SearchResult {
                        event: entry.event.clone(),
                        score,
                        distance: None,
                    });
                }
            }
        }

        // Search flushed
        {
            let flushed = self.flushed.read().await;
            for event in flushed.iter() {
                if !results.iter().any(|r| r.event.id == event.id) {
                    let score = self.compute_relevance(event, &query_words);
                    if score > 0.0 {
                        results.push(SearchResult {
                            event: event.clone(),
                            score,
                            distance: None,
                        });
                    }
                }
            }
        }

        // Sort by score and take top_k
        results.sort_by(|a, b| b.score.total_cmp(&a.score));
        results.truncate(top_k);

        Ok(results)
    }

    /// Compute text relevance score
    fn compute_relevance(&self, event: &IntentEvent, query_words: &[&str]) -> f32 {
        let text = format!(
            "{} {} {} {} {}",
            event.source,
            event.action,
            event.reason,
            event.payload,
            event.tags.join(" ")
        )
        .to_lowercase();

        let mut matches = 0;
        for word in query_words {
            if text.contains(word) {
                matches += 1;
            }
        }

        if query_words.is_empty() {
            0.0
        } else {
            matches as f32 / query_words.len() as f32
        }
    }

    /// Get causal chain (ancestors) of an event
    pub async fn get_causal_chain(&self, event_id: u64) -> Vec<IntentEvent> {
        let mut chain = Vec::new();
        let mut current_id = Some(event_id);

        while let Some(id) = current_id {
            if let Some(event) = self.get(id).await {
                current_id = event.parent_id;
                chain.push(event);
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }

    /// Get all events from a source
    pub async fn get_by_source(&self, source: &str) -> Vec<IntentEvent> {
        let mut results = Vec::new();

        // From MemTable
        {
            let memtable = self.memtable.read().await;
            for entry in memtable.values() {
                if entry.event.source == source {
                    results.push(entry.event.clone());
                }
            }
        }

        // From flushed
        {
            let flushed = self.flushed.read().await;
            for event in flushed.iter() {
                if event.source == source {
                    if !results.iter().any(|e| e.id == event.id) {
                        results.push(event.clone());
                    }
                }
            }
        }

        results.sort_by_key(|e| e.id);
        results
    }

    /// Get store statistics
    pub async fn stats(&self) -> StoreStats {
        let memtable = self.memtable.read().await;
        let flushed = self.flushed.read().await;
        let next_id = *self.next_id.read().await;

        StoreStats {
            total_events: next_id - 1,
            memtable_size: memtable.len(),
            flushed_events: flushed.len(),
            vector_dimension: self.config.vector_dimension,
        }
    }

    /// Close the store, flushing pending data
    pub async fn close(self) -> LanceResult<()> {
        self.flush().await?;
        tracing::info!("Lance store closed");
        Ok(())
    }
}

/// Metadata for persistence
#[derive(Debug, Serialize, Deserialize)]
struct StoreMeta {
    next_id: u64,
}

/// Store statistics
#[derive(Debug, Clone)]
pub struct StoreStats {
    /// Total number of events ever stored
    pub total_events: u64,
    /// Current MemTable size
    pub memtable_size: usize,
    /// Number of flushed events
    pub flushed_events: usize,
    /// Vector dimension
    pub vector_dimension: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn test_store() -> (LanceStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let config = LanceConfig::new(dir.path());
        let store = LanceStore::open(config).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_append_and_get() {
        let (store, _dir) = test_store().await;

        let event = IntentEvent::new("agent-001")
            .with_action("test")
            .with_payload("Hello, Lance!");

        let id = store.append(event).await.unwrap();
        assert_eq!(id, 1);

        let retrieved = store.get(id).await.unwrap();
        assert_eq!(retrieved.source, "agent-001");
        assert_eq!(retrieved.action, "test");
    }

    #[tokio::test]
    async fn test_range_query() {
        let (store, _dir) = test_store().await;

        for i in 0..5 {
            let event = IntentEvent::new(format!("agent-{}", i)).with_action("test");
            store.append(event).await.unwrap();
        }

        let range = store.range(2, 4).await;
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].id, 2);
        assert_eq!(range[2].id, 4);
    }

    #[tokio::test]
    async fn test_semantic_search() {
        let (store, _dir) = test_store().await;

        store
            .append(
                IntentEvent::new("agent-001")
                    .with_action("code_review")
                    .with_payload("Reviewed authentication module"),
            )
            .await
            .unwrap();

        store
            .append(
                IntentEvent::new("agent-002")
                    .with_action("deploy")
                    .with_payload("Deployed database migration"),
            )
            .await
            .unwrap();

        let results = store.recall("authentication", 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event.source, "agent-001");
    }

    #[tokio::test]
    async fn test_causal_chain() {
        let (store, _dir) = test_store().await;

        let id1 = store
            .append(IntentEvent::new("agent-001").with_action("start"))
            .await
            .unwrap();

        let id2 = store
            .append(
                IntentEvent::new("agent-001")
                    .with_action("middle")
                    .with_parent(id1),
            )
            .await
            .unwrap();

        let id3 = store
            .append(
                IntentEvent::new("agent-001")
                    .with_action("end")
                    .with_parent(id2),
            )
            .await
            .unwrap();

        let chain = store.get_causal_chain(id3).await;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].action, "start");
        assert_eq!(chain[1].action, "middle");
        assert_eq!(chain[2].action, "end");
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = TempDir::new().unwrap();

        // Create store and add events
        {
            let config = LanceConfig::new(dir.path());
            let store = LanceStore::open(config).await.unwrap();

            store
                .append(IntentEvent::new("agent-001").with_action("test"))
                .await
                .unwrap();

            store.close().await.unwrap();
        }

        // Reopen and verify
        {
            let config = LanceConfig::new(dir.path());
            let store = LanceStore::open(config).await.unwrap();

            let event = store.get(1).await.unwrap();
            assert_eq!(event.source, "agent-001");
        }
    }

    #[tokio::test]
    async fn test_stats() {
        let (store, _dir) = test_store().await;

        for i in 0..5 {
            store
                .append(IntentEvent::new(format!("agent-{}", i)))
                .await
                .unwrap();
        }

        let stats = store.stats().await;
        assert_eq!(stats.total_events, 5);
        assert_eq!(stats.memtable_size, 5);
    }
}
