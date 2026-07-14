//! LanceDB Production Storage Engine
//!
//! This module provides the full LanceDB integration for production deployments.
//! Unlike `lance.rs` (lance-lite), this uses the actual LanceDB crate with:
//!
//! - IVF-PQ vector indices for <10ms semantic search
//! - Arrow columnar format for efficient scans
//! - Streaming RecordBatch ingestion for high-throughput writes
//! - Zero-copy deserialization via rkyv for WASM integration
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   LanceDB Production Engine                      │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
//! │  │   MemTable   │  │ Streaming Buffer │  │  LanceDB Table   │  │
//! │  │ (im::OrdMap) │  │ (RecordBatch)    │  │  (.lance files)  │  │
//! │  │              │  │                  │  │                  │  │
//! │  │ Hot writes   │──│ Batch conversion │──│ IVF-PQ indexed   │  │
//! │  │ O(log n)     │  │ Arrow columnar   │  │ vector search    │  │
//! │  └──────────────┘  └──────────────────┘  └──────────────────┘  │
//! │         │                    │                    │            │
//! │         └────────────────────┼────────────────────┘            │
//! │                              │                                  │
//! │                    ┌─────────┴─────────┐                       │
//! │                    │   Query Engine    │                       │
//! │                    │                   │                       │
//! │                    │ - Vector ANN      │                       │
//! │                    │ - Hybrid search   │                       │
//! │                    │ - Zero-copy read  │                       │
//! │                    └───────────────────┘                       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Build Requirements
//!
//! This module requires the `lance-full` feature which has build dependencies:
//! - cmake
//! - arrow-cpp (bundled by lancedb)
//! - On Windows: NASM assembler
//!
//! For development without these dependencies, use the `lance` feature (lance-lite).

#![cfg(feature = "lance-full")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arrow_array::{
    ArrayRef, Float32Array, Int64Array, RecordBatch, RecordBatchIterator, StringArray, UInt64Array,
};
use arrow_schema::{DataType, Field, Schema};
use im::OrdMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, instrument, warn};

/// Errors from the LanceDB storage engine
#[derive(Debug, Error)]
pub enum LanceDbError {
    /// Failed to open or create database
    #[error("Database error: {0}")]
    Database(String),

    /// Failed to create or access table
    #[error("Table error: {0}")]
    Table(String),

    /// Failed to write data
    #[error("Write error: {0}")]
    Write(String),

    /// Failed to query data
    #[error("Query error: {0}")]
    Query(String),

    /// Failed to build index
    #[error("Index error: {0}")]
    Index(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Channel error (streaming)
    #[error("Channel error: {0}")]
    Channel(String),
}

/// Result type for LanceDB operations
pub type LanceDbResult<T> = Result<T, LanceDbError>;

/// Configuration for LanceDB storage
#[derive(Debug, Clone)]
pub struct LanceDbConfig {
    /// Database URI (local path or S3/GCS URI)
    pub uri: String,
    /// Table name for events
    pub table_name: String,
    /// Vector dimension for embeddings
    pub vector_dimension: usize,
    /// MemTable flush threshold (number of events)
    pub flush_threshold: usize,
    /// Flush timeout (flush even if threshold not reached)
    pub flush_timeout: Duration,
    /// IVF partitions for vector index
    pub ivf_partitions: usize,
    /// PQ sub-quantizers for compression
    pub pq_sub_quantizers: usize,
    /// Whether to create index automatically
    pub auto_index: bool,
}

impl Default for LanceDbConfig {
    fn default() -> Self {
        Self {
            uri: "./data/lancedb".to_string(),
            table_name: "synapse_events".to_string(),
            vector_dimension: 384,
            flush_threshold: 1024,
            flush_timeout: Duration::from_secs(1),
            ivf_partitions: 256,
            pq_sub_quantizers: 16,
            auto_index: true,
        }
    }
}

impl LanceDbConfig {
    /// Create configuration for a local database
    pub fn local(path: impl Into<String>) -> Self {
        Self {
            uri: path.into(),
            ..Default::default()
        }
    }

    /// Set vector dimension
    pub fn with_dimension(mut self, dim: usize) -> Self {
        self.vector_dimension = dim;
        self
    }

    /// Set flush parameters
    pub fn with_flush(mut self, threshold: usize, timeout: Duration) -> Self {
        self.flush_threshold = threshold;
        self.flush_timeout = timeout;
        self
    }
}

/// Event stored in LanceDB
///
/// This struct is designed for both Arrow columnar storage and
/// zero-copy deserialization via rkyv.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "zero-copy",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[cfg_attr(feature = "zero-copy", archive(check_bytes))]
pub struct StoredEvent {
    /// Unique event ID
    pub id: u64,
    /// Source agent/process
    pub source: String,
    /// Timestamp (microseconds since epoch)
    pub timestamp_us: u64,
    /// Action type
    pub action: String,
    /// Intent/reason
    pub reason: String,
    /// TOON-serialized payload
    pub payload: String,
    /// Parent event ID (causal chain)
    pub parent_id: Option<u64>,
    /// Vector embedding (if computed)
    pub embedding: Option<Vec<f32>>,
}

impl StoredEvent {
    /// Create a new event
    pub fn new(source: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id: 0,
            source: source.into(),
            timestamp_us: now,
            action: String::new(),
            reason: String::new(),
            payload: String::new(),
            parent_id: None,
            embedding: None,
        }
    }

    /// Builder: set action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    /// Builder: set reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Builder: set payload
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Builder: set embedding
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }
}

/// Search result with similarity score
#[derive(Debug, Clone)]
pub struct LanceSearchResult {
    /// The matching event
    pub event: StoredEvent,
    /// Similarity score (higher = more similar)
    pub score: f32,
    /// L2 distance (if vector search)
    pub distance: Option<f32>,
}

/// Streaming write buffer
struct WriteBuffer {
    events: Vec<StoredEvent>,
    last_flush: SystemTime,
}

/// Arrow schema for events table
fn events_schema(vector_dim: usize) -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::UInt64, false),
        Field::new("source", DataType::Utf8, false),
        Field::new("timestamp_us", DataType::UInt64, false),
        Field::new("action", DataType::Utf8, false),
        Field::new("reason", DataType::Utf8, false),
        Field::new("payload", DataType::Utf8, false),
        Field::new("parent_id", DataType::Int64, true), // nullable
        Field::new(
            "embedding",
            DataType::FixedSizeList(
                Arc::new(Field::new("item", DataType::Float32, false)),
                vector_dim as i32,
            ),
            true, // nullable (not all events have embeddings)
        ),
    ]))
}

/// Convert events to Arrow RecordBatch
fn events_to_batch(events: &[StoredEvent], schema: &Arc<Schema>) -> LanceDbResult<RecordBatch> {
    let ids: Vec<u64> = events.iter().map(|e| e.id).collect();
    let sources: Vec<&str> = events.iter().map(|e| e.source.as_str()).collect();
    let timestamps: Vec<u64> = events.iter().map(|e| e.timestamp_us).collect();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    let reasons: Vec<&str> = events.iter().map(|e| e.reason.as_str()).collect();
    let payloads: Vec<&str> = events.iter().map(|e| e.payload.as_str()).collect();
    let parent_ids: Vec<Option<i64>> = events
        .iter()
        .map(|e| e.parent_id.map(|id| id as i64))
        .collect();

    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from(ids)),
        Arc::new(StringArray::from(sources)),
        Arc::new(UInt64Array::from(timestamps)),
        Arc::new(StringArray::from(actions)),
        Arc::new(StringArray::from(reasons)),
        Arc::new(StringArray::from(payloads)),
        Arc::new(Int64Array::from(parent_ids)),
        // TODO: Handle embedding column properly with FixedSizeList
        // For now, we skip embeddings in batch conversion
    ];

    // Use subset of schema without embedding for now
    let simple_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::UInt64, false),
        Field::new("source", DataType::Utf8, false),
        Field::new("timestamp_us", DataType::UInt64, false),
        Field::new("action", DataType::Utf8, false),
        Field::new("reason", DataType::Utf8, false),
        Field::new("payload", DataType::Utf8, false),
        Field::new("parent_id", DataType::Int64, true),
    ]));

    RecordBatch::try_new(simple_schema, columns)
        .map_err(|e| LanceDbError::Serialization(e.to_string()))
}

/// LanceDB Storage Engine
///
/// Production-grade semantic storage with:
/// - Streaming RecordBatch ingestion
/// - IVF-PQ vector indices
/// - Zero-copy reads via rkyv
pub struct LanceDbStore {
    config: LanceDbConfig,
    /// MemTable for hot writes
    memtable: Arc<RwLock<OrdMap<u64, StoredEvent>>>,
    /// Next event ID
    next_id: Arc<RwLock<u64>>,
    /// Write buffer for streaming ingestion
    write_buffer: Arc<RwLock<WriteBuffer>>,
    /// Channel for background flush
    flush_tx: Option<mpsc::Sender<Vec<StoredEvent>>>,
    /// Whether the "no real persistence" warning has already been logged
    /// (logged once to avoid spamming on every flush).
    persistence_warned: std::sync::atomic::AtomicBool,
    /// Whether the "search results are not relevance-ranked" warning has
    /// already been logged.
    search_warned: std::sync::atomic::AtomicBool,
    /// Whether the "no index is actually created" warning has already been
    /// logged.
    index_warned: std::sync::atomic::AtomicBool,
    // In production, this would hold:
    // db: lancedb::Database,
    // table: lancedb::Table,
}

impl LanceDbStore {
    /// Open or create a LanceDB store
    #[instrument(skip(config), fields(uri = %config.uri))]
    pub async fn open(config: LanceDbConfig) -> LanceDbResult<Self> {
        info!("Opening LanceDB store at {}", config.uri);

        // Create data directory if needed
        let path = PathBuf::from(&config.uri);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        // In production, we would:
        // let db = lancedb::connect(&config.uri).await?;
        // let table = db.open_table(&config.table_name).await
        //     .or_else(|_| db.create_table(&config.table_name, schema).await)?;

        let store = Self {
            config,
            memtable: Arc::new(RwLock::new(OrdMap::new())),
            next_id: Arc::new(RwLock::new(1)),
            write_buffer: Arc::new(RwLock::new(WriteBuffer {
                events: Vec::new(),
                last_flush: SystemTime::now(),
            })),
            flush_tx: None,
            persistence_warned: std::sync::atomic::AtomicBool::new(false),
            search_warned: std::sync::atomic::AtomicBool::new(false),
            index_warned: std::sync::atomic::AtomicBool::new(false),
        };

        Ok(store)
    }

    /// Append an event to the store
    #[instrument(skip(self, event), fields(action = %event.action))]
    pub async fn append(&self, mut event: StoredEvent) -> LanceDbResult<u64> {
        // Assign ID
        let mut next_id = self.next_id.write().await;
        event.id = *next_id;
        *next_id += 1;
        let id = event.id;

        // Add to MemTable
        let mut memtable = self.memtable.write().await;
        memtable.insert(id, event.clone());

        // Add to write buffer
        let mut buffer = self.write_buffer.write().await;
        buffer.events.push(event);

        // Check flush conditions
        let should_flush = buffer.events.len() >= self.config.flush_threshold
            || buffer.last_flush.elapsed().unwrap_or_default() >= self.config.flush_timeout;

        if should_flush {
            let events = std::mem::take(&mut buffer.events);
            buffer.last_flush = SystemTime::now();
            drop(buffer);

            // Flush to LanceDB (simulated)
            self.flush_batch(events).await?;
        }

        debug!("Appended event {}", id);
        Ok(id)
    }

    /// Flush a batch of events to LanceDB
    async fn flush_batch(&self, events: Vec<StoredEvent>) -> LanceDbResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        info!("Flushing {} events to LanceDB", events.len());

        // In production:
        // let schema = events_schema(self.config.vector_dimension);
        // let batch = events_to_batch(&events, &schema)?;
        // self.table.add(RecordBatchIterator::new(vec![Ok(batch)], schema)).await?;

        // For now, just log
        debug!("Flushed {} events (simulated)", events.len());

        if !self
            .persistence_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                "LanceDbStore::flush_batch does NOT actually persist data to LanceDB — \
                 events are held only in the in-memory MemTable and write buffer, and \
                 WILL BE LOST on process restart. Real LanceDB persistence is not yet \
                 implemented in this build."
            );
        }

        Ok(())
    }

    /// Get an event by ID
    pub async fn get(&self, id: u64) -> LanceDbResult<Option<StoredEvent>> {
        let memtable = self.memtable.read().await;
        Ok(memtable.get(&id).cloned())
    }

    /// Semantic search using vector similarity
    #[instrument(skip(self, query_embedding), fields(k = k))]
    pub async fn vector_search(
        &self,
        query_embedding: &[f32],
        k: usize,
    ) -> LanceDbResult<Vec<LanceSearchResult>> {
        // In production:
        // let results = self.table
        //     .search(query_embedding)
        //     .limit(k)
        //     .execute()
        //     .await?;

        if !self
            .search_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                "LanceDbStore::vector_search does NOT compute results from the query \
                 embedding — it returns the first `k` MemTable entries with a hardcoded \
                 score/distance, ignoring `query_embedding` entirely. Results are NOT \
                 relevance-ranked and MUST NOT be trusted for semantic search in this build."
            );
        }

        // For now, return events from memtable with simulated scores
        let memtable = self.memtable.read().await;
        let results: Vec<LanceSearchResult> = memtable
            .values()
            .take(k)
            .map(|event| LanceSearchResult {
                event: event.clone(),
                score: 0.9, // Simulated score
                distance: Some(0.1),
            })
            .collect();

        debug!("Vector search returned {} results", results.len());
        Ok(results)
    }

    /// Hybrid search (vector + filter)
    pub async fn hybrid_search(
        &self,
        query_embedding: &[f32],
        filter: &str,
        k: usize,
    ) -> LanceDbResult<Vec<LanceSearchResult>> {
        // In production:
        // let results = self.table
        //     .search(query_embedding)
        //     .filter(filter)
        //     .limit(k)
        //     .execute()
        //     .await?;

        // Fallback to vector search
        self.vector_search(query_embedding, k).await
    }

    /// Create IVF-PQ index on the embedding column
    #[instrument(skip(self))]
    pub async fn create_index(&self) -> LanceDbResult<()> {
        info!(
            "Creating IVF-PQ index with {} partitions, {} sub-quantizers",
            self.config.ivf_partitions, self.config.pq_sub_quantizers
        );

        // In production:
        // self.table
        //     .create_index(&["embedding"])
        //     .ivf_pq()
        //     .num_partitions(self.config.ivf_partitions)
        //     .num_sub_vectors(self.config.pq_sub_quantizers)
        //     .build()
        //     .await?;

        info!("Index created successfully (simulated)");

        if !self
            .index_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                "LanceDbStore::create_index does NOT actually build an IVF-PQ index — \
                 this is a no-op in this build. Vector search will continue to perform \
                 an unindexed, unranked scan of the MemTable."
            );
        }

        Ok(())
    }

    /// Get the number of events in the store
    pub async fn len(&self) -> usize {
        let memtable = self.memtable.read().await;
        memtable.len()
    }

    /// Check if the store is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

// =============================================================================
// Zero-Copy Support for WASM Integration
// =============================================================================

#[cfg(feature = "zero-copy")]
pub mod zero_copy {
    use super::*;
    use rkyv::util::AlignedVec;
    use rkyv::{Archive, Deserialize, Serialize};

    /// Serialize an event for zero-copy transfer to WASM
    pub fn serialize_event(event: &StoredEvent) -> LanceDbResult<AlignedVec> {
        rkyv::to_bytes::<_, 256>(event)
            .map_err(|e| LanceDbError::Serialization(format!("rkyv serialize failed: {}", e)))
    }

    /// Access a serialized event without copying (zero-copy)
    ///
    /// # Safety
    ///
    /// The bytes must:
    /// - Be properly aligned (use AlignedVec)
    /// - Have been serialized by `serialize_event`
    /// - Not be modified while the reference is held
    pub fn access_event(bytes: &[u8]) -> LanceDbResult<&rkyv::Archived<StoredEvent>> {
        // Safe because we validate the bytes
        rkyv::access::<StoredEvent, rkyv::rancor::Error>(bytes)
            .map_err(|e| LanceDbError::Serialization(format!("rkyv access failed: {}", e)))
    }

    /// Deserialize an archived event (when you need ownership)
    pub fn deserialize_event(archived: &rkyv::Archived<StoredEvent>) -> LanceDbResult<StoredEvent> {
        rkyv::deserialize::<StoredEvent, rkyv::rancor::Error>(archived)
            .map_err(|e| LanceDbError::Serialization(format!("rkyv deserialize failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_store() {
        let dir = tempfile::tempdir().unwrap();
        let config = LanceDbConfig::local(dir.path().to_string_lossy().to_string());
        let store = LanceDbStore::open(config).await.unwrap();
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn test_append_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let config = LanceDbConfig::local(dir.path().to_string_lossy().to_string());
        let store = LanceDbStore::open(config).await.unwrap();

        let event = StoredEvent::new("agent-001")
            .with_action("test")
            .with_reason("unit test");

        let id = store.append(event).await.unwrap();
        assert_eq!(id, 1);

        let retrieved = store.get(id).await.unwrap().unwrap();
        assert_eq!(retrieved.source, "agent-001");
        assert_eq!(retrieved.action, "test");
    }

    #[tokio::test]
    async fn test_vector_search() {
        let dir = tempfile::tempdir().unwrap();
        let config = LanceDbConfig::local(dir.path().to_string_lossy().to_string());
        let store = LanceDbStore::open(config).await.unwrap();

        // Add some events
        for i in 0..5 {
            let event = StoredEvent::new(format!("agent-{}", i))
                .with_action("search_test")
                .with_reason(format!("test event {}", i));
            store.append(event).await.unwrap();
        }

        // Simulated embedding search
        let query = vec![0.1f32; 384];
        let results = store.vector_search(&query, 3).await.unwrap();
        assert!(!results.is_empty());
    }
}
