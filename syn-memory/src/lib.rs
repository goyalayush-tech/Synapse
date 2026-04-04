//! # syn-memory
//!
//! Event sourcing, knowledge graph, and vector memory for Synapse.
//!
//! This crate provides:
//! - Event sourcing: Append-only event log with replay capability
//! - Knowledge graph: Entity-relationship graph with temporal tracking
//! - Vector memory: LLM embedding storage and semantic search
//! - Consensus protocols: LLM-mediated conflict resolution
//! - Lance storage: Columnar event storage with vector indices
//!
//! ## Features
//!
//! - **Event Store**: Immutable event log for full auditability
//! - **Knowledge Graph**: Queryable graph of agents, tasks, and resources
//! - **Vector Search**: Semantic similarity search on embeddings
//! - **Consensus**: Multi-agent conflict resolution
//! - **Lance-lite**: Development storage (BTreeMap + JSON, no build deps)
//! - **Lance-full**: Production LanceDB with IVF-PQ indices

#[cfg(feature = "event-sourcing")]
pub mod event_store;

#[cfg(feature = "graph")]
pub mod graph;

#[cfg(feature = "vector")]
pub mod vector;

#[cfg(feature = "lance")]
pub mod lance;

#[cfg(feature = "lance-full")]
pub mod lancedb;

pub mod consensus;

// Embedding support
pub mod embedder;

// CRDT hyper-state for multi-agent collaboration
#[cfg(feature = "crdt")]
pub mod crdt;

#[cfg(feature = "event-sourcing")]
pub use event_store::{Event, EventStore, EventStoreError, EventStoreResult, Snapshot, InMemoryEventStore, FileEventStore};

#[cfg(feature = "graph")]
pub use graph::{GraphError, GraphQuery, GraphResult, KnowledgeGraph, Node, Relationship};

#[cfg(feature = "vector")]
pub use vector::{VectorError, VectorMemory, VectorResult};

#[cfg(feature = "lance")]
pub use lance::{LanceStore, LanceConfig, LanceError, LanceResult, IntentEvent, SearchResult, StoreStats};

#[cfg(feature = "lance-full")]
pub use lancedb::{LanceDbStore, LanceDbConfig, LanceDbError, LanceDbResult, StoredEvent, LanceSearchResult};

pub use consensus::{ConsensusError, ConsensusProtocol, ConsensusResult};
pub use embedder::{Embedder, EmbedderConfig, EmbedderError, EmbedderResult};

#[cfg(feature = "crdt")]
pub use crdt::{CrdtBlackboard, CrdtConfig, CrdtError, CrdtResult, CrdtValue, DocumentId, SyncMessage, DocumentChange};

