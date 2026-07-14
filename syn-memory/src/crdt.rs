//! # CRDT Hyper-State Module
//!
//! Conflict-Free Replicated Data Types for multi-agent collaboration.
//!
//! ## The Blackboard Pattern
//!
//! Agents need two types of memory:
//! - **Long-term (The Log)**: "What happened?" - Handled by LanceDB
//! - **Short-term (The Blackboard)**: "What is true now?" - Handled by CRDTs
//!
//! Multiple agents can write to the "Plan" document simultaneously.
//! The CRDT ensures mathematical convergence without locking.
//!
//! ## Use Case
//!
//! Agent A writes code; Agent B reviews it; Agent C updates the task status.
//! All happen in parallel on the shared CRDT state.
//!
//! ## Why Automerge
//!
//! - **Conflict-Free**: No coordination needed between writers
//! - **Rich Data Types**: Maps, Lists, Text (not just counters)
//! - **Sync Protocol**: Built-in binary sync messages for P2P
//! - **Rust-Native**: Pure Rust implementation
//!
//! ## Phase 8: Distributed Sync
//!
//! - **Peer Discovery**: Gossip-based peer discovery
//! - **Sync Protocol**: Background sync with configurable intervals
//! - **Conflict History**: Track and visualize merge conflicts

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, instrument, warn};

#[cfg(feature = "crdt")]
use automerge::hydrate::Value as HydrateValue;
#[cfg(feature = "crdt")]
use automerge::sync::SyncDoc;
#[cfg(feature = "crdt")]
use automerge::{
    transaction::Transactable, AutoCommit, ObjId as ExId, ObjType, ReadDoc, ScalarValue,
};

/// Errors from CRDT operations
#[derive(Debug, Error)]
pub enum CrdtError {
    #[error("Document not found: {0}")]
    DocumentNotFound(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Merge conflict: {0}")]
    MergeConflict(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Automerge error: {0}")]
    #[cfg(feature = "crdt")]
    Automerge(#[from] automerge::AutomergeError),

    #[error("CRDT feature not enabled")]
    FeatureNotEnabled,

    #[error("Peer connection failed: {0}")]
    PeerConnectionFailed(String),

    #[error("Sync timeout")]
    SyncTimeout,

    #[error("Channel closed")]
    ChannelClosed,
}

pub type CrdtResult<T> = Result<T, CrdtError>;

/// A document identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentId(pub String);

impl DocumentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for DocumentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for DocumentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A sync message for P2P CRDT synchronization
#[derive(Debug, Clone)]
pub struct SyncMessage {
    /// Document this message pertains to
    pub document_id: DocumentId,
    /// Binary sync payload (Automerge sync protocol)
    pub payload: Vec<u8>,
    /// Sender's actor ID
    pub sender: String,
}

// ============================================================================
// Phase 8: Distributed Sync Infrastructure
// ============================================================================

/// Peer information for distributed sync
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub id: String,
    /// Network address
    pub addr: SocketAddr,
    /// Last seen timestamp (unix millis)
    pub last_seen: u64,
    /// Is this peer currently connected
    pub connected: bool,
}

/// Conflict information for visualization
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    /// Document where conflict occurred
    pub document_id: DocumentId,
    /// Path to conflicting value
    pub path: Vec<String>,
    /// Conflicting values from different actors
    pub values: Vec<ConflictingValue>,
    /// Timestamp when conflict was detected
    pub detected_at: u64,
    /// How conflict was resolved
    pub resolution: ConflictResolution,
}

/// A conflicting value from a specific actor
#[derive(Debug, Clone)]
pub struct ConflictingValue {
    /// Actor who wrote this value
    pub actor: String,
    /// The value they wrote
    pub value: CrdtValue,
    /// When they wrote it
    pub timestamp: u64,
}

/// How a conflict was resolved
#[derive(Debug, Clone)]
pub enum ConflictResolution {
    /// Automatic resolution by CRDT semantics (last-writer-wins, etc.)
    Automatic,
    /// Manual resolution by a specific actor
    Manual { resolver: String },
    /// Pending resolution
    Pending,
}

/// Events emitted by the sync system
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Peer discovered
    PeerDiscovered(PeerInfo),
    /// Peer disconnected
    PeerDisconnected(String),
    /// Document synced with peer
    DocumentSynced {
        document_id: DocumentId,
        peer_id: String,
        bytes_transferred: usize,
    },
    /// Conflict detected
    ConflictDetected(ConflictInfo),
    /// Sync error occurred
    SyncError { peer_id: String, error: String },
}

/// Configuration for distributed CRDT sync
#[derive(Debug, Clone)]
pub struct DistributedSyncConfig {
    /// Sync interval in milliseconds
    pub sync_interval_ms: u64,
    /// Peer discovery interval in milliseconds
    pub discovery_interval_ms: u64,
    /// Maximum peers to connect to
    pub max_peers: usize,
    /// Timeout for sync operations in milliseconds
    pub sync_timeout_ms: u64,
    /// Enable gossip-based peer discovery
    pub enable_gossip: bool,
    /// Seed peers for initial discovery
    pub seed_peers: Vec<SocketAddr>,
}

impl Default for DistributedSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval_ms: 1000,      // 1 second
            discovery_interval_ms: 5000, // 5 seconds
            max_peers: 10,
            sync_timeout_ms: 5000, // 5 seconds
            enable_gossip: true,
            seed_peers: Vec::new(),
        }
    }
}

/// Distributed sync manager for peer-to-peer CRDT synchronization
#[cfg(feature = "crdt")]
pub struct DistributedSyncManager {
    /// Local blackboard
    blackboard: Arc<CrdtBlackboard>,
    /// Configuration
    config: DistributedSyncConfig,
    /// Known peers
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Conflict history
    conflicts: Arc<RwLock<Vec<ConflictInfo>>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<SyncEvent>,
    /// Shutdown signal
    shutdown_tx: mpsc::Sender<()>,
}

#[cfg(feature = "crdt")]
impl DistributedSyncManager {
    /// Create a new distributed sync manager
    pub fn new(
        blackboard: Arc<CrdtBlackboard>,
        config: DistributedSyncConfig,
    ) -> (Self, broadcast::Receiver<SyncEvent>) {
        let (event_tx, event_rx) = broadcast::channel(100);
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);

        warn!(
            "DistributedSyncManager has no real network transport in this build: \
             sync_with_peer/sync_all only generate automerge sync messages locally and \
             never send them over the network to a remote peer. No data is actually \
             exchanged with remote peers."
        );

        (
            Self {
                blackboard,
                config,
                peers: Arc::new(RwLock::new(HashMap::new())),
                conflicts: Arc::new(RwLock::new(Vec::new())),
                event_tx,
                shutdown_tx,
            },
            event_rx,
        )
    }

    /// Add a peer to the sync network
    #[instrument(skip(self))]
    pub async fn add_peer(&self, peer: PeerInfo) -> CrdtResult<()> {
        let mut peers = self.peers.write().await;
        info!("Adding peer: {} at {}", peer.id, peer.addr);
        peers.insert(peer.id.clone(), peer.clone());

        let _ = self.event_tx.send(SyncEvent::PeerDiscovered(peer));
        Ok(())
    }

    /// Remove a peer from the sync network
    #[instrument(skip(self))]
    pub async fn remove_peer(&self, peer_id: &str) -> CrdtResult<()> {
        let mut peers = self.peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!("Removed peer: {}", peer_id);
            let _ = self
                .event_tx
                .send(SyncEvent::PeerDisconnected(peer_id.to_string()));
        }
        Ok(())
    }

    /// Get all known peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Sync a document with a specific peer
    #[instrument(skip(self))]
    pub async fn sync_with_peer(
        &self,
        doc_id: &DocumentId,
        peer_id: &str,
    ) -> CrdtResult<SyncStats> {
        let peers = self.peers.read().await;
        let _peer = peers
            .get(peer_id)
            .ok_or_else(|| CrdtError::PeerConnectionFailed(format!("Unknown peer: {}", peer_id)))?;

        // Generate sync message
        let msg = self
            .blackboard
            .generate_sync_message(doc_id, peer_id)
            .await?;

        let bytes_sent = msg.as_ref().map(|m| m.payload.len()).unwrap_or(0);

        // In a real implementation, this would send the message over the network
        // and receive a response. For now, we simulate local sync.
        debug!(
            "Generated sync message for peer {}: {} bytes",
            peer_id, bytes_sent
        );

        let stats = SyncStats {
            messages_sent: if msg.is_some() { 1 } else { 0 },
            messages_received: 0,
            bytes_sent,
            bytes_received: 0,
            conflicts_detected: 0,
        };

        let _ = self.event_tx.send(SyncEvent::DocumentSynced {
            document_id: doc_id.clone(),
            peer_id: peer_id.to_string(),
            bytes_transferred: bytes_sent,
        });

        Ok(stats)
    }

    /// Sync all documents with all peers
    #[instrument(skip(self))]
    pub async fn sync_all(&self) -> CrdtResult<SyncStats> {
        let docs = self.blackboard.list_documents().await;
        let peers = self.get_peers().await;

        let mut total_stats = SyncStats::default();

        for doc_id in &docs {
            for peer in &peers {
                match self.sync_with_peer(doc_id, &peer.id).await {
                    Ok(stats) => {
                        total_stats.messages_sent += stats.messages_sent;
                        total_stats.messages_received += stats.messages_received;
                        total_stats.bytes_sent += stats.bytes_sent;
                        total_stats.bytes_received += stats.bytes_received;
                        total_stats.conflicts_detected += stats.conflicts_detected;
                    }
                    Err(e) => {
                        warn!("Failed to sync {} with {}: {}", doc_id.as_str(), peer.id, e);
                        let _ = self.event_tx.send(SyncEvent::SyncError {
                            peer_id: peer.id.clone(),
                            error: e.to_string(),
                        });
                    }
                }
            }
        }

        Ok(total_stats)
    }

    /// Record a conflict for visualization
    pub async fn record_conflict(&self, conflict: ConflictInfo) {
        let mut conflicts = self.conflicts.write().await;
        let _ = self
            .event_tx
            .send(SyncEvent::ConflictDetected(conflict.clone()));
        conflicts.push(conflict);

        // Keep only last 1000 conflicts
        if conflicts.len() > 1000 {
            conflicts.remove(0);
        }
    }

    /// Get conflict history
    pub async fn get_conflicts(&self) -> Vec<ConflictInfo> {
        let conflicts = self.conflicts.read().await;
        conflicts.clone()
    }

    /// Get conflicts for a specific document
    pub async fn get_document_conflicts(&self, doc_id: &DocumentId) -> Vec<ConflictInfo> {
        let conflicts = self.conflicts.read().await;
        conflicts
            .iter()
            .filter(|c| &c.document_id == doc_id)
            .cloned()
            .collect()
    }

    /// Subscribe to sync events
    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_tx.subscribe()
    }

    /// Shutdown the sync manager
    pub async fn shutdown(&self) -> CrdtResult<()> {
        let _ = self.shutdown_tx.send(()).await;
        Ok(())
    }
}

/// Statistics from a sync operation
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Number of sync messages sent
    pub messages_sent: usize,
    /// Number of sync messages received
    pub messages_received: usize,
    /// Total bytes sent
    pub bytes_sent: usize,
    /// Total bytes received
    pub bytes_received: usize,
    /// Number of conflicts detected
    pub conflicts_detected: usize,
}

/// Represents a change to a document
#[derive(Debug, Clone)]
pub struct DocumentChange {
    /// Path to the changed value (e.g., ["tasks", "task-1", "status"])
    pub path: Vec<String>,
    /// The new value
    pub value: CrdtValue,
    /// Actor who made the change
    pub actor: String,
    /// Timestamp of the change
    pub timestamp: u64,
}

/// Values that can be stored in CRDT documents
#[derive(Debug, Clone)]
pub enum CrdtValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<CrdtValue>),
    Map(HashMap<String, CrdtValue>),
}

impl CrdtValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            CrdtValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CrdtValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            CrdtValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

#[cfg(feature = "crdt")]
impl From<&ScalarValue> for CrdtValue {
    fn from(sv: &ScalarValue) -> Self {
        match sv {
            ScalarValue::Null => CrdtValue::Null,
            ScalarValue::Boolean(b) => CrdtValue::Bool(*b),
            ScalarValue::Int(n) => CrdtValue::Int(*n),
            ScalarValue::Uint(n) => CrdtValue::Uint(*n),
            ScalarValue::F64(f) => CrdtValue::Float(*f),
            ScalarValue::Str(s) => CrdtValue::String(s.to_string()),
            ScalarValue::Bytes(b) => CrdtValue::Bytes(b.to_vec()),
            _ => CrdtValue::Null, // Counter, Timestamp, Unknown handled as null
        }
    }
}

/// Configuration for the CRDT store
#[derive(Debug, Clone)]
pub struct CrdtConfig {
    /// Actor ID for this node (used in conflict resolution)
    pub actor_id: String,
    /// Maximum document size in bytes
    pub max_document_size: usize,
    /// Enable change history tracking
    pub track_history: bool,
}

impl Default for CrdtConfig {
    fn default() -> Self {
        Self {
            actor_id: uuid_simple(),
            max_document_size: 10 * 1024 * 1024, // 10 MB
            track_history: true,
        }
    }
}

/// Generate a simple UUID-like string
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

// ============================================================================
// Recursive nested Map/List support for automerge documents
// ============================================================================
//
// automerge stores nested Maps/Lists as their own sub-objects addressed by
// an `ExId`. To read a nested object we need to recursively walk it (via
// `ReadDoc::hydrate`, which returns a fully-materialized `hydrate::Value`
// tree) and to write one we need to recursively create sub-objects (via
// `Transactable::put_object`/`insert_object`) and populate them.

/// Recursively convert a fully-hydrated automerge value into a [`CrdtValue`].
#[cfg(feature = "crdt")]
fn from_hydrate_value(value: HydrateValue) -> CrdtValue {
    match value {
        HydrateValue::Scalar(sv) => CrdtValue::from(&sv),
        HydrateValue::Map(map) => {
            let mut out = HashMap::new();
            for (key, map_value) in map.iter() {
                out.insert(key.clone(), from_hydrate_value(map_value.value.clone()));
            }
            CrdtValue::Map(out)
        }
        HydrateValue::List(list) => {
            let items = list
                .iter()
                .map(|list_value| from_hydrate_value(list_value.value.clone()))
                .collect();
            CrdtValue::List(items)
        }
        HydrateValue::Text(text) => CrdtValue::String(text.to_string()),
    }
}

/// Recursively write a [`CrdtValue`] at map key `key` of object `obj`.
///
/// Scalars are written directly via `put`. `Map`/`List` values create a
/// real nested automerge sub-object via `put_object` and recurse into it,
/// so nested writes are symmetric with the recursive reads performed by
/// [`from_hydrate_value`] / `CrdtBlackboard::get`.
#[cfg(feature = "crdt")]
fn put_map_value(doc: &mut AutoCommit, obj: &ExId, key: &str, value: CrdtValue) -> CrdtResult<()> {
    match value {
        CrdtValue::Null => {
            doc.delete(obj, key)?;
        }
        CrdtValue::Bool(b) => {
            doc.put(obj, key, b)?;
        }
        CrdtValue::Int(n) => {
            doc.put(obj, key, n)?;
        }
        CrdtValue::Uint(n) => {
            doc.put(obj, key, n as i64)?; // Automerge uses i64
        }
        CrdtValue::Float(f) => {
            doc.put(obj, key, f)?;
        }
        CrdtValue::String(s) => {
            doc.put(obj, key, s)?;
        }
        CrdtValue::Bytes(b) => {
            doc.put(obj, key, b)?;
        }
        CrdtValue::Map(map) => {
            let child = doc.put_object(obj, key, ObjType::Map)?;
            for (k, v) in map {
                put_map_value(doc, &child, &k, v)?;
            }
        }
        CrdtValue::List(list) => {
            let child = doc.put_object(obj, key, ObjType::List)?;
            for (i, v) in list.into_iter().enumerate() {
                insert_list_value(doc, &child, i, v)?;
            }
        }
    }
    Ok(())
}

/// Recursively write a [`CrdtValue`] at list index `index` of object `obj`.
///
/// Mirrors [`put_map_value`] but uses `insert`/`insert_object` since list
/// elements are addressed by position rather than by key.
#[cfg(feature = "crdt")]
fn insert_list_value(
    doc: &mut AutoCommit,
    obj: &ExId,
    index: usize,
    value: CrdtValue,
) -> CrdtResult<()> {
    match value {
        CrdtValue::Null => {
            doc.insert(obj, index, ScalarValue::Null)?;
        }
        CrdtValue::Bool(b) => {
            doc.insert(obj, index, b)?;
        }
        CrdtValue::Int(n) => {
            doc.insert(obj, index, n)?;
        }
        CrdtValue::Uint(n) => {
            doc.insert(obj, index, n as i64)?;
        }
        CrdtValue::Float(f) => {
            doc.insert(obj, index, f)?;
        }
        CrdtValue::String(s) => {
            doc.insert(obj, index, s)?;
        }
        CrdtValue::Bytes(b) => {
            doc.insert(obj, index, b)?;
        }
        CrdtValue::Map(map) => {
            let child = doc.insert_object(obj, index, ObjType::Map)?;
            for (k, v) in map {
                put_map_value(doc, &child, &k, v)?;
            }
        }
        CrdtValue::List(list) => {
            let child = doc.insert_object(obj, index, ObjType::List)?;
            for (i, v) in list.into_iter().enumerate() {
                insert_list_value(doc, &child, i, v)?;
            }
        }
    }
    Ok(())
}

/// The CRDT Blackboard - a multi-agent collaborative state store
///
/// This is the "Short-Term Memory" of Synapse, allowing multiple agents
/// to read and write shared state without coordination.
#[cfg(feature = "crdt")]
pub struct CrdtBlackboard {
    /// Configuration
    config: CrdtConfig,
    /// Documents keyed by ID
    documents: Arc<RwLock<HashMap<DocumentId, AutoCommit>>>,
    /// Pending sync states for each peer
    sync_states: Arc<RwLock<HashMap<String, HashMap<DocumentId, automerge::sync::State>>>>,
}

#[cfg(feature = "crdt")]
impl CrdtBlackboard {
    /// Create a new CRDT blackboard
    pub fn new(config: CrdtConfig) -> Self {
        Self {
            config,
            documents: Arc::new(RwLock::new(HashMap::new())),
            sync_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create or get a document
    #[instrument(skip(self))]
    pub async fn get_or_create_document(&self, doc_id: &DocumentId) -> CrdtResult<()> {
        let mut docs = self.documents.write().await;
        if !docs.contains_key(doc_id) {
            let mut doc = AutoCommit::new();
            // Initialize with an empty map at root
            doc.put_object(automerge::ROOT, "data", ObjType::Map)?;
            docs.insert(doc_id.clone(), doc);
            debug!("Created new document: {}", doc_id.as_str());
        }
        Ok(())
    }

    /// Set a value at a path in a document
    ///
    /// Path example: ["tasks", "task-1", "status"]
    #[instrument(skip(self, value))]
    pub async fn set(
        &self,
        doc_id: &DocumentId,
        path: &[&str],
        value: CrdtValue,
    ) -> CrdtResult<()> {
        if path.is_empty() {
            return Err(CrdtError::InvalidPath("Path cannot be empty".into()));
        }

        let mut docs = self.documents.write().await;
        let doc = docs
            .get_mut(doc_id)
            .ok_or_else(|| CrdtError::DocumentNotFound(doc_id.0.clone()))?;

        // Navigate to parent, creating intermediate maps as needed
        let data_obj = doc
            .get(automerge::ROOT, "data")?
            .ok_or_else(|| CrdtError::InvalidPath("Root data object not found".into()))?
            .1;

        let mut current = data_obj;
        for (i, key) in path[..path.len() - 1].iter().enumerate() {
            match doc.get(&current, *key)? {
                Some((_, obj_id)) => {
                    current = obj_id;
                }
                None => {
                    // Create intermediate map
                    current = doc.put_object(&current, *key, ObjType::Map)?;
                    debug!("Created intermediate map at path segment {}: {}", i, key);
                }
            }
        }

        // Set the final value. `put_map_value` handles scalars directly via
        // `put`/`delete` and recursively creates nested automerge
        // sub-objects for `CrdtValue::Map`/`CrdtValue::List`, so nested
        // writes are fully supported (symmetric with the recursive reads in
        // `get()`).
        let final_key = path[path.len() - 1];
        put_map_value(doc, &current, final_key, value)?;

        debug!(
            "Set value at path {:?} in document {}",
            path,
            doc_id.as_str()
        );
        Ok(())
    }

    /// Get a value at a path in a document
    #[instrument(skip(self))]
    pub async fn get(&self, doc_id: &DocumentId, path: &[&str]) -> CrdtResult<Option<CrdtValue>> {
        if path.is_empty() {
            return Err(CrdtError::InvalidPath("Path cannot be empty".into()));
        }

        let docs = self.documents.read().await;
        let doc = docs
            .get(doc_id)
            .ok_or_else(|| CrdtError::DocumentNotFound(doc_id.0.clone()))?;

        // Navigate to the data root
        let data_obj = match doc.get(automerge::ROOT, "data")? {
            Some((_, obj)) => obj,
            None => return Ok(None),
        };

        // Navigate the path
        let mut current = data_obj;
        for key in &path[..path.len() - 1] {
            match doc.get(&current, *key)? {
                Some((_, obj_id)) => {
                    current = obj_id;
                }
                None => return Ok(None),
            }
        }

        // Get the final value
        let final_key = path[path.len() - 1];
        match doc.get(&current, final_key)? {
            Some((value, obj_id)) => {
                let crdt_value = match value {
                    automerge::Value::Scalar(sv) => CrdtValue::from(sv.as_ref()),
                    automerge::Value::Object(_) => {
                        // Nested Map/List: fully resolve the nested object
                        // via automerge's `hydrate` API, which recursively
                        // materializes the sub-object tree, and convert it
                        // into a real (non-placeholder) `CrdtValue`.
                        match doc.hydrate(&obj_id, None) {
                            Ok(hydrated) => from_hydrate_value(hydrated),
                            Err(e) => {
                                warn!(
                                    "Failed to hydrate nested object at path {:?} in document {}: {} — returning empty placeholder",
                                    path, doc_id.as_str(), e
                                );
                                CrdtValue::Map(HashMap::new())
                            }
                        }
                    }
                };
                Ok(Some(crdt_value))
            }
            None => Ok(None),
        }
    }

    /// Generate a sync message for a peer
    #[instrument(skip(self))]
    pub async fn generate_sync_message(
        &self,
        doc_id: &DocumentId,
        peer_id: &str,
    ) -> CrdtResult<Option<SyncMessage>> {
        let mut docs = self.documents.write().await;
        let doc = docs
            .get_mut(doc_id)
            .ok_or_else(|| CrdtError::DocumentNotFound(doc_id.0.clone()))?;

        let mut sync_states = self.sync_states.write().await;
        let peer_states = sync_states.entry(peer_id.to_string()).or_default();
        let sync_state = peer_states
            .entry(doc_id.clone())
            .or_insert_with(automerge::sync::State::new);

        let result = doc.sync().generate_sync_message(sync_state);
        match result {
            Some(msg) => Ok(Some(SyncMessage {
                document_id: doc_id.clone(),
                payload: msg.encode(),
                sender: self.config.actor_id.clone(),
            })),
            None => Ok(None),
        }
    }

    /// Receive and apply a sync message from a peer
    #[instrument(skip(self, message))]
    pub async fn receive_sync_message(
        &self,
        message: SyncMessage,
    ) -> CrdtResult<Option<SyncMessage>> {
        let mut docs = self.documents.write().await;
        let doc = docs
            .get_mut(&message.document_id)
            .ok_or_else(|| CrdtError::DocumentNotFound(message.document_id.0.clone()))?;

        let mut sync_states = self.sync_states.write().await;
        let peer_states = sync_states.entry(message.sender.clone()).or_default();
        let sync_state = peer_states
            .entry(message.document_id.clone())
            .or_insert_with(automerge::sync::State::new);

        let decoded = automerge::sync::Message::decode(&message.payload)
            .map_err(|e| CrdtError::Serialization(e.to_string()))?;

        doc.sync().receive_sync_message(sync_state, decoded)?;

        // Generate response if needed - capture result before match to avoid borrow issues
        let response_msg = doc.sync().generate_sync_message(sync_state);
        let result = match response_msg {
            Some(response) => Ok(Some(SyncMessage {
                document_id: message.document_id,
                payload: response.encode(),
                sender: self.config.actor_id.clone(),
            })),
            None => Ok(None),
        };
        result
    }

    /// Export a document as bytes for persistence
    pub async fn save_document(&self, doc_id: &DocumentId) -> CrdtResult<Vec<u8>> {
        let mut docs = self.documents.write().await;
        let doc = docs
            .get_mut(doc_id)
            .ok_or_else(|| CrdtError::DocumentNotFound(doc_id.0.clone()))?;
        Ok(doc.save())
    }

    /// Load a document from bytes
    pub async fn load_document(&self, doc_id: DocumentId, bytes: &[u8]) -> CrdtResult<()> {
        let doc = AutoCommit::load(bytes)?;
        let mut docs = self.documents.write().await;
        docs.insert(doc_id, doc);
        Ok(())
    }

    /// Get all document IDs
    pub async fn list_documents(&self) -> Vec<DocumentId> {
        let docs = self.documents.read().await;
        docs.keys().cloned().collect()
    }

    /// Delete a document
    pub async fn delete_document(&self, doc_id: &DocumentId) -> CrdtResult<bool> {
        let mut docs = self.documents.write().await;
        Ok(docs.remove(doc_id).is_some())
    }
}

/// Mock implementation when CRDT feature is disabled
#[cfg(not(feature = "crdt"))]
pub struct CrdtBlackboard {
    _config: CrdtConfig,
}

#[cfg(not(feature = "crdt"))]
impl CrdtBlackboard {
    pub fn new(config: CrdtConfig) -> Self {
        Self { _config: config }
    }

    pub async fn get_or_create_document(&self, _doc_id: &DocumentId) -> CrdtResult<()> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn set(
        &self,
        _doc_id: &DocumentId,
        _path: &[&str],
        _value: CrdtValue,
    ) -> CrdtResult<()> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn get(&self, _doc_id: &DocumentId, _path: &[&str]) -> CrdtResult<Option<CrdtValue>> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn generate_sync_message(
        &self,
        _doc_id: &DocumentId,
        _peer_id: &str,
    ) -> CrdtResult<Option<SyncMessage>> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn receive_sync_message(
        &self,
        _message: SyncMessage,
    ) -> CrdtResult<Option<SyncMessage>> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn save_document(&self, _doc_id: &DocumentId) -> CrdtResult<Vec<u8>> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn load_document(&self, _doc_id: DocumentId, _bytes: &[u8]) -> CrdtResult<()> {
        Err(CrdtError::FeatureNotEnabled)
    }

    pub async fn list_documents(&self) -> Vec<DocumentId> {
        Vec::new()
    }

    pub async fn delete_document(&self, _doc_id: &DocumentId) -> CrdtResult<bool> {
        Err(CrdtError::FeatureNotEnabled)
    }
}

#[cfg(all(test, feature = "crdt"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_set_document() {
        let blackboard = CrdtBlackboard::new(CrdtConfig::default());
        let doc_id = DocumentId::new("test-doc");

        blackboard.get_or_create_document(&doc_id).await.unwrap();

        // Set a simple value
        blackboard
            .set(&doc_id, &["status"], CrdtValue::String("active".into()))
            .await
            .unwrap();

        // Read it back
        let value = blackboard.get(&doc_id, &["status"]).await.unwrap();
        assert!(matches!(value, Some(CrdtValue::String(s)) if s == "active"));
    }

    #[tokio::test]
    async fn test_nested_path() {
        let blackboard = CrdtBlackboard::new(CrdtConfig::default());
        let doc_id = DocumentId::new("tasks");

        blackboard.get_or_create_document(&doc_id).await.unwrap();

        // Set nested value
        blackboard
            .set(
                &doc_id,
                &["task-1", "status"],
                CrdtValue::String("in-progress".into()),
            )
            .await
            .unwrap();

        blackboard
            .set(&doc_id, &["task-1", "priority"], CrdtValue::Int(1))
            .await
            .unwrap();

        // Read values
        let status = blackboard
            .get(&doc_id, &["task-1", "status"])
            .await
            .unwrap();
        assert!(matches!(status, Some(CrdtValue::String(s)) if s == "in-progress"));

        let priority = blackboard
            .get(&doc_id, &["task-1", "priority"])
            .await
            .unwrap();
        assert!(matches!(priority, Some(CrdtValue::Int(1))));
    }

    #[tokio::test]
    async fn test_nested_map_and_list_roundtrip() {
        let blackboard = CrdtBlackboard::new(CrdtConfig::default());
        let doc_id = DocumentId::new("nested");

        blackboard.get_or_create_document(&doc_id).await.unwrap();

        // Set a nested Map value directly (not via intermediate path
        // segments) to exercise put_object/recursive writes.
        let mut inner = HashMap::new();
        inner.insert("name".to_string(), CrdtValue::String("alice".into()));
        inner.insert("age".to_string(), CrdtValue::Int(30));
        inner.insert(
            "tags".to_string(),
            CrdtValue::List(vec![
                CrdtValue::String("admin".into()),
                CrdtValue::String("dev".into()),
            ]),
        );

        blackboard
            .set(&doc_id, &["profile"], CrdtValue::Map(inner))
            .await
            .unwrap();

        // Read the whole nested object back — this must be a real,
        // fully-populated Map, not the empty placeholder.
        let value = blackboard.get(&doc_id, &["profile"]).await.unwrap();
        match value {
            Some(CrdtValue::Map(map)) => {
                assert_eq!(map.len(), 3);
                assert!(matches!(map.get("name"), Some(CrdtValue::String(s)) if s == "alice"));
                assert!(matches!(map.get("age"), Some(CrdtValue::Int(30))));
                match map.get("tags") {
                    Some(CrdtValue::List(items)) => {
                        assert_eq!(items.len(), 2);
                        assert!(matches!(&items[0], CrdtValue::String(s) if s == "admin"));
                        assert!(matches!(&items[1], CrdtValue::String(s) if s == "dev"));
                    }
                    other => panic!("expected nested list for 'tags', got {other:?}"),
                }
            }
            other => panic!("expected nested map for 'profile', got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let blackboard = CrdtBlackboard::new(CrdtConfig::default());
        let doc_id = DocumentId::new("persistent");

        blackboard.get_or_create_document(&doc_id).await.unwrap();
        blackboard
            .set(&doc_id, &["key"], CrdtValue::String("value".into()))
            .await
            .unwrap();

        // Save
        let bytes = blackboard.save_document(&doc_id).await.unwrap();

        // Load into new blackboard
        let blackboard2 = CrdtBlackboard::new(CrdtConfig::default());
        blackboard2
            .load_document(doc_id.clone(), &bytes)
            .await
            .unwrap();

        // Verify
        let value = blackboard2.get(&doc_id, &["key"]).await.unwrap();
        assert!(matches!(value, Some(CrdtValue::String(s)) if s == "value"));
    }
}
