//! Event sourcing implementation.
//!
//! Event sourcing persists each state change as an immutable event log
//! rather than overwriting current state. This enables:
//! - Full auditability: every decision is recorded
//! - Time-travel debugging: replay events to any point in time
//! - Resilience: agents can replay their log to restore state after crashes

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can occur during event store operations.
#[derive(Debug, Error)]
pub enum EventStoreError {
    /// Failed to append event.
    #[error("Failed to append event: {0}")]
    AppendFailed(String),

    /// Failed to read events.
    #[error("Failed to read events: {0}")]
    ReadFailed(String),

    /// Event not found.
    #[error("Event not found: {0}")]
    EventNotFound(String),

    /// Snapshot not found.
    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),

    /// Replay failed.
    #[error("Replay failed: {0}")]
    ReplayFailed(String),
}

/// Result type for event store operations.
pub type EventStoreResult<T> = Result<T, EventStoreError>;

/// An event in the event store.
///
/// Events are immutable records of state changes. They contain:
/// - What happened (event type and data)
/// - When it happened (timestamp)
/// - Why it happened (reason/context)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub event_id: u64,
    /// Event type (e.g., "agent.decided", "task.completed").
    pub event_type: String,
    /// Timestamp when the event occurred.
    pub timestamp: SystemTime,
    /// Event payload (JSON-serialized).
    pub payload: serde_json::Value,
    /// Reason/context for the event.
    pub reason: Option<String>,
    /// Agent or entity that produced the event.
    pub source: Option<String>,
}

impl Event {
    /// Creates a new event.
    #[must_use]
    pub fn new(
        event_id: u64,
        event_type: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_id,
            event_type: event_type.into(),
            timestamp: SystemTime::now(),
            payload,
            reason: None,
            source: None,
        }
    }

    /// Sets the reason for the event.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the source of the event.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

/// Snapshot of state at a specific point in time.
///
/// Snapshots allow efficient state reconstruction without replaying
/// all events from the beginning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Event ID at which this snapshot was taken.
    pub event_id: u64,
    /// Timestamp when the snapshot was taken.
    pub timestamp: SystemTime,
    /// Serialized state at this point.
    pub state: serde_json::Value,
}

/// Event store interface.
///
/// The event store maintains an append-only log of events and provides
/// functionality to replay events and reconstruct state.
#[async_trait::async_trait]
pub trait EventStore: Send + Sync {
    /// Appends an event to the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be appended.
    async fn append(&mut self, event: Event) -> EventStoreResult<()>;

    /// Reads events in the given range.
    ///
    /// # Arguments
    ///
    /// * `from_id` - Starting event ID (inclusive).
    /// * `to_id` - Ending event ID (inclusive).
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    async fn read_range(&self, from_id: u64, to_id: u64) -> EventStoreResult<Vec<Event>>;

    /// Reads all events from a starting point.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    async fn read_from(&self, from_id: u64) -> EventStoreResult<Vec<Event>>;

    /// Replays events to reconstruct state.
    ///
    /// # Arguments
    ///
    /// * `from_id` - Starting event ID.
    /// * `to_id` - Ending event ID (None means all events).
    /// * `initial_state` - Initial state to start from.
    /// * `apply` - Function to apply each event to the state.
    ///
    /// # Errors
    ///
    /// Returns an error if replay fails.
    async fn replay<F, S>(
        &self,
        from_id: u64,
        to_id: Option<u64>,
        initial_state: S,
        apply: F,
    ) -> EventStoreResult<S>
    where
        F: Fn(S, &Event) -> S + Send + Sync,
        S: Send + Sync;

    /// Creates a snapshot at the current state.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshot creation fails.
    async fn create_snapshot(&mut self, state: serde_json::Value) -> EventStoreResult<Snapshot>;

    /// Loads the most recent snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if no snapshot exists or loading fails.
    async fn load_snapshot(&self) -> EventStoreResult<Option<Snapshot>>;
}

/// In-memory event store implementation.
///
/// This is a simple implementation for development and testing.
/// Production implementations would use persistent storage.
#[derive(Debug, Default)]
pub struct InMemoryEventStore {
    events: Vec<Event>,
    snapshots: Vec<Snapshot>,
    next_event_id: u64,
}

impl InMemoryEventStore {
    /// Creates a new in-memory event store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            snapshots: Vec::new(),
            next_event_id: 1,
        }
    }
}

#[async_trait::async_trait]
impl EventStore for InMemoryEventStore {
    async fn append(&mut self, mut event: Event) -> EventStoreResult<()> {
        event.event_id = self.next_event_id;
        self.next_event_id += 1;
        self.events.push(event);
        Ok(())
    }

    async fn read_range(&self, from_id: u64, to_id: u64) -> EventStoreResult<Vec<Event>> {
        Ok(self
            .events
            .iter()
            .filter(|e| e.event_id >= from_id && e.event_id <= to_id)
            .cloned()
            .collect())
    }

    async fn read_from(&self, from_id: u64) -> EventStoreResult<Vec<Event>> {
        Ok(self
            .events
            .iter()
            .filter(|e| e.event_id >= from_id)
            .cloned()
            .collect())
    }

    async fn replay<F, S>(
        &self,
        from_id: u64,
        to_id: Option<u64>,
        mut state: S,
        apply: F,
    ) -> EventStoreResult<S>
    where
        F: Fn(S, &Event) -> S + Send + Sync,
        S: Send + Sync,
    {
        let events = if let Some(to) = to_id {
            self.read_range(from_id, to).await?
        } else {
            self.read_from(from_id).await?
        };

        for event in &events {
            state = apply(state, event);
        }

        Ok(state)
    }

    async fn create_snapshot(&mut self, state: serde_json::Value) -> EventStoreResult<Snapshot> {
        let snapshot = Snapshot {
            event_id: self.next_event_id - 1,
            timestamp: SystemTime::now(),
            state,
        };
        self.snapshots.push(snapshot.clone());
        Ok(snapshot)
    }

    async fn load_snapshot(&self) -> EventStoreResult<Option<Snapshot>> {
        Ok(self.snapshots.last().cloned())
    }
}

// =============================================================================
// File-Based Persistent Event Store
// =============================================================================

use std::path::{Path, PathBuf};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::Mutex;

/// File-based event store for persistent storage.
///
/// Stores events as newline-delimited JSON (NDJSON) files for durability.
/// Optimized for append-only writes and sequential reads.
///
/// ## File Layout
///
/// ```text
/// data_dir/
///   events/
///     events_000001.ndjson  # Events 1-10000
///     events_000002.ndjson  # Events 10001-20000
///   snapshots/
///     snapshot_000100.json  # Snapshot at event 100
///     snapshot_001000.json  # Snapshot at event 1000
///   metadata.json           # Store metadata
/// ```
///
/// ## Example
///
/// ```no_run
/// use syn_memory::event_store::FileEventStore;
/// use syn_memory::Event;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = FileEventStore::open("./data").await?;
/// let event = Event::new(0, "test.event", serde_json::json!({"key": "value"}));
/// // store.append(event).await?;
/// # Ok(())
/// # }
/// ```
pub struct FileEventStore {
    /// Base directory for storage.
    data_dir: PathBuf,
    /// Current event file handle.
    current_file: Mutex<Option<BufWriter<File>>>,
    /// Next event ID.
    next_event_id: Mutex<u64>,
    /// Events per file.
    events_per_file: u64,
    /// Cached events (for fast reads).
    cache: Mutex<Vec<Event>>,
    /// Maximum cache size.
    max_cache_size: usize,
}

impl FileEventStore {
    /// Creates or opens a file-based event store.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or metadata cannot be read.
    pub async fn open(data_dir: impl AsRef<Path>) -> EventStoreResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();

        // Create directory structure
        fs::create_dir_all(data_dir.join("events")).await
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to create events dir: {e}")))?;
        fs::create_dir_all(data_dir.join("snapshots")).await
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to create snapshots dir: {e}")))?;

        // Load or initialize metadata
        let metadata_path = data_dir.join("metadata.json");
        let next_event_id = if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path).await
                .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read metadata: {e}")))?;
            let meta: StoreMetadata = serde_json::from_str(&content)
                .map_err(|e| EventStoreError::ReadFailed(format!("Invalid metadata: {e}")))?;
            meta.next_event_id
        } else {
            1
        };

        Ok(Self {
            data_dir,
            current_file: Mutex::new(None),
            next_event_id: Mutex::new(next_event_id),
            events_per_file: 10_000,
            cache: Mutex::new(Vec::new()),
            max_cache_size: 1000,
        })
    }

    /// Sets the number of events per file.
    #[must_use]
    pub fn with_events_per_file(mut self, count: u64) -> Self {
        self.events_per_file = count;
        self
    }

    /// Sets the maximum cache size.
    #[must_use]
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.max_cache_size = size;
        self
    }

    /// Returns the path to an events file for a given event ID.
    fn events_file_path(&self, event_id: u64) -> PathBuf {
        let file_num = (event_id.saturating_sub(1)) / self.events_per_file;
        self.data_dir.join("events").join(format!("events_{file_num:06}.ndjson"))
    }

    /// Returns the path to a snapshot file.
    fn snapshot_path(&self, event_id: u64) -> PathBuf {
        self.data_dir.join("snapshots").join(format!("snapshot_{event_id:06}.json"))
    }

    /// Saves metadata to disk.
    async fn save_metadata(&self) -> EventStoreResult<()> {
        let next_id = *self.next_event_id.lock().await;
        let meta = StoreMetadata { next_event_id: next_id };
        let content = serde_json::to_string_pretty(&meta)
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to serialize metadata: {e}")))?;
        
        fs::write(self.data_dir.join("metadata.json"), content).await
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to write metadata: {e}")))?;
        
        Ok(())
    }

    /// Gets or creates the file handle for the current events file.
    async fn get_current_file(&self, event_id: u64) -> EventStoreResult<()> {
        let path = self.events_file_path(event_id);
        let mut file_guard = self.current_file.lock().await;

        // Check if we need a new file
        let need_new_file = file_guard.is_none();

        if need_new_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
                .map_err(|e| EventStoreError::AppendFailed(format!("Failed to open events file: {e}")))?;
            *file_guard = Some(BufWriter::new(file));
        }

        Ok(())
    }

    /// Reads all events from a specific file.
    async fn read_events_file(&self, path: &Path) -> EventStoreResult<Vec<Event>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path).await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to open events file: {e}")))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut events = Vec::new();

        while let Some(line) = lines.next_line().await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read line: {e}")))?
        {
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line)
                .map_err(|e| EventStoreError::ReadFailed(format!("Invalid event JSON: {e}")))?;
            events.push(event);
        }

        Ok(events)
    }

    /// Returns all events files in order.
    async fn list_events_files(&self) -> EventStoreResult<Vec<PathBuf>> {
        let events_dir = self.data_dir.join("events");
        let mut entries = fs::read_dir(&events_dir).await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read events dir: {e}")))?;
        
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read dir entry: {e}")))?
        {
            let path = entry.path();
            if path.extension().map(|e| e == "ndjson").unwrap_or(false) {
                files.push(path);
            }
        }
        
        files.sort();
        Ok(files)
    }
}

#[async_trait::async_trait]
impl EventStore for FileEventStore {
    async fn append(&mut self, mut event: Event) -> EventStoreResult<()> {
        let mut next_id = self.next_event_id.lock().await;
        event.event_id = *next_id;
        
        // Ensure file is open
        self.get_current_file(event.event_id).await?;

        // Serialize and write
        let line = serde_json::to_string(&event)
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to serialize event: {e}")))?;
        
        {
            let mut file_guard = self.current_file.lock().await;
            if let Some(ref mut writer) = *file_guard {
                writer.write_all(line.as_bytes()).await
                    .map_err(|e| EventStoreError::AppendFailed(format!("Failed to write event: {e}")))?;
                writer.write_all(b"\n").await
                    .map_err(|e| EventStoreError::AppendFailed(format!("Failed to write newline: {e}")))?;
                writer.flush().await
                    .map_err(|e| EventStoreError::AppendFailed(format!("Failed to flush: {e}")))?;
            }
        }

        // Update cache
        {
            let mut cache = self.cache.lock().await;
            cache.push(event);
            if cache.len() > self.max_cache_size {
                cache.remove(0);
            }
        }

        *next_id += 1;
        
        // Periodically save metadata
        if *next_id % 100 == 0 {
            drop(next_id);
            self.save_metadata().await?;
        }

        Ok(())
    }

    async fn read_range(&self, from_id: u64, to_id: u64) -> EventStoreResult<Vec<Event>> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            let cached: Vec<Event> = cache.iter()
                .filter(|e| e.event_id >= from_id && e.event_id <= to_id)
                .cloned()
                .collect();
            if !cached.is_empty() && cached.len() >= (to_id - from_id + 1) as usize {
                return Ok(cached);
            }
        }

        // Read from files
        let files = self.list_events_files().await?;
        let mut events = Vec::new();

        for file in files {
            let file_events = self.read_events_file(&file).await?;
            for event in file_events {
                if event.event_id >= from_id && event.event_id <= to_id {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    async fn read_from(&self, from_id: u64) -> EventStoreResult<Vec<Event>> {
        let files = self.list_events_files().await?;
        let mut events = Vec::new();

        for file in files {
            let file_events = self.read_events_file(&file).await?;
            for event in file_events {
                if event.event_id >= from_id {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    async fn replay<F, S>(
        &self,
        from_id: u64,
        to_id: Option<u64>,
        mut state: S,
        apply: F,
    ) -> EventStoreResult<S>
    where
        F: Fn(S, &Event) -> S + Send + Sync,
        S: Send + Sync,
    {
        let events = if let Some(to) = to_id {
            self.read_range(from_id, to).await?
        } else {
            self.read_from(from_id).await?
        };

        for event in &events {
            state = apply(state, event);
        }

        Ok(state)
    }

    async fn create_snapshot(&mut self, state: serde_json::Value) -> EventStoreResult<Snapshot> {
        let next_id = *self.next_event_id.lock().await;
        let event_id = next_id.saturating_sub(1);
        
        let snapshot = Snapshot {
            event_id,
            timestamp: SystemTime::now(),
            state,
        };

        // Save to file
        let path = self.snapshot_path(event_id);
        let content = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to serialize snapshot: {e}")))?;
        fs::write(&path, content).await
            .map_err(|e| EventStoreError::AppendFailed(format!("Failed to write snapshot: {e}")))?;

        tracing::info!("Created snapshot at event {event_id}");
        Ok(snapshot)
    }

    async fn load_snapshot(&self) -> EventStoreResult<Option<Snapshot>> {
        let snapshots_dir = self.data_dir.join("snapshots");
        if !snapshots_dir.exists() {
            return Ok(None);
        }

        let mut entries = fs::read_dir(&snapshots_dir).await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read snapshots dir: {e}")))?;
        
        let mut latest_path: Option<PathBuf> = None;
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read dir entry: {e}")))?
        {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                latest_path = Some(match latest_path {
                    Some(p) if path > p => path,
                    Some(p) => p,
                    None => path,
                });
            }
        }

        match latest_path {
            Some(path) => {
                let content = fs::read_to_string(&path).await
                    .map_err(|e| EventStoreError::ReadFailed(format!("Failed to read snapshot: {e}")))?;
                let snapshot: Snapshot = serde_json::from_str(&content)
                    .map_err(|e| EventStoreError::ReadFailed(format!("Invalid snapshot: {e}")))?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }
}

/// Metadata stored for the event store.
#[derive(Debug, Serialize, Deserialize)]
struct StoreMetadata {
    next_event_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_store_append_and_read() {
        let mut store = InMemoryEventStore::new();
        let event = Event::new(0, "test.event", serde_json::json!({"key": "value"}));
        store.append(event.clone()).await.expect("append failed");

        let events = store.read_from(1).await.expect("read failed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "test.event");
    }

    #[tokio::test]
    async fn event_store_replay() {
        let mut store = InMemoryEventStore::new();
        
        let event1 = Event::new(0, "increment", serde_json::json!({}));
        let event2 = Event::new(0, "increment", serde_json::json!({}));
        
        store.append(event1).await.expect("append failed");
        store.append(event2).await.expect("append failed");

        let final_count = store
            .replay(1, None, 0, |count, _event| count + 1)
            .await
            .expect("replay failed");

        assert_eq!(final_count, 2);
    }

    #[tokio::test]
    async fn in_memory_snapshot() {
        let mut store = InMemoryEventStore::new();
        let event = Event::new(0, "test", serde_json::json!({}));
        store.append(event).await.expect("append failed");

        let state = serde_json::json!({"counter": 1});
        let snapshot = store.create_snapshot(state.clone()).await.expect("snapshot failed");
        assert_eq!(snapshot.event_id, 1);

        let loaded = store.load_snapshot().await.expect("load failed");
        assert!(loaded.is_some());
        assert_eq!(loaded.as_ref().map(|s| &s.state), Some(&state));
    }

    #[tokio::test]
    async fn file_event_store_basic() {
        // Create a temporary directory for testing
        let temp_dir = std::env::temp_dir().join(format!("syn_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        {
            let mut store = FileEventStore::open(&temp_dir).await.expect("open failed");
            
            let event1 = Event::new(0, "test.created", serde_json::json!({"id": 1}));
            let event2 = Event::new(0, "test.updated", serde_json::json!({"id": 1, "value": "hello"}));
            
            store.append(event1).await.expect("append 1 failed");
            store.append(event2).await.expect("append 2 failed");

            let events = store.read_from(1).await.expect("read failed");
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].event_type, "test.created");
            assert_eq!(events[1].event_type, "test.updated");
        }

        // Reopen and verify persistence
        {
            let store = FileEventStore::open(&temp_dir).await.expect("reopen failed");
            let events = store.read_from(1).await.expect("read failed");
            assert_eq!(events.len(), 2);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn file_event_store_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!("syn_snap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        {
            let mut store = FileEventStore::open(&temp_dir).await.expect("open failed");
            let event = Event::new(0, "test", serde_json::json!({}));
            store.append(event).await.expect("append failed");

            let state = serde_json::json!({"version": 1, "data": [1, 2, 3]});
            store.create_snapshot(state.clone()).await.expect("snapshot failed");

            let loaded = store.load_snapshot().await.expect("load failed");
            assert!(loaded.is_some());
            let snap = loaded.expect("snapshot should exist");
            assert_eq!(snap.state, state);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn file_event_store_replay() {
        let temp_dir = std::env::temp_dir().join(format!("syn_replay_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        {
            let mut store = FileEventStore::open(&temp_dir).await.expect("open failed");
            
            for i in 1..=5 {
                let event = Event::new(0, "add", serde_json::json!({"value": i}));
                store.append(event).await.expect("append failed");
            }

            let sum = store.replay(1, None, 0i64, |acc, event| {
                let val = event.payload.get("value")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                acc + val
            }).await.expect("replay failed");

            assert_eq!(sum, 15); // 1+2+3+4+5
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn event_builder() {
        let event = Event::new(0, "test.event", serde_json::json!({}))
            .with_reason("Testing the builder")
            .with_source("test-agent");

        assert_eq!(event.reason, Some("Testing the builder".to_string()));
        assert_eq!(event.source, Some("test-agent".to_string()));
    }
}

