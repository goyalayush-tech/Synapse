//! # Policy Hot-Reload
//!
//! File watcher for zero-downtime policy updates. Monitors Cedar policy files
//! and automatically reloads them when changes are detected.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Policy Hot-Reload                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │   ┌────────────┐     ┌────────────┐     ┌────────────────────┐ │
//! │   │  File      │────▶│  Debounce  │────▶│  Policy Reload     │ │
//! │   │  Watcher   │     │  (500ms)   │     │  (atomic swap)     │ │
//! │   └────────────┘     └────────────┘     └────────────────────┘ │
//! │         │                                        │              │
//! │         ▼                                        ▼              │
//! │   ┌────────────┐                          ┌────────────────┐   │
//! │   │ inotify/   │                          │ Validation &   │   │
//! │   │ FSEvents   │                          │ Compilation    │   │
//! │   └────────────┘                          └────────────────┘   │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Debounced events**: Multiple rapid saves trigger single reload
//! - **Atomic swap**: New policies are validated before replacing old ones
//! - **Error isolation**: Invalid policies don't affect running system
//! - **Metrics**: Track reload success/failure counts

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

/// Errors that can occur during hot-reload operations.
#[derive(Debug, Error)]
pub enum HotReloadError {
    #[error("Failed to create file watcher: {0}")]
    WatcherCreation(String),

    #[error("Failed to watch path: {path}: {source}")]
    WatchPath { path: PathBuf, source: String },

    #[error("Failed to read policy file: {path}: {source}")]
    ReadFile { path: PathBuf, source: String },

    #[error("Policy reload failed: {0}")]
    ReloadFailed(String),

    #[error("Channel closed unexpectedly")]
    ChannelClosed,
}

pub type HotReloadResult<T> = Result<T, HotReloadError>;

/// Configuration for the hot-reload watcher.
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Debounce duration - wait this long after last change before reloading.
    pub debounce_duration: Duration,

    /// Whether to reload recursively (watch subdirectories).
    pub recursive: bool,

    /// File extensions to watch (e.g., [".cedar", ".policy"]).
    pub extensions: Vec<String>,

    /// Maximum file size to load (in bytes).
    pub max_file_size: usize,

    /// Whether to validate policies before swapping.
    pub validate_before_swap: bool,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            debounce_duration: Duration::from_millis(500),
            recursive: true,
            extensions: vec![".cedar".to_string(), ".policy".to_string()],
            max_file_size: 10 * 1024 * 1024, // 10 MB
            validate_before_swap: true,
        }
    }
}

/// Statistics about hot-reload operations.
#[derive(Debug, Clone, Default)]
pub struct HotReloadStats {
    /// Number of successful reloads.
    pub successful_reloads: u64,
    /// Number of failed reloads.
    pub failed_reloads: u64,
    /// Number of files being watched.
    pub watched_files: usize,
    /// Last reload timestamp (milliseconds since epoch).
    pub last_reload_ms: Option<u64>,
    /// Last error message.
    pub last_error: Option<String>,
}

/// Callback type for policy reload events.
pub type ReloadCallback = Box<dyn Fn(&str, &Path) -> Result<(), String> + Send + Sync>;

/// A file watcher for hot-reloading policies.
///
/// Watches specified directories for changes to policy files and
/// triggers reloads when modifications are detected.
pub struct PolicyWatcher {
    /// Configuration.
    config: HotReloadConfig,
    /// Watched paths.
    watched_paths: RwLock<HashMap<PathBuf, WatchedPath>>,
    /// Statistics.
    stats: Arc<RwLock<HotReloadStats>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// The underlying file watcher.
    _watcher: Option<RecommendedWatcher>,
}

/// Information about a watched path.
#[derive(Debug, Clone)]
struct WatchedPath {
    /// The path being watched.
    path: PathBuf,
    /// Last known content hash.
    content_hash: Option<u64>,
    /// Whether this is a directory or file.
    is_directory: bool,
}

impl PolicyWatcher {
    /// Create a new policy watcher with the given configuration.
    pub fn new(config: HotReloadConfig) -> Self {
        Self {
            config,
            watched_paths: RwLock::new(HashMap::new()),
            stats: Arc::new(RwLock::new(HotReloadStats::default())),
            shutdown_tx: None,
            _watcher: None,
        }
    }

    /// Create a watcher with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HotReloadConfig::default())
    }

    /// Start watching for policy changes.
    ///
    /// The callback will be invoked with the new policy content and path
    /// whenever a policy file is modified.
    #[instrument(skip(self, callback))]
    pub async fn start<F>(&mut self, callback: F) -> HotReloadResult<()>
    where
        F: Fn(&str, &Path) -> Result<(), String> + Send + Sync + 'static,
    {
        let (event_tx, mut event_rx) = mpsc::channel::<PathBuf>(100);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Clone what we need for the watcher callback
        let extensions = self.config.extensions.clone();

        // Create the file system watcher
        let watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                // Only care about modify/create events
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                ) {
                    for path in event.paths {
                        // Check extension
                        if let Some(ext) = path.extension() {
                            let ext_str = format!(".{}", ext.to_string_lossy());
                            if extensions.iter().any(|e| e == &ext_str) {
                                let _ = event_tx.blocking_send(path);
                            }
                        }
                    }
                }
            }
        })
        .map_err(|e| HotReloadError::WatcherCreation(e.to_string()))?;

        self._watcher = Some(watcher);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn the debounce/reload task
        let stats = self.stats.clone();
        let debounce_duration = self.config.debounce_duration;
        let max_file_size = self.config.max_file_size;
        let callback = Arc::new(callback);

        tokio::spawn(async move {
            let mut pending_reloads: HashMap<PathBuf, tokio::time::Instant> = HashMap::new();
            let mut interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    // Receive new file events
                    Some(path) = event_rx.recv() => {
                        debug!(path = %path.display(), "File change detected");
                        pending_reloads.insert(path, tokio::time::Instant::now());
                    }

                    // Check for debounced reloads
                    _ = interval.tick() => {
                        let now = tokio::time::Instant::now();
                        let ready: Vec<PathBuf> = pending_reloads
                            .iter()
                            .filter(|(_, &time)| now.duration_since(time) >= debounce_duration)
                            .map(|(path, _)| path.clone())
                            .collect();

                        for path in ready {
                            pending_reloads.remove(&path);
                            Self::reload_policy(&path, max_file_size, &callback, &stats).await;
                        }
                    }

                    // Handle shutdown
                    _ = shutdown_rx.recv() => {
                        info!("Policy watcher shutting down");
                        break;
                    }
                }
            }
        });

        info!("Policy watcher started");
        Ok(())
    }

    /// Watch a directory or file for policy changes.
    #[instrument(skip(self))]
    pub fn watch(&mut self, path: impl AsRef<Path>) -> HotReloadResult<()> {
        let path = path.as_ref().to_path_buf();

        if let Some(ref mut watcher) = self._watcher {
            let mode = if self.config.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };

            watcher.watch(&path, mode).map_err(|e| HotReloadError::WatchPath {
                path: path.clone(),
                source: e.to_string(),
            })?;

            let is_directory = path.is_dir();
            let watched = WatchedPath {
                path: path.clone(),
                content_hash: None,
                is_directory,
            };

            self.watched_paths.write().insert(path.clone(), watched);

            // Update stats
            {
                let mut stats = self.stats.write();
                stats.watched_files = self.watched_paths.read().len();
            }

            info!(path = %path.display(), "Now watching path for policy changes");
            Ok(())
        } else {
            Err(HotReloadError::WatcherCreation(
                "Watcher not started - call start() first".into(),
            ))
        }
    }

    /// Stop watching a path.
    pub fn unwatch(&mut self, path: impl AsRef<Path>) -> HotReloadResult<()> {
        let path = path.as_ref().to_path_buf();

        if let Some(ref mut watcher) = self._watcher {
            watcher.unwatch(&path).map_err(|e| HotReloadError::WatchPath {
                path: path.clone(),
                source: e.to_string(),
            })?;

            self.watched_paths.write().remove(&path);

            // Update stats
            {
                let mut stats = self.stats.write();
                stats.watched_files = self.watched_paths.read().len();
            }

            info!(path = %path.display(), "Stopped watching path");
            Ok(())
        } else {
            Ok(()) // No-op if watcher not running
        }
    }

    /// Stop the watcher.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        self._watcher = None;
        info!("Policy watcher stopped");
    }

    /// Get hot-reload statistics.
    pub fn stats(&self) -> HotReloadStats {
        self.stats.read().clone()
    }

    /// Manually trigger a reload for a specific path.
    #[instrument(skip(self, callback))]
    pub async fn force_reload<F>(&self, path: impl AsRef<Path>, callback: F) -> HotReloadResult<()>
    where
        F: Fn(&str, &Path) -> Result<(), String>,
    {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| HotReloadError::ReadFile {
                path: path.to_path_buf(),
                source: e.to_string(),
            })?;

        callback(&content, path).map_err(|e| HotReloadError::ReloadFailed(e))?;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.successful_reloads += 1;
            stats.last_reload_ms = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            );
            stats.last_error = None;
        }

        Ok(())
    }

    // Internal helper to reload a policy file
    async fn reload_policy<F>(
        path: &Path,
        max_size: usize,
        callback: &Arc<F>,
        stats: &Arc<RwLock<HotReloadStats>>,
    ) where
        F: Fn(&str, &Path) -> Result<(), String>,
    {
        // Check file size
        match tokio::fs::metadata(path).await {
            Ok(meta) => {
                if meta.len() as usize > max_size {
                    error!(
                        path = %path.display(),
                        size = meta.len(),
                        max_size = max_size,
                        "Policy file too large"
                    );
                    let mut s = stats.write();
                    s.failed_reloads += 1;
                    s.last_error = Some(format!("File too large: {} bytes", meta.len()));
                    return;
                }
            }
            Err(e) => {
                error!(path = %path.display(), error = %e, "Failed to get file metadata");
                let mut s = stats.write();
                s.failed_reloads += 1;
                s.last_error = Some(e.to_string());
                return;
            }
        }

        // Read file content
        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(e) => {
                error!(path = %path.display(), error = %e, "Failed to read policy file");
                let mut s = stats.write();
                s.failed_reloads += 1;
                s.last_error = Some(e.to_string());
                return;
            }
        };

        // Invoke callback
        match callback(&content, path) {
            Ok(()) => {
                info!(path = %path.display(), "Policy reloaded successfully");
                let mut s = stats.write();
                s.successful_reloads += 1;
                s.last_reload_ms = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                );
                s.last_error = None;
            }
            Err(e) => {
                error!(path = %path.display(), error = %e, "Policy reload failed");
                let mut s = stats.write();
                s.failed_reloads += 1;
                s.last_error = Some(e);
            }
        }
    }
}

impl Drop for PolicyWatcher {
    fn drop(&mut self) {
        // Best-effort shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

/// Builder for PolicyWatcher with fluent API.
pub struct PolicyWatcherBuilder {
    config: HotReloadConfig,
    initial_paths: Vec<PathBuf>,
}

impl PolicyWatcherBuilder {
    pub fn new() -> Self {
        Self {
            config: HotReloadConfig::default(),
            initial_paths: Vec::new(),
        }
    }

    /// Set the debounce duration.
    pub fn debounce(mut self, duration: Duration) -> Self {
        self.config.debounce_duration = duration;
        self
    }

    /// Set whether to watch recursively.
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.config.recursive = recursive;
        self
    }

    /// Add a file extension to watch.
    pub fn extension(mut self, ext: impl Into<String>) -> Self {
        self.config.extensions.push(ext.into());
        self
    }

    /// Set the file extensions to watch (replacing defaults).
    pub fn extensions(mut self, exts: Vec<String>) -> Self {
        self.config.extensions = exts;
        self
    }

    /// Set the maximum file size.
    pub fn max_file_size(mut self, size: usize) -> Self {
        self.config.max_file_size = size;
        self
    }

    /// Add a path to watch on startup.
    pub fn watch(mut self, path: impl Into<PathBuf>) -> Self {
        self.initial_paths.push(path.into());
        self
    }

    /// Build the PolicyWatcher.
    pub fn build(self) -> PolicyWatcher {
        PolicyWatcher::new(self.config)
    }

    /// Build and start the watcher with the given callback.
    pub async fn build_and_start<F>(self, callback: F) -> HotReloadResult<PolicyWatcher>
    where
        F: Fn(&str, &Path) -> Result<(), String> + Send + Sync + 'static,
    {
        let mut watcher = self.build();
        watcher.start(callback).await?;

        // Watch initial paths
        for path in self.initial_paths {
            watcher.watch(&path)?;
        }

        Ok(watcher)
    }
}

impl Default for PolicyWatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Integration with CedarPolicy for automatic hot-reload.
#[cfg(feature = "cedar")]
pub mod cedar_integration {
    use super::*;
    use crate::cedar::{CedarError, CedarPolicy};

    /// Create a hot-reload callback for Cedar policies.
    pub fn cedar_reload_callback(
        policy: Arc<CedarPolicy>,
    ) -> impl Fn(&str, &Path) -> Result<(), String> + Send + Sync {
        move |content: &str, path: &Path| {
            info!(path = %path.display(), "Reloading Cedar policies");
            
            policy.load_policies(content).map_err(|e| {
                match e {
                    CedarError::ParseError(s) => format!("Parse error: {}", s),
                    CedarError::ValidationError(s) => format!("Validation error: {}", s),
                    e => e.to_string(),
                }
            })
        }
    }

    /// Extension trait for CedarPolicy to enable hot-reload.
    #[async_trait::async_trait]
    pub trait CedarHotReload {
        /// Start watching a directory for policy changes.
        async fn watch_directory(&self, path: impl AsRef<Path> + Send) -> HotReloadResult<PolicyWatcher>;
    }

    #[async_trait::async_trait]
    impl CedarHotReload for Arc<CedarPolicy> {
        async fn watch_directory(&self, path: impl AsRef<Path> + Send) -> HotReloadResult<PolicyWatcher> {
            let policy = self.clone();
            let path = path.as_ref().to_path_buf();

            PolicyWatcherBuilder::new()
                .extensions(vec![".cedar".to_string()])
                .watch(path)
                .build_and_start(cedar_reload_callback(policy))
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_watcher_creation() {
        let watcher = PolicyWatcher::with_defaults();
        assert_eq!(watcher.stats().watched_files, 0);
    }

    #[tokio::test]
    async fn test_builder_api() {
        let _watcher = PolicyWatcherBuilder::new()
            .debounce(Duration::from_millis(100))
            .recursive(false)
            .extension(".policy")
            .max_file_size(1024 * 1024)
            .build();
    }

    #[tokio::test]
    async fn test_force_reload() {
        let temp_dir = TempDir::new().unwrap();
        let policy_file = temp_dir.path().join("test.cedar");
        std::fs::write(&policy_file, "permit(principal, action, resource);").unwrap();

        let reload_count = Arc::new(AtomicUsize::new(0));
        let count = reload_count.clone();

        let watcher = PolicyWatcher::with_defaults();
        watcher
            .force_reload(&policy_file, move |content, _path| {
                count.fetch_add(1, Ordering::SeqCst);
                assert!(content.contains("permit"));
                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(reload_count.load(Ordering::SeqCst), 1);
        assert_eq!(watcher.stats().successful_reloads, 1);
    }
}
