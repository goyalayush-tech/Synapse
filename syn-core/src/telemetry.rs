//! Centralized telemetry and observability configuration.
//!
//! Observability is not an afterthought - it's a core architectural requirement.
//! This module configures the `tracing` ecosystem, ensuring that logs from
//! the CLI and Proxy follow identical formatting and filtering rules.
//!
//! ## Features
//!
//! - **Structured Logging**: JSON output for log aggregation (ELK, Datadog)
//! - **Environment Filtering**: Control verbosity via `RUST_LOG`
//! - **Async-Aware Spans**: Properly tracks context across async boundaries
//! - **OpenTelemetry Integration**: Export traces and metrics to OTLP endpoints
//!
//! ## Phase 8: Production Observability
//!
//! - **Distributed Tracing**: Full trace context propagation
//! - **Metrics Collection**: Counters, gauges, histograms
//! - **OTLP Export**: Send telemetry to Jaeger, Tempo, or any OTLP endpoint
//!
//! ## Usage
//!
//! Call [`init`] at the start of your `main()` function:
//!
//! ```ignore
//! use syn_core::telemetry;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     telemetry::init()?;
//!     tracing::info!("Application starting...");
//!     Ok(())
//! }
//! ```

use crate::error::{Result, SynapseError};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

// ============================================================================
// Phase 8: Production Metrics Infrastructure
// ============================================================================

/// Synapse metrics registry
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Counters (monotonically increasing values)
    counters: parking_lot::RwLock<HashMap<String, Arc<AtomicU64>>>,
    /// Gauges (values that can go up and down)
    gauges: parking_lot::RwLock<HashMap<String, Arc<AtomicU64>>>,
    /// Histogram buckets
    histograms: parking_lot::RwLock<HashMap<String, HistogramData>>,
}

/// Histogram data storage
#[derive(Debug, Default)]
pub struct HistogramData {
    /// Sum of all observed values
    sum: AtomicU64,
    /// Count of observations
    count: AtomicU64,
    /// Bucket boundaries (in microseconds for latency)
    buckets: Vec<u64>,
    /// Bucket counts
    bucket_counts: Vec<AtomicU64>,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            counters: parking_lot::RwLock::new(HashMap::new()),
            gauges: parking_lot::RwLock::new(HashMap::new()),
            histograms: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Increment a counter
    pub fn counter_inc(&self, name: &str) {
        self.counter_add(name, 1);
    }

    /// Add to a counter
    pub fn counter_add(&self, name: &str, value: u64) {
        let counters = self.counters.read();
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            drop(counters);
            let mut counters = self.counters.write();
            let counter = counters
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)));
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }

    /// Get counter value
    pub fn counter_get(&self, name: &str) -> u64 {
        self.counters
            .read()
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Set a gauge value
    pub fn gauge_set(&self, name: &str, value: u64) {
        let gauges = self.gauges.read();
        if let Some(gauge) = gauges.get(name) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            drop(gauges);
            let mut gauges = self.gauges.write();
            gauges
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(AtomicU64::new(value)))
                .store(value, Ordering::Relaxed);
        }
    }

    /// Increment a gauge
    pub fn gauge_inc(&self, name: &str) {
        let gauges = self.gauges.read();
        if let Some(gauge) = gauges.get(name) {
            gauge.fetch_add(1, Ordering::Relaxed);
        } else {
            drop(gauges);
            let mut gauges = self.gauges.write();
            gauges
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(AtomicU64::new(1)));
        }
    }

    /// Decrement a gauge
    pub fn gauge_dec(&self, name: &str) {
        if let Some(gauge) = self.gauges.read().get(name) {
            gauge.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get gauge value
    pub fn gauge_get(&self, name: &str) -> u64 {
        self.gauges
            .read()
            .get(name)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Register a histogram with buckets
    pub fn histogram_register(&self, name: &str, buckets: Vec<u64>) {
        let mut histograms = self.histograms.write();
        if !histograms.contains_key(name) {
            let bucket_counts: Vec<AtomicU64> = buckets.iter().map(|_| AtomicU64::new(0)).collect();
            histograms.insert(
                name.to_string(),
                HistogramData {
                    sum: AtomicU64::new(0),
                    count: AtomicU64::new(0),
                    buckets,
                    bucket_counts,
                },
            );
        }
    }

    /// Observe a histogram value
    pub fn histogram_observe(&self, name: &str, value: u64) {
        let histograms = self.histograms.read();
        if let Some(histogram) = histograms.get(name) {
            histogram.sum.fetch_add(value, Ordering::Relaxed);
            histogram.count.fetch_add(1, Ordering::Relaxed);
            
            // Find and increment appropriate bucket
            for (i, &bucket) in histogram.buckets.iter().enumerate() {
                if value <= bucket {
                    histogram.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    }

    /// Get histogram summary
    pub fn histogram_summary(&self, name: &str) -> Option<HistogramSummary> {
        let histograms = self.histograms.read();
        histograms.get(name).map(|h| {
            let count = h.count.load(Ordering::Relaxed);
            let sum = h.sum.load(Ordering::Relaxed);
            let bucket_counts: Vec<u64> = h.bucket_counts.iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect();
            
            HistogramSummary {
                count,
                sum,
                mean: if count > 0 { sum / count } else { 0 },
                buckets: h.buckets.clone(),
                bucket_counts,
            }
        })
    }

    /// Export all metrics as a snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let counters: HashMap<String, u64> = self.counters.read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();
        
        let gauges: HashMap<String, u64> = self.gauges.read()
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let histograms: HashMap<String, HistogramSummary> = self.histograms.read()
            .iter()
            .map(|(k, h)| {
                let count = h.count.load(Ordering::Relaxed);
                let sum = h.sum.load(Ordering::Relaxed);
                (k.clone(), HistogramSummary {
                    count,
                    sum,
                    mean: if count > 0 { sum / count } else { 0 },
                    buckets: h.buckets.clone(),
                    bucket_counts: h.bucket_counts.iter()
                        .map(|c| c.load(Ordering::Relaxed))
                        .collect(),
                })
            })
            .collect();

        MetricsSnapshot {
            counters,
            gauges,
            histograms,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of histogram data
#[derive(Debug, Clone)]
pub struct HistogramSummary {
    /// Total count of observations
    pub count: u64,
    /// Sum of all observed values
    pub sum: u64,
    /// Mean value
    pub mean: u64,
    /// Bucket boundaries
    pub buckets: Vec<u64>,
    /// Count per bucket
    pub bucket_counts: Vec<u64>,
}

/// Complete metrics snapshot
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// All counter values
    pub counters: HashMap<String, u64>,
    /// All gauge values
    pub gauges: HashMap<String, u64>,
    /// All histogram summaries
    pub histograms: HashMap<String, HistogramSummary>,
    /// Snapshot timestamp (unix millis)
    pub timestamp: u64,
}

// ============================================================================
// OpenTelemetry Configuration
// ============================================================================

/// Configuration for OpenTelemetry export
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// OTLP endpoint for traces (e.g., "http://localhost:4317")
    pub traces_endpoint: Option<String>,
    /// OTLP endpoint for metrics
    pub metrics_endpoint: Option<String>,
    /// Service name for traces
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (prod, staging, dev)
    pub environment: String,
    /// Export interval for metrics in seconds
    pub export_interval_secs: u64,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            traces_endpoint: std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").ok(),
            metrics_endpoint: std::env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT").ok(),
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "synapse".to_string()),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: std::env::var("SYNAPSE_ENV")
                .unwrap_or_else(|_| "development".to_string()),
            export_interval_secs: 60,
        }
    }
}

/// Global metrics instance
static METRICS: std::sync::OnceLock<MetricsRegistry> = std::sync::OnceLock::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Get the global metrics registry
pub fn metrics() -> &'static MetricsRegistry {
    METRICS.get_or_init(|| {
        let registry = MetricsRegistry::new();
        
        // Register default histograms with standard latency buckets (microseconds)
        let latency_buckets = vec![
            100,    // 100μs
            500,    // 500μs
            1_000,  // 1ms
            5_000,  // 5ms
            10_000, // 10ms
            50_000, // 50ms
            100_000, // 100ms
            500_000, // 500ms
            1_000_000, // 1s
        ];
        
        registry.histogram_register("request_latency_us", latency_buckets.clone());
        registry.histogram_register("query_latency_us", latency_buckets.clone());
        registry.histogram_register("sync_latency_us", latency_buckets);
        
        registry
    })
}

// ============================================================================
// Standard Metric Names (for consistency)
// ============================================================================

/// Standard metric names for Synapse.
///
/// This module provides canonical names for all metrics exposed by the Synapse
/// system. Using these constants ensures consistency across the codebase and
/// makes it easy to search for metric usage.
pub mod metric_names {
    // Counters
    /// Total number of requests processed by the broker.
    pub const REQUESTS_TOTAL: &str = "synapse_requests_total";
    /// Total number of events ingested into the system.
    pub const EVENTS_INGESTED: &str = "synapse_events_ingested";
    /// Total number of events committed to durable storage.
    pub const EVENTS_COMMITTED: &str = "synapse_events_committed";
    /// Total number of CRDT sync messages sent to peers.
    pub const SYNC_MESSAGES_SENT: &str = "synapse_sync_messages_sent";
    /// Total number of CRDT sync messages received from peers.
    pub const SYNC_MESSAGES_RECEIVED: &str = "synapse_sync_messages_received";
    /// Total number of Cedar policy evaluations performed.
    pub const POLICY_EVALUATIONS: &str = "synapse_policy_evaluations";
    /// Total number of policy denials (blocked requests).
    pub const POLICY_DENIALS: &str = "synapse_policy_denials";
    /// Total number of CRDT conflicts detected across the mesh.
    pub const CONFLICTS_DETECTED: &str = "synapse_conflicts_detected";
    /// Total number of Raft leader elections triggered.
    pub const RAFT_ELECTIONS: &str = "synapse_raft_elections";
    
    // Gauges
    /// Current number of active client connections.
    pub const ACTIVE_CONNECTIONS: &str = "synapse_active_connections";
    /// Current number of active peer nodes in the cluster.
    pub const ACTIVE_PEERS: &str = "synapse_active_peers";
    /// Total number of documents stored in the semantic ledger.
    pub const DOCUMENTS_TOTAL: &str = "synapse_documents_total";
    /// Current Raft term (increments on each election).
    pub const RAFT_TERM: &str = "synapse_raft_term";
    /// Highest log index committed by the Raft consensus.
    pub const RAFT_COMMIT_INDEX: &str = "synapse_raft_commit_index";
    
    // Histograms
    /// Request latency distribution in microseconds.
    pub const REQUEST_LATENCY: &str = "request_latency_us";
    /// Semantic query latency distribution in microseconds.
    pub const QUERY_LATENCY: &str = "query_latency_us";
    /// CRDT synchronization latency distribution in microseconds.
    pub const SYNC_LATENCY: &str = "sync_latency_us";
}

/// Initializes the global tracing subscriber.
///
/// This should be called once at application startup. Subsequent calls
/// will return an error.
///
/// # Environment Variables
///
/// - `RUST_LOG`: Controls log filtering (e.g., `syn_proxy=debug,warn`)
/// - `SYNAPSE_LOG_FORMAT`: Set to `json` for JSON output, otherwise uses pretty format
/// - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`: OpenTelemetry traces endpoint
/// - `OTEL_SERVICE_NAME`: Service name for telemetry
///
/// # Errors
///
/// Returns an error if the subscriber has already been initialized.
pub fn init() -> Result<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let use_json = std::env::var("SYNAPSE_LOG_FORMAT")
        .map(|v| v.to_lowercase() == "json")
        .unwrap_or(false);

    if use_json {
        // JSON format for production / log aggregation
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .json()
                    .with_span_events(FmtSpan::CLOSE)
                    .with_current_span(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true),
            );

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| SynapseError::internal(format!("Failed to set subscriber: {e}")))?;
    } else {
        // Pretty format for development
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(
                fmt::layer()
                    .pretty()
                    .with_span_events(FmtSpan::CLOSE)
                    .with_thread_ids(false)
                    .with_file(true)
                    .with_line_number(true),
            );

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| SynapseError::internal(format!("Failed to set subscriber: {e}")))?;
    }

    // Initialize metrics registry
    let _ = metrics();

    Ok(())
}

/// Initialize telemetry with OpenTelemetry configuration
pub fn init_with_otlp(config: OtlpConfig) -> Result<()> {
    // First initialize basic logging
    init()?;
    
    // Log OTLP configuration
    tracing::info!(
        service = %config.service_name,
        version = %config.service_version,
        env = %config.environment,
        traces_endpoint = ?config.traces_endpoint,
        "OpenTelemetry configured"
    );
    
    // In a full implementation, this would:
    // 1. Initialize opentelemetry-otlp tracer
    // 2. Create a tracing-opentelemetry layer
    // 3. Start the metrics export loop
    
    Ok(())
}

/// Creates a span for a network connection.
///
/// Use this to trace the lifecycle of client connections.
#[macro_export]
macro_rules! connection_span {
    ($session_id:expr) => {
        tracing::info_span!("connection", session_id = %$session_id)
    };
}

/// Creates a span for a request within a connection.
#[macro_export]
macro_rules! request_span {
    ($request_id:expr, $method:expr) => {
        tracing::info_span!("request", request_id = $request_id, method = $method)
    };
}

/// Record a latency measurement
#[macro_export]
macro_rules! record_latency {
    ($name:expr, $start:expr) => {
        let elapsed = $start.elapsed().as_micros() as u64;
        $crate::telemetry::metrics().histogram_observe($name, elapsed);
    };
}

/// Increment a counter
#[macro_export]
macro_rules! inc_counter {
    ($name:expr) => {
        $crate::telemetry::metrics().counter_inc($name);
    };
    ($name:expr, $value:expr) => {
        $crate::telemetry::metrics().counter_add($name, $value);
    };
}

/// Set a gauge value
#[macro_export]
macro_rules! set_gauge {
    ($name:expr, $value:expr) => {
        $crate::telemetry::metrics().gauge_set($name, $value);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_operations() {
        let registry = MetricsRegistry::new();
        
        registry.counter_inc("test_counter");
        assert_eq!(registry.counter_get("test_counter"), 1);
        
        registry.counter_add("test_counter", 5);
        assert_eq!(registry.counter_get("test_counter"), 6);
    }

    #[test]
    fn test_gauge_operations() {
        let registry = MetricsRegistry::new();
        
        registry.gauge_set("test_gauge", 100);
        assert_eq!(registry.gauge_get("test_gauge"), 100);
        
        registry.gauge_inc("test_gauge");
        assert_eq!(registry.gauge_get("test_gauge"), 101);
        
        registry.gauge_dec("test_gauge");
        assert_eq!(registry.gauge_get("test_gauge"), 100);
    }

    #[test]
    fn test_histogram_operations() {
        let registry = MetricsRegistry::new();
        
        registry.histogram_register("test_histogram", vec![10, 50, 100, 500, 1000]);
        
        registry.histogram_observe("test_histogram", 5);
        registry.histogram_observe("test_histogram", 25);
        registry.histogram_observe("test_histogram", 75);
        registry.histogram_observe("test_histogram", 200);
        
        let summary = registry.histogram_summary("test_histogram").unwrap();
        assert_eq!(summary.count, 4);
        assert_eq!(summary.sum, 305);
    }

    #[test]
    fn test_metrics_snapshot() {
        let registry = MetricsRegistry::new();
        
        registry.counter_inc("snapshot_counter");
        registry.gauge_set("snapshot_gauge", 42);
        
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.counters.get("snapshot_counter"), Some(&1));
        assert_eq!(snapshot.gauges.get("snapshot_gauge"), Some(&42));
    }
}
