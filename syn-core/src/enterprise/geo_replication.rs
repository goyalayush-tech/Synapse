//! Geographic Replication
//!
//! This module provides cross-region data replication for global deployments:
//!
//! - **Multi-Region**: Replicate data across geographic regions
//! - **Conflict Resolution**: Handle concurrent writes from different regions
//! - **Latency Optimization**: Route reads to nearest replica
//! - **Consistency Models**: Strong, eventual, and bounded staleness
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    GEO REPLICATION                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │   US-WEST          US-EAST          EU-WEST          APAC       │
//! │  ┌────────┐      ┌────────┐      ┌────────┐      ┌────────┐    │
//! │  │Primary │◄────►│Replica │◄────►│Replica │◄────►│Replica │    │
//! │  │        │      │        │      │        │      │        │    │
//! │  └───┬────┘      └───┬────┘      └───┬────┘      └───┬────┘    │
//! │      │               │               │               │          │
//! │      └───────────────┴───────────────┴───────────────┘          │
//! │                          │                                       │
//! │                 ┌────────┴────────┐                             │
//! │                 │ReplicationManager│                             │
//! │                 │  Conflict Res.  │                             │
//! │                 └─────────────────┘                             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::RwLock;

/// Geographic region identifier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoRegion {
    /// Region code (e.g., "us-west-2", "eu-central-1")
    pub code: String,
    /// Human-readable name
    pub name: String,
    /// Approximate latitude
    pub latitude: f64,
    /// Approximate longitude
    pub longitude: f64,
}

impl GeoRegion {
    /// Create a new region.
    pub fn new(code: impl Into<String>, name: impl Into<String>, lat: f64, lon: f64) -> Self {
        Self {
            code: code.into(),
            name: name.into(),
            latitude: lat,
            longitude: lon,
        }
    }

    /// Calculate approximate distance to another region (haversine formula).
    pub fn distance_to(&self, other: &GeoRegion) -> f64 {
        let r = 6371.0; // Earth's radius in km

        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        r * c
    }

    /// Estimate latency to another region based on distance.
    pub fn estimated_latency_ms(&self, other: &GeoRegion) -> u64 {
        // Rough estimate: ~0.02ms per km (speed of light in fiber is about 200km/ms)
        let distance = self.distance_to(other);
        (distance * 0.02) as u64 + 5 // Add 5ms base latency
    }
}

/// Well-known regions.
impl GeoRegion {
    /// US West (Oregon)
    pub fn us_west() -> Self {
        Self::new("us-west-2", "US West (Oregon)", 45.8, -119.5)
    }

    /// US East (Virginia)
    pub fn us_east() -> Self {
        Self::new("us-east-1", "US East (Virginia)", 37.5, -79.0)
    }

    /// EU West (Ireland)
    pub fn eu_west() -> Self {
        Self::new("eu-west-1", "EU West (Ireland)", 53.3, -6.3)
    }

    /// EU Central (Frankfurt)
    pub fn eu_central() -> Self {
        Self::new("eu-central-1", "EU Central (Frankfurt)", 50.1, 8.7)
    }

    /// Asia Pacific (Tokyo)
    pub fn ap_northeast() -> Self {
        Self::new("ap-northeast-1", "Asia Pacific (Tokyo)", 35.7, 139.7)
    }

    /// Asia Pacific (Singapore)
    pub fn ap_southeast() -> Self {
        Self::new("ap-southeast-1", "Asia Pacific (Singapore)", 1.3, 103.8)
    }
}

/// Consistency model for reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsistencyModel {
    /// Always read from primary (highest consistency)
    Strong,
    /// Read from any replica (highest availability)
    Eventual,
    /// Read from replica with bounded staleness
    BoundedStaleness {
        /// Maximum lag in milliseconds
        max_lag_ms: u64,
    },
    /// Read your own writes
    Session,
    /// Read from majority of replicas
    Quorum,
}

impl Default for ConsistencyModel {
    fn default() -> Self {
        Self::Eventual
    }
}

/// Conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Last write wins (based on timestamp)
    LastWriteWins,
    /// First write wins
    FirstWriteWins,
    /// Primary region wins
    PrimaryWins,
    /// Higher version wins
    VersionWins,
    /// Custom merge function
    CustomMerge,
}

impl Default for ConflictStrategy {
    fn default() -> Self {
        Self::LastWriteWins
    }
}

/// Configuration for geo-replication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Primary region
    pub primary_region: GeoRegion,
    /// Replica regions
    pub replica_regions: Vec<GeoRegion>,
    /// Default consistency model
    pub default_consistency: ConsistencyModel,
    /// Conflict resolution strategy
    pub conflict_strategy: ConflictStrategy,
    /// Replication lag threshold for alerts (ms)
    pub lag_alert_threshold_ms: u64,
    /// Enable automatic failover
    pub auto_failover: bool,
    /// Failover threshold (consecutive failures)
    pub failover_threshold: u32,
    /// Sync interval in milliseconds
    pub sync_interval_ms: u64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            primary_region: GeoRegion::us_west(),
            replica_regions: vec![GeoRegion::us_east(), GeoRegion::eu_west()],
            default_consistency: ConsistencyModel::Eventual,
            conflict_strategy: ConflictStrategy::LastWriteWins,
            lag_alert_threshold_ms: 1000,
            auto_failover: true,
            failover_threshold: 3,
            sync_interval_ms: 100,
        }
    }
}

/// Replication state for a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionState {
    /// Region identifier
    pub region: GeoRegion,
    /// Is this the current primary?
    pub is_primary: bool,
    /// Is the region healthy?
    pub healthy: bool,
    /// Last successful sync time
    pub last_sync: Option<SystemTime>,
    /// Current replication lag in milliseconds
    pub lag_ms: u64,
    /// Consecutive failure count
    pub failure_count: u32,
    /// Total bytes replicated
    pub bytes_replicated: u64,
    /// Total operations replicated
    pub ops_replicated: u64,
}

impl RegionState {
    /// Create a new region state.
    fn new(region: GeoRegion, is_primary: bool) -> Self {
        Self {
            region,
            is_primary,
            healthy: true,
            last_sync: None,
            lag_ms: 0,
            failure_count: 0,
            bytes_replicated: 0,
            ops_replicated: 0,
        }
    }
}

/// A replication event representing a change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEvent {
    /// Unique event ID
    pub id: String,
    /// Source region
    pub source_region: String,
    /// Event type
    pub event_type: ReplicationEventType,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Version/sequence number
    pub version: u64,
    /// Data payload
    pub payload: Vec<u8>,
    /// Checksum for integrity
    pub checksum: String,
}

/// Type of replication event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationEventType {
    /// Insert new data
    Insert,
    /// Update existing data
    Update,
    /// Delete data
    Delete,
    /// Schema change
    SchemaChange,
    /// Checkpoint/snapshot
    Checkpoint,
}

/// A detected conflict between regions.
#[derive(Debug, Clone)]
pub struct ReplicationConflict {
    /// Conflict ID
    pub id: String,
    /// Key that has conflict
    pub key: String,
    /// Local version
    pub local: ConflictVersion,
    /// Remote version
    pub remote: ConflictVersion,
    /// Detected at
    pub detected_at: SystemTime,
    /// Resolution (if resolved)
    pub resolution: Option<ConflictResolution>,
}

/// Version info for a conflict.
#[derive(Debug, Clone)]
pub struct ConflictVersion {
    /// Region that produced this version
    pub region: String,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Version number
    pub version: u64,
    /// Value hash
    pub value_hash: String,
}

/// How a conflict was resolved.
#[derive(Debug, Clone)]
pub struct ConflictResolution {
    /// Winning region
    pub winner: String,
    /// Strategy used
    pub strategy: ConflictStrategy,
    /// Resolved at
    pub resolved_at: SystemTime,
}

/// Errors from replication operations.
#[derive(Debug, Error)]
pub enum ReplicationError {
    /// Region not found
    #[error("Region not found: {0}")]
    RegionNotFound(String),

    /// Region is unhealthy
    #[error("Region is unhealthy: {0}")]
    RegionUnhealthy(String),

    /// Replication lag too high
    #[error("Replication lag too high: {0}ms (threshold: {1}ms)")]
    LagTooHigh(u64, u64),

    /// Conflict detected
    #[error("Conflict detected for key: {0}")]
    ConflictDetected(String),

    /// Failover in progress
    #[error("Failover in progress")]
    FailoverInProgress,

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Consistency violation
    #[error("Consistency violation: {0}")]
    ConsistencyViolation(String),
}

/// Result type for replication operations.
pub type ReplicationResult<T> = std::result::Result<T, ReplicationError>;

/// Resolves conflicts between concurrent writes.
pub struct ConflictResolver {
    strategy: ConflictStrategy,
    primary_region: String,
}

impl ConflictResolver {
    /// Create a new conflict resolver.
    pub fn new(strategy: ConflictStrategy, primary_region: String) -> Self {
        Self {
            strategy,
            primary_region,
        }
    }

    /// Resolve a conflict between two versions.
    pub fn resolve(&self, conflict: &ReplicationConflict) -> ConflictResolution {
        let winner = match self.strategy {
            ConflictStrategy::LastWriteWins => {
                if conflict.local.timestamp >= conflict.remote.timestamp {
                    conflict.local.region.clone()
                } else {
                    conflict.remote.region.clone()
                }
            }
            ConflictStrategy::FirstWriteWins => {
                if conflict.local.timestamp <= conflict.remote.timestamp {
                    conflict.local.region.clone()
                } else {
                    conflict.remote.region.clone()
                }
            }
            ConflictStrategy::PrimaryWins => {
                if conflict.local.region == self.primary_region {
                    conflict.local.region.clone()
                } else if conflict.remote.region == self.primary_region {
                    conflict.remote.region.clone()
                } else {
                    // Neither is primary, fall back to last write wins
                    if conflict.local.timestamp >= conflict.remote.timestamp {
                        conflict.local.region.clone()
                    } else {
                        conflict.remote.region.clone()
                    }
                }
            }
            ConflictStrategy::VersionWins => {
                if conflict.local.version >= conflict.remote.version {
                    conflict.local.region.clone()
                } else {
                    conflict.remote.region.clone()
                }
            }
            ConflictStrategy::CustomMerge => {
                // For custom merge, would invoke user-defined function
                // Default to last write wins
                if conflict.local.timestamp >= conflict.remote.timestamp {
                    conflict.local.region.clone()
                } else {
                    conflict.remote.region.clone()
                }
            }
        };

        ConflictResolution {
            winner,
            strategy: self.strategy,
            resolved_at: SystemTime::now(),
        }
    }
}

/// Manages geo-replication across regions.
pub struct ReplicationManager {
    config: ReplicationConfig,
    regions: RwLock<HashMap<String, RegionState>>,
    conflicts: RwLock<Vec<ReplicationConflict>>,
    resolver: ConflictResolver,
    failover_in_progress: RwLock<bool>,
}

impl ReplicationManager {
    /// Create a new replication manager.
    pub fn new(config: ReplicationConfig) -> Self {
        let mut regions = HashMap::new();

        // Add primary
        regions.insert(
            config.primary_region.code.clone(),
            RegionState::new(config.primary_region.clone(), true),
        );

        // Add replicas
        for region in &config.replica_regions {
            regions.insert(region.code.clone(), RegionState::new(region.clone(), false));
        }

        let resolver =
            ConflictResolver::new(config.conflict_strategy, config.primary_region.code.clone());

        Self {
            config,
            regions: RwLock::new(regions),
            conflicts: RwLock::new(Vec::new()),
            resolver,
            failover_in_progress: RwLock::new(false),
        }
    }

    /// Get the current primary region.
    pub async fn primary_region(&self) -> Option<GeoRegion> {
        let regions = self.regions.read().await;
        regions
            .values()
            .find(|r| r.is_primary)
            .map(|r| r.region.clone())
    }

    /// Get all healthy replica regions.
    pub async fn healthy_replicas(&self) -> Vec<GeoRegion> {
        let regions = self.regions.read().await;
        regions
            .values()
            .filter(|r| !r.is_primary && r.healthy)
            .map(|r| r.region.clone())
            .collect()
    }

    /// Select the best region for a read based on client location.
    pub async fn select_read_region(
        &self,
        client_location: Option<&GeoRegion>,
        consistency: ConsistencyModel,
    ) -> ReplicationResult<GeoRegion> {
        match consistency {
            ConsistencyModel::Strong => {
                // Must read from primary
                self.primary_region()
                    .await
                    .ok_or_else(|| ReplicationError::RegionUnhealthy("No primary".to_string()))
            }
            ConsistencyModel::Eventual | ConsistencyModel::Session => {
                // Read from nearest healthy replica
                let regions = self.regions.read().await;
                let healthy: Vec<_> = regions.values().filter(|r| r.healthy).collect();

                if healthy.is_empty() {
                    return Err(ReplicationError::RegionUnhealthy(
                        "No healthy regions".to_string(),
                    ));
                }

                if let Some(client) = client_location {
                    // Find nearest
                    healthy
                        .into_iter()
                        .min_by(|a, b| {
                            let dist_a = client.distance_to(&a.region);
                            let dist_b = client.distance_to(&b.region);
                            dist_a.total_cmp(&dist_b)
                        })
                        .map(|r| r.region.clone())
                        .ok_or_else(|| ReplicationError::RegionNotFound("No regions".to_string()))
                } else {
                    // Return primary as default
                    healthy
                        .into_iter()
                        .find(|r| r.is_primary)
                        .or_else(|| regions.values().find(|r| r.healthy))
                        .map(|r| r.region.clone())
                        .ok_or_else(|| {
                            ReplicationError::RegionUnhealthy("No healthy regions".to_string())
                        })
                }
            }
            ConsistencyModel::BoundedStaleness { max_lag_ms } => {
                // Read from replica within staleness bounds
                let regions = self.regions.read().await;

                if let Some(client) = client_location {
                    regions
                        .values()
                        .filter(|r| r.healthy && r.lag_ms <= max_lag_ms)
                        .min_by(|a, b| {
                            let dist_a = client.distance_to(&a.region);
                            let dist_b = client.distance_to(&b.region);
                            dist_a.total_cmp(&dist_b)
                        })
                        .map(|r| r.region.clone())
                        .ok_or_else(|| ReplicationError::LagTooHigh(0, max_lag_ms))
                } else {
                    // Return any within bounds
                    regions
                        .values()
                        .find(|r| r.healthy && r.lag_ms <= max_lag_ms)
                        .map(|r| r.region.clone())
                        .ok_or_else(|| ReplicationError::LagTooHigh(0, max_lag_ms))
                }
            }
            ConsistencyModel::Quorum => {
                // For quorum, return primary (actual quorum logic would be more complex)
                self.primary_region()
                    .await
                    .ok_or_else(|| ReplicationError::RegionUnhealthy("No primary".to_string()))
            }
        }
    }

    /// Update region health status.
    pub async fn update_region_health(
        &self,
        region_code: &str,
        healthy: bool,
        lag_ms: u64,
    ) -> ReplicationResult<()> {
        let mut regions = self.regions.write().await;

        let region = regions
            .get_mut(region_code)
            .ok_or_else(|| ReplicationError::RegionNotFound(region_code.to_string()))?;

        region.healthy = healthy;
        region.lag_ms = lag_ms;
        region.last_sync = Some(SystemTime::now());

        if !healthy {
            region.failure_count += 1;

            // Check for auto-failover
            if region.is_primary
                && self.config.auto_failover
                && region.failure_count >= self.config.failover_threshold
            {
                drop(regions);
                self.trigger_failover().await?;
            }
        } else {
            region.failure_count = 0;
        }

        Ok(())
    }

    /// Record a replication event.
    pub async fn record_replication(
        &self,
        region_code: &str,
        bytes: u64,
        ops: u64,
    ) -> ReplicationResult<()> {
        let mut regions = self.regions.write().await;

        let region = regions
            .get_mut(region_code)
            .ok_or_else(|| ReplicationError::RegionNotFound(region_code.to_string()))?;

        region.bytes_replicated += bytes;
        region.ops_replicated += ops;
        region.last_sync = Some(SystemTime::now());

        Ok(())
    }

    /// Trigger a failover to the next healthy replica.
    pub async fn trigger_failover(&self) -> ReplicationResult<GeoRegion> {
        {
            let in_progress = self.failover_in_progress.read().await;
            if *in_progress {
                return Err(ReplicationError::FailoverInProgress);
            }
        }

        {
            let mut in_progress = self.failover_in_progress.write().await;
            *in_progress = true;
        }

        let result = async {
            let mut regions = self.regions.write().await;

            // Find current primary
            let current_primary = regions
                .values()
                .find(|r| r.is_primary)
                .map(|r| r.region.code.clone());

            // Find best healthy replica to promote
            let new_primary = regions
                .values()
                .filter(|r| !r.is_primary && r.healthy)
                .min_by_key(|r| r.lag_ms)
                .map(|r| r.region.code.clone());

            if let Some(new_primary_code) = new_primary {
                // Demote old primary
                if let Some(old) = current_primary {
                    if let Some(region) = regions.get_mut(&old) {
                        region.is_primary = false;
                    }
                }

                // Promote new primary
                if let Some(region) = regions.get_mut(&new_primary_code) {
                    region.is_primary = true;
                    return Ok(region.region.clone());
                }
            }

            Err(ReplicationError::RegionUnhealthy(
                "No healthy replicas for failover".to_string(),
            ))
        }
        .await;

        {
            let mut in_progress = self.failover_in_progress.write().await;
            *in_progress = false;
        }

        result
    }

    /// Record a detected conflict.
    pub async fn record_conflict(&self, conflict: ReplicationConflict) {
        let mut conflicts = self.conflicts.write().await;
        conflicts.push(conflict);
    }

    /// Resolve all pending conflicts.
    pub async fn resolve_conflicts(&self) -> Vec<ConflictResolution> {
        let mut conflicts = self.conflicts.write().await;

        let resolutions: Vec<_> = conflicts
            .iter_mut()
            .filter(|c| c.resolution.is_none())
            .map(|c| {
                let resolution = self.resolver.resolve(c);
                c.resolution = Some(resolution.clone());
                resolution
            })
            .collect();

        resolutions
    }

    /// Get replication statistics.
    pub async fn stats(&self) -> ReplicationStats {
        let regions = self.regions.read().await;
        let conflicts = self.conflicts.read().await;

        let region_stats: Vec<_> = regions
            .values()
            .map(|r| RegionStats {
                code: r.region.code.clone(),
                is_primary: r.is_primary,
                healthy: r.healthy,
                lag_ms: r.lag_ms,
                bytes_replicated: r.bytes_replicated,
                ops_replicated: r.ops_replicated,
            })
            .collect();

        let unresolved_conflicts = conflicts.iter().filter(|c| c.resolution.is_none()).count();

        ReplicationStats {
            regions: region_stats,
            total_conflicts: conflicts.len(),
            unresolved_conflicts,
        }
    }
}

/// Statistics about a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionStats {
    /// Region code
    pub code: String,
    /// Is primary
    pub is_primary: bool,
    /// Is healthy
    pub healthy: bool,
    /// Current lag in ms
    pub lag_ms: u64,
    /// Total bytes replicated
    pub bytes_replicated: u64,
    /// Total operations replicated
    pub ops_replicated: u64,
}

/// Overall replication statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStats {
    /// Per-region statistics
    pub regions: Vec<RegionStats>,
    /// Total conflicts detected
    pub total_conflicts: usize,
    /// Unresolved conflicts
    pub unresolved_conflicts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_region_distance() {
        let us_west = GeoRegion::us_west();
        let us_east = GeoRegion::us_east();
        let eu_west = GeoRegion::eu_west();

        // US West to US East should be ~3,700 km
        let dist_us = us_west.distance_to(&us_east);
        assert!(dist_us > 3000.0 && dist_us < 5000.0);

        // US West to EU West should be ~7,500 km
        let dist_eu = us_west.distance_to(&eu_west);
        assert!(dist_eu > 7000.0 && dist_eu < 9000.0);
    }

    #[tokio::test]
    async fn test_replication_manager_creation() {
        let manager = ReplicationManager::new(ReplicationConfig::default());

        let primary = manager.primary_region().await;
        assert!(primary.is_some());
        assert_eq!(primary.unwrap().code, "us-west-2");
    }

    #[tokio::test]
    async fn test_read_region_selection() {
        let manager = ReplicationManager::new(ReplicationConfig::default());

        // Strong consistency should return primary
        let region = manager
            .select_read_region(None, ConsistencyModel::Strong)
            .await
            .unwrap();
        assert_eq!(region.code, "us-west-2");
    }

    #[test]
    fn test_conflict_resolution() {
        let resolver =
            ConflictResolver::new(ConflictStrategy::LastWriteWins, "us-west-2".to_string());

        let now = SystemTime::now();
        let earlier = now - Duration::from_secs(10);

        let conflict = ReplicationConflict {
            id: "conflict-1".to_string(),
            key: "test-key".to_string(),
            local: ConflictVersion {
                region: "us-west-2".to_string(),
                timestamp: earlier,
                version: 1,
                value_hash: "hash1".to_string(),
            },
            remote: ConflictVersion {
                region: "us-east-1".to_string(),
                timestamp: now,
                version: 2,
                value_hash: "hash2".to_string(),
            },
            detected_at: now,
            resolution: None,
        };

        let resolution = resolver.resolve(&conflict);
        assert_eq!(resolution.winner, "us-east-1"); // Last write wins
    }
}
