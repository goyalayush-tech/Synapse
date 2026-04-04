//! Backup and Disaster Recovery
//!
//! This module provides enterprise-grade backup and DR capabilities:
//!
//! - **Automated Backups**: Scheduled and on-demand backups
//! - **Point-in-Time Recovery**: Restore to any moment in time
//! - **Incremental Backups**: Efficient delta-based backups
//! - **Cross-Region DR**: Replicate backups to multiple regions
//! - **Encryption**: At-rest and in-transit encryption
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    BACKUP & RECOVERY                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                   BackupManager                          │    │
//! │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │    │
//! │  │  │ Scheduler│  │Retention │  │ Storage  │              │    │
//! │  │  │          │  │ Policy   │  │ Provider │              │    │
//! │  │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │    │
//! │  │       │             │             │                     │    │
//! │  │       └─────────────┴─────────────┘                     │    │
//! │  └─────────────────────────┬───────────────────────────────┘    │
//! │                            │                                     │
//! │  ┌─────────────────────────┴───────────────────────────────┐    │
//! │  │                    Recovery Points                       │    │
//! │  │  [Full-1] ──► [Incr-1] ──► [Incr-2] ──► [Full-2] ──► ...│   │
//! │  └─────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Backup type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup of all data
    Full,
    /// Incremental backup (changes since last backup)
    Incremental,
    /// Differential backup (changes since last full backup)
    Differential,
    /// Snapshot (point-in-time copy)
    Snapshot,
}

impl Default for BackupType {
    fn default() -> Self {
        Self::Incremental
    }
}

/// Backup status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupStatus {
    /// Backup is pending
    Pending,
    /// Backup is in progress
    InProgress,
    /// Backup completed successfully
    Completed,
    /// Backup failed
    Failed,
    /// Backup was cancelled
    Cancelled,
    /// Backup is being verified
    Verifying,
    /// Backup is being deleted
    Deleting,
}

/// Schedule for automated backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupSchedule {
    /// Run once (manual)
    Once,
    /// Run every N minutes
    Minutes(u32),
    /// Run every N hours
    Hourly(u32),
    /// Run daily at specific hour (0-23)
    Daily {
        /// Hour of day (0-23)
        hour: u32,
    },
    /// Run weekly on specific day (0=Sun, 6=Sat) at hour
    Weekly {
        /// Day of week (0=Sunday, 6=Saturday)
        day: u32,
        /// Hour of day (0-23)
        hour: u32,
    },
    /// Run monthly on specific day at hour
    Monthly {
        /// Day of month (1-31)
        day: u32,
        /// Hour of day (0-23)
        hour: u32,
    },
    /// Custom cron expression
    Cron(String),
}

impl Default for BackupSchedule {
    fn default() -> Self {
        Self::Daily { hour: 2 } // 2 AM daily
    }
}

impl BackupSchedule {
    /// Calculate next run time from now.
    pub fn next_run(&self, from: SystemTime) -> SystemTime {
        match self {
            BackupSchedule::Once => from,
            BackupSchedule::Minutes(n) => from + Duration::from_secs(*n as u64 * 60),
            BackupSchedule::Hourly(n) => from + Duration::from_secs(*n as u64 * 3600),
            BackupSchedule::Daily { hour: _ } => from + Duration::from_secs(86400),
            BackupSchedule::Weekly { .. } => from + Duration::from_secs(86400 * 7),
            BackupSchedule::Monthly { .. } => from + Duration::from_secs(86400 * 30),
            BackupSchedule::Cron(_) => from + Duration::from_secs(3600), // Simplified
        }
    }
}

/// Retention policy for backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Keep backups for this many days
    pub retain_days: u32,
    /// Minimum number of full backups to keep
    pub min_full_backups: u32,
    /// Keep one backup per week for this many weeks
    pub weekly_retention_weeks: u32,
    /// Keep one backup per month for this many months
    pub monthly_retention_months: u32,
    /// Keep one backup per year for this many years
    pub yearly_retention_years: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retain_days: 30,
            min_full_backups: 3,
            weekly_retention_weeks: 4,
            monthly_retention_months: 12,
            yearly_retention_years: 7,
        }
    }
}

/// Storage location for backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageLocation {
    /// Local filesystem
    Local {
        /// Path to local backup directory
        path: PathBuf,
    },
    /// S3-compatible storage
    S3 {
        /// S3 bucket name
        bucket: String,
        /// Object key prefix
        prefix: String,
        /// AWS region
        region: String,
    },
    /// Azure Blob Storage
    AzureBlob {
        /// Azure container name
        container: String,
        /// Blob prefix
        prefix: String,
    },
    /// Google Cloud Storage
    GCS {
        /// GCS bucket name
        bucket: String,
        /// Object prefix
        prefix: String,
    },
}

impl Default for StorageLocation {
    fn default() -> Self {
        Self::Local {
            path: PathBuf::from("./backups"),
        }
    }
}

/// Configuration for backup management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Primary storage location
    pub primary_storage: StorageLocation,
    /// Secondary storage for DR (optional)
    pub secondary_storage: Option<StorageLocation>,
    /// Backup schedule
    pub schedule: BackupSchedule,
    /// Full backup schedule (defaults to weekly)
    pub full_backup_schedule: BackupSchedule,
    /// Retention policy
    pub retention: RetentionPolicy,
    /// Enable compression
    pub compression_enabled: bool,
    /// Compression level (1-9)
    pub compression_level: u32,
    /// Enable encryption
    pub encryption_enabled: bool,
    /// Enable checksum verification
    pub verify_checksums: bool,
    /// Parallel upload threads
    pub parallel_uploads: u32,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            primary_storage: StorageLocation::default(),
            secondary_storage: None,
            schedule: BackupSchedule::Daily { hour: 2 },
            full_backup_schedule: BackupSchedule::Weekly { day: 0, hour: 3 },
            retention: RetentionPolicy::default(),
            compression_enabled: true,
            compression_level: 6,
            encryption_enabled: true,
            verify_checksums: true,
            parallel_uploads: 4,
        }
    }
}

/// A point in time that can be recovered to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPoint {
    /// Unique identifier
    pub id: String,
    /// Backup type
    pub backup_type: BackupType,
    /// Status
    pub status: BackupStatus,
    /// Creation time
    pub created_at: SystemTime,
    /// Completion time (if completed)
    pub completed_at: Option<SystemTime>,
    /// Size in bytes
    pub size_bytes: u64,
    /// Number of files/objects
    pub object_count: u64,
    /// Parent backup ID (for incremental)
    pub parent_id: Option<String>,
    /// Storage location
    pub location: StorageLocation,
    /// Checksum
    pub checksum: String,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Tenant ID (if tenant-specific)
    pub tenant_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl RecoveryPoint {
    /// Create a new recovery point.
    pub fn new(id: String, backup_type: BackupType, location: StorageLocation) -> Self {
        Self {
            id,
            backup_type,
            status: BackupStatus::Pending,
            created_at: SystemTime::now(),
            completed_at: None,
            size_bytes: 0,
            object_count: 0,
            parent_id: None,
            location,
            checksum: String::new(),
            metadata: HashMap::new(),
            tenant_id: None,
            error: None,
        }
    }
    
    /// Check if this is a full backup.
    pub fn is_full(&self) -> bool {
        matches!(self.backup_type, BackupType::Full)
    }
    
    /// Check if backup is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, BackupStatus::Completed)
    }
    
    /// Get backup age.
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or(Duration::ZERO)
    }
}

/// Errors from backup operations.
#[derive(Debug, Error)]
pub enum BackupError {
    /// Backup not found
    #[error("Backup not found: {0}")]
    NotFound(String),
    
    /// Backup in progress
    #[error("Backup already in progress")]
    InProgress,
    
    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),
    
    /// Checksum mismatch
    #[error("Checksum mismatch for backup {0}")]
    ChecksumMismatch(String),
    
    /// Recovery failed
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),
    
    /// Invalid backup chain
    #[error("Invalid backup chain: {0}")]
    InvalidChain(String),
    
    /// Retention policy violation
    #[error("Cannot delete backup: retention policy requires keeping it")]
    RetentionViolation,
    
    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for backup operations.
pub type BackupResult<T> = std::result::Result<T, BackupError>;

/// Progress information for backup operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupProgress {
    /// Backup ID
    pub backup_id: String,
    /// Current phase
    pub phase: String,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Total bytes (if known)
    pub total_bytes: Option<u64>,
    /// Objects processed
    pub objects_processed: u64,
    /// Total objects (if known)
    pub total_objects: Option<u64>,
    /// Start time
    pub started_at: SystemTime,
    /// Estimated completion time
    pub estimated_completion: Option<SystemTime>,
}

impl BackupProgress {
    /// Calculate percentage complete.
    pub fn percentage(&self) -> Option<f64> {
        if let Some(total) = self.total_bytes {
            if total > 0 {
                return Some((self.bytes_processed as f64 / total as f64) * 100.0);
            }
        }
        None
    }
    
    /// Calculate throughput in bytes per second.
    pub fn throughput(&self) -> f64 {
        let elapsed = SystemTime::now()
            .duration_since(self.started_at)
            .unwrap_or(Duration::from_secs(1));
        
        self.bytes_processed as f64 / elapsed.as_secs_f64()
    }
}

/// Statistics about backup operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupStats {
    /// Total backups created
    pub total_backups: u64,
    /// Successful backups
    pub successful_backups: u64,
    /// Failed backups
    pub failed_backups: u64,
    /// Total bytes backed up
    pub total_bytes: u64,
    /// Total recoveries performed
    pub total_recoveries: u64,
    /// Successful recoveries
    pub successful_recoveries: u64,
    /// Average backup duration in seconds
    pub avg_backup_duration_secs: f64,
    /// Last backup time
    pub last_backup_at: Option<SystemTime>,
    /// Last successful backup time
    pub last_successful_at: Option<SystemTime>,
}

/// Manages backups and recovery operations.
pub struct BackupManager {
    config: BackupConfig,
    recovery_points: RwLock<Vec<RecoveryPoint>>,
    current_backup: RwLock<Option<BackupProgress>>,
    stats: RwLock<BackupStats>,
    next_scheduled: RwLock<Option<SystemTime>>,
}

impl BackupManager {
    /// Create a new backup manager.
    pub fn new(config: BackupConfig) -> Self {
        Self {
            config,
            recovery_points: RwLock::new(Vec::new()),
            current_backup: RwLock::new(None),
            stats: RwLock::new(BackupStats::default()),
            next_scheduled: RwLock::new(None),
        }
    }
    
    /// Start a new backup.
    pub async fn start_backup(
        &self,
        backup_type: BackupType,
        tenant_id: Option<String>,
    ) -> BackupResult<RecoveryPoint> {
        // Check if backup already in progress
        {
            let current = self.current_backup.read().await;
            if current.is_some() {
                return Err(BackupError::InProgress);
            }
        }
        
        let backup_id = format!(
            "backup-{}-{}",
            chrono_like_timestamp(),
            rand_id()
        );
        
        let mut recovery_point = RecoveryPoint::new(
            backup_id.clone(),
            backup_type,
            self.config.primary_storage.clone(),
        );
        recovery_point.tenant_id = tenant_id;
        recovery_point.status = BackupStatus::InProgress;
        
        // For incremental, find parent
        if matches!(backup_type, BackupType::Incremental | BackupType::Differential) {
            let points = self.recovery_points.read().await;
            let parent = points.iter()
                .filter(|p| p.is_complete())
                .filter(|p| {
                    if backup_type == BackupType::Incremental {
                        true // Any completed backup
                    } else {
                        p.is_full() // Only full backups for differential
                    }
                })
                .last();
            
            if let Some(p) = parent {
                recovery_point.parent_id = Some(p.id.clone());
            } else if backup_type == BackupType::Incremental {
                // No parent found, upgrade to full
                recovery_point.backup_type = BackupType::Full;
            }
        }
        
        // Set progress
        {
            let mut current = self.current_backup.write().await;
            *current = Some(BackupProgress {
                backup_id: backup_id.clone(),
                phase: "initializing".to_string(),
                bytes_processed: 0,
                total_bytes: None,
                objects_processed: 0,
                total_objects: None,
                started_at: SystemTime::now(),
                estimated_completion: None,
            });
        }
        
        // Add to recovery points
        {
            let mut points = self.recovery_points.write().await;
            points.push(recovery_point.clone());
        }
        
        Ok(recovery_point)
    }
    
    /// Update backup progress.
    pub async fn update_progress(
        &self,
        backup_id: &str,
        bytes: u64,
        objects: u64,
        phase: &str,
    ) -> BackupResult<()> {
        let mut current = self.current_backup.write().await;
        
        if let Some(ref mut progress) = *current {
            if progress.backup_id == backup_id {
                progress.bytes_processed = bytes;
                progress.objects_processed = objects;
                progress.phase = phase.to_string();
            }
        }
        
        Ok(())
    }
    
    /// Complete a backup.
    pub async fn complete_backup(
        &self,
        backup_id: &str,
        size_bytes: u64,
        object_count: u64,
        checksum: String,
    ) -> BackupResult<RecoveryPoint> {
        let mut points = self.recovery_points.write().await;
        
        let point = points
            .iter_mut()
            .find(|p| p.id == backup_id)
            .ok_or_else(|| BackupError::NotFound(backup_id.to_string()))?;
        
        point.status = BackupStatus::Completed;
        point.completed_at = Some(SystemTime::now());
        point.size_bytes = size_bytes;
        point.object_count = object_count;
        point.checksum = checksum;
        
        let result = point.clone();
        
        // Clear current backup
        {
            let mut current = self.current_backup.write().await;
            *current = None;
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_backups += 1;
            stats.successful_backups += 1;
            stats.total_bytes += size_bytes;
            stats.last_backup_at = Some(SystemTime::now());
            stats.last_successful_at = Some(SystemTime::now());
        }
        
        // Schedule next backup
        {
            let mut next = self.next_scheduled.write().await;
            *next = Some(self.config.schedule.next_run(SystemTime::now()));
        }
        
        Ok(result)
    }
    
    /// Fail a backup.
    pub async fn fail_backup(&self, backup_id: &str, error: String) -> BackupResult<()> {
        let mut points = self.recovery_points.write().await;
        
        let point = points
            .iter_mut()
            .find(|p| p.id == backup_id)
            .ok_or_else(|| BackupError::NotFound(backup_id.to_string()))?;
        
        point.status = BackupStatus::Failed;
        point.error = Some(error);
        
        // Clear current backup
        {
            let mut current = self.current_backup.write().await;
            *current = None;
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_backups += 1;
            stats.failed_backups += 1;
            stats.last_backup_at = Some(SystemTime::now());
        }
        
        Ok(())
    }
    
    /// List recovery points.
    pub async fn list_recovery_points(&self) -> Vec<RecoveryPoint> {
        let points = self.recovery_points.read().await;
        points.clone()
    }
    
    /// Get a specific recovery point.
    pub async fn get_recovery_point(&self, id: &str) -> BackupResult<RecoveryPoint> {
        let points = self.recovery_points.read().await;
        points
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| BackupError::NotFound(id.to_string()))
    }
    
    /// Find the latest recovery point.
    pub async fn latest_recovery_point(&self) -> Option<RecoveryPoint> {
        let points = self.recovery_points.read().await;
        points
            .iter()
            .filter(|p| p.is_complete())
            .max_by_key(|p| p.created_at)
            .cloned()
    }
    
    /// Find recovery points for point-in-time recovery.
    pub async fn find_recovery_chain(&self, target_time: SystemTime) -> BackupResult<Vec<RecoveryPoint>> {
        let points = self.recovery_points.read().await;
        
        // Find the most recent full backup before target time
        let base = points
            .iter()
            .filter(|p| p.is_complete() && p.is_full())
            .filter(|p| p.created_at <= target_time)
            .max_by_key(|p| p.created_at);
        
        let base = match base {
            Some(b) => b,
            None => return Err(BackupError::InvalidChain(
                "No full backup found before target time".to_string()
            )),
        };
        
        // Find all incremental backups between base and target
        let mut chain = vec![base.clone()];
        
        let incrementals: Vec<_> = points
            .iter()
            .filter(|p| p.is_complete())
            .filter(|p| p.created_at > base.created_at && p.created_at <= target_time)
            .filter(|p| matches!(p.backup_type, BackupType::Incremental))
            .collect();
        
        chain.extend(incrementals.into_iter().cloned());
        chain.sort_by_key(|p| p.created_at);
        
        Ok(chain)
    }
    
    /// Delete a recovery point.
    pub async fn delete_recovery_point(&self, id: &str) -> BackupResult<()> {
        let mut points = self.recovery_points.write().await;
        
        // Check retention policy
        let point = points
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| BackupError::NotFound(id.to_string()))?;
        
        // Check if this is a required full backup
        if point.is_full() {
            let full_count = points.iter()
                .filter(|p| p.is_full() && p.is_complete())
                .count();
            
            if full_count <= self.config.retention.min_full_backups as usize {
                return Err(BackupError::RetentionViolation);
            }
        }
        
        // Check if any incremental depends on this
        let has_dependents = points.iter().any(|p| p.parent_id.as_deref() == Some(id));
        if has_dependents {
            return Err(BackupError::InvalidChain(
                "Cannot delete backup with dependent incrementals".to_string()
            ));
        }
        
        points.retain(|p| p.id != id);
        
        Ok(())
    }
    
    /// Apply retention policy.
    pub async fn apply_retention(&self) -> BackupResult<Vec<String>> {
        let mut points = self.recovery_points.write().await;
        let now = SystemTime::now();
        let retention_threshold = now - Duration::from_secs(
            self.config.retention.retain_days as u64 * 86400
        );
        
        let mut deleted = Vec::new();
        
        // Find backups to delete
        let to_delete: Vec<_> = points
            .iter()
            .filter(|p| p.is_complete())
            .filter(|p| p.created_at < retention_threshold)
            .filter(|p| {
                // Keep minimum full backups
                if p.is_full() {
                    let full_count = points.iter()
                        .filter(|pp| pp.is_full() && pp.is_complete())
                        .count();
                    full_count > self.config.retention.min_full_backups as usize
                } else {
                    true
                }
            })
            .filter(|p| {
                // Keep if has dependents
                !points.iter().any(|pp| pp.parent_id.as_deref() == Some(&p.id))
            })
            .map(|p| p.id.clone())
            .collect();
        
        for id in to_delete {
            points.retain(|p| p.id != id);
            deleted.push(id);
        }
        
        Ok(deleted)
    }
    
    /// Get current backup progress.
    pub async fn current_progress(&self) -> Option<BackupProgress> {
        let current = self.current_backup.read().await;
        current.clone()
    }
    
    /// Get backup statistics.
    pub async fn stats(&self) -> BackupStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Get next scheduled backup time.
    pub async fn next_scheduled_backup(&self) -> Option<SystemTime> {
        let next = self.next_scheduled.read().await;
        *next
    }
}

// Helper functions

fn chrono_like_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format!("{}", now.as_secs())
}

fn rand_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_backup_manager_creation() {
        let manager = BackupManager::new(BackupConfig::default());
        let points = manager.list_recovery_points().await;
        assert!(points.is_empty());
    }
    
    #[tokio::test]
    async fn test_start_full_backup() {
        let manager = BackupManager::new(BackupConfig::default());
        
        let backup = manager.start_backup(BackupType::Full, None).await.unwrap();
        
        assert!(backup.is_full());
        assert_eq!(backup.status, BackupStatus::InProgress);
    }
    
    #[tokio::test]
    async fn test_complete_backup() {
        let manager = BackupManager::new(BackupConfig::default());
        
        let backup = manager.start_backup(BackupType::Full, None).await.unwrap();
        
        let completed = manager
            .complete_backup(&backup.id, 1024 * 1024, 100, "checksum123".to_string())
            .await
            .unwrap();
        
        assert!(completed.is_complete());
        assert_eq!(completed.size_bytes, 1024 * 1024);
        assert_eq!(completed.object_count, 100);
    }
    
    #[tokio::test]
    async fn test_incremental_needs_parent() {
        let manager = BackupManager::new(BackupConfig::default());
        
        // First incremental without full should become full
        let backup = manager.start_backup(BackupType::Incremental, None).await.unwrap();
        assert!(backup.is_full()); // Upgraded to full
    }
    
    #[tokio::test]
    async fn test_retention_policy() {
        let config = BackupConfig {
            retention: RetentionPolicy {
                retain_days: 0, // Immediate expiry for testing
                min_full_backups: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let manager = BackupManager::new(config);
        
        // Create and complete two backups
        for _ in 0..2 {
            let backup = manager.start_backup(BackupType::Full, None).await.unwrap();
            manager
                .complete_backup(&backup.id, 1024, 10, "test".to_string())
                .await
                .unwrap();
        }
        
        // Apply retention - should keep min_full_backups (1)
        let deleted = manager.apply_retention().await.unwrap();
        
        let remaining = manager.list_recovery_points().await;
        assert!(remaining.len() >= 1);
    }
    
    #[test]
    fn test_schedule_next_run() {
        let schedule = BackupSchedule::Daily { hour: 2 };
        let now = SystemTime::now();
        let next = schedule.next_run(now);
        
        let diff = next.duration_since(now).unwrap();
        assert_eq!(diff.as_secs(), 86400);
    }
}
