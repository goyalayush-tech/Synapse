//! Application state shared across handlers.

use std::time::SystemTime;
use tokio::sync::RwLock;

use syn_core::enterprise::{
    AuditConfig, BackupConfig, EnterpriseConfig, EnterpriseContext, RateLimitConfig, TenantConfig,
};

use crate::config::AdminConfig;
use crate::error::AdminResult;

/// Cluster node information.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Node ID
    pub id: String,
    /// Node address
    pub address: String,
    /// Node status
    pub status: NodeStatus,
    /// Last heartbeat
    pub last_heartbeat: SystemTime,
}

/// Node status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is healthy
    Healthy,
    /// Node is degraded
    Degraded,
    /// Node is offline
    Offline,
}

/// Cluster metrics.
#[derive(Debug, Clone, Default)]
pub struct ClusterMetrics {
    /// Total events processed
    pub events_processed: u64,
    /// Events per second
    pub events_per_second: f64,
    /// Active connections
    pub active_connections: u64,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Storage used in bytes
    pub storage_bytes: u64,
}

/// Application state.
pub struct AppState {
    /// Admin configuration
    pub config: AdminConfig,
    /// Enterprise context
    pub enterprise: EnterpriseContext,
    /// Cluster nodes (mock for now)
    pub nodes: RwLock<Vec<NodeInfo>>,
    /// Cluster metrics
    pub metrics: RwLock<ClusterMetrics>,
    /// Server start time
    pub started_at: SystemTime,
}

impl AppState {
    /// Create new application state.
    pub async fn new(config: AdminConfig) -> AdminResult<Self> {
        // Initialize enterprise context with default config
        let enterprise_config = EnterpriseConfig {
            tenancy_enabled: true,
            tenant_config: TenantConfig::default(),
            audit_enabled: true,
            audit_config: AuditConfig::default(),
            rate_limit_enabled: true,
            rate_limit_config: RateLimitConfig::default(),
            geo_replication_enabled: false,
            replication_config: Default::default(),
            backup_enabled: true,
            backup_config: BackupConfig::default(),
        };

        let enterprise = EnterpriseContext::new(enterprise_config).await;

        // Initialize mock cluster nodes
        let nodes = vec![
            NodeInfo {
                id: "node-1".to_string(),
                address: "127.0.0.1:9001".to_string(),
                status: NodeStatus::Healthy,
                last_heartbeat: SystemTime::now(),
            },
            NodeInfo {
                id: "node-2".to_string(),
                address: "127.0.0.1:9002".to_string(),
                status: NodeStatus::Healthy,
                last_heartbeat: SystemTime::now(),
            },
            NodeInfo {
                id: "node-3".to_string(),
                address: "127.0.0.1:9003".to_string(),
                status: NodeStatus::Degraded,
                last_heartbeat: SystemTime::now(),
            },
        ];

        Ok(Self {
            config,
            enterprise,
            nodes: RwLock::new(nodes),
            metrics: RwLock::new(ClusterMetrics::default()),
            started_at: SystemTime::now(),
        })
    }

    /// Get server uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.started_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Format uptime as human-readable string.
    pub fn uptime_human(&self) -> String {
        let secs = self.uptime_secs();
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;

        if days > 0 {
            format!("{}d {}h {}m", days, hours, mins)
        } else if hours > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}m", mins)
        }
    }
}
