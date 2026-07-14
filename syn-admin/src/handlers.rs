//! HTML page handlers.

use askama::Template;
use axum::extract::State;
use std::sync::Arc;

use crate::error::AdminResult;
use crate::state::{AppState, NodeStatus};

/// Dashboard page template.
#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    /// Page title
    pub title: String,
    /// Number of healthy nodes
    pub healthy_nodes: usize,
    /// Total nodes
    pub total_nodes: usize,
    /// Active tenants
    pub active_tenants: usize,
    /// Events processed
    pub events_processed: u64,
    /// Server uptime
    pub uptime: String,
    /// Refresh interval in seconds
    pub refresh_interval: u64,
}

/// Tenants page template.
#[derive(Template)]
#[template(path = "tenants.html")]
pub struct TenantsTemplate {
    /// Page title
    pub title: String,
    /// List of tenants
    pub tenants: Vec<TenantRow>,
}

/// Tenant row for display.
pub struct TenantRow {
    /// Tenant ID
    pub id: String,
    /// Tenant name
    pub name: String,
    /// Tier
    pub tier: String,
    /// Status
    pub status: String,
    /// Request count
    pub request_count: u64,
}

/// Audit page template.
#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditTemplate {
    /// Page title
    pub title: String,
    /// Total entries
    pub total_entries: usize,
    /// Chain verified
    pub chain_verified: bool,
}

/// Backups page template.
#[derive(Template)]
#[template(path = "backups.html")]
pub struct BackupsTemplate {
    /// Page title
    pub title: String,
    /// List of backups
    pub backups: Vec<BackupRow>,
    /// Next scheduled backup
    pub next_scheduled: String,
}

/// Backup row for display.
pub struct BackupRow {
    /// Backup ID
    pub id: String,
    /// Backup type
    pub backup_type: String,
    /// Status
    pub status: String,
    /// Size
    pub size: String,
    /// Created at
    pub created_at: String,
}

/// Settings page template.
#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    /// Page title
    pub title: String,
    /// Cluster address
    pub cluster_addr: String,
    /// Auth enabled
    pub auth_enabled: bool,
}

/// Dashboard page handler.
pub async fn dashboard(State(state): State<Arc<AppState>>) -> AdminResult<DashboardTemplate> {
    let nodes = state.nodes.read().await;
    let healthy = nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Healthy)
        .count();
    let metrics = state.metrics.read().await;
    let tenants = state.enterprise.tenancy.list_tenants().await;

    Ok(DashboardTemplate {
        title: "Dashboard - Synapse Admin".to_string(),
        healthy_nodes: healthy,
        total_nodes: nodes.len(),
        active_tenants: tenants.len(),
        events_processed: metrics.events_processed,
        uptime: state.uptime_human(),
        refresh_interval: state.config.refresh_interval,
    })
}

/// Tenants page handler.
pub async fn tenants_page(State(state): State<Arc<AppState>>) -> AdminResult<TenantsTemplate> {
    let tenants = state.enterprise.tenancy.list_tenants().await;

    let tenant_rows: Vec<TenantRow> = tenants
        .into_iter()
        .map(|t| {
            TenantRow {
                id: t.id.to_string(),
                name: t.name.clone(),
                tier: format!("{:?}", t.tier),
                status: format!("{:?}", t.status),
                request_count: 0, // TODO: Get from metrics
            }
        })
        .collect();

    Ok(TenantsTemplate {
        title: "Tenants - Synapse Admin".to_string(),
        tenants: tenant_rows,
    })
}

/// Audit page handler.
pub async fn audit_page(State(state): State<Arc<AppState>>) -> AdminResult<AuditTemplate> {
    let stats = state.enterprise.audit.stats().await;
    let verified = state.enterprise.audit.verify_chain().await.is_ok();

    Ok(AuditTemplate {
        title: "Audit Log - Synapse Admin".to_string(),
        total_entries: stats.total_entries as usize,
        chain_verified: verified,
    })
}

/// Backups page handler.
pub async fn backups_page(State(state): State<Arc<AppState>>) -> AdminResult<BackupsTemplate> {
    let backups = state.enterprise.backup.list_recovery_points().await;
    let next = state.enterprise.backup.next_scheduled_backup().await;

    let backup_rows: Vec<BackupRow> = backups
        .into_iter()
        .map(|b| BackupRow {
            id: b.id.clone(),
            backup_type: format!("{:?}", b.backup_type),
            status: format!("{:?}", b.status),
            size: format_bytes(b.size_bytes),
            created_at: format_time(b.created_at),
        })
        .collect();

    let next_scheduled = next
        .map(|t| format_time(t))
        .unwrap_or_else(|| "Not scheduled".to_string());

    Ok(BackupsTemplate {
        title: "Backups - Synapse Admin".to_string(),
        backups: backup_rows,
        next_scheduled,
    })
}

/// Settings page handler.
pub async fn settings_page(State(state): State<Arc<AppState>>) -> AdminResult<SettingsTemplate> {
    Ok(SettingsTemplate {
        title: "Settings - Synapse Admin".to_string(),
        cluster_addr: state.config.cluster_addr.clone(),
        auth_enabled: state.config.auth_enabled,
    })
}

// Helper functions

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_time(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple ISO-like format
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_default();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
