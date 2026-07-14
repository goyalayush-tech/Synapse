//! Backup management API.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use syn_core::enterprise::BackupType;

use crate::error::{AdminError, AdminResult};
use crate::state::AppState;

/// Backup response.
#[derive(Serialize)]
pub struct BackupResponse {
    /// Backup ID
    pub id: String,
    /// Backup type
    pub backup_type: String,
    /// Status
    pub status: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Size formatted
    pub size_human: String,
    /// Object count
    pub object_count: u64,
    /// Created at
    pub created_at: String,
    /// Completed at
    pub completed_at: Option<String>,
    /// Parent backup ID (for incremental)
    pub parent_id: Option<String>,
    /// Checksum
    pub checksum: String,
}

/// Create backup request.
#[derive(Deserialize)]
pub struct CreateBackupRequest {
    /// Backup type
    pub backup_type: Option<String>,
    /// Tenant ID (optional, for tenant-specific backup)
    pub tenant_id: Option<String>,
}

/// Restore request.
#[derive(Deserialize)]
pub struct RestoreRequest {
    /// Target time (ISO timestamp) for point-in-time recovery
    pub target_time: Option<String>,
}

/// List all backups.
pub async fn list_backups(State(state): State<Arc<AppState>>) -> Json<Vec<BackupResponse>> {
    let backups = state.enterprise.backup.list_recovery_points().await;

    let responses: Vec<BackupResponse> = backups
        .into_iter()
        .map(|b| BackupResponse {
            id: b.id.clone(),
            backup_type: format!("{:?}", b.backup_type),
            status: format!("{:?}", b.status),
            size_bytes: b.size_bytes,
            size_human: format_bytes(b.size_bytes),
            object_count: b.object_count,
            created_at: format_time(b.created_at),
            completed_at: b.completed_at.map(format_time),
            parent_id: b.parent_id.clone(),
            checksum: b.checksum.clone(),
        })
        .collect();

    Json(responses)
}

/// Get a specific backup.
pub async fn get_backup(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AdminResult<Json<BackupResponse>> {
    let backup = state.enterprise.backup.get_recovery_point(&id).await?;

    Ok(Json(BackupResponse {
        id: backup.id.clone(),
        backup_type: format!("{:?}", backup.backup_type),
        status: format!("{:?}", backup.status),
        size_bytes: backup.size_bytes,
        size_human: format_bytes(backup.size_bytes),
        object_count: backup.object_count,
        created_at: format_time(backup.created_at),
        completed_at: backup.completed_at.map(format_time),
        parent_id: backup.parent_id.clone(),
        checksum: backup.checksum.clone(),
    }))
}

/// Create a new backup.
pub async fn create_backup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBackupRequest>,
) -> AdminResult<Json<BackupResponse>> {
    let backup_type = match req.backup_type.as_deref() {
        Some("Full") => BackupType::Full,
        Some("Differential") => BackupType::Differential,
        Some("Snapshot") => BackupType::Snapshot,
        _ => BackupType::Incremental,
    };

    let backup = state
        .enterprise
        .backup
        .start_backup(backup_type, req.tenant_id)
        .await?;

    Ok(Json(BackupResponse {
        id: backup.id.clone(),
        backup_type: format!("{:?}", backup.backup_type),
        status: format!("{:?}", backup.status),
        size_bytes: backup.size_bytes,
        size_human: format_bytes(backup.size_bytes),
        object_count: backup.object_count,
        created_at: format_time(backup.created_at),
        completed_at: backup.completed_at.map(format_time),
        parent_id: backup.parent_id.clone(),
        checksum: backup.checksum.clone(),
    }))
}

/// Delete a backup.
pub async fn delete_backup(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AdminResult<Json<serde_json::Value>> {
    state.enterprise.backup.delete_recovery_point(&id).await?;

    Ok(Json(serde_json::json!({
        "status": "deleted",
        "id": id,
    })))
}

/// Restore from a backup.
///
/// `syn_core::enterprise::backup::BackupManager` has no method that actually
/// performs (or queues) a restore -- it can create, complete, list, and
/// delete recovery points, and `find_recovery_chain` can compute which
/// recovery points *would* be needed for a point-in-time restore, but
/// nothing in its public API applies a backup back onto the running system.
/// Returning a fabricated `"restore_initiated"` success would mislead
/// callers into thinking data recovery is underway when nothing happens.
/// Instead, we verify the backup exists (a real check) and then honestly
/// report that restore execution is not implemented in this build.
pub async fn restore_backup(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(_req): Json<RestoreRequest>,
) -> AdminResult<Json<serde_json::Value>> {
    // Verify the backup exists before reporting anything about it.
    state.enterprise.backup.get_recovery_point(&id).await?;

    Err(AdminError::NotImplemented(format!(
        "Restore execution is not implemented in this build: \
         syn_core::enterprise::backup::BackupManager has no method to apply a backup back \
         onto the running system (only create/list/delete recovery points are supported). \
         Backup '{}' exists and was verified, but no restore was queued or performed.",
        id
    )))
}

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

    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
