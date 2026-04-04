//! Audit log API.

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::error::AdminResult;
use crate::state::AppState;

/// Audit entry response.
#[derive(Serialize)]
pub struct AuditEntryResponse {
    /// Sequence number (used as ID)
    pub sequence: u64,
    /// Severity
    pub severity: String,
    /// Category
    pub category: String,
    /// Action
    pub action: String,
    /// Actor (who performed the action)
    pub actor: String,
    /// Resource affected
    pub resource: String,
    /// Details
    pub details: Option<String>,
    /// Timestamp
    pub timestamp: String,
    /// Hash
    pub hash: String,
}

/// List query parameters.
#[derive(Deserialize)]
pub struct ListQuery {
    /// Maximum entries to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Filter by severity
    pub severity: Option<String>,
    /// Filter by category
    pub category: Option<String>,
}

/// Chain verification response.
#[derive(Serialize)]
pub struct VerifyResponse {
    /// Whether the chain is valid
    pub valid: bool,
    /// Total entries in chain
    pub entries_count: u64,
    /// Error message if invalid
    pub error: Option<String>,
}

/// List audit entries.
pub async fn list_entries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Json<Vec<AuditEntryResponse>> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    
    let entries = state.enterprise.audit.list_entries(offset, limit).await;
    
    let responses: Vec<AuditEntryResponse> = entries.into_iter().map(|e| {
        AuditEntryResponse {
            sequence: e.sequence,
            severity: format!("{:?}", e.event.severity),
            category: format!("{:?}", e.event.category),
            action: e.event.action.clone(),
            actor: e.event.actor.clone(),
            resource: e.event.resource.clone(),
            details: e.event.details.clone(),
            timestamp: format_time(e.timestamp),
            hash: e.hash.clone(),
        }
    }).collect();
    
    Json(responses)
}

/// Export audit entries.
pub async fn export_entries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Json<Vec<AuditEntryResponse>> {
    // Same as list but typically returns more entries
    let limit = query.limit.unwrap_or(10000);
    let offset = query.offset.unwrap_or(0);
    
    let entries = state.enterprise.audit.list_entries(offset, limit).await;
    
    let responses: Vec<AuditEntryResponse> = entries.into_iter().map(|e| {
        AuditEntryResponse {
            sequence: e.sequence,
            severity: format!("{:?}", e.event.severity),
            category: format!("{:?}", e.event.category),
            action: e.event.action.clone(),
            actor: e.event.actor.clone(),
            resource: e.event.resource.clone(),
            details: e.event.details.clone(),
            timestamp: format_time(e.timestamp),
            hash: e.hash.clone(),
        }
    }).collect();
    
    Json(responses)
}

/// Verify audit chain integrity.
pub async fn verify_chain(
    State(state): State<Arc<AppState>>,
) -> AdminResult<Json<VerifyResponse>> {
    let stats = state.enterprise.audit.stats().await;
    
    match state.enterprise.audit.verify_chain().await {
        Ok(is_valid) => Ok(Json(VerifyResponse {
            valid: is_valid,
            entries_count: stats.in_memory_entries,
            error: if is_valid { None } else { Some("Chain integrity check failed".to_string()) },
        })),
        Err(e) => Ok(Json(VerifyResponse {
            valid: false,
            entries_count: 0,
            error: Some(e.to_string()),
        })),
    }
}

fn format_time(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
