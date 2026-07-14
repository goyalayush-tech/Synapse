//! Tenant management API.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use syn_core::enterprise::{TenantId, TenantTier};

use crate::error::{AdminError, AdminResult};
use crate::state::AppState;

/// Tenant response.
#[derive(Serialize)]
pub struct TenantResponse {
    /// Tenant ID
    pub id: String,
    /// Tenant name
    pub name: String,
    /// Tier
    pub tier: String,
    /// Status
    pub status: String,
    /// Created at
    pub created_at: String,
    /// Quota
    pub quota: QuotaInfo,
}

/// Quota info.
#[derive(Serialize)]
pub struct QuotaInfo {
    /// Max requests per second
    pub max_rps: u64,
    /// Max storage bytes
    pub max_storage_bytes: u64,
    /// Max namespaces
    pub max_namespaces: u32,
}

/// Create tenant request.
#[derive(Deserialize)]
pub struct CreateTenantRequest {
    /// Tenant ID (optional, will be generated if not provided)
    pub id: Option<String>,
    /// Tenant name
    pub name: String,
    /// Tier (optional, defaults to Free)
    pub tier: Option<String>,
}

/// Update quota request.
#[derive(Deserialize)]
pub struct UpdateQuotaRequest {
    /// Max requests per second
    pub max_rps: Option<u64>,
    /// Max storage bytes
    pub max_storage_bytes: Option<u64>,
    /// Max namespaces
    pub max_namespaces: Option<u32>,
}

/// List all tenants.
pub async fn list_tenants(State(state): State<Arc<AppState>>) -> Json<Vec<TenantResponse>> {
    let tenants = state.enterprise.tenancy.list_tenants().await;

    let responses: Vec<TenantResponse> = tenants
        .into_iter()
        .map(|t| TenantResponse {
            id: t.id.to_string(),
            name: t.name.clone(),
            tier: format!("{:?}", t.tier),
            status: format!("{:?}", t.status),
            created_at: format_time(t.created_at),
            quota: QuotaInfo {
                max_rps: t.quota.max_rps,
                max_storage_bytes: t.quota.max_storage_bytes,
                max_namespaces: t.quota.max_namespaces,
            },
        })
        .collect();

    Json(responses)
}

/// Get a specific tenant.
pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AdminResult<Json<TenantResponse>> {
    let tenant_id = TenantId::new(&id);
    let tenant = state
        .enterprise
        .tenancy
        .get_tenant(&tenant_id)
        .await
        .map_err(|e| AdminError::NotFound(format!("Tenant not found: {} - {}", id, e)))?;

    Ok(Json(TenantResponse {
        id: tenant.id.to_string(),
        name: tenant.name.clone(),
        tier: format!("{:?}", tenant.tier),
        status: format!("{:?}", tenant.status),
        created_at: format_time(tenant.created_at),
        quota: QuotaInfo {
            max_rps: tenant.quota.max_rps,
            max_storage_bytes: tenant.quota.max_storage_bytes,
            max_namespaces: tenant.quota.max_namespaces,
        },
    }))
}

/// Create a new tenant.
pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTenantRequest>,
) -> AdminResult<Json<TenantResponse>> {
    let tier = match req.tier.as_deref() {
        Some("Starter") => Some(TenantTier::Starter),
        Some("Professional") => Some(TenantTier::Professional),
        Some("Enterprise") => Some(TenantTier::Enterprise),
        Some("Free") => Some(TenantTier::Free),
        _ => None,
    };

    // Generate a tenant ID if not provided
    let tenant_id = match req.id {
        Some(id) => TenantId::new(&id),
        None => TenantId::new(&uuid::Uuid::new_v4().to_string()),
    };

    let tenant = state
        .enterprise
        .tenancy
        .create_tenant(tenant_id, req.name, tier)
        .await?;

    Ok(Json(TenantResponse {
        id: tenant.id.to_string(),
        name: tenant.name.clone(),
        tier: format!("{:?}", tenant.tier),
        status: format!("{:?}", tenant.status),
        created_at: format_time(tenant.created_at),
        quota: QuotaInfo {
            max_rps: tenant.quota.max_rps,
            max_storage_bytes: tenant.quota.max_storage_bytes,
            max_namespaces: tenant.quota.max_namespaces,
        },
    }))
}

/// Delete a tenant.
pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AdminResult<Json<serde_json::Value>> {
    let tenant_id = TenantId::new(&id);
    state.enterprise.tenancy.delete_tenant(&tenant_id).await?;

    Ok(Json(serde_json::json!({
        "status": "deleted",
        "id": id,
    })))
}

/// Update tenant quota.
pub async fn update_quota(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateQuotaRequest>,
) -> AdminResult<Json<TenantResponse>> {
    let tenant_id = TenantId::new(&id);

    // Get current tenant
    let mut tenant = state
        .enterprise
        .tenancy
        .get_tenant(&tenant_id)
        .await
        .map_err(|e| AdminError::NotFound(format!("Tenant not found: {} - {}", id, e)))?;

    // Update quota fields
    if let Some(rps) = req.max_rps {
        tenant.quota.max_rps = rps;
    }
    if let Some(storage) = req.max_storage_bytes {
        tenant.quota.max_storage_bytes = storage;
    }
    if let Some(ns) = req.max_namespaces {
        tenant.quota.max_namespaces = ns;
    }

    // Update tenant via the manager
    state
        .enterprise
        .tenancy
        .update_tenant(tenant.clone())
        .await?;

    Ok(Json(TenantResponse {
        id: tenant.id.to_string(),
        name: tenant.name.clone(),
        tier: format!("{:?}", tenant.tier),
        status: format!("{:?}", tenant.status),
        created_at: format_time(tenant.created_at),
        quota: QuotaInfo {
            max_rps: tenant.quota.max_rps,
            max_storage_bytes: tenant.quota.max_storage_bytes,
            max_namespaces: tenant.quota.max_namespaces,
        },
    }))
}

fn format_time(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
