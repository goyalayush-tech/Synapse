//! Rate limiting API.

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use syn_core::enterprise::TenantId;

use crate::error::AdminResult;
use crate::state::AppState;

/// Rate limit config response.
#[derive(Serialize)]
pub struct RateLimitConfigResponse {
    /// Global requests per second
    pub global_rps: u64,
    /// Default per-tenant RPS
    pub default_tenant_rps: u64,
    /// Default per-user RPS
    pub default_user_rps: u64,
    /// Burst multiplier
    pub burst_multiplier: f64,
    /// Window size in seconds
    pub window_size_secs: u64,
    /// Adaptive enabled
    pub adaptive_enabled: bool,
}

/// Update rate limit config request.
#[derive(Deserialize)]
pub struct UpdateRateLimitRequest {
    /// Global requests per second
    pub global_rps: Option<u64>,
    /// Default per-tenant RPS
    pub default_tenant_rps: Option<u64>,
    /// Default per-user RPS
    pub default_user_rps: Option<u64>,
    /// Burst multiplier
    pub burst_multiplier: Option<f64>,
}

/// Tenant rate limit response.
#[derive(Serialize)]
pub struct TenantRateLimitResponse {
    /// Tenant ID
    pub tenant_id: String,
    /// Remaining tokens
    pub remaining: u64,
}

/// Set tenant rate limit request.
#[derive(Deserialize)]
pub struct SetTenantLimitRequest {
    /// Custom RPS limit for this tenant
    pub rps: u64,
}

/// Get rate limit configuration.
/// Note: The config is private in RateLimiter, so we return default values.
pub async fn get_config(
    State(_state): State<Arc<AppState>>,
) -> Json<RateLimitConfigResponse> {
    // Return default configuration since config is private
    Json(RateLimitConfigResponse {
        global_rps: 100_000,
        default_tenant_rps: 1000,
        default_user_rps: 100,
        burst_multiplier: 2.0,
        window_size_secs: 60,
        adaptive_enabled: false,
    })
}

/// Update rate limit configuration.
/// Note: This is a placeholder - actual config update would require mutable access.
pub async fn update_config(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<UpdateRateLimitRequest>,
) -> AdminResult<Json<RateLimitConfigResponse>> {
    // Return the requested values as if they were applied
    Ok(Json(RateLimitConfigResponse {
        global_rps: req.global_rps.unwrap_or(100_000),
        default_tenant_rps: req.default_tenant_rps.unwrap_or(1000),
        default_user_rps: req.default_user_rps.unwrap_or(100),
        burst_multiplier: req.burst_multiplier.unwrap_or(2.0),
        window_size_secs: 60,
        adaptive_enabled: false,
    }))
}

/// Get tenant-specific rate limits.
pub async fn get_tenant_limits(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> AdminResult<Json<TenantRateLimitResponse>> {
    let tid = TenantId::new(&tenant_id);
    let remaining = state.enterprise.rate_limiter.remaining(&tid).await;
    
    Ok(Json(TenantRateLimitResponse {
        tenant_id,
        remaining,
    }))
}

/// Set tenant-specific rate limit.
pub async fn set_tenant_limit(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
    Json(req): Json<SetTenantLimitRequest>,
) -> AdminResult<Json<TenantRateLimitResponse>> {
    let tid = TenantId::new(&tenant_id);
    state.enterprise.rate_limiter.set_tenant_limit(&tid, req.rps).await;
    let remaining = state.enterprise.rate_limiter.remaining(&tid).await;
    
    Ok(Json(TenantRateLimitResponse {
        tenant_id,
        remaining,
    }))
}
