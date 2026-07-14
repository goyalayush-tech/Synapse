//! Rate limiting API.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use syn_core::enterprise::TenantId;

use crate::error::{AdminError, AdminResult};
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
    /// Explains which (if any) fields above are not sourced from the live
    /// `RateLimiter` because `syn_core::enterprise::rate_limit::RateLimiter`
    /// currently keeps its `RateLimitConfig` private with no read accessor.
    /// `None` once/if a real accessor is added upstream.
    pub note: Option<String>,
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
///
/// `syn_core::enterprise::rate_limit::RateLimiter` keeps its `RateLimitConfig`
/// as a private field with no public read accessor, and doesn't expose the
/// values used to build the global token bucket at construction time either.
/// There is currently no way to read the *live* global configuration through
/// `state.enterprise.rate_limiter`'s public API without a `syn-core` change,
/// which is out of scope here. Rather than silently presenting fabricated
/// numbers as live data, we return the compiled-in defaults
/// (`RateLimitConfig::default()`, which is also what the admin's
/// `EnterpriseContext` is constructed with in `AppState::new`) and clearly
/// flag them as such via the `note` field.
pub async fn get_config(State(_state): State<Arc<AppState>>) -> Json<RateLimitConfigResponse> {
    let defaults = syn_core::enterprise::RateLimitConfig::default();
    Json(RateLimitConfigResponse {
        global_rps: defaults.global_rps,
        default_tenant_rps: defaults.default_tenant_rps,
        default_user_rps: defaults.default_user_rps,
        burst_multiplier: defaults.burst_multiplier,
        window_size_secs: defaults.window_size_secs,
        adaptive_enabled: defaults.adaptive_enabled,
        note: Some(
            "These are compiled-in defaults, not the live RateLimiter configuration: \
             syn_core::enterprise::rate_limit::RateLimiter does not expose a read accessor \
             for its RateLimitConfig. Per-tenant limits (GET /api/rate-limits/:tenant_id) \
             do reflect live state."
                .to_string(),
        ),
    })
}

/// Update rate limit configuration.
///
/// `syn_core::enterprise::rate_limit::RateLimiter` has no method to mutate its
/// global `RateLimitConfig` after construction -- the only supported runtime
/// mutation is `set_tenant_limit`, which is per-tenant and reachable via
/// `POST /api/rate-limits/:tenant_id` (see `set_tenant_limit` below).
/// Rather than echoing the request back as if it had been applied, this
/// honestly reports that global config updates are not supported in this
/// build.
pub async fn update_config(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<UpdateRateLimitRequest>,
) -> AdminResult<Json<RateLimitConfigResponse>> {
    Err(AdminError::NotImplemented(
        "Global rate limit configuration is read-only in this build: \
         syn_core::enterprise::rate_limit::RateLimiter does not expose a mutator for its \
         global RateLimitConfig. Use POST /api/rate-limits/:tenant_id to set a per-tenant limit."
            .to_string(),
    ))
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
    state
        .enterprise
        .rate_limiter
        .set_tenant_limit(&tid, req.rps)
        .await;
    let remaining = state.enterprise.rate_limiter.remaining(&tid).await;

    Ok(Json(TenantRateLimitResponse {
        tenant_id,
        remaining,
    }))
}
