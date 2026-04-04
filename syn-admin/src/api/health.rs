//! Health check API.

use std::sync::Arc;
use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::AppState;

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// Health check endpoint.
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
    })
}
