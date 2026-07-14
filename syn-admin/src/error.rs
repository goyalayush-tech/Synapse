//! Error types for the admin web UI.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Admin UI errors.
#[derive(Debug, Error)]
pub enum AdminError {
    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Unauthorized
    #[error("Unauthorized")]
    Unauthorized,

    /// Forbidden
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Feature not implemented / not supported by the underlying API in this build
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Enterprise error
    #[error("Enterprise error: {0}")]
    Enterprise(#[from] syn_core::EnterpriseError),

    /// Tenant error
    #[error("Tenant error: {0}")]
    Tenant(#[from] syn_core::TenantError),

    /// Audit error
    #[error("Audit error: {0}")]
    Audit(#[from] syn_core::AuditError),

    /// Backup error
    #[error("Backup error: {0}")]
    Backup(#[from] syn_core::BackupError),
}

/// Result type for admin operations.
pub type AdminResult<T> = std::result::Result<T, AdminError>;

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AdminError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AdminError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AdminError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AdminError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AdminError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AdminError::NotImplemented(msg) => (StatusCode::NOT_IMPLEMENTED, msg.clone()),
            AdminError::Enterprise(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AdminError::Tenant(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AdminError::Audit(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AdminError::Backup(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        let body = json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
            }
        });

        (status, Json(body)).into_response()
    }
}
