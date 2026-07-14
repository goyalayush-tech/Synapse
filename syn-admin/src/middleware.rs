//! Authentication middleware for the admin API.
//!
//! When `AdminConfig::auth_enabled` is `true` (set via `ADMIN_AUTH_ENABLED=1`),
//! every request handled by this middleware must present a bearer token that
//! matches `AdminConfig::session_secret` (set via `ADMIN_SESSION_SECRET`).
//! When `auth_enabled` is `false` (the default), requests pass through
//! unchanged, preserving the existing dev-mode behavior.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::error::AdminError;
use crate::state::AppState;

/// Axum middleware enforcing bearer-token authentication on protected routes.
///
/// Intended to be applied via `.layer(middleware::from_fn_with_state(state, require_auth))`
/// on the `/api` nested router in `main.rs`.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.config.auth_enabled {
        return next.run(req).await;
    }

    let provided_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match provided_token {
        Some(token)
            if constant_time_eq(token.as_bytes(), state.config.session_secret.as_bytes()) =>
        {
            next.run(req).await
        }
        _ => {
            let err: Response = AdminError::Unauthorized.into_response();
            // AdminError::Unauthorized already maps to 401 with a JSON body
            // consistent with the rest of the crate's error responses.
            debug_assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
            err
        }
    }
}

/// Compare two byte slices in (best-effort) constant time.
///
/// This avoids leaking the matching token content via early-exit timing
/// differences. Slice length is still observable (a length mismatch is
/// rejected immediately), but that alone does not reveal token content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn equal_slices_match() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
    }

    #[test]
    fn different_slices_do_not_match() {
        assert!(!constant_time_eq(b"secret-token", b"wrong-token!"));
    }

    #[test]
    fn different_lengths_do_not_match() {
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
    }
}
