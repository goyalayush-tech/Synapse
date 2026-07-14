//! Configuration for the admin web UI.

use std::env;

/// Admin server configuration.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// Listen address (e.g., "0.0.0.0:8080")
    pub listen_addr: String,
    /// Base URL for the admin UI
    pub base_url: String,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Session secret for cookies
    pub session_secret: String,
    /// Synapse cluster address
    pub cluster_addr: String,
    /// Refresh interval for dashboard (seconds)
    pub refresh_interval: u64,
    /// Allowed CORS origins for cross-origin API access.
    ///
    /// Empty by default, meaning no cross-origin requests are permitted
    /// (same-origin only). Populate via `ADMIN_CORS_ORIGINS` with a
    /// comma-separated list of origins (e.g.
    /// `https://admin.example.com,https://ops.example.com`) to allow
    /// specific origins to call the API.
    pub cors_allowed_origins: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            base_url: "http://localhost:8080".to_string(),
            auth_enabled: false,
            session_secret: "change-me-in-production".to_string(),
            cluster_addr: "127.0.0.1:9000".to_string(),
            refresh_interval: 5,
            cors_allowed_origins: Vec::new(),
        }
    }
}

impl AdminConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        Self {
            listen_addr: env::var("ADMIN_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            base_url: env::var("ADMIN_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            auth_enabled: env::var("ADMIN_AUTH_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            session_secret: env::var("ADMIN_SESSION_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
            cluster_addr: env::var("SYNAPSE_CLUSTER_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9000".to_string()),
            refresh_interval: env::var("ADMIN_REFRESH_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            cors_allowed_origins: env::var("ADMIN_CORS_ORIGINS")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}
