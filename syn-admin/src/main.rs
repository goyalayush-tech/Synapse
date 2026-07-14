//! syn-admin - Enterprise Admin Web UI
//!
//! Run with: `cargo run --bin syn-admin`
//! Access at: http://localhost:8080

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::info;

use syn_admin::{api, handlers, middleware as admin_middleware, AdminConfig, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syn_admin=debug,tower_http=debug".into()),
        )
        .init();

    // Load configuration
    let config = AdminConfig::from_env();
    let addr: SocketAddr = config.listen_addr.parse()?;

    // Initialize application state
    let state = Arc::new(AppState::new(config).await?);

    // Build the CORS layer from the configured origin allowlist. Empty by
    // default (ADMIN_CORS_ORIGINS unset), which means no cross-origin
    // browser access is permitted -- same-origin requests are unaffected by
    // CORS entirely, and this crate has no public unauthenticated use case
    // that requires a wildcard. Mutating methods are restricted to the
    // allowlist; GET is included too since admin data is sensitive and
    // should not be readable cross-origin by default either.
    let allowed_origins: Vec<HeaderValue> = state
        .config
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);

    // Build router
    let app = Router::new()
        // HTML pages
        .route("/", get(handlers::dashboard))
        .route("/tenants", get(handlers::tenants_page))
        .route("/audit", get(handlers::audit_page))
        .route("/backups", get(handlers::backups_page))
        .route("/settings", get(handlers::settings_page))
        // API endpoints, protected by bearer-token auth when
        // ADMIN_AUTH_ENABLED=1 (see syn_admin::middleware::require_auth).
        .nest(
            "/api",
            api_routes().layer(middleware::from_fn_with_state(
                state.clone(),
                admin_middleware::require_auth,
            )),
        )
        // Static files
        .nest_service("/static", ServeDir::new("syn-admin/static"))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
        .with_state(state);

    info!("🚀 syn-admin starting on http://{}", addr);
    info!("📊 Dashboard: http://{}/", addr);
    info!("📡 API: http://{}/api/health", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build API routes
fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Health & Status
        .route("/health", get(api::health::health_check))
        .route("/cluster", get(api::cluster::get_status))
        .route("/metrics", get(api::cluster::get_metrics))
        // Tenants
        .route("/tenants", get(api::tenants::list_tenants))
        .route("/tenants", post(api::tenants::create_tenant))
        .route("/tenants/:id", get(api::tenants::get_tenant))
        .route("/tenants/:id", delete(api::tenants::delete_tenant))
        .route("/tenants/:id/quota", post(api::tenants::update_quota))
        // Audit
        .route("/audit", get(api::audit::list_entries))
        .route("/audit/export", get(api::audit::export_entries))
        .route("/audit/verify", post(api::audit::verify_chain))
        // Backups
        .route("/backups", get(api::backups::list_backups))
        .route("/backups", post(api::backups::create_backup))
        .route("/backups/:id", get(api::backups::get_backup))
        .route("/backups/:id", delete(api::backups::delete_backup))
        .route("/backups/:id/restore", post(api::backups::restore_backup))
        // Rate Limits
        .route("/rate-limits", get(api::rate_limits::get_config))
        .route("/rate-limits", post(api::rate_limits::update_config))
        .route(
            "/rate-limits/:tenant_id",
            get(api::rate_limits::get_tenant_limits),
        )
        .route(
            "/rate-limits/:tenant_id",
            post(api::rate_limits::set_tenant_limit),
        )
}
