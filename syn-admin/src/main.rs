//! syn-admin - Enterprise Admin Web UI
//!
//! Run with: `cargo run --bin syn-admin`
//! Access at: http://localhost:8080

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{get, post, delete},
    Router,
};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::info;

use syn_admin::{
    AdminConfig, AppState,
    api, handlers,
};

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

    // Build router
    let app = Router::new()
        // HTML pages
        .route("/", get(handlers::dashboard))
        .route("/tenants", get(handlers::tenants_page))
        .route("/audit", get(handlers::audit_page))
        .route("/backups", get(handlers::backups_page))
        .route("/settings", get(handlers::settings_page))
        // API endpoints
        .nest("/api", api_routes())
        // Static files
        .nest_service("/static", ServeDir::new("syn-admin/static"))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
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
        .route("/rate-limits/:tenant_id", get(api::rate_limits::get_tenant_limits))
}
