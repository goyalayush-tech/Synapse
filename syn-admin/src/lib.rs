//! # syn-admin
//!
//! Enterprise Admin Web UI for Synapse cluster management.
//!
//! This crate provides a server-rendered dashboard for:
//! - Cluster health monitoring
//! - Tenant management
//! - Audit log viewing
//! - Rate limit configuration
//! - Backup management
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      SYN-ADMIN WEB UI                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                    Axum Router                           │    │
//! │  ├─────────────────────────────────────────────────────────┤    │
//! │  │  /              → Dashboard (HTML)                      │    │
//! │  │  /api/health    → Health Check (JSON)                   │    │
//! │  │  /api/cluster   → Cluster Status (JSON)                 │    │
//! │  │  /api/tenants   → Tenant CRUD (JSON)                    │    │
//! │  │  /api/audit     → Audit Logs (JSON)                     │    │
//! │  │  /api/backups   → Backup Management (JSON)              │    │
//! │  │  /static/*      → Static Assets (CSS, JS)               │    │
//! │  └─────────────────────────────────────────────────────────┘    │
//! │                              │                                   │
//! │  ┌───────────────────────────┴───────────────────────────┐      │
//! │  │                   AppState (Arc)                       │      │
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │      │
//! │  │  │ Enterprise  │  │   Metrics   │  │   Config    │   │      │
//! │  │  │  Context    │  │   Registry  │  │             │   │      │
//! │  │  └─────────────┘  └─────────────┘  └─────────────┘   │      │
//! │  └───────────────────────────────────────────────────────┘      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod api;
pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod state;
pub mod templates;

pub use config::AdminConfig;
pub use error::{AdminError, AdminResult};
pub use state::AppState;
