//! # syn-core
//!
//! Core domain logic and shared infrastructure for the Synapse distributed event ledger.
//!
//! This crate serves as the foundational bedrock, containing:
//! - **Domain Types**: Newtypes like [`SessionId`] that prevent primitive obsession
//! - **Error Handling**: Unified [`SynapseError`] enum for consistent error propagation
//! - **Telemetry**: Centralized tracing configuration for observability
//! - **Uncopyable Runtime**: Environmental Entanglement orchestration
//! - **Enterprise**: Multi-tenancy, audit logging, rate limiting, geo-replication, backup/DR
//!
//! ## Design Philosophy
//!
//! `syn-core` is designed to be "pure" - it contains no I/O logic and has minimal
//! dependencies. This ensures fast compilation and easy testing. All crates in the
//! workspace depend on `syn-core`, but `syn-core` depends on none of them.

pub mod error;
pub mod telemetry;
pub mod types;
pub mod uncopyable;
pub mod enterprise;

// Re-export primary types for ergonomic imports
pub use error::{Result, SynapseError};
pub use types::SessionId;
pub use uncopyable::{
    EbpfEvent, IntentRecord, PolicyVerdict, UncopyableConfig, UncopyableRuntime, RuntimeStats,
};

// Re-export enterprise types for convenience
pub use enterprise::{
    // Context and config
    EnterpriseContext, EnterpriseConfig, EnterpriseError,
    // Tenancy
    TenantId, Tenant, TenantManager, TenantConfig, Namespace, ResourceQuota,
    TenantTier, TenantStatus, TenantError, TenantResult,
    // Audit
    AuditEvent, AuditChain, AuditEntry, AuditSeverity, AuditCategory, AuditConfig,
    AuditError, AuditResult,
    // Rate limiting
    RateLimiter, RateLimitConfig, RateLimitResult, TokenBucket, SlidingWindow,
    QuotaManager, QuotaConfig,
    // Geo-replication
    GeoRegion, ReplicationConfig, ReplicationManager, ConflictResolver,
    ReplicationError, ReplicationResult,
    // Backup
    BackupManager, BackupConfig, BackupSchedule, RecoveryPoint, BackupType,
    BackupError, BackupResult,
};
