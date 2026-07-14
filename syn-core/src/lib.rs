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

pub mod enterprise;
pub mod error;
pub mod telemetry;
pub mod types;
pub mod uncopyable;

// Re-export primary types for ergonomic imports
pub use error::{Result, SynapseError};
pub use types::SessionId;
pub use uncopyable::{
    EbpfEvent, IntentRecord, PolicyVerdict, RuntimeStats, UncopyableConfig, UncopyableRuntime,
};

// Re-export enterprise types for convenience
pub use enterprise::{
    AuditCategory,
    AuditChain,
    AuditConfig,
    AuditEntry,
    AuditError,
    // Audit
    AuditEvent,
    AuditResult,
    AuditSeverity,
    BackupConfig,
    BackupError,
    // Backup
    BackupManager,
    BackupResult,
    BackupSchedule,
    BackupType,
    ConflictResolver,
    EnterpriseConfig,
    // Context and config
    EnterpriseContext,
    EnterpriseError,
    // Geo-replication
    GeoRegion,
    Namespace,
    QuotaConfig,
    QuotaManager,
    RateLimitConfig,
    RateLimitResult,
    // Rate limiting
    RateLimiter,
    RecoveryPoint,
    ReplicationConfig,
    ReplicationError,
    ReplicationManager,
    ReplicationResult,
    ResourceQuota,
    SlidingWindow,
    Tenant,
    TenantConfig,
    TenantError,
    // Tenancy
    TenantId,
    TenantManager,
    TenantResult,
    TenantStatus,
    TenantTier,
    TokenBucket,
};
