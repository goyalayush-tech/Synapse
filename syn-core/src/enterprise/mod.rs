//! Enterprise Features for Synapse
//!
//! This module provides enterprise-grade capabilities for production deployments:
//!
//! - **Multi-tenancy**: Namespace isolation, resource quotas, and data segregation
//! - **Audit Logging**: Tamper-proof cryptographic audit chain for compliance
//! - **Rate Limiting**: Per-tenant request quotas and throttling
//! - **Geo-replication**: Cross-region data replication with conflict resolution
//! - **SSO Integration**: SAML/OIDC authentication for enterprise identity
//! - **Backup/DR**: Point-in-time recovery and disaster recovery
//!
//! # Architecture
//!
//! Enterprise features are designed to be optional and modular. They can be
//! enabled via feature flags and compose with the core Synapse functionality.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    ENTERPRISE LAYER                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌─────────────┐  │
//! │  │ Tenancy   │  │  Audit    │  │  Rate     │  │   Geo       │  │
//! │  │ Manager   │  │  Chain    │  │  Limiter  │  │   Repl      │  │
//! │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └──────┬──────┘  │
//! │        │              │              │               │         │
//! │        └──────────────┴──────────────┴───────────────┘         │
//! │                              │                                  │
//! │                    ┌─────────┴─────────┐                       │
//! │                    │  EnterpriseContext │                       │
//! │                    └───────────────────┘                       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod audit;
pub mod backup;
pub mod geo_replication;
pub mod rate_limit;
pub mod tenancy;

pub use audit::{
    AuditCategory, AuditChain, AuditConfig, AuditEntry, AuditError, AuditEvent, AuditResult,
    AuditSeverity,
};
pub use backup::{
    BackupConfig, BackupError, BackupManager, BackupResult, BackupSchedule, BackupType,
    RecoveryPoint,
};
pub use geo_replication::{
    ConflictResolver, GeoRegion, ReplicationConfig, ReplicationError, ReplicationManager,
    ReplicationResult,
};
pub use rate_limit::{
    QuotaConfig, QuotaManager, RateLimitConfig, RateLimitResult, RateLimiter, SlidingWindow,
    TokenBucket,
};
pub use tenancy::{
    Namespace, ResourceQuota, Tenant, TenantConfig, TenantError, TenantId, TenantManager,
    TenantResult, TenantStatus, TenantTier,
};

use std::sync::Arc;

/// Enterprise context that holds all enterprise service instances.
///
/// This provides a single entry point for accessing enterprise features
/// and ensures proper initialization order.
#[derive(Clone)]
pub struct EnterpriseContext {
    /// Tenant management
    pub tenancy: Arc<TenantManager>,
    /// Audit logging
    pub audit: Arc<AuditChain>,
    /// Rate limiting
    pub rate_limiter: Arc<RateLimiter>,
    /// Geo-replication
    pub replication: Arc<ReplicationManager>,
    /// Backup management
    pub backup: Arc<BackupManager>,
}

/// Configuration for all enterprise features.
#[derive(Debug, Clone)]
pub struct EnterpriseConfig {
    /// Enable multi-tenancy
    pub tenancy_enabled: bool,
    /// Tenant configuration
    pub tenant_config: TenantConfig,
    /// Enable audit logging
    pub audit_enabled: bool,
    /// Audit configuration
    pub audit_config: AuditConfig,
    /// Enable rate limiting
    pub rate_limit_enabled: bool,
    /// Rate limit configuration
    pub rate_limit_config: RateLimitConfig,
    /// Enable geo-replication
    pub geo_replication_enabled: bool,
    /// Replication configuration
    pub replication_config: ReplicationConfig,
    /// Enable backup/DR
    pub backup_enabled: bool,
    /// Backup configuration
    pub backup_config: BackupConfig,
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            tenancy_enabled: false,
            tenant_config: TenantConfig::default(),
            audit_enabled: true, // Audit on by default for compliance
            audit_config: AuditConfig::default(),
            rate_limit_enabled: true,
            rate_limit_config: RateLimitConfig::default(),
            geo_replication_enabled: false,
            replication_config: ReplicationConfig::default(),
            backup_enabled: false,
            backup_config: BackupConfig::default(),
        }
    }
}

impl EnterpriseContext {
    /// Create a new enterprise context with the given configuration.
    pub async fn new(config: EnterpriseConfig) -> Self {
        let tenancy = Arc::new(TenantManager::new(config.tenant_config));
        let audit = Arc::new(AuditChain::new(config.audit_config));
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_config));
        let replication = Arc::new(ReplicationManager::new(config.replication_config));
        let backup = Arc::new(BackupManager::new(config.backup_config));

        Self {
            tenancy,
            audit,
            rate_limiter,
            replication,
            backup,
        }
    }

    /// Check if a request is allowed based on tenant quotas and rate limits.
    pub async fn check_request(
        &self,
        tenant_id: &TenantId,
        request_cost: u64,
    ) -> Result<(), EnterpriseError> {
        // Check tenant exists and is active
        self.tenancy.validate_tenant(tenant_id).await?;

        // Check rate limits
        self.rate_limiter.check(tenant_id, request_cost).await?;

        Ok(())
    }

    /// Record an audit event.
    pub async fn audit(&self, event: AuditEvent) -> AuditResult<AuditEntry> {
        self.audit.record(event).await
    }
}

/// Errors from enterprise features.
#[derive(Debug, thiserror::Error)]
pub enum EnterpriseError {
    /// Tenant error
    #[error("Tenant error: {0}")]
    Tenant(#[from] TenantError),

    /// Audit error
    #[error("Audit error: {0}")]
    Audit(#[from] AuditError),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Replication error
    #[error("Replication error: {0}")]
    Replication(#[from] ReplicationError),

    /// Backup error
    #[error("Backup error: {0}")]
    Backup(#[from] BackupError),
}
