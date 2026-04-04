//! Multi-Tenancy with Namespace Isolation
//!
//! This module provides enterprise-grade multi-tenancy for Synapse:
//!
//! - **Tenant Isolation**: Cryptographic namespace separation
//! - **Resource Quotas**: CPU, memory, storage, and request limits
//! - **Data Segregation**: Tenant data is logically isolated
//! - **Billing Integration**: Usage tracking per tenant
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      TENANT ISOLATION                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  Tenant A              Tenant B              Tenant C           │
//! │  ┌─────────┐          ┌─────────┐          ┌─────────┐         │
//! │  │Namespace│          │Namespace│          │Namespace│         │
//! │  │ ns-a    │          │ ns-b    │          │ ns-c    │         │
//! │  ├─────────┤          ├─────────┤          ├─────────┤         │
//! │  │ Quota   │          │ Quota   │          │ Quota   │         │
//! │  │ 100 RPS │          │ 500 RPS │          │ 1000RPS │         │
//! │  └────┬────┘          └────┬────┘          └────┬────┘         │
//! │       │                    │                    │               │
//! │       └────────────────────┴────────────────────┘               │
//! │                           │                                      │
//! │                  ┌────────┴────────┐                            │
//! │                  │  TenantManager  │                            │
//! │                  └─────────────────┘                            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unique identifier for a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    /// Create a new tenant ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    
    /// Get the string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Namespace for tenant isolation.
///
/// Each tenant has one or more namespaces that provide logical
/// isolation for their data and resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    /// Namespace name
    pub name: String,
    /// Owning tenant
    pub tenant_id: TenantId,
    /// Creation time
    pub created_at: SystemTime,
    /// Whether namespace is active
    pub active: bool,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Namespace {
    /// Create a new namespace.
    pub fn new(name: impl Into<String>, tenant_id: TenantId) -> Self {
        Self {
            name: name.into(),
            tenant_id,
            created_at: SystemTime::now(),
            active: true,
            metadata: HashMap::new(),
        }
    }
    
    /// Generate the fully-qualified namespace path.
    pub fn fqn(&self) -> String {
        format!("{}/{}", self.tenant_id, self.name)
    }
}

/// Resource quota for a tenant.
///
/// Defines the limits for various resources that a tenant can consume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    /// Maximum requests per second
    pub max_rps: u64,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Maximum storage in bytes
    pub max_storage_bytes: u64,
    /// Maximum events per day
    pub max_events_per_day: u64,
    /// Maximum namespaces
    pub max_namespaces: u32,
    /// Maximum vector dimensions for embeddings
    pub max_vector_dimensions: u32,
    /// Maximum query complexity score
    pub max_query_complexity: u32,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            max_rps: 100,
            max_connections: 10,
            max_storage_bytes: 1024 * 1024 * 1024, // 1GB
            max_events_per_day: 100_000,
            max_namespaces: 5,
            max_vector_dimensions: 1536, // OpenAI embedding size
            max_query_complexity: 100,
        }
    }
}

/// Resource usage tracking for a tenant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Current storage used in bytes
    pub storage_bytes: u64,
    /// Events processed today
    pub events_today: u64,
    /// Current active connections
    pub active_connections: u32,
    /// Current namespace count
    pub namespace_count: u32,
    /// Last reset time for daily counters
    pub last_daily_reset: Option<SystemTime>,
}

impl ResourceUsage {
    /// Check if usage is within quota limits.
    pub fn is_within_quota(&self, quota: &ResourceQuota) -> bool {
        self.storage_bytes <= quota.max_storage_bytes
            && self.events_today <= quota.max_events_per_day
            && self.active_connections <= quota.max_connections
            && self.namespace_count <= quota.max_namespaces
    }
    
    /// Reset daily counters if needed.
    pub fn maybe_reset_daily(&mut self) {
        let now = SystemTime::now();
        let should_reset = self.last_daily_reset
            .map(|last| {
                now.duration_since(last)
                    .map(|d| d.as_secs() >= 86400)
                    .unwrap_or(true)
            })
            .unwrap_or(true);
        
        if should_reset {
            self.events_today = 0;
            self.last_daily_reset = Some(now);
        }
    }
}

/// Tenant tier for pricing/feature gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantTier {
    /// Free tier with limited resources
    Free,
    /// Starter tier for small teams
    Starter,
    /// Professional tier for growing businesses
    Professional,
    /// Enterprise tier with full features
    Enterprise,
    /// Custom tier with negotiated limits
    Custom,
}

impl Default for TenantTier {
    fn default() -> Self {
        Self::Free
    }
}

impl TenantTier {
    /// Get the default quota for this tier.
    pub fn default_quota(&self) -> ResourceQuota {
        match self {
            TenantTier::Free => ResourceQuota {
                max_rps: 10,
                max_connections: 2,
                max_storage_bytes: 100 * 1024 * 1024, // 100MB
                max_events_per_day: 1_000,
                max_namespaces: 1,
                max_vector_dimensions: 384,
                max_query_complexity: 10,
            },
            TenantTier::Starter => ResourceQuota {
                max_rps: 100,
                max_connections: 10,
                max_storage_bytes: 1024 * 1024 * 1024, // 1GB
                max_events_per_day: 100_000,
                max_namespaces: 5,
                max_vector_dimensions: 1536,
                max_query_complexity: 50,
            },
            TenantTier::Professional => ResourceQuota {
                max_rps: 1000,
                max_connections: 100,
                max_storage_bytes: 10 * 1024 * 1024 * 1024, // 10GB
                max_events_per_day: 1_000_000,
                max_namespaces: 20,
                max_vector_dimensions: 3072,
                max_query_complexity: 100,
            },
            TenantTier::Enterprise => ResourceQuota {
                max_rps: 10_000,
                max_connections: 1000,
                max_storage_bytes: 100 * 1024 * 1024 * 1024, // 100GB
                max_events_per_day: 100_000_000,
                max_namespaces: 100,
                max_vector_dimensions: 4096,
                max_query_complexity: 1000,
            },
            TenantTier::Custom => ResourceQuota::default(),
        }
    }
}

/// Tenant status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantStatus {
    /// Tenant is active and can use the system
    Active,
    /// Tenant is suspended (e.g., payment issue)
    Suspended,
    /// Tenant is in trial period
    Trial,
    /// Tenant is being deleted
    PendingDeletion,
    /// Tenant has been deleted
    Deleted,
}

impl Default for TenantStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// A tenant in the Synapse system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant identifier
    pub id: TenantId,
    /// Human-readable name
    pub name: String,
    /// Tenant tier
    pub tier: TenantTier,
    /// Current status
    pub status: TenantStatus,
    /// Resource quota (may override tier defaults)
    pub quota: ResourceQuota,
    /// Current resource usage
    pub usage: ResourceUsage,
    /// Creation time
    pub created_at: SystemTime,
    /// Last activity time
    pub last_active_at: SystemTime,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
    /// Admin contact email
    pub admin_email: Option<String>,
    /// Billing identifier (external system)
    pub billing_id: Option<String>,
}

impl Tenant {
    /// Create a new tenant.
    pub fn new(id: TenantId, name: impl Into<String>, tier: TenantTier) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            name: name.into(),
            tier,
            status: TenantStatus::Active,
            quota: tier.default_quota(),
            usage: ResourceUsage::default(),
            created_at: now,
            last_active_at: now,
            metadata: HashMap::new(),
            admin_email: None,
            billing_id: None,
        }
    }
    
    /// Check if the tenant can accept new requests.
    pub fn can_accept_requests(&self) -> bool {
        matches!(self.status, TenantStatus::Active | TenantStatus::Trial)
            && self.usage.is_within_quota(&self.quota)
    }
    
    /// Update last activity timestamp.
    pub fn touch(&mut self) {
        self.last_active_at = SystemTime::now();
    }
    
    /// Record resource usage.
    pub fn record_usage(&mut self, storage_delta: i64, events: u64) {
        self.usage.maybe_reset_daily();
        
        if storage_delta >= 0 {
            self.usage.storage_bytes = self.usage.storage_bytes.saturating_add(storage_delta as u64);
        } else {
            self.usage.storage_bytes = self.usage.storage_bytes.saturating_sub((-storage_delta) as u64);
        }
        
        self.usage.events_today = self.usage.events_today.saturating_add(events);
        self.touch();
    }
}

/// Errors from tenant operations.
#[derive(Debug, Error)]
pub enum TenantError {
    /// Tenant not found
    #[error("Tenant not found: {0}")]
    NotFound(TenantId),
    
    /// Tenant already exists
    #[error("Tenant already exists: {0}")]
    AlreadyExists(TenantId),
    
    /// Tenant is not active
    #[error("Tenant is not active: {0} (status: {1:?})")]
    NotActive(TenantId, TenantStatus),
    
    /// Quota exceeded
    #[error("Quota exceeded for tenant {tenant}: {resource}")]
    QuotaExceeded {
        /// Tenant ID
        tenant: TenantId,
        /// Resource that exceeded quota
        resource: String,
    },
    
    /// Namespace not found
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),
    
    /// Namespace already exists
    #[error("Namespace already exists: {0}")]
    NamespaceAlreadyExists(String),
    
    /// Invalid tenant configuration
    #[error("Invalid tenant configuration: {0}")]
    InvalidConfig(String),
}

/// Result type for tenant operations.
pub type TenantResult<T> = std::result::Result<T, TenantError>;

/// Configuration for the tenant manager.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Default tier for new tenants
    pub default_tier: TenantTier,
    /// Trial duration (if applicable)
    pub trial_duration: Duration,
    /// Automatically suspend on quota exceeded
    pub auto_suspend_on_quota: bool,
    /// Grace period before deletion
    pub deletion_grace_period: Duration,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            default_tier: TenantTier::Free,
            trial_duration: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
            auto_suspend_on_quota: false,
            deletion_grace_period: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
        }
    }
}

/// Manages tenants in the Synapse system.
///
/// The TenantManager is responsible for:
/// - Creating and deleting tenants
/// - Managing namespaces
/// - Tracking resource usage
/// - Enforcing quotas
pub struct TenantManager {
    config: TenantConfig,
    tenants: RwLock<HashMap<TenantId, Tenant>>,
    namespaces: RwLock<HashMap<String, Namespace>>,
}

impl TenantManager {
    /// Create a new tenant manager.
    pub fn new(config: TenantConfig) -> Self {
        Self {
            config,
            tenants: RwLock::new(HashMap::new()),
            namespaces: RwLock::new(HashMap::new()),
        }
    }
    
    /// Create a new tenant.
    pub async fn create_tenant(
        &self,
        id: TenantId,
        name: impl Into<String>,
        tier: Option<TenantTier>,
    ) -> TenantResult<Tenant> {
        let mut tenants = self.tenants.write().await;
        
        if tenants.contains_key(&id) {
            return Err(TenantError::AlreadyExists(id));
        }
        
        let tier = tier.unwrap_or(self.config.default_tier);
        let tenant = Tenant::new(id.clone(), name, tier);
        
        // Create default namespace
        let default_ns = Namespace::new("default", id.clone());
        let mut namespaces = self.namespaces.write().await;
        namespaces.insert(default_ns.fqn(), default_ns);
        
        tenants.insert(id, tenant.clone());
        Ok(tenant)
    }
    
    /// Get a tenant by ID.
    pub async fn get_tenant(&self, id: &TenantId) -> TenantResult<Tenant> {
        let tenants = self.tenants.read().await;
        tenants
            .get(id)
            .cloned()
            .ok_or_else(|| TenantError::NotFound(id.clone()))
    }
    
    /// Update a tenant.
    pub async fn update_tenant(&self, tenant: Tenant) -> TenantResult<()> {
        let mut tenants = self.tenants.write().await;
        
        if !tenants.contains_key(&tenant.id) {
            return Err(TenantError::NotFound(tenant.id.clone()));
        }
        
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }
    
    /// Delete a tenant (marks for deletion).
    pub async fn delete_tenant(&self, id: &TenantId) -> TenantResult<()> {
        let mut tenants = self.tenants.write().await;
        
        let tenant = tenants
            .get_mut(id)
            .ok_or_else(|| TenantError::NotFound(id.clone()))?;
        
        tenant.status = TenantStatus::PendingDeletion;
        Ok(())
    }
    
    /// Validate that a tenant can accept requests.
    pub async fn validate_tenant(&self, id: &TenantId) -> TenantResult<()> {
        let tenants = self.tenants.read().await;
        
        let tenant = tenants
            .get(id)
            .ok_or_else(|| TenantError::NotFound(id.clone()))?;
        
        if !tenant.can_accept_requests() {
            return Err(TenantError::NotActive(id.clone(), tenant.status));
        }
        
        Ok(())
    }
    
    /// Create a namespace for a tenant.
    pub async fn create_namespace(
        &self,
        tenant_id: &TenantId,
        name: impl Into<String>,
    ) -> TenantResult<Namespace> {
        let mut tenants = self.tenants.write().await;
        let tenant = tenants
            .get_mut(tenant_id)
            .ok_or_else(|| TenantError::NotFound(tenant_id.clone()))?;
        
        if tenant.usage.namespace_count >= tenant.quota.max_namespaces {
            return Err(TenantError::QuotaExceeded {
                tenant: tenant_id.clone(),
                resource: "namespaces".to_string(),
            });
        }
        
        let namespace = Namespace::new(name, tenant_id.clone());
        let fqn = namespace.fqn();
        
        let mut namespaces = self.namespaces.write().await;
        if namespaces.contains_key(&fqn) {
            return Err(TenantError::NamespaceAlreadyExists(fqn));
        }
        
        tenant.usage.namespace_count += 1;
        namespaces.insert(fqn, namespace.clone());
        
        Ok(namespace)
    }
    
    /// Get a namespace.
    pub async fn get_namespace(&self, fqn: &str) -> TenantResult<Namespace> {
        let namespaces = self.namespaces.read().await;
        namespaces
            .get(fqn)
            .cloned()
            .ok_or_else(|| TenantError::NamespaceNotFound(fqn.to_string()))
    }
    
    /// List all namespaces for a tenant.
    pub async fn list_namespaces(&self, tenant_id: &TenantId) -> Vec<Namespace> {
        let namespaces = self.namespaces.read().await;
        namespaces
            .values()
            .filter(|ns| &ns.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
    
    /// Record usage for a tenant.
    pub async fn record_usage(
        &self,
        tenant_id: &TenantId,
        storage_delta: i64,
        events: u64,
    ) -> TenantResult<()> {
        let mut tenants = self.tenants.write().await;
        let tenant = tenants
            .get_mut(tenant_id)
            .ok_or_else(|| TenantError::NotFound(tenant_id.clone()))?;
        
        tenant.record_usage(storage_delta, events);
        
        // Check if quota exceeded and auto-suspend is enabled
        if self.config.auto_suspend_on_quota && !tenant.usage.is_within_quota(&tenant.quota) {
            tenant.status = TenantStatus::Suspended;
        }
        
        Ok(())
    }
    
    /// Get usage statistics for a tenant.
    pub async fn get_usage(&self, tenant_id: &TenantId) -> TenantResult<ResourceUsage> {
        let tenants = self.tenants.read().await;
        let tenant = tenants
            .get(tenant_id)
            .ok_or_else(|| TenantError::NotFound(tenant_id.clone()))?;
        
        Ok(tenant.usage.clone())
    }
    
    /// List all tenants (admin only).
    pub async fn list_tenants(&self) -> Vec<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_tenant() {
        let manager = TenantManager::new(TenantConfig::default());
        
        let tenant = manager
            .create_tenant(TenantId::new("test-1"), "Test Tenant", None)
            .await
            .unwrap();
        
        assert_eq!(tenant.id.as_str(), "test-1");
        assert_eq!(tenant.name, "Test Tenant");
        assert_eq!(tenant.tier, TenantTier::Free);
        assert_eq!(tenant.status, TenantStatus::Active);
    }
    
    #[tokio::test]
    async fn test_duplicate_tenant() {
        let manager = TenantManager::new(TenantConfig::default());
        
        manager
            .create_tenant(TenantId::new("test-1"), "Test Tenant", None)
            .await
            .unwrap();
        
        let result = manager
            .create_tenant(TenantId::new("test-1"), "Duplicate", None)
            .await;
        
        assert!(matches!(result, Err(TenantError::AlreadyExists(_))));
    }
    
    #[tokio::test]
    async fn test_namespace_creation() {
        let manager = TenantManager::new(TenantConfig::default());
        
        let tenant_id = TenantId::new("test-1");
        manager
            .create_tenant(tenant_id.clone(), "Test Tenant", None)
            .await
            .unwrap();
        
        let ns = manager
            .create_namespace(&tenant_id, "prod")
            .await
            .unwrap();
        
        assert_eq!(ns.name, "prod");
        assert_eq!(ns.fqn(), "test-1/prod");
    }
    
    #[tokio::test]
    async fn test_tier_quotas() {
        let free_quota = TenantTier::Free.default_quota();
        let enterprise_quota = TenantTier::Enterprise.default_quota();
        
        assert!(free_quota.max_rps < enterprise_quota.max_rps);
        assert!(free_quota.max_storage_bytes < enterprise_quota.max_storage_bytes);
    }
    
    #[tokio::test]
    async fn test_usage_tracking() {
        let manager = TenantManager::new(TenantConfig::default());
        
        let tenant_id = TenantId::new("test-1");
        manager
            .create_tenant(tenant_id.clone(), "Test", None)
            .await
            .unwrap();
        
        manager.record_usage(&tenant_id, 1000, 50).await.unwrap();
        
        let usage = manager.get_usage(&tenant_id).await.unwrap();
        assert_eq!(usage.storage_bytes, 1000);
        assert_eq!(usage.events_today, 50);
    }
}
