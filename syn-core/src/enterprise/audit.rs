//! Tamper-Proof Audit Logging
//!
//! This module provides enterprise-grade audit logging with:
//!
//! - **Cryptographic Chain**: Each entry is hash-linked to the previous using SHA-256
//! - **Integrity Checksums**: Entries carry a checksum derived from the chain hash for
//!   tamper-evidence. This is **not** a digital signature: there is no asymmetric key
//!   material and no non-repudiation guarantee. A malicious actor with write access to
//!   the chain can recompute the checksum after altering an entry. Real signing would
//!   require a PKI / key-management story that does not exist yet.
//! - **Compliance Ready**: SOC2, HIPAA, GDPR compatible
//! - **Immutable Log**: Append-only with integrity verification
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     AUDIT CHAIN                                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  Entry N-2         Entry N-1         Entry N                    │
//! │  ┌─────────┐      ┌─────────┐      ┌─────────┐                 │
//! │  │ Hash(0) │──────│Hash(N-2)│──────│Hash(N-1)│                 │
//! │  │ Event   │      │ Event   │      │ Event   │                 │
//! │  │ Sig     │      │ Sig     │      │ Sig     │                 │
//! │  └─────────┘      └─────────┘      └─────────┘                 │
//! │       │                │                │                       │
//! │       └────────────────┴────────────────┘                       │
//! │                        │                                         │
//! │               ┌────────┴────────┐                               │
//! │               │   AuditChain    │                               │
//! │               └─────────────────┘                               │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Once;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::RwLock;

/// Ensures the "no real signing" warning is only emitted once per process,
/// no matter how many `AuditChain` instances are created.
static SIGNING_WARNING: Once = Once::new();

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    /// Debug-level audit event
    Debug,
    /// Informational event
    Info,
    /// Warning-level event
    Warning,
    /// Error-level event
    Error,
    /// Critical security event
    Critical,
}

impl Default for AuditSeverity {
    fn default() -> Self {
        Self::Info
    }
}

/// Category of audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditCategory {
    /// Authentication events
    Authentication,
    /// Authorization/access control events
    Authorization,
    /// Data access events
    DataAccess,
    /// Data modification events
    DataModification,
    /// Configuration changes
    ConfigChange,
    /// System events
    System,
    /// Security-related events
    Security,
    /// Policy evaluation events
    Policy,
    /// Network events
    Network,
    /// Tenant management events
    Tenant,
    /// Custom category
    Custom(String),
}

/// An audit event to be logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event category
    pub category: AuditCategory,
    /// Event severity
    pub severity: AuditSeverity,
    /// Event action (e.g., "login", "read", "write")
    pub action: String,
    /// Actor who performed the action (user/process ID)
    pub actor: String,
    /// Resource affected
    pub resource: String,
    /// Tenant ID (if applicable)
    pub tenant_id: Option<String>,
    /// Whether the action succeeded
    pub success: bool,
    /// Additional details
    pub details: Option<String>,
    /// Client IP address
    pub client_ip: Option<String>,
    /// User agent or process name
    pub user_agent: Option<String>,
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event.
    pub fn new(
        category: AuditCategory,
        action: impl Into<String>,
        actor: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity: AuditSeverity::Info,
            action: action.into(),
            actor: actor.into(),
            resource: resource.into(),
            tenant_id: None,
            success: true,
            details: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
            session_id: None,
        }
    }

    /// Set severity level.
    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set tenant ID.
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set success status.
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set details.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Set client IP.
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set request ID.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

/// A single entry in the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique sequence number
    pub sequence: u64,
    /// Timestamp of the event
    pub timestamp: SystemTime,
    /// Hash of the previous entry (empty for first entry)
    pub prev_hash: String,
    /// The audit event
    pub event: AuditEvent,
    /// SHA-256 hash of this entry
    pub hash: String,
    /// Integrity checksum derived from the entry hash (NOT a cryptographic digital
    /// signature - there is no asymmetric key involved, so this provides no
    /// non-repudiation guarantee, only tamper-evidence via the hash chain).
    pub signature: String,
}

impl AuditEntry {
    /// Compute the SHA-256 hash for this entry.
    fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(format!("{:?}", self.timestamp).as_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(format!("{:?}", self.event).as_bytes());

        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Verify the hash of this entry.
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// Configuration for the audit chain.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Maximum entries to keep in memory
    pub max_memory_entries: usize,
    /// Minimum severity to log
    pub min_severity: AuditSeverity,
    /// Enable signature verification
    pub verify_signatures: bool,
    /// Flush interval in seconds
    pub flush_interval_secs: u64,
    /// Enable async logging
    pub async_logging: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_memory_entries: 10_000,
            min_severity: AuditSeverity::Info,
            verify_signatures: true,
            flush_interval_secs: 60,
            async_logging: true,
        }
    }
}

/// Errors from audit operations.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Chain integrity violation
    #[error("Audit chain integrity violation at sequence {0}")]
    IntegrityViolation(u64),

    /// Signature verification failed
    #[error("Signature verification failed for entry {0}")]
    SignatureInvalid(u64),

    /// Storage error
    #[error("Audit storage error: {0}")]
    StorageError(String),

    /// Entry not found
    #[error("Audit entry not found: sequence {0}")]
    NotFound(u64),

    /// Chain is locked
    #[error("Audit chain is locked")]
    Locked,
}

/// Result type for audit operations.
pub type AuditResult<T> = std::result::Result<T, AuditError>;

/// Tamper-proof audit chain.
///
/// The AuditChain maintains a cryptographic chain of audit entries where
/// each entry contains a hash of the previous entry, making tampering
/// detectable.
pub struct AuditChain {
    config: AuditConfig,
    entries: RwLock<VecDeque<AuditEntry>>,
    sequence: RwLock<u64>,
    last_hash: RwLock<String>,
}

impl AuditChain {
    /// Create a new audit chain.
    pub fn new(config: AuditConfig) -> Self {
        SIGNING_WARNING.call_once(|| {
            tracing::warn!(
                "AuditChain does not implement real cryptographic signing: entries carry a \
                 SHA-256-derived integrity checksum (hash chaining) for tamper-evidence only. \
                 There is no asymmetric key material and therefore no non-repudiation guarantee."
            );
        });

        Self {
            config,
            entries: RwLock::new(VecDeque::new()),
            sequence: RwLock::new(0),
            last_hash: RwLock::new(String::new()),
        }
    }

    /// Record an audit event.
    pub async fn record(&self, event: AuditEvent) -> AuditResult<AuditEntry> {
        // Check severity filter
        if event.severity < self.config.min_severity {
            // Create a dummy entry for filtered events
            return Ok(AuditEntry {
                sequence: 0,
                timestamp: SystemTime::now(),
                prev_hash: String::new(),
                event,
                hash: String::new(),
                signature: String::new(),
            });
        }

        let mut sequence = self.sequence.write().await;
        let mut last_hash = self.last_hash.write().await;
        let mut entries = self.entries.write().await;

        *sequence += 1;
        let seq = *sequence;

        let mut entry = AuditEntry {
            sequence: seq,
            timestamp: SystemTime::now(),
            prev_hash: last_hash.clone(),
            event,
            hash: String::new(),
            signature: String::new(),
        };

        // Compute hash
        entry.hash = entry.compute_hash();

        // Integrity checksum derived from the hash (NOT a real cryptographic signature -
        // see the AuditChain::new warning and module docs for details).
        entry.signature = format!("sig:{}", entry.hash);

        // Update chain state
        *last_hash = entry.hash.clone();

        // Add to in-memory buffer
        entries.push_back(entry.clone());

        // Trim if needed
        while entries.len() > self.config.max_memory_entries {
            entries.pop_front();
        }

        Ok(entry)
    }

    /// Verify the integrity of the entire chain.
    pub async fn verify_integrity(&self) -> AuditResult<bool> {
        let entries = self.entries.read().await;

        let mut prev_hash = String::new();

        for entry in entries.iter() {
            // Verify hash
            if !entry.verify_hash() {
                return Err(AuditError::IntegrityViolation(entry.sequence));
            }

            // Verify chain linkage
            if entry.prev_hash != prev_hash {
                return Err(AuditError::IntegrityViolation(entry.sequence));
            }

            prev_hash = entry.hash.clone();
        }

        Ok(true)
    }

    /// Get an entry by sequence number.
    pub async fn get_entry(&self, sequence: u64) -> AuditResult<AuditEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .find(|e| e.sequence == sequence)
            .cloned()
            .ok_or(AuditError::NotFound(sequence))
    }

    /// Query entries by time range.
    pub async fn query_by_time(&self, start: SystemTime, end: SystemTime) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Query entries by category.
    pub async fn query_by_category(&self, category: &AuditCategory) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|e| &e.event.category == category)
            .cloned()
            .collect()
    }

    /// Query entries by actor.
    pub async fn query_by_actor(&self, actor: &str) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|e| e.event.actor == actor)
            .cloned()
            .collect()
    }

    /// Query entries by tenant.
    pub async fn query_by_tenant(&self, tenant_id: &str) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|e| e.event.tenant_id.as_deref() == Some(tenant_id))
            .cloned()
            .collect()
    }

    /// Get recent entries.
    pub async fn recent(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries.iter().rev().take(count).cloned().collect()
    }

    /// Get the current chain length.
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Check if chain is empty.
    pub async fn is_empty(&self) -> bool {
        let entries = self.entries.read().await;
        entries.is_empty()
    }

    /// Get chain statistics.
    pub async fn stats(&self) -> AuditChainStats {
        let entries = self.entries.read().await;
        let sequence = *self.sequence.read().await;

        let mut by_category = std::collections::HashMap::new();
        let mut by_severity = std::collections::HashMap::new();

        for entry in entries.iter() {
            *by_category
                .entry(format!("{:?}", entry.event.category))
                .or_insert(0u64) += 1;
            *by_severity
                .entry(format!("{:?}", entry.event.severity))
                .or_insert(0u64) += 1;
        }

        AuditChainStats {
            total_entries: sequence,
            in_memory_entries: entries.len() as u64,
            by_category,
            by_severity,
        }
    }

    /// List all entries with pagination.
    pub async fn list_entries(&self, offset: usize, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;

        entries.iter().skip(offset).take(limit).cloned().collect()
    }

    /// Verify the integrity of the entire chain.
    /// Returns Ok(true) if chain is valid, Ok(false) if corrupted.
    pub async fn verify_chain(&self) -> crate::Result<bool> {
        let entries = self.entries.read().await;

        if entries.is_empty() {
            return Ok(true);
        }

        // Verify each entry's hash chain
        for i in 1..entries.len() {
            let prev = &entries[i - 1];
            let curr = &entries[i];

            // Verify hash linkage
            if curr.prev_hash != prev.hash {
                return Ok(false);
            }

            // Verify sequence numbers
            if curr.sequence != prev.sequence + 1 {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Statistics about the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainStats {
    /// Total entries ever recorded
    pub total_entries: u64,
    /// Entries currently in memory
    pub in_memory_entries: u64,
    /// Entries by category
    pub by_category: std::collections::HashMap<String, u64>,
    /// Entries by severity
    pub by_severity: std::collections::HashMap<String, u64>,
}

// Convenience functions for common audit events

/// Log an authentication event.
pub fn auth_event(actor: &str, success: bool, details: Option<&str>) -> AuditEvent {
    let mut event = AuditEvent::new(
        AuditCategory::Authentication,
        if success { "login" } else { "login_failed" },
        actor,
        "session",
    )
    .with_success(success)
    .with_severity(if success {
        AuditSeverity::Info
    } else {
        AuditSeverity::Warning
    });

    if let Some(d) = details {
        event = event.with_details(d);
    }

    event
}

/// Log a data access event.
pub fn data_access_event(actor: &str, resource: &str, action: &str) -> AuditEvent {
    AuditEvent::new(AuditCategory::DataAccess, action, actor, resource)
}

/// Log a security event.
pub fn security_event(
    action: &str,
    actor: &str,
    resource: &str,
    severity: AuditSeverity,
) -> AuditEvent {
    AuditEvent::new(AuditCategory::Security, action, actor, resource).with_severity(severity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_chain_creation() {
        let chain = AuditChain::new(AuditConfig::default());
        assert!(chain.is_empty().await);
    }

    #[tokio::test]
    async fn test_record_event() {
        let chain = AuditChain::new(AuditConfig::default());

        let event = AuditEvent::new(
            AuditCategory::Authentication,
            "login",
            "user@example.com",
            "session",
        );

        let entry = chain.record(event).await.unwrap();

        assert_eq!(entry.sequence, 1);
        assert!(!entry.hash.is_empty());
        assert!(entry.verify_hash());
    }

    #[tokio::test]
    async fn test_chain_integrity() {
        let chain = AuditChain::new(AuditConfig::default());

        // Record multiple events
        for i in 0..10 {
            let event = AuditEvent::new(
                AuditCategory::DataAccess,
                "read",
                format!("user-{}", i),
                "document",
            );
            chain.record(event).await.unwrap();
        }

        // Verify integrity
        assert!(chain.verify_integrity().await.unwrap());
    }

    #[tokio::test]
    async fn test_query_by_actor() {
        let chain = AuditChain::new(AuditConfig::default());

        let event1 = AuditEvent::new(AuditCategory::DataAccess, "read", "alice", "doc1");
        let event2 = AuditEvent::new(AuditCategory::DataAccess, "write", "bob", "doc2");
        let event3 = AuditEvent::new(AuditCategory::DataAccess, "read", "alice", "doc3");

        chain.record(event1).await.unwrap();
        chain.record(event2).await.unwrap();
        chain.record(event3).await.unwrap();

        let alice_events = chain.query_by_actor("alice").await;
        assert_eq!(alice_events.len(), 2);
    }

    #[tokio::test]
    async fn test_convenience_functions() {
        let event = auth_event("user@test.com", true, Some("MFA verified"));
        assert_eq!(event.category, AuditCategory::Authentication);
        assert!(event.success);

        let event = security_event(
            "intrusion_attempt",
            "unknown",
            "firewall",
            AuditSeverity::Critical,
        );
        assert_eq!(event.severity, AuditSeverity::Critical);
    }
}
