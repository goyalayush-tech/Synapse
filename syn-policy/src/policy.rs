//! Policy Trait and Types
//!
//! This module defines the core `Policy` trait that all policy implementations
//! must satisfy. Policies can be:
//! - Native Rust implementations (fast, type-safe)
//! - WebAssembly modules (portable, sandboxed, hot-reloadable)
//!
//! # Design Notes
//!
//! The `Policy` trait is designed to be:
//! - Async-first (policies may need to query external state)
//! - Context-aware (policies receive rich context about the event)
//! - Composable (policies can be chained)

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::verdict::Verdict;

/// Unique identifier for a policy
pub type PolicyId = String;

/// Errors that can occur during policy operations
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy evaluation failed
    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),
    
    /// Policy timed out
    #[error("Policy evaluation timed out after {0:?}")]
    Timeout(Duration),
    
    /// Policy resource limit exceeded
    #[error("Policy resource limit exceeded: {0}")]
    ResourceLimit(String),
    
    /// Invalid policy configuration
    #[error("Invalid policy configuration: {0}")]
    InvalidConfig(String),
    
    /// Policy not found
    #[error("Policy not found: {0}")]
    NotFound(String),
}

/// Result type for policy operations
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Metadata about a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Unique policy identifier
    pub id: PolicyId,
    /// Human-readable name
    pub name: String,
    /// Policy version
    pub version: String,
    /// Description of what the policy does
    pub description: String,
    /// Author/owner
    pub author: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// When the policy was created
    pub created_at: SystemTime,
    /// When the policy was last updated
    pub updated_at: SystemTime,
    /// Maximum execution time before timeout
    pub timeout: Duration,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// Priority (higher = evaluated first)
    pub priority: i32,
}

impl PolicyMetadata {
    /// Create new policy metadata
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.into(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: None,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            timeout: Duration::from_millis(100),
            enabled: true,
            priority: 0,
        }
    }
    
    /// Set the version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }
    
    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
    
    /// Set the author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }
    
    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
    
    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Set the priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// Context provided to policy during evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Event ID being evaluated
    pub event_id: u64,
    /// Source of the event
    pub source: String,
    /// Event action/type
    pub action: String,
    /// Event payload (serialized)
    pub payload: String,
    /// Timestamp of the event
    pub timestamp_us: u64,
    /// Additional metadata
    pub metadata: serde_json::Value,
    /// Results from previous policies in the chain
    pub previous_verdicts: Vec<(PolicyId, Verdict)>,
}

impl PolicyContext {
    /// Create a new policy context
    pub fn new(event_id: u64, source: impl Into<String>) -> Self {
        Self {
            event_id,
            source: source.into(),
            action: String::new(),
            payload: String::new(),
            timestamp_us: 0,
            metadata: serde_json::json!({}),
            previous_verdicts: Vec::new(),
        }
    }
    
    /// Set the action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }
    
    /// Set the payload
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }
    
    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp_us: u64) -> Self {
        self.timestamp_us = timestamp_us;
        self
    }
    
    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
    
    /// Add a previous verdict
    pub fn add_verdict(mut self, policy_id: PolicyId, verdict: Verdict) -> Self {
        self.previous_verdicts.push((policy_id, verdict));
        self
    }
}

/// Core policy trait
///
/// All policy implementations must implement this trait. The trait is
/// async-first to support policies that need to query external state.
///
/// # Example
///
/// ```ignore
/// use syn_policy::{Policy, PolicyContext, PolicyResult, Verdict};
///
/// struct RateLimitPolicy {
///     max_requests: u32,
///     window_secs: u64,
/// }
///
/// #[async_trait]
/// impl Policy for RateLimitPolicy {
///     fn metadata(&self) -> &PolicyMetadata {
///         &self.metadata
///     }
///     
///     async fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult<Verdict> {
///         // Check rate limit
///         if self.is_over_limit(&ctx.source) {
///             Ok(Verdict::deny("Rate limit exceeded"))
///         } else {
///             Ok(Verdict::allow())
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Policy: Send + Sync {
    /// Get policy metadata
    fn metadata(&self) -> &PolicyMetadata;
    
    /// Evaluate the policy against an event context
    ///
    /// Returns a verdict indicating whether the event is allowed,
    /// denied, or should be transformed.
    async fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult<Verdict>;
    
    /// Called when the policy is loaded
    async fn on_load(&self) -> PolicyResult<()> {
        Ok(())
    }
    
    /// Called when the policy is unloaded
    async fn on_unload(&self) -> PolicyResult<()> {
        Ok(())
    }
}

/// A policy that always allows events
#[derive(Debug)]
pub struct AllowAllPolicy {
    metadata: PolicyMetadata,
}

impl AllowAllPolicy {
    /// Create a new allow-all policy
    pub fn new() -> Self {
        Self {
            metadata: PolicyMetadata::new("allow-all", "Allow All")
                .with_description("Allows all events to pass through"),
        }
    }
}

impl Default for AllowAllPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Policy for AllowAllPolicy {
    fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
    
    async fn evaluate(&self, _ctx: &PolicyContext) -> PolicyResult<Verdict> {
        Ok(Verdict::allow())
    }
}

/// A policy that denies all events
#[derive(Debug)]
pub struct DenyAllPolicy {
    metadata: PolicyMetadata,
    reason: String,
}

impl DenyAllPolicy {
    /// Create a new deny-all policy
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            metadata: PolicyMetadata::new("deny-all", "Deny All")
                .with_description("Denies all events"),
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl Policy for DenyAllPolicy {
    fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
    
    async fn evaluate(&self, _ctx: &PolicyContext) -> PolicyResult<Verdict> {
        Ok(Verdict::deny(&self.reason))
    }
}

/// A policy that filters events by action
#[derive(Debug)]
pub struct ActionFilterPolicy {
    metadata: PolicyMetadata,
    allowed_actions: Vec<String>,
}

impl ActionFilterPolicy {
    /// Create a new action filter policy
    pub fn new(allowed_actions: Vec<String>) -> Self {
        Self {
            metadata: PolicyMetadata::new("action-filter", "Action Filter")
                .with_description("Filters events by action type"),
            allowed_actions,
        }
    }
}

#[async_trait]
impl Policy for ActionFilterPolicy {
    fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
    
    async fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult<Verdict> {
        if self.allowed_actions.contains(&ctx.action) {
            Ok(Verdict::allow())
        } else {
            Ok(Verdict::deny_with_code(
                "ACTION_NOT_ALLOWED",
                format!("Action '{}' is not in allowed list", ctx.action),
            ))
        }
    }
}

/// A policy that filters events by source
#[derive(Debug)]
pub struct SourceFilterPolicy {
    metadata: PolicyMetadata,
    allowed_sources: Vec<String>,
}

impl SourceFilterPolicy {
    /// Create a new source filter policy
    pub fn new(allowed_sources: Vec<String>) -> Self {
        Self {
            metadata: PolicyMetadata::new("source-filter", "Source Filter")
                .with_description("Filters events by source"),
            allowed_sources,
        }
    }
}

#[async_trait]
impl Policy for SourceFilterPolicy {
    fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
    
    async fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult<Verdict> {
        if self.allowed_sources.iter().any(|s| ctx.source.starts_with(s)) {
            Ok(Verdict::allow())
        } else {
            Ok(Verdict::deny_with_code(
                "SOURCE_NOT_ALLOWED",
                format!("Source '{}' is not in allowed list", ctx.source),
            ))
        }
    }
}

/// A composite policy that chains multiple policies
pub struct PolicyChain {
    metadata: PolicyMetadata,
    policies: Vec<Arc<dyn Policy>>,
    /// If true, stop on first deny; otherwise, evaluate all
    fail_fast: bool,
}

impl std::fmt::Debug for PolicyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyChain")
            .field("metadata", &self.metadata)
            .field("policy_count", &self.policies.len())
            .field("fail_fast", &self.fail_fast)
            .finish()
    }
}

impl PolicyChain {
    /// Create a new policy chain
    pub fn new(id: impl Into<String>, policies: Vec<Arc<dyn Policy>>) -> Self {
        Self {
            metadata: PolicyMetadata::new(id, "Policy Chain")
                .with_description("Chains multiple policies together"),
            policies,
            fail_fast: true,
        }
    }
    
    /// Set fail-fast behavior
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }
}

#[async_trait]
impl Policy for PolicyChain {
    fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
    
    async fn evaluate(&self, ctx: &PolicyContext) -> PolicyResult<Verdict> {
        let mut ctx = ctx.clone();
        
        for policy in &self.policies {
            if !policy.metadata().enabled {
                continue;
            }
            
            let verdict = policy.evaluate(&ctx).await?;
            let policy_id = policy.metadata().id.clone();
            
            if self.fail_fast && verdict.is_denied() {
                return Ok(verdict.with_policy(policy_id));
            }
            
            ctx = ctx.add_verdict(policy_id, verdict);
        }
        
        // If we got here, all policies allowed
        Ok(Verdict::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_allow_all_policy() {
        let policy = AllowAllPolicy::new();
        let ctx = PolicyContext::new(1, "test-source");
        
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_allowed());
    }
    
    #[tokio::test]
    async fn test_deny_all_policy() {
        let policy = DenyAllPolicy::new("System maintenance");
        let ctx = PolicyContext::new(1, "test-source");
        
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_denied());
        assert_eq!(
            verdict.denial_reason().expect("should have reason").message,
            "System maintenance"
        );
    }
    
    #[tokio::test]
    async fn test_action_filter_policy() {
        let policy = ActionFilterPolicy::new(vec!["read".to_string(), "list".to_string()]);
        
        // Allowed action
        let ctx = PolicyContext::new(1, "test").with_action("read");
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_allowed());
        
        // Denied action
        let ctx = PolicyContext::new(2, "test").with_action("delete");
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_denied());
    }
    
    #[tokio::test]
    async fn test_source_filter_policy() {
        let policy = SourceFilterPolicy::new(vec!["agent-".to_string(), "system-".to_string()]);
        
        // Allowed source
        let ctx = PolicyContext::new(1, "agent-001");
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_allowed());
        
        // Denied source
        let ctx = PolicyContext::new(2, "unknown-source");
        let verdict = policy.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_denied());
    }
    
    #[tokio::test]
    async fn test_policy_chain() {
        let chain = PolicyChain::new("test-chain", vec![
            Arc::new(SourceFilterPolicy::new(vec!["agent-".to_string()])),
            Arc::new(ActionFilterPolicy::new(vec!["read".to_string()])),
        ]);
        
        // Both pass
        let ctx = PolicyContext::new(1, "agent-001").with_action("read");
        let verdict = chain.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_allowed());
        
        // Source fails
        let ctx = PolicyContext::new(2, "unknown").with_action("read");
        let verdict = chain.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_denied());
        
        // Action fails
        let ctx = PolicyContext::new(3, "agent-001").with_action("delete");
        let verdict = chain.evaluate(&ctx).await.expect("should succeed");
        assert!(verdict.is_denied());
    }
    
    #[test]
    fn test_policy_metadata() {
        let meta = PolicyMetadata::new("test-policy", "Test Policy")
            .with_version("2.0.0")
            .with_description("A test policy")
            .with_author("Test Author")
            .with_tag("test")
            .with_priority(10);
        
        assert_eq!(meta.id, "test-policy");
        assert_eq!(meta.version, "2.0.0");
        assert_eq!(meta.author, Some("Test Author".to_string()));
        assert_eq!(meta.priority, 10);
    }
}
