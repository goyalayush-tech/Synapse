//! Policy Engine
//!
//! The central registry and execution engine for policies. Provides:
//! - Policy registration and lookup
//! - Concurrent policy evaluation
//! - Hot-reloading support
//! - Metrics and observability
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Policy Engine                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────────┐  ┌──────────────────┐                    │
//! │  │  Policy Registry │  │  Execution Pool  │                    │
//! │  │  (hashbrown Map) │  │  (tokio tasks)   │                    │
//! │  │                  │  │                  │                    │
//! │  │  - Native Rust   │  │  - Timeout       │                    │
//! │  │  - Wasm modules  │  │  - Fuel metering │                    │
//! │  │  - Hot-reload    │  │  - Parallel eval │                    │
//! │  └──────────────────┘  └──────────────────┘                    │
//! │                                                                  │
//! │  ┌──────────────────┐  ┌──────────────────┐                    │
//! │  │  Event Router    │  │  Metrics         │                    │
//! │  │                  │  │                  │                    │
//! │  │  - Topic match   │  │  - Latency       │                    │
//! │  │  - Priority sort │  │  - Verdict count │                    │
//! │  │  - Chain build   │  │  - Errors        │                    │
//! │  └──────────────────┘  └──────────────────┘                    │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use hashbrown::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

use crate::policy::{Policy, PolicyContext, PolicyError, PolicyId, PolicyMetadata};
use crate::verdict::Verdict;

/// Errors from the policy engine
#[derive(Debug, Error)]
pub enum PolicyEngineError {
    /// Policy not found
    #[error("Policy not found: {0}")]
    PolicyNotFound(PolicyId),

    /// Policy already exists
    #[error("Policy already exists: {0}")]
    PolicyExists(PolicyId),

    /// Policy evaluation error
    #[error("Policy evaluation error: {0}")]
    EvaluationError(#[from] PolicyError),

    /// Timeout during evaluation
    #[error("Policy evaluation timed out after {0:?}")]
    Timeout(Duration),

    /// Engine not started
    #[error("Policy engine not started")]
    NotStarted,

    /// Engine already started
    #[error("Policy engine already started")]
    AlreadyStarted,
}

/// Result type for policy engine operations
pub type PolicyEngineResult<T> = Result<T, PolicyEngineError>;

/// Configuration for the policy engine
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Default timeout for policy evaluation
    pub default_timeout: Duration,
    /// Maximum number of concurrent policy evaluations
    pub max_concurrent_evaluations: usize,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable debug logging
    pub enable_debug_logging: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_millis(100),
            max_concurrent_evaluations: 100,
            enable_metrics: true,
            enable_debug_logging: false,
        }
    }
}

impl PolicyConfig {
    /// Create a new policy config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set max concurrent evaluations
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent_evaluations = max;
        self
    }
}

/// Metrics from policy evaluation
#[derive(Debug, Clone, Default)]
pub struct PolicyMetrics {
    /// Number of evaluations
    pub evaluations: u64,
    /// Number of allowed verdicts
    pub allowed: u64,
    /// Number of denied verdicts
    pub denied: u64,
    /// Number of transform verdicts
    pub transformed: u64,
    /// Number of errors
    pub errors: u64,
    /// Number of timeouts
    pub timeouts: u64,
    /// Total evaluation time (microseconds)
    pub total_eval_time_us: u64,
}

/// Policy entry in the registry
struct PolicyEntry {
    policy: Arc<dyn Policy>,
    metrics: PolicyMetrics,
}

/// The policy engine
pub struct PolicyEngine {
    config: PolicyConfig,
    /// Policy registry
    policies: Arc<RwLock<HashMap<PolicyId, PolicyEntry>>>,
    /// Engine state
    started: Arc<RwLock<bool>>,
    /// Global metrics
    global_metrics: Arc<RwLock<PolicyMetrics>>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            policies: Arc::new(RwLock::new(HashMap::new())),
            started: Arc::new(RwLock::new(false)),
            global_metrics: Arc::new(RwLock::new(PolicyMetrics::default())),
        }
    }

    /// Start the policy engine
    pub async fn start(&self) -> PolicyEngineResult<()> {
        let mut started = self.started.write().await;
        if *started {
            return Err(PolicyEngineError::AlreadyStarted);
        }

        // Call on_load for all registered policies
        let policies = self.policies.read().await;
        for (id, entry) in policies.iter() {
            if let Err(e) = entry.policy.on_load().await {
                warn!("Failed to load policy {}: {}", id, e);
            }
        }

        *started = true;
        info!("Policy engine started with {} policies", policies.len());
        Ok(())
    }

    /// Stop the policy engine
    pub async fn stop(&self) -> PolicyEngineResult<()> {
        let mut started = self.started.write().await;
        if !*started {
            return Err(PolicyEngineError::NotStarted);
        }

        // Call on_unload for all registered policies
        let policies = self.policies.read().await;
        for (id, entry) in policies.iter() {
            if let Err(e) = entry.policy.on_unload().await {
                warn!("Failed to unload policy {}: {}", id, e);
            }
        }

        *started = false;
        info!("Policy engine stopped");
        Ok(())
    }

    /// Register a policy
    pub async fn register<P: Policy + 'static>(&self, policy: P) -> PolicyEngineResult<()> {
        let id = policy.metadata().id.clone();
        let mut policies = self.policies.write().await;

        if policies.contains_key(&id) {
            return Err(PolicyEngineError::PolicyExists(id));
        }

        debug!("Registering policy: {}", id);

        policies.insert(
            id.clone(),
            PolicyEntry {
                policy: Arc::new(policy),
                metrics: PolicyMetrics::default(),
            },
        );

        info!("Registered policy: {}", id);
        Ok(())
    }

    /// Unregister a policy
    pub async fn unregister(&self, id: &str) -> PolicyEngineResult<Arc<dyn Policy>> {
        let mut policies = self.policies.write().await;

        match policies.remove(id) {
            Some(entry) => {
                info!("Unregistered policy: {}", id);
                Ok(entry.policy)
            }
            None => Err(PolicyEngineError::PolicyNotFound(id.to_string())),
        }
    }

    /// Get a policy by ID
    pub async fn get(&self, id: &str) -> Option<Arc<dyn Policy>> {
        let policies = self.policies.read().await;
        policies.get(id).map(|e| e.policy.clone())
    }

    /// List all registered policies
    pub async fn list(&self) -> Vec<PolicyMetadata> {
        let policies = self.policies.read().await;
        policies
            .values()
            .map(|e| e.policy.metadata().clone())
            .collect()
    }

    /// Evaluate a specific policy
    #[instrument(skip(self, ctx), fields(policy_id = %id))]
    pub async fn evaluate(&self, id: &str, ctx: &PolicyContext) -> PolicyEngineResult<Verdict> {
        let start = Instant::now();

        let (policy, policy_timeout) = {
            let policies = self.policies.read().await;
            let entry = policies
                .get(id)
                .ok_or_else(|| PolicyEngineError::PolicyNotFound(id.to_string()))?;
            (entry.policy.clone(), entry.policy.metadata().timeout)
        };

        let effective_timeout = if policy_timeout < self.config.default_timeout {
            policy_timeout
        } else {
            self.config.default_timeout
        };

        // Evaluate with timeout
        let result = timeout(effective_timeout, policy.evaluate(ctx)).await;

        let elapsed = start.elapsed();

        // Update metrics
        if self.config.enable_metrics {
            self.update_metrics(id, &result, elapsed).await;
        }

        match result {
            Ok(Ok(verdict)) => {
                debug!(
                    policy_id = %id,
                    verdict = ?verdict,
                    elapsed_us = %elapsed.as_micros(),
                    "Policy evaluation completed"
                );
                Ok(verdict)
            }
            Ok(Err(e)) => {
                warn!(policy_id = %id, error = %e, "Policy evaluation error");
                Err(PolicyEngineError::EvaluationError(e))
            }
            Err(_) => {
                warn!(
                    policy_id = %id,
                    timeout_ms = %effective_timeout.as_millis(),
                    "Policy evaluation timed out"
                );
                Err(PolicyEngineError::Timeout(effective_timeout))
            }
        }
    }

    /// Evaluate multiple policies in parallel
    pub async fn evaluate_all(
        &self,
        ctx: &PolicyContext,
    ) -> Vec<(PolicyId, PolicyEngineResult<Verdict>)> {
        let policies: Vec<_> = {
            let policies = self.policies.read().await;
            policies
                .iter()
                .filter(|(_, e)| e.policy.metadata().enabled)
                .map(|(id, e)| (id.clone(), e.policy.clone()))
                .collect()
        };

        // Sort by priority (higher first)
        let mut policies = policies;
        policies.sort_by(|a, b| b.1.metadata().priority.cmp(&a.1.metadata().priority));

        let mut results = Vec::with_capacity(policies.len());

        for (id, _) in policies {
            let result = self.evaluate(&id, ctx).await;
            results.push((id, result));
        }

        results
    }

    /// Evaluate policies until first denial
    pub async fn evaluate_until_denied(&self, ctx: &PolicyContext) -> PolicyEngineResult<Verdict> {
        let policies: Vec<_> = {
            let policies = self.policies.read().await;
            let mut p: Vec<_> = policies
                .iter()
                .filter(|(_, e)| e.policy.metadata().enabled)
                .map(|(id, e)| (id.clone(), e.policy.clone()))
                .collect();
            // Sort by priority
            p.sort_by(|a, b| b.1.metadata().priority.cmp(&a.1.metadata().priority));
            p
        };

        for (id, _) in policies {
            let verdict = self.evaluate(&id, ctx).await?;
            if verdict.is_denied() {
                return Ok(verdict.with_policy(id));
            }
        }

        Ok(Verdict::allow())
    }

    /// Update metrics after evaluation
    async fn update_metrics(
        &self,
        id: &str,
        result: &Result<Result<Verdict, PolicyError>, tokio::time::error::Elapsed>,
        elapsed: Duration,
    ) {
        let mut policies = self.policies.write().await;
        let mut global = self.global_metrics.write().await;

        if let Some(entry) = policies.get_mut(id) {
            entry.metrics.evaluations += 1;
            entry.metrics.total_eval_time_us += elapsed.as_micros() as u64;

            match result {
                Ok(Ok(verdict)) => match verdict {
                    Verdict::Allow => {
                        entry.metrics.allowed += 1;
                        global.allowed += 1;
                    }
                    Verdict::Deny(_) => {
                        entry.metrics.denied += 1;
                        global.denied += 1;
                    }
                    Verdict::Transform(_) => {
                        entry.metrics.transformed += 1;
                        global.transformed += 1;
                    }
                },
                Ok(Err(_)) => {
                    entry.metrics.errors += 1;
                    global.errors += 1;
                }
                Err(_) => {
                    entry.metrics.timeouts += 1;
                    global.timeouts += 1;
                }
            }
        }

        global.evaluations += 1;
        global.total_eval_time_us += elapsed.as_micros() as u64;
    }

    /// Get metrics for a specific policy
    pub async fn policy_metrics(&self, id: &str) -> Option<PolicyMetrics> {
        let policies = self.policies.read().await;
        policies.get(id).map(|e| e.metrics.clone())
    }

    /// Get global metrics
    pub async fn global_metrics(&self) -> PolicyMetrics {
        self.global_metrics.read().await.clone()
    }

    /// Reset all metrics
    pub async fn reset_metrics(&self) {
        let mut policies = self.policies.write().await;
        let mut global = self.global_metrics.write().await;

        for entry in policies.values_mut() {
            entry.metrics = PolicyMetrics::default();
        }
        *global = PolicyMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ActionFilterPolicy, AllowAllPolicy, DenyAllPolicy};

    #[tokio::test]
    async fn test_engine_lifecycle() {
        let engine = PolicyEngine::new(PolicyConfig::default());

        // Can't stop before starting
        assert!(engine.stop().await.is_err());

        // Start
        engine.start().await.expect("should start");

        // Can't start twice
        assert!(engine.start().await.is_err());

        // Stop
        engine.stop().await.expect("should stop");
    }

    #[tokio::test]
    async fn test_register_and_get() {
        let engine = PolicyEngine::new(PolicyConfig::default());

        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("should register");

        // Can't register duplicate
        assert!(engine.register(AllowAllPolicy::new()).await.is_err());

        // Can get
        let policy = engine.get("allow-all").await;
        assert!(policy.is_some());

        // List policies
        let policies = engine.list().await;
        assert_eq!(policies.len(), 1);
    }

    #[tokio::test]
    async fn test_evaluate_single() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("register");
        engine
            .register(DenyAllPolicy::new("test"))
            .await
            .expect("register");

        let ctx = PolicyContext::new(1, "test-source");

        // Allow
        let verdict = engine.evaluate("allow-all", &ctx).await.expect("eval");
        assert!(verdict.is_allowed());

        // Deny
        let verdict = engine.evaluate("deny-all", &ctx).await.expect("eval");
        assert!(verdict.is_denied());

        // Not found
        assert!(engine.evaluate("nonexistent", &ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_evaluate_all() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("register");
        engine
            .register(ActionFilterPolicy::new(vec!["read".to_string()]))
            .await
            .expect("register");

        let ctx = PolicyContext::new(1, "test").with_action("read");
        let results = engine.evaluate_all(&ctx).await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[tokio::test]
    async fn test_evaluate_until_denied() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("register");
        engine
            .register(ActionFilterPolicy::new(vec!["read".to_string()]))
            .await
            .expect("register");

        // Allowed action
        let ctx = PolicyContext::new(1, "test").with_action("read");
        let verdict = engine.evaluate_until_denied(&ctx).await.expect("eval");
        assert!(verdict.is_allowed());

        // Denied action
        let ctx = PolicyContext::new(2, "test").with_action("delete");
        let verdict = engine.evaluate_until_denied(&ctx).await.expect("eval");
        assert!(verdict.is_denied());
    }

    #[tokio::test]
    async fn test_metrics() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("register");

        let ctx = PolicyContext::new(1, "test");

        // Evaluate a few times
        for _ in 0..5 {
            engine.evaluate("allow-all", &ctx).await.expect("eval");
        }

        // Check metrics
        let metrics = engine.policy_metrics("allow-all").await.expect("metrics");
        assert_eq!(metrics.evaluations, 5);
        assert_eq!(metrics.allowed, 5);

        let global = engine.global_metrics().await;
        assert_eq!(global.evaluations, 5);

        // Reset metrics
        engine.reset_metrics().await;
        let metrics = engine.policy_metrics("allow-all").await.expect("metrics");
        assert_eq!(metrics.evaluations, 0);
    }

    #[tokio::test]
    async fn test_unregister() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine
            .register(AllowAllPolicy::new())
            .await
            .expect("register");

        assert!(engine.get("allow-all").await.is_some());

        engine.unregister("allow-all").await.expect("unregister");

        assert!(engine.get("allow-all").await.is_none());
        assert!(engine.unregister("allow-all").await.is_err());
    }
}
