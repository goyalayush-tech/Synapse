//! Rate Limiting and Quotas
//!
//! This module provides enterprise-grade rate limiting:
//!
//! - **Token Bucket**: Burst-friendly rate limiting
//! - **Sliding Window**: Smooth rate enforcement
//! - **Per-Tenant Quotas**: Individual limits per tenant
//! - **Hierarchical Limits**: Global, tenant, and user levels
//!
//! # Algorithms
//!
//! ## Token Bucket
//! Allows bursts up to bucket size, then enforces steady rate.
//!
//! ## Sliding Window
//! Counts requests in a rolling time window for smooth limiting.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      RATE LIMITER                                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────────────────────────────────────────────────┐    │
//! │  │                    Global Limit                          │    │
//! │  │                   (System-wide)                          │    │
//! │  └────────────────────────┬────────────────────────────────┘    │
//! │                           │                                      │
//! │  ┌──────────────┬─────────┴─────────┬──────────────┐            │
//! │  │  Tenant A    │    Tenant B       │  Tenant C    │            │
//! │  │  100 RPS     │    500 RPS        │  1000 RPS    │            │
//! │  └──────┬───────┘    └──────┬───────┘└──────┬──────┘            │
//! │         │                   │               │                    │
//! │    ┌────┴────┐         ┌────┴────┐     ┌────┴────┐              │
//! │    │User Lim │         │User Lim │     │User Lim │              │
//! │    └─────────┘         └─────────┘     └─────────┘              │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use super::tenancy::TenantId;

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Remaining tokens/requests
        remaining: u64,
        /// Reset time
        reset_at: Instant,
    },
    /// Request is denied
    Denied {
        /// Retry after this duration
        retry_after: Duration,
        /// Limit that was exceeded
        limit_type: String,
    },
}

impl RateLimitResult {
    /// Check if the request was allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }
}

/// Token bucket for rate limiting.
///
/// Allows bursts up to the bucket capacity, then enforces
/// a steady token refill rate.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum tokens in the bucket
    capacity: u64,
    /// Current token count
    tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    pub fn new(capacity: u64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }
    
    /// Try to consume tokens.
    pub fn try_consume(&mut self, tokens: u64) -> RateLimitResult {
        self.refill();
        
        let tokens_f = tokens as f64;
        
        if self.tokens >= tokens_f {
            self.tokens -= tokens_f;
            RateLimitResult::Allowed {
                remaining: self.tokens as u64,
                reset_at: Instant::now() + Duration::from_secs_f64(
                    (self.capacity as f64 - self.tokens) / self.refill_rate
                ),
            }
        } else {
            let deficit = tokens_f - self.tokens;
            let wait_secs = deficit / self.refill_rate;
            RateLimitResult::Denied {
                retry_after: Duration::from_secs_f64(wait_secs),
                limit_type: "token_bucket".to_string(),
            }
        }
    }
    
    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.refill_rate;
        
        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }
    
    /// Get current token count.
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }
}

/// Sliding window rate limiter.
///
/// Tracks requests in a rolling time window for smooth rate limiting
/// without the burst behavior of token buckets.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Window duration
    window_size: Duration,
    /// Maximum requests per window
    max_requests: u64,
    /// Request timestamps
    requests: Vec<Instant>,
}

impl SlidingWindow {
    /// Create a new sliding window limiter.
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            window_size,
            max_requests,
            requests: Vec::with_capacity(max_requests as usize),
        }
    }
    
    /// Try to record a request.
    pub fn try_request(&mut self) -> RateLimitResult {
        let now = Instant::now();
        let window_start = now - self.window_size;
        
        // Remove expired requests
        self.requests.retain(|&t| t > window_start);
        
        if (self.requests.len() as u64) < self.max_requests {
            self.requests.push(now);
            RateLimitResult::Allowed {
                remaining: self.max_requests - self.requests.len() as u64,
                reset_at: now + self.window_size,
            }
        } else {
            // Find oldest request to determine retry time
            let oldest = self.requests.first().copied().unwrap_or(now);
            let retry_after = self.window_size - now.duration_since(oldest);
            
            RateLimitResult::Denied {
                retry_after,
                limit_type: "sliding_window".to_string(),
            }
        }
    }
    
    /// Get current request count in the window.
    pub fn current_count(&mut self) -> u64 {
        let now = Instant::now();
        let window_start = now - self.window_size;
        self.requests.retain(|&t| t > window_start);
        self.requests.len() as u64
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Global requests per second limit
    pub global_rps: u64,
    /// Default per-tenant RPS
    pub default_tenant_rps: u64,
    /// Default per-user RPS
    pub default_user_rps: u64,
    /// Burst multiplier for token bucket
    pub burst_multiplier: f64,
    /// Sliding window size in seconds
    pub window_size_secs: u64,
    /// Enable adaptive rate limiting
    pub adaptive_enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 100_000,
            default_tenant_rps: 1000,
            default_user_rps: 100,
            burst_multiplier: 2.0,
            window_size_secs: 60,
            adaptive_enabled: false,
        }
    }
}

/// Per-tenant rate limit state.
struct TenantLimiter {
    /// Token bucket for burst handling
    bucket: TokenBucket,
    /// Sliding window for smooth limiting (reserved for advanced rate limiting)
    #[allow(dead_code)]
    window: SlidingWindow,
    /// Custom RPS limit (overrides default)
    custom_rps: Option<u64>,
    /// Last activity time
    last_active: Instant,
}

/// Main rate limiter.
///
/// Provides hierarchical rate limiting with global, tenant, and user levels.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Global rate limiter
    global: RwLock<TokenBucket>,
    /// Per-tenant limiters
    tenant_limiters: RwLock<HashMap<TenantId, TenantLimiter>>,
    /// Per-user limiters (tenant_id:user_id -> limiter)
    user_limiters: RwLock<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = TokenBucket::new(
            (config.global_rps as f64 * config.burst_multiplier) as u64,
            config.global_rps as f64,
        );
        
        Self {
            config,
            global: RwLock::new(global_bucket),
            tenant_limiters: RwLock::new(HashMap::new()),
            user_limiters: RwLock::new(HashMap::new()),
        }
    }
    
    /// Check if a request is allowed for a tenant.
    pub async fn check(
        &self,
        tenant_id: &TenantId,
        cost: u64,
    ) -> Result<(), super::EnterpriseError> {
        // Check global limit first
        {
            let mut global = self.global.write().await;
            if let RateLimitResult::Denied { retry_after, .. } = global.try_consume(cost) {
                return Err(super::EnterpriseError::RateLimitExceeded(
                    format!("Global rate limit exceeded. Retry after {:?}", retry_after)
                ));
            }
        }
        
        // Check tenant limit
        let result = {
            let mut limiters = self.tenant_limiters.write().await;
            
            let limiter = limiters.entry(tenant_id.clone()).or_insert_with(|| {
                let rps = self.config.default_tenant_rps;
                TenantLimiter {
                    bucket: TokenBucket::new(
                        (rps as f64 * self.config.burst_multiplier) as u64,
                        rps as f64,
                    ),
                    window: SlidingWindow::new(
                        Duration::from_secs(self.config.window_size_secs),
                        rps * self.config.window_size_secs,
                    ),
                    custom_rps: None,
                    last_active: Instant::now(),
                }
            });
            
            limiter.last_active = Instant::now();
            limiter.bucket.try_consume(cost)
        };
        
        match result {
            RateLimitResult::Allowed { .. } => Ok(()),
            RateLimitResult::Denied { retry_after, .. } => {
                Err(super::EnterpriseError::RateLimitExceeded(
                    format!("Tenant rate limit exceeded. Retry after {:?}", retry_after)
                ))
            }
        }
    }
    
    /// Check with user-level limiting.
    pub async fn check_user(
        &self,
        tenant_id: &TenantId,
        user_id: &str,
        cost: u64,
    ) -> Result<(), super::EnterpriseError> {
        // First check tenant limit
        self.check(tenant_id, cost).await?;
        
        // Then check user limit
        let key = format!("{}:{}", tenant_id, user_id);
        let result = {
            let mut limiters = self.user_limiters.write().await;
            
            let limiter = limiters.entry(key).or_insert_with(|| {
                let rps = self.config.default_user_rps;
                TokenBucket::new(
                    (rps as f64 * self.config.burst_multiplier) as u64,
                    rps as f64,
                )
            });
            
            limiter.try_consume(cost)
        };
        
        match result {
            RateLimitResult::Allowed { .. } => Ok(()),
            RateLimitResult::Denied { retry_after, .. } => {
                Err(super::EnterpriseError::RateLimitExceeded(
                    format!("User rate limit exceeded. Retry after {:?}", retry_after)
                ))
            }
        }
    }
    
    /// Set custom rate limit for a tenant.
    pub async fn set_tenant_limit(&self, tenant_id: &TenantId, rps: u64) {
        let mut limiters = self.tenant_limiters.write().await;
        
        let limiter = limiters.entry(tenant_id.clone()).or_insert_with(|| {
            TenantLimiter {
                bucket: TokenBucket::new(
                    (rps as f64 * self.config.burst_multiplier) as u64,
                    rps as f64,
                ),
                window: SlidingWindow::new(
                    Duration::from_secs(self.config.window_size_secs),
                    rps * self.config.window_size_secs,
                ),
                custom_rps: Some(rps),
                last_active: Instant::now(),
            }
        });
        
        limiter.custom_rps = Some(rps);
        limiter.bucket = TokenBucket::new(
            (rps as f64 * self.config.burst_multiplier) as u64,
            rps as f64,
        );
    }
    
    /// Get remaining quota for a tenant.
    pub async fn remaining(&self, tenant_id: &TenantId) -> u64 {
        let mut limiters = self.tenant_limiters.write().await;
        
        if let Some(limiter) = limiters.get_mut(tenant_id) {
            limiter.bucket.available()
        } else {
            self.config.default_tenant_rps
        }
    }
    
    /// Clean up stale limiters.
    pub async fn cleanup(&self, max_idle: Duration) {
        let now = Instant::now();
        
        {
            let mut tenant_limiters = self.tenant_limiters.write().await;
            tenant_limiters.retain(|_, v| now.duration_since(v.last_active) < max_idle);
        }
        
        // User limiters don't track last_active, so we skip cleanup
        // In production, you'd want a more sophisticated cleanup strategy
    }
}

/// Quota management for tracking usage limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    /// Reset period in seconds
    pub reset_period_secs: u64,
    /// Soft limit warning threshold (percentage)
    pub soft_limit_threshold: f64,
    /// Enable email alerts on quota warnings
    pub alert_on_warning: bool,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            reset_period_secs: 86400, // Daily
            soft_limit_threshold: 0.8, // 80%
            alert_on_warning: true,
        }
    }
}

/// Quota tracking for a resource.
#[derive(Debug, Clone)]
pub struct QuotaTracker {
    /// Maximum allowed
    limit: u64,
    /// Current usage
    used: u64,
    /// Period start time
    period_start: Instant,
    /// Period duration
    period_duration: Duration,
}

impl QuotaTracker {
    /// Create a new quota tracker.
    pub fn new(limit: u64, period_duration: Duration) -> Self {
        Self {
            limit,
            used: 0,
            period_start: Instant::now(),
            period_duration,
        }
    }
    
    /// Try to use quota.
    pub fn try_use(&mut self, amount: u64) -> Result<u64, u64> {
        self.maybe_reset();
        
        if self.used + amount <= self.limit {
            self.used += amount;
            Ok(self.limit - self.used)
        } else {
            Err(self.limit - self.used) // Return remaining
        }
    }
    
    /// Check usage without consuming.
    pub fn check(&mut self) -> (u64, u64) {
        self.maybe_reset();
        (self.used, self.limit)
    }
    
    /// Reset if period has elapsed.
    fn maybe_reset(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.period_start) >= self.period_duration {
            self.used = 0;
            self.period_start = now;
        }
    }
    
    /// Get percentage used.
    pub fn percentage_used(&mut self) -> f64 {
        self.maybe_reset();
        if self.limit == 0 {
            return 0.0;
        }
        (self.used as f64 / self.limit as f64) * 100.0
    }
}

/// Manages quotas across multiple resources and tenants.
pub struct QuotaManager {
    config: QuotaConfig,
    quotas: RwLock<HashMap<String, QuotaTracker>>,
}

impl QuotaManager {
    /// Create a new quota manager.
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            quotas: RwLock::new(HashMap::new()),
        }
    }
    
    /// Set a quota for a resource.
    pub async fn set_quota(&self, key: &str, limit: u64) {
        let mut quotas = self.quotas.write().await;
        quotas.insert(
            key.to_string(),
            QuotaTracker::new(
                limit,
                Duration::from_secs(self.config.reset_period_secs),
            ),
        );
    }
    
    /// Try to use quota.
    pub async fn try_use(&self, key: &str, amount: u64) -> Result<u64, String> {
        let mut quotas = self.quotas.write().await;
        
        if let Some(tracker) = quotas.get_mut(key) {
            tracker.try_use(amount).map_err(|remaining| {
                format!("Quota exceeded for {}. Remaining: {}", key, remaining)
            })
        } else {
            // No quota set means unlimited
            Ok(u64::MAX)
        }
    }
    
    /// Get quota status.
    pub async fn status(&self, key: &str) -> Option<(u64, u64, f64)> {
        let mut quotas = self.quotas.write().await;
        
        quotas.get_mut(key).map(|tracker| {
            let (used, limit) = tracker.check();
            let percent = tracker.percentage_used();
            (used, limit, percent)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 1.0);
        
        // Should allow initial burst
        assert!(bucket.try_consume(5).is_allowed());
        assert_eq!(bucket.available(), 5);
        
        // Should deny when empty
        assert!(bucket.try_consume(10).is_allowed() == false);
    }
    
    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(Duration::from_secs(1), 5);
        
        // Should allow up to limit
        for _ in 0..5 {
            assert!(window.try_request().is_allowed());
        }
        
        // Should deny after limit
        assert!(!window.try_request().is_allowed());
    }
    
    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(RateLimitConfig {
            global_rps: 1000,
            default_tenant_rps: 10,
            default_user_rps: 5,
            burst_multiplier: 2.0,
            window_size_secs: 60,
            adaptive_enabled: false,
        });
        
        let tenant = TenantId::new("test");
        
        // Should allow initial requests
        assert!(limiter.check(&tenant, 1).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_quota_tracker() {
        let mut tracker = QuotaTracker::new(100, Duration::from_secs(3600));
        
        assert!(tracker.try_use(50).is_ok());
        assert_eq!(tracker.percentage_used(), 50.0);
        
        assert!(tracker.try_use(60).is_err()); // Would exceed
        assert!(tracker.try_use(50).is_ok());  // Exactly at limit
        assert!(tracker.try_use(1).is_err());  // Over limit
    }
}
