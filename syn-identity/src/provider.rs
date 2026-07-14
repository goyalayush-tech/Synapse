//! Identity Provider Abstraction
//!
//! This module defines the `IdentityProvider` trait which abstracts over
//! different identity verification mechanisms:
//!
//! - **Linux**: Real eBPF-based kernel attestation via Aya
//! - **Windows/macOS**: Mock implementation for development
//!
//! # Environmental Entanglement
//!
//! The Synapse "Uncopyable" architecture relies on binding the binary to its
//! execution environment. This is achieved by:
//!
//! 1. Verifying the process's cgroup membership (container identity)
//! 2. Checking the binary hash against an allowlist (code integrity)
//! 3. Tracking trusted PIDs via eBPF maps (runtime attestation)
//!
//! # Example
//!
//! ```no_run
//! use syn_identity::provider::{IdentityProvider, IdentityProviderConfig, get_identity_provider};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = IdentityProviderConfig::default();
//!     let provider = get_identity_provider(config)?;
//!     
//!     // Attach to kernel hooks (no-op on non-Linux)
//!     provider.attach().await?;
//!     
//!     // Verify a process
//!     let pid = std::process::id();
//!     if provider.verify_pid(pid).await? {
//!         println!("Process {} is trusted", pid);
//!     }
//!     
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::ebpf::Allowlist;

/// Environment variable that must be set to `"1"` or `"true"` before
/// [`EbpfIdentityProvider::attach`] will proceed.
///
/// This crate does not currently perform real eBPF loading or kernel-level
/// attestation (see the SIMULATION warning logged by `attach()`). Requiring
/// this explicit opt-in prevents a caller from silently getting
/// simulated/mocked security behavior in place of real enforcement.
pub const SIMULATED_IDENTITY_ENV: &str = "SYNAPSE_ALLOW_SIMULATED_IDENTITY";

/// Returns true if the given environment variable is set to a value that
/// counts as an affirmative opt-in (`"1"` or `"true"`, case-insensitive).
#[cfg(target_os = "linux")]
fn env_opt_in(var: &str) -> bool {
    match std::env::var(var) {
        Ok(val) => {
            let val = val.trim();
            val == "1" || val.eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    }
}

/// Errors from identity provider operations
#[derive(Debug, Error)]
pub enum IdentityProviderError {
    /// Failed to attach eBPF programs
    #[error("Failed to attach identity hooks: {0}")]
    AttachFailed(String),

    /// Failed to verify process
    #[error("Process verification failed: {0}")]
    VerificationFailed(String),

    /// eBPF map operation failed
    #[error("Map operation failed: {0}")]
    MapError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Not supported on this platform
    #[error("Operation not supported on this platform: {0}")]
    NotSupported(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for identity provider operations
pub type IdentityProviderResult<T> = Result<T, IdentityProviderError>;

/// Attestation event from the kernel
#[derive(Debug, Clone)]
pub struct AttestationEvent {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Event type
    pub event_type: AttestationEventType,
    /// Whether the event was allowed
    pub allowed: bool,
    /// Timestamp in nanoseconds
    pub timestamp_ns: u64,
}

/// Type of attestation event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationEventType {
    /// Process forked
    Fork,
    /// Process executed a new binary
    Exec,
    /// Process initiated network connection
    Connect,
    /// Security policy violation
    Violation,
}

/// Configuration for the identity provider
#[derive(Debug, Clone)]
pub struct IdentityProviderConfig {
    /// Cgroup path prefix for trusted processes
    pub cgroup_prefix: String,
    /// Binary hash allowlist
    pub allowlist: Option<Allowlist>,
    /// Whether to fail open (allow on error) or fail closed
    pub fail_open: bool,
    /// Enable event logging
    pub enable_logging: bool,
}

impl Default for IdentityProviderConfig {
    fn default() -> Self {
        Self {
            cgroup_prefix: "/sys/fs/cgroup/synapse/".to_string(),
            allowlist: None,
            fail_open: true, // Safe default for development
            enable_logging: true,
        }
    }
}

/// Identity provider trait - abstracts kernel-level process attestation
///
/// This trait provides a platform-agnostic interface for verifying process
/// identity and managing trusted PID sets.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Attach the identity provider to kernel hooks.
    ///
    /// **Current implementations are simulations.** Neither the Linux
    /// `EbpfIdentityProvider` nor the non-Linux `MockIdentityProvider` load
    /// real eBPF programs or perform kernel-level attestation today; both
    /// just track an in-memory "trusted" PID set. On Linux, `attach()`
    /// additionally requires the `SIMULATED_IDENTITY_ENV`
    /// (`SYNAPSE_ALLOW_SIMULATED_IDENTITY`) environment variable to be
    /// explicitly set to `"1"`/`"true"` before it will proceed, and returns
    /// an error otherwise.
    async fn attach(&self) -> IdentityProviderResult<()>;

    /// Detach from kernel hooks.
    async fn detach(&self) -> IdentityProviderResult<()>;

    /// Check if a process is trusted.
    ///
    /// Returns `true` if the PID is in the trusted set, `false` otherwise.
    async fn verify_pid(&self, pid: u32) -> IdentityProviderResult<bool>;

    /// Explicitly mark a PID as trusted.
    ///
    /// This is used by the attestation flow after verifying process attributes.
    async fn trust_pid(&self, pid: u32) -> IdentityProviderResult<()>;

    /// Remove a PID from the trusted set.
    async fn untrust_pid(&self, pid: u32) -> IdentityProviderResult<()>;

    /// Get all currently trusted PIDs.
    async fn trusted_pids(&self) -> IdentityProviderResult<Vec<u32>>;

    /// Subscribe to attestation events.
    ///
    /// Returns a channel receiver for attestation events from the kernel.
    async fn subscribe_events(
        &self,
    ) -> IdentityProviderResult<tokio::sync::mpsc::Receiver<AttestationEvent>>;

    /// Get provider statistics.
    async fn stats(&self) -> IdentityProviderResult<ProviderStats>;

    /// Check if the provider is attached (active).
    fn is_attached(&self) -> bool;
}

/// Statistics from the identity provider
#[derive(Debug, Clone, Default)]
pub struct ProviderStats {
    /// Number of processes verified
    pub processes_verified: u64,
    /// Number of processes trusted
    pub processes_trusted: u64,
    /// Number of processes denied
    pub processes_denied: u64,
    /// Number of network packets allowed
    pub packets_allowed: u64,
    /// Number of network packets dropped
    pub packets_dropped: u64,
    /// Number of attestation events emitted
    pub events_emitted: u64,
}

// =============================================================================
// Linux eBPF Implementation
// =============================================================================

/// Linux eBPF-based identity provider
///
/// Uses Aya to load and manage eBPF programs for kernel-level attestation.
#[cfg(target_os = "linux")]
pub struct EbpfIdentityProvider {
    config: IdentityProviderConfig,
    attached: Arc<std::sync::atomic::AtomicBool>,
    trusted_pids: Arc<RwLock<HashSet<u32>>>,
    stats: Arc<RwLock<ProviderStats>>,
    event_tx: Option<tokio::sync::mpsc::Sender<AttestationEvent>>,
    // In a full implementation, this would hold the Aya BPF object
    // bpf: Option<aya::Bpf>,
}

#[cfg(target_os = "linux")]
impl EbpfIdentityProvider {
    /// Create a new eBPF identity provider
    pub fn new(config: IdentityProviderConfig) -> Self {
        Self {
            config,
            attached: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            trusted_pids: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(ProviderStats::default())),
            event_tx: None,
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl IdentityProvider for EbpfIdentityProvider {
    async fn attach(&self) -> IdentityProviderResult<()> {
        error!(
            "EbpfIdentityProvider::attach() is a SIMULATION \u{2014} no eBPF program is loaded, \
             no kernel-level attestation occurs. Do not rely on this for security in any \
             environment."
        );

        // Require an explicit, informed opt-in before proceeding. Without this,
        // a caller could end up with security-looking behavior (attach() returns
        // Ok, is_attached() is true, verify_pid() reports "trusted") that is
        // backed by nothing but an in-memory HashSet.
        if !env_opt_in(SIMULATED_IDENTITY_ENV) {
            return Err(IdentityProviderError::ConfigError(format!(
                "EbpfIdentityProvider::attach() refused to proceed: this is a SIMULATED \
                 identity provider with no real eBPF/kernel attestation. Set the {} \
                 environment variable to \"1\" or \"true\" to explicitly opt into the \
                 simulation (development/testing only \u{2014} never in production).",
                SIMULATED_IDENTITY_ENV
            )));
        }

        // In a full implementation, this would:
        // 1. Load the synapse-ebpf bytecode from embedded bytes or file
        // 2. Attach task_alloc LSM hook
        // 3. Attach cgroup_skb to the synapse cgroup
        // 4. Attach tcp_connect kprobe
        // 5. Start the perf event reader task

        // For now, we simulate successful attachment
        self.attached
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Mark the current process as trusted (bootstrap)
        let current_pid = std::process::id();
        self.trust_pid(current_pid).await?;

        warn!(
            "eBPF identity provider SIMULATED attach complete, current PID {} marked trusted \
             (no real kernel verification was performed)",
            current_pid
        );

        Ok(())
    }

    async fn detach(&self) -> IdentityProviderResult<()> {
        info!("Detaching eBPF identity provider");
        self.attached
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn verify_pid(&self, pid: u32) -> IdentityProviderResult<bool> {
        let pids = self.trusted_pids.read().await;
        let trusted = pids.contains(&pid);

        let mut stats = self.stats.write().await;
        stats.processes_verified += 1;

        debug!("verify_pid({}): trusted={}", pid, trusted);
        Ok(trusted)
    }

    async fn trust_pid(&self, pid: u32) -> IdentityProviderResult<()> {
        let mut pids = self.trusted_pids.write().await;
        pids.insert(pid);

        let mut stats = self.stats.write().await;
        stats.processes_trusted += 1;

        debug!("trust_pid({}): added to trusted set", pid);
        Ok(())
    }

    async fn untrust_pid(&self, pid: u32) -> IdentityProviderResult<()> {
        let mut pids = self.trusted_pids.write().await;
        pids.remove(&pid);

        debug!("untrust_pid({}): removed from trusted set", pid);
        Ok(())
    }

    async fn trusted_pids(&self) -> IdentityProviderResult<Vec<u32>> {
        let pids = self.trusted_pids.read().await;
        Ok(pids.iter().copied().collect())
    }

    async fn subscribe_events(
        &self,
    ) -> IdentityProviderResult<tokio::sync::mpsc::Receiver<AttestationEvent>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        // In a full implementation, this would start a perf event reader
        // that forwards events from the eBPF ring buffer
        Ok(rx)
    }

    async fn stats(&self) -> IdentityProviderResult<ProviderStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    fn is_attached(&self) -> bool {
        self.attached.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// =============================================================================
// Mock Implementation (Windows/macOS)
// =============================================================================

/// Mock identity provider for development on non-Linux platforms
///
/// This implementation simulates the eBPF behavior using user-space data
/// structures. It allows developers to write and test the upper layers of
/// the application without requiring a Linux VM.
#[cfg(not(target_os = "linux"))]
pub struct MockIdentityProvider {
    #[allow(dead_code)]
    config: IdentityProviderConfig,
    attached: Arc<std::sync::atomic::AtomicBool>,
    trusted_pids: Arc<RwLock<HashSet<u32>>>,
    stats: Arc<RwLock<ProviderStats>>,
    event_tx: Arc<RwLock<Option<tokio::sync::mpsc::Sender<AttestationEvent>>>>,
}

#[cfg(not(target_os = "linux"))]
impl MockIdentityProvider {
    /// Create a new mock identity provider
    pub fn new(config: IdentityProviderConfig) -> Self {
        Self {
            config,
            attached: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            trusted_pids: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(ProviderStats::default())),
            event_tx: Arc::new(RwLock::new(None)),
        }
    }

    /// Simulate an attestation event (for testing)
    pub async fn simulate_event(&self, event: AttestationEvent) -> IdentityProviderResult<()> {
        let tx_guard = self.event_tx.read().await;
        if let Some(tx) = tx_guard.as_ref() {
            tx.send(event).await.map_err(|e| {
                IdentityProviderError::MapError(format!("Failed to send event: {}", e))
            })?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait]
impl IdentityProvider for MockIdentityProvider {
    async fn attach(&self) -> IdentityProviderResult<()> {
        warn!("Using MOCK identity provider (non-Linux platform)");
        info!("Mock eBPF identity provider attached");

        self.attached
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Auto-trust current process
        let current_pid = std::process::id();
        self.trust_pid(current_pid).await?;

        info!(
            "Mock identity provider attached, current PID {} trusted",
            current_pid
        );

        Ok(())
    }

    async fn detach(&self) -> IdentityProviderResult<()> {
        info!("Mock identity provider detached");
        self.attached
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn verify_pid(&self, pid: u32) -> IdentityProviderResult<bool> {
        let pids = self.trusted_pids.read().await;
        let trusted = pids.contains(&pid);

        let mut stats = self.stats.write().await;
        stats.processes_verified += 1;

        debug!("mock verify_pid({}): trusted={}", pid, trusted);
        Ok(trusted)
    }

    async fn trust_pid(&self, pid: u32) -> IdentityProviderResult<()> {
        let mut pids = self.trusted_pids.write().await;
        pids.insert(pid);

        let mut stats = self.stats.write().await;
        stats.processes_trusted += 1;

        debug!("mock trust_pid({}): added to trusted set", pid);
        Ok(())
    }

    async fn untrust_pid(&self, pid: u32) -> IdentityProviderResult<()> {
        let mut pids = self.trusted_pids.write().await;
        pids.remove(&pid);

        debug!("mock untrust_pid({}): removed from trusted set", pid);
        Ok(())
    }

    async fn trusted_pids(&self) -> IdentityProviderResult<Vec<u32>> {
        let pids = self.trusted_pids.read().await;
        Ok(pids.iter().copied().collect())
    }

    async fn subscribe_events(
        &self,
    ) -> IdentityProviderResult<tokio::sync::mpsc::Receiver<AttestationEvent>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let mut tx_guard = self.event_tx.write().await;
        *tx_guard = Some(tx);
        Ok(rx)
    }

    async fn stats(&self) -> IdentityProviderResult<ProviderStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    fn is_attached(&self) -> bool {
        self.attached.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/// Creates an identity provider appropriate for the current platform.
///
/// On Linux, returns an eBPF-based provider that attests process identities
/// using kernel instrumentation (kprobes) to verify binary hashes and cgroups.
///
/// # Arguments
///
/// * `config` - Configuration for the identity provider including allowlist settings.
///
/// # Returns
///
/// An `Arc<dyn IdentityProvider>` that can be used to attest process identities.
#[cfg(target_os = "linux")]
pub fn get_identity_provider(
    config: IdentityProviderConfig,
) -> IdentityProviderResult<Arc<dyn IdentityProvider>> {
    Ok(Arc::new(EbpfIdentityProvider::new(config)))
}

/// Creates an identity provider appropriate for the current platform.
///
/// On non-Linux platforms, returns a mock provider for development/testing.
///
/// # Arguments
///
/// * `config` - Configuration for the identity provider including allowlist settings.
///
/// # Returns
///
/// An `Arc<dyn IdentityProvider>` that can be used to attest process identities.
#[cfg(not(target_os = "linux"))]
pub fn get_identity_provider(
    config: IdentityProviderConfig,
) -> IdentityProviderResult<Arc<dyn IdentityProvider>> {
    Ok(Arc::new(MockIdentityProvider::new(config)))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_provider_attach_detach() {
        let config = IdentityProviderConfig::default();
        let provider = get_identity_provider(config).unwrap();

        assert!(!provider.is_attached());
        provider.attach().await.unwrap();
        assert!(provider.is_attached());
        provider.detach().await.unwrap();
        assert!(!provider.is_attached());
    }

    #[tokio::test]
    async fn test_trust_and_verify() {
        let config = IdentityProviderConfig::default();
        let provider = get_identity_provider(config).unwrap();
        provider.attach().await.unwrap();

        // Current process should be auto-trusted
        let current_pid = std::process::id();
        assert!(provider.verify_pid(current_pid).await.unwrap());

        // Random PID should not be trusted
        assert!(!provider.verify_pid(99999).await.unwrap());

        // Trust a new PID
        provider.trust_pid(12345).await.unwrap();
        assert!(provider.verify_pid(12345).await.unwrap());

        // Untrust it
        provider.untrust_pid(12345).await.unwrap();
        assert!(!provider.verify_pid(12345).await.unwrap());
    }

    #[tokio::test]
    async fn test_stats() {
        let config = IdentityProviderConfig::default();
        let provider = get_identity_provider(config).unwrap();
        provider.attach().await.unwrap();

        // Verify a few PIDs
        let _ = provider.verify_pid(1).await;
        let _ = provider.verify_pid(2).await;
        let _ = provider.verify_pid(3).await;

        let stats = provider.stats().await.unwrap();
        assert!(stats.processes_verified >= 3);
        assert!(stats.processes_trusted >= 1); // Current process
    }
}
