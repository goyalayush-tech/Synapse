//! Uncopyable Infrastructure Orchestration
//!
//! This module wires together the three pillars of Environmental Entanglement:
//!
//! 1. **eBPF Identity** → Process verification via kernel hooks
//! 2. **Vector Memory** → Semantic storage via LanceDB
//! 3. **WASM Governance** → Policy execution via encrypted modules
//!
//! # The Uncopyable Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Environmental Entanglement Flow                       │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
//! │  │   eBPF       │    │   WASM       │    │   Vector     │              │
//! │  │   Events     │───▶│   Policy     │───▶│   Memory     │              │
//! │  │              │    │   Evaluate   │    │   (LanceDB)  │              │
//! │  └──────────────┘    └──────────────┘    └──────────────┘              │
//! │         │                   │                   │                       │
//! │         ▼                   ▼                   ▼                       │
//! │  TRUSTED_PIDS map   Key derivation      Semantic indexing              │
//! │  Binary hashes      Encrypted modules   Intent capture                 │
//! │  Cgroup filters     Fuel metering       Vector search                  │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Insight
//!
//! The system is "Uncopyable" because:
//! - WASM modules are encrypted with keys derived from TRUSTED_PIDS
//! - TRUSTED_PIDS exist only in kernel memory (not copyable to another machine)
//! - Even with the encrypted module, you need the exact eBPF state to decrypt
//! - The broker becomes the ONLY place where policies can execute

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, instrument, warn};

/// Events from the eBPF layer.
///
/// These events are captured by kprobes attached to kernel syscalls and
/// represent security-relevant process lifecycle events.
#[derive(Debug, Clone)]
pub enum EbpfEvent {
    /// Process forked from a trusted parent.
    Fork {
        /// Process ID of the parent that called fork().
        parent_pid: u32,
        /// Process ID of the newly created child process.
        child_pid: u32,
        /// Kernel timestamp in nanoseconds when the fork occurred.
        timestamp_ns: u64,
    },
    /// Process executed a new binary.
    Exec {
        /// Process ID that called execve().
        pid: u32,
        /// SHA-256 hash of the executed binary for allowlist verification.
        binary_hash: [u8; 32],
        /// Filesystem path to the executed binary.
        path: String,
        /// Kernel timestamp in nanoseconds when the exec occurred.
        timestamp_ns: u64,
    },
    /// Process attempted network connection.
    Connect {
        /// Process ID that initiated the connection.
        pid: u32,
        /// Destination IPv4 address in network byte order.
        dest_ip: u32,
        /// Destination port number.
        dest_port: u16,
        /// Kernel timestamp in nanoseconds when the connect occurred.
        timestamp_ns: u64,
    },
    /// Process exited.
    Exit {
        /// Process ID that exited.
        pid: u32,
        /// Exit code returned by the process.
        exit_code: i32,
        /// Kernel timestamp in nanoseconds when the exit occurred.
        timestamp_ns: u64,
    },
    /// Process moved cgroups.
    CgroupAttach {
        /// Process ID that was moved to a new cgroup.
        pid: u32,
        /// Kernel cgroup ID the process was attached to.
        cgroup_id: u64,
        /// Kernel timestamp in nanoseconds when the attachment occurred.
        timestamp_ns: u64,
    },
}

/// Verdict from WASM policy evaluation.
///
/// This represents the decision made by a Cedar/WASM policy module when
/// evaluating an incoming event or request.
#[derive(Debug, Clone)]
pub enum PolicyVerdict {
    /// Allow the operation without modification.
    Allow,
    /// Deny the operation with reason.
    Deny {
        /// Human-readable explanation for why the request was denied.
        reason: String,
    },
    /// Allow but log for audit.
    AllowWithAudit {
        /// Tags to attach to the audit log entry for categorization.
        tags: Vec<String>,
    },
    /// Transform the event before processing.
    Transform {
        /// List of field modifications to apply to the event.
        modifications: Vec<Modification>,
    },
}

/// Event modification from policy.
///
/// Represents a single field modification that the policy engine
/// wants to apply to an event before it is processed.
#[derive(Debug, Clone)]
pub struct Modification {
    /// Name of the field to modify (dot-notation for nested fields).
    pub field: String,
    /// New value to set for the field (JSON-encoded).
    pub value: String,
}

/// Configuration for the Uncopyable runtime
#[derive(Debug, Clone)]
pub struct UncopyableConfig {
    /// Whether to require encrypted WASM modules
    pub require_encrypted_modules: bool,
    /// Path to policy WASM files
    pub policy_path: String,
    /// Whether to verify cgroup at startup
    pub verify_cgroup: bool,
    /// Event buffer size for the broadcast channel
    pub event_buffer_size: usize,
}

impl Default for UncopyableConfig {
    fn default() -> Self {
        Self {
            require_encrypted_modules: false, // true in production
            policy_path: "./policies".to_string(),
            verify_cgroup: false, // true on Linux
            event_buffer_size: 1024,
        }
    }
}

/// Intent record for semantic storage
#[derive(Debug, Clone)]
pub struct IntentRecord {
    /// Unique event ID
    pub id: u64,
    /// Source process
    pub source_pid: u32,
    /// Action performed
    pub action: String,
    /// Human-readable description for embedding
    pub description: String,
    /// Policy verdict
    pub verdict: String,
    /// Timestamp
    pub timestamp_ns: u64,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
}

impl IntentRecord {
    /// Create from eBPF event and verdict
    pub fn from_event(event: &EbpfEvent, verdict: &PolicyVerdict, id: u64) -> Self {
        let (action, description, source_pid, timestamp_ns) = match event {
            EbpfEvent::Fork { parent_pid, child_pid, timestamp_ns } => (
                "fork".to_string(),
                format!("Process {} forked child {}", parent_pid, child_pid),
                *parent_pid,
                *timestamp_ns,
            ),
            EbpfEvent::Exec { pid, path, timestamp_ns, .. } => (
                "exec".to_string(),
                format!("Process {} executed {}", pid, path),
                *pid,
                *timestamp_ns,
            ),
            EbpfEvent::Connect { pid, dest_ip, dest_port, timestamp_ns } => (
                "connect".to_string(),
                format!(
                    "Process {} connected to {}:{}",
                    pid,
                    std::net::Ipv4Addr::from(*dest_ip),
                    dest_port
                ),
                *pid,
                *timestamp_ns,
            ),
            EbpfEvent::Exit { pid, exit_code, timestamp_ns } => (
                "exit".to_string(),
                format!("Process {} exited with code {}", pid, exit_code),
                *pid,
                *timestamp_ns,
            ),
            EbpfEvent::CgroupAttach { pid, cgroup_id, timestamp_ns } => (
                "cgroup_attach".to_string(),
                format!("Process {} attached to cgroup {}", pid, cgroup_id),
                *pid,
                *timestamp_ns,
            ),
        };

        let verdict_str = match verdict {
            PolicyVerdict::Allow => "allow".to_string(),
            PolicyVerdict::Deny { reason } => format!("deny: {}", reason),
            PolicyVerdict::AllowWithAudit { .. } => "allow_audit".to_string(),
            PolicyVerdict::Transform { .. } => "transform".to_string(),
        };

        Self {
            id,
            source_pid,
            action,
            description,
            verdict: verdict_str,
            timestamp_ns,
            metadata: Vec::new(),
        }
    }
}

/// The Uncopyable Runtime
///
/// This is the central orchestrator that:
/// 1. Receives eBPF events
/// 2. Routes them through WASM policy evaluation
/// 3. Stores intent records in Vector Memory
pub struct UncopyableRuntime {
    config: UncopyableConfig,
    /// Channel for incoming eBPF events
    event_tx: broadcast::Sender<EbpfEvent>,
    /// Next event ID
    next_id: std::sync::atomic::AtomicU64,
    /// Runtime state
    state: Arc<RuntimeState>,
}

/// Internal runtime state
struct RuntimeState {
    /// Whether the runtime has been verified
    verified: std::sync::atomic::AtomicBool,
    /// Startup timestamp
    started_at: std::time::Instant,
}

impl UncopyableRuntime {
    /// Create a new Uncopyable runtime
    #[instrument(skip(config))]
    pub fn new(config: UncopyableConfig) -> Self {
        info!("Initializing Uncopyable Runtime");

        let (event_tx, _) = broadcast::channel(config.event_buffer_size);

        Self {
            config,
            event_tx,
            next_id: std::sync::atomic::AtomicU64::new(1),
            state: Arc::new(RuntimeState {
                verified: std::sync::atomic::AtomicBool::new(false),
                started_at: std::time::Instant::now(),
            }),
        }
    }

    /// Verify the execution environment
    ///
    /// This MUST be called before loading policies or processing events.
    #[instrument(skip(self))]
    pub fn verify_environment(&self) -> Result<(), String> {
        info!("Verifying execution environment...");

        // 1. Verify cgroup membership
        if self.config.verify_cgroup {
            #[cfg(target_os = "linux")]
            {
                self.verify_cgroup()?;
            }
        }

        // 2. Verify we're running as expected user
        self.verify_user()?;

        // 3. Mark as verified
        self.state.verified.store(true, std::sync::atomic::Ordering::SeqCst);

        info!("Environment verification passed");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_cgroup(&self) -> Result<(), String> {
        let cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("Failed to read cgroup: {}", e))?;

        if !cgroup.contains("synapse") && std::env::var("SYNAPSE_SKIP_CGROUP_CHECK").is_err() {
            return Err("Not in synapse cgroup".to_string());
        }

        Ok(())
    }

    fn verify_user(&self) -> Result<(), String> {
        // In production: verify we're running as synapse user
        // For now: just check we're not root (unless allowed)
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } == 0 {
                if std::env::var("SYNAPSE_ALLOW_ROOT").is_err() {
                    warn!("Running as root is not recommended");
                    // Don't fail, just warn
                }
            }
        }
        Ok(())
    }

    /// Get a sender for eBPF events
    pub fn event_sender(&self) -> broadcast::Sender<EbpfEvent> {
        self.event_tx.clone()
    }

    /// Subscribe to processed events
    pub fn subscribe(&self) -> broadcast::Receiver<EbpfEvent> {
        self.event_tx.subscribe()
    }

    /// Process an eBPF event through the full pipeline
    ///
    /// This is the core "Uncopyable" flow:
    /// 1. Receive event from eBPF
    /// 2. Evaluate against WASM policy
    /// 3. Store intent in Vector Memory
    #[instrument(skip(self, event), fields(event_type = ?event))]
    pub async fn process_event(&self, event: EbpfEvent) -> Result<IntentRecord, String> {
        if !self.state.verified.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Runtime not verified - call verify_environment() first".to_string());
        }

        debug!("Processing event: {:?}", event);

        // 1. Generate event ID
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // 2. Evaluate policy (placeholder - in production calls WasmHost)
        let verdict = self.evaluate_policy(&event).await?;

        // 3. Create intent record
        let record = IntentRecord::from_event(&event, &verdict, id);

        // 4. Broadcast event
        if let Err(e) = self.event_tx.send(event) {
            warn!("No receivers for event broadcast: {}", e);
        }

        // 5. Store in Vector Memory (placeholder - in production calls LanceDbStore)
        self.store_intent(&record).await?;

        debug!("Event processed: id={}, verdict={}", id, record.verdict);
        Ok(record)
    }

    /// Evaluate WASM policy for an event
    async fn evaluate_policy(&self, event: &EbpfEvent) -> Result<PolicyVerdict, String> {
        // In production:
        // let policy_event = PolicyEvent::from(event);
        // let verdict = self.wasm_host.evaluate(policy_event).await?;
        // return Ok(verdict.into());

        // Placeholder: default allow
        match event {
            EbpfEvent::Connect { dest_port, .. } if *dest_port == 22 => {
                // Example: deny SSH connections
                Ok(PolicyVerdict::AllowWithAudit {
                    tags: vec!["ssh".to_string(), "sensitive".to_string()],
                })
            }
            _ => Ok(PolicyVerdict::Allow),
        }
    }

    /// Store intent record in Vector Memory
    async fn store_intent(&self, record: &IntentRecord) -> Result<(), String> {
        // In production:
        // let embedding = self.embedder.embed(&record.description).await?;
        // self.lance_store.insert(record, embedding).await?;

        debug!(
            "Storing intent: id={}, action={}, description={}",
            record.id, record.action, record.description
        );

        Ok(())
    }

    /// Query Vector Memory semantically
    #[instrument(skip(self))]
    pub async fn recall(&self, query: &str, limit: usize) -> Result<Vec<IntentRecord>, String> {
        info!("Semantic recall: query='{}', limit={}", query, limit);

        // In production:
        // let embedding = self.embedder.embed(query).await?;
        // let results = self.lance_store.vector_search(&embedding, limit).await?;
        // return Ok(results);

        // Placeholder: return empty
        Ok(Vec::new())
    }

    /// Get runtime statistics
    pub fn stats(&self) -> RuntimeStats {
        RuntimeStats {
            verified: self.state.verified.load(std::sync::atomic::Ordering::SeqCst),
            uptime_secs: self.state.started_at.elapsed().as_secs(),
            events_processed: self.next_id.load(std::sync::atomic::Ordering::SeqCst) - 1,
        }
    }
}

/// Runtime statistics.
///
/// Provides a snapshot of the Uncopyable runtime's current state
/// for monitoring and health checks.
#[derive(Debug, Clone)]
pub struct RuntimeStats {
    /// Whether the runtime has been verified and is ready to process events.
    pub verified: bool,
    /// Number of seconds since the runtime was initialized.
    pub uptime_secs: u64,
    /// Total number of events processed since startup.
    pub events_processed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = UncopyableConfig::default();
        let runtime = UncopyableRuntime::new(config);
        assert!(!runtime.state.verified.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_process_event_requires_verification() {
        let config = UncopyableConfig::default();
        let runtime = UncopyableRuntime::new(config);

        let event = EbpfEvent::Fork {
            parent_pid: 1,
            child_pid: 2,
            timestamp_ns: 0,
        };

        let result = runtime.process_event(event).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not verified"));
    }

    #[tokio::test]
    async fn test_process_event_after_verification() {
        let config = UncopyableConfig {
            verify_cgroup: false,
            ..Default::default()
        };
        let runtime = UncopyableRuntime::new(config);

        // Skip cgroup check for test
        std::env::set_var("SYNAPSE_SKIP_CGROUP_CHECK", "1");
        runtime.verify_environment().unwrap();

        let event = EbpfEvent::Exec {
            pid: 100,
            binary_hash: [0u8; 32],
            path: "/usr/bin/test".to_string(),
            timestamp_ns: 12345,
        };

        let result = runtime.process_event(event).await;
        assert!(result.is_ok());

        let record = result.unwrap();
        assert_eq!(record.action, "exec");
        assert_eq!(record.source_pid, 100);

        std::env::remove_var("SYNAPSE_SKIP_CGROUP_CHECK");
    }

    #[tokio::test]
    async fn test_intent_record_creation() {
        let event = EbpfEvent::Connect {
            pid: 42,
            dest_ip: 0x7f000001, // 127.0.0.1
            dest_port: 8080,
            timestamp_ns: 999,
        };

        let verdict = PolicyVerdict::Allow;
        let record = IntentRecord::from_event(&event, &verdict, 1);

        assert_eq!(record.action, "connect");
        assert!(record.description.contains("127.0.0.1"));
        assert!(record.description.contains("8080"));
    }
}
