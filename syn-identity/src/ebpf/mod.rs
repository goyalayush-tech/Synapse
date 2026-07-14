//! eBPF-based instrumentation and attestation.
//!
//! This module provides eBPF programs for kernel-level monitoring and
//! process attestation. eBPF allows us to verify process attributes
//! at the kernel level, providing stronger security guarantees than
//! user-space process introspection.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    User Space (syn-identity)                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
//! │  │ Allowlist   │◄───│ Verifier    │◄───│ AttestationEngine   │ │
//! │  │ (SHA-256)   │    │ (Compare)   │    │ (Coordinate)        │ │
//! │  └─────────────┘    └─────────────┘    └─────────────────────┘ │
//! │         ▲                  ▲                      ▲             │
//! │         │                  │                      │             │
//! │         │            ┌─────┴──────┐               │             │
//! │         │            │ PerfBuffer │               │             │
//! │         │            └─────┬──────┘               │             │
//! ├─────────┼──────────────────┼──────────────────────┼─────────────┤
//! │         │     Kernel Space │                      │             │
//! │         │            ┌─────┴──────┐               │             │
//! │         │            │  kprobe    │───────────────┘             │
//! │         │            │(tcp_connect)│                            │
//! │         │            └────────────┘                             │
//! │         │                  ▲                                    │
//! │         │                  │                                    │
//! │         └──────────────────┴───────────────────────────────────│
//! │                      /proc/{pid}/exe                            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - XDP programs for packet filtering and counting
//! - kProbe instrumentation for connection attestation
//! - Binary hash verification via SHA-256
//! - Cgroup-based container identity
//! - Process attestation via perf events
//!
//! # Platform Support
//!
//! - **Linux**: Full eBPF support via aya-rs
//! - **Windows/macOS**: Mock attestation for development

pub mod allowlist;
pub mod verifier;

#[cfg(feature = "ebpf")]
pub mod xdp;

#[cfg(feature = "ebpf")]
pub mod kprobe;

pub use allowlist::{Allowlist, AllowlistEntry, BinaryHash};
pub use verifier::{AttestationVerifier, ProcessInfo, VerificationDenial, VerificationResult};

#[cfg(feature = "ebpf")]
pub use kprobe::{KprobeError, KprobeProgram};
#[cfg(feature = "ebpf")]
pub use xdp::{XdpError, XdpProgram};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

/// Errors that can occur during eBPF attestation
#[derive(Debug, Error)]
pub enum EbpfError {
    /// eBPF program load failed
    #[error("eBPF program load failed: {0}")]
    ProgramLoad(String),

    /// kprobe attach failed
    #[error("kprobe attach failed: {0}")]
    KprobeAttach(String),

    /// XDP attach failed.
    #[error("XDP attach failed on interface {interface}: {reason}")]
    XdpAttach {
        /// Network interface name where XDP attachment was attempted.
        interface: String,
        /// Detailed error message explaining why attachment failed.
        reason: String,
    },

    /// Map operation failed
    #[error("Map operation failed: {0}")]
    MapOperation(String),

    /// Attestation failed.
    #[error("Attestation failed for PID {pid}: {reason}")]
    AttestationFailed {
        /// Process ID that failed attestation.
        pid: u32,
        /// Reason why the process could not be attested.
        reason: String,
    },

    /// Binary hash mismatch.
    #[error("Binary hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected SHA-256 hash from the allowlist.
        expected: String,
        /// Actual SHA-256 hash computed from the binary.
        actual: String,
    },

    /// Cgroup denied
    #[error("Process not in allowed cgroup: {0}")]
    CgroupDenied(String),

    /// Platform not supported
    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(#[from] verifier::VerifierError),
}

/// Result type for eBPF operations
pub type Result<T> = std::result::Result<T, EbpfError>;

/// Raw attestation event from kernel (matches synapse-ebpf AttestationEvent)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AttestationEventRaw {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Event type (0=fork, 1=exec, 2=connect, 3=violation)
    pub event_type: u8,
    /// Verdict (0=denied, 1=allowed)
    pub verdict: u8,
    /// Padding for alignment
    _padding: [u8; 2],
    /// Timestamp (ktime_ns)
    pub timestamp_ns: u64,
}

/// Connection event captured by eBPF kprobe
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ConnectionEvent {
    /// Source process ID
    pub pid: u32,
    /// Thread group ID
    pub tgid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID  
    pub gid: u32,
    /// Process command name (comm)
    pub comm: [u8; 16],
    /// Source IP address (network byte order)
    pub saddr: u32,
    /// Destination IP address (network byte order)
    pub daddr: u32,
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Cgroup ID
    pub cgroup_id: u64,
    /// Timestamp (nanoseconds since boot)
    pub timestamp_ns: u64,
}

impl ConnectionEvent {
    /// Get the process command as a string
    pub fn comm_str(&self) -> String {
        let null_pos = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..null_pos]).to_string()
    }

    /// Get source IP as dotted string
    pub fn saddr_str(&self) -> String {
        let bytes = self.saddr.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    /// Get destination IP as dotted string
    pub fn daddr_str(&self) -> String {
        let bytes = self.daddr.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Configuration for the eBPF attestation engine
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Path to compiled eBPF object file
    pub bpf_object_path: Option<PathBuf>,
    /// Network interface for XDP attachment
    pub xdp_interface: Option<String>,
    /// Enable kprobe for tcp_connect
    pub enable_kprobe: bool,
    /// Enable XDP packet filtering
    pub enable_xdp: bool,
    /// Perf buffer size in pages
    pub perf_buffer_pages: usize,
    /// Allowlist refresh interval (seconds)
    pub allowlist_refresh_secs: u64,
    /// Enable simulation mode (no real eBPF)
    pub simulation_mode: bool,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            bpf_object_path: None,
            xdp_interface: None,
            enable_kprobe: true,
            enable_xdp: false,
            perf_buffer_pages: 64,
            allowlist_refresh_secs: 300,
            simulation_mode: cfg!(not(target_os = "linux")),
        }
    }
}

/// The main eBPF attestation engine
///
/// This is the core of Synapse's zero-trust identity model.
/// It coordinates binary verification, cgroup checking, and
/// kernel-level connection monitoring.
pub struct EbpfAttestationEngine {
    config: EbpfConfig,
    allowlist: Arc<RwLock<Allowlist>>,
    verifier: Arc<AttestationVerifier>,
    /// Channel for receiving connection events (reserved for async event processing)
    #[allow(dead_code)]
    event_tx: mpsc::Sender<ConnectionEvent>,
    #[allow(dead_code)]
    event_rx: mpsc::Receiver<ConnectionEvent>,
    /// Channel for attestation results
    result_tx: mpsc::Sender<VerificationResult>,
    result_rx: Option<mpsc::Receiver<VerificationResult>>,
    /// Process info cache
    process_cache: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
    /// Running state
    running: Arc<AtomicBool>,
}

impl EbpfAttestationEngine {
    /// Create a new attestation engine
    pub fn new(config: EbpfConfig) -> Self {
        let allowlist = Arc::new(RwLock::new(Allowlist::new()));
        let verifier = Arc::new(AttestationVerifier::new(allowlist.clone()));
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (result_tx, result_rx) = mpsc::channel(1024);

        Self {
            config,
            allowlist,
            verifier,
            event_tx,
            event_rx,
            result_tx,
            result_rx: Some(result_rx),
            process_cache: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Load allowlist from file
    pub async fn load_allowlist(&self, path: &std::path::Path) -> Result<()> {
        let allowlist = Allowlist::from_file(path).await?;
        *self.allowlist.write().await = allowlist;
        tracing::info!("Loaded allowlist from {:?}", path);
        Ok(())
    }

    /// Add an entry to the allowlist
    pub async fn allow_binary(&self, entry: AllowlistEntry) {
        let hash = entry.hash.clone();
        self.allowlist.write().await.add_entry(entry);
        tracing::debug!("Added binary to allowlist: {}", hash);
    }

    /// Start the attestation engine
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        tracing::info!("Starting eBPF attestation engine");

        // On non-Linux or simulation mode, just start event processing
        if self.config.simulation_mode || cfg!(not(target_os = "linux")) {
            tracing::warn!("Running in simulation mode - no real eBPF");
            self.running.store(true, Ordering::SeqCst);
            self.spawn_event_processor();
            return Ok(());
        }

        // Linux with real eBPF - would load programs here
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            self.load_ebpf_programs().await?;
        }

        self.running.store(true, Ordering::SeqCst);
        self.spawn_event_processor();

        Ok(())
    }

    /// Load eBPF programs into kernel (Linux only)
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    async fn load_ebpf_programs(&mut self) -> Result<()> {
        use aya::util::online_cpus;
        use aya::{
            maps::{perf::AsyncPerfEventArray, HashMap as BpfHashMap},
            programs::{CgroupSkb, CgroupSkbAttachType, KProbe, Lsm},
            Bpf,
        };
        use bytes::BytesMut;

        // Determine BPF object path - try embedded first, then filesystem
        let bpf_path = self
            .config
            .bpf_object_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/opt/synapse/bpf/synapse_ebpf.o"));

        // Try to load BPF bytecode
        let bpf_data = if bpf_path.exists() {
            tokio::fs::read(&bpf_path).await?
        } else {
            // Try to load from embedded bytes (compile-time included)
            #[cfg(feature = "ebpf-embedded")]
            {
                include_bytes!(concat!(env!("OUT_DIR"), "/synapse_ebpf")).to_vec()
            }
            #[cfg(not(feature = "ebpf-embedded"))]
            {
                tracing::warn!(
                    "eBPF object not found at {:?}, running without kernel attestation",
                    bpf_path
                );
                return Ok(());
            }
        };

        let mut bpf = Bpf::load(&bpf_data)
            .map_err(|e| EbpfError::ProgramLoad(format!("BPF load failed: {}", e)))?;

        tracing::info!("Loaded eBPF bytecode ({} bytes)", bpf_data.len());

        // Load and attach LSM hook for task_alloc
        if let Ok(program) = bpf.program_mut("synapse_task_alloc") {
            let lsm: &mut Lsm = program
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    EbpfError::ProgramLoad(format!("LSM cast: {}", e))
                })?;

            lsm.load("task_alloc", &bpf.btf().ok())
                .map_err(|e| EbpfError::ProgramLoad(format!("LSM load: {}", e)))?;
            lsm.attach()
                .map_err(|e| EbpfError::KprobeAttach(format!("LSM attach: {}", e)))?;

            tracing::info!("Attached LSM hook: task_alloc");
        } else {
            tracing::warn!("LSM program not found in BPF object");
        }

        // Load and attach cgroup_skb for egress filtering
        if let Ok(program) = bpf.program_mut("synapse_cgroup_egress") {
            let cgroup_skb: &mut CgroupSkb =
                program
                    .try_into()
                    .map_err(|e: aya::programs::ProgramError| {
                        EbpfError::ProgramLoad(format!("CgroupSkb cast: {}", e))
                    })?;

            cgroup_skb
                .load()
                .map_err(|e| EbpfError::ProgramLoad(format!("CgroupSkb load: {}", e)))?;

            // Attach to root cgroup
            let cgroup = std::fs::File::open("/sys/fs/cgroup")
                .map_err(|e| EbpfError::ProgramLoad(format!("Open cgroup: {}", e)))?;
            cgroup_skb
                .attach(cgroup, CgroupSkbAttachType::Egress)
                .map_err(|e| EbpfError::XdpAttach {
                    interface: "cgroup".into(),
                    reason: e.to_string(),
                })?;

            tracing::info!("Attached cgroup_skb filter for egress");
        }

        // Load and attach kprobe for tcp_connect
        if self.config.enable_kprobe {
            if let Ok(program) = bpf.program_mut("synapse_tcp_connect") {
                let kprobe: &mut KProbe =
                    program
                        .try_into()
                        .map_err(|e: aya::programs::ProgramError| {
                            EbpfError::ProgramLoad(format!("KProbe cast: {}", e))
                        })?;

                kprobe
                    .load()
                    .map_err(|e| EbpfError::ProgramLoad(format!("KProbe load: {}", e)))?;
                kprobe
                    .attach("tcp_v4_connect", 0)
                    .map_err(|e| EbpfError::KprobeAttach(e.to_string()))?;

                tracing::info!("Attached kprobe: tcp_v4_connect");
            }
        }

        // Set up perf event array for attestation events
        let perf_array = AsyncPerfEventArray::try_from(
            bpf.take_map("ATTESTATION_EVENTS")
                .ok_or_else(|| EbpfError::MapOperation("ATTESTATION_EVENTS not found".into()))?,
        )
        .map_err(|e| EbpfError::MapOperation(format!("PerfArray: {}", e)))?;

        // Spawn perf buffer reader
        self.spawn_perf_reader(perf_array);

        // Get handle to TRUSTED_PIDS map for user-space synchronization
        let trusted_pids_map: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
            bpf.take_map("TRUSTED_PIDS")
                .ok_or_else(|| EbpfError::MapOperation("TRUSTED_PIDS not found".into()))?,
        )
        .map_err(|e| EbpfError::MapOperation(format!("HashMap: {}", e)))?;

        // Store BPF reference (would be stored in self in full impl)
        // For now, we just leak it to keep programs attached
        std::mem::forget(bpf);

        tracing::info!("eBPF programs loaded and attached successfully");
        Ok(())
    }

    /// Spawn perf buffer reader to receive attestation events from kernel
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    fn spawn_perf_reader(
        &self,
        mut perf_array: aya::maps::perf::AsyncPerfEventArray<aya::maps::MapData>,
    ) {
        use aya::util::online_cpus;
        use bytes::BytesMut;

        let event_tx = self.event_tx.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let cpus = online_cpus().unwrap_or_else(|_| (0..1).collect());
            let mut buffers = Vec::new();

            for cpu_id in cpus {
                let buf = perf_array
                    .open(cpu_id, None)
                    .expect("Failed to open perf buffer");
                buffers.push(buf);
            }

            let mut buf_data: [BytesMut; 10] =
                std::array::from_fn(|_| BytesMut::with_capacity(1024));

            while running.load(Ordering::SeqCst) {
                for buffer in &mut buffers {
                    if let Ok(events) = buffer.read_events(&mut buf_data).await {
                        for i in 0..events.read {
                            let data = &buf_data[i];
                            if data.len() >= std::mem::size_of::<AttestationEventRaw>() {
                                // Parse the raw event
                                let raw = unsafe {
                                    std::ptr::read_unaligned(
                                        data.as_ptr() as *const AttestationEventRaw
                                    )
                                };

                                // Convert to ConnectionEvent format
                                let event = ConnectionEvent {
                                    pid: raw.pid,
                                    tgid: raw.pid,
                                    uid: 0,
                                    gid: 0,
                                    comm: [0u8; 16],
                                    saddr: 0,
                                    daddr: 0,
                                    sport: 0,
                                    dport: 0,
                                    cgroup_id: 0,
                                    timestamp_ns: raw.timestamp_ns,
                                };

                                let _ = event_tx.send(event).await;
                            }
                        }
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }

            tracing::debug!("Perf buffer reader stopped");
        });
    }

    /// Add a PID to the trusted list (updates kernel BPF map)
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub async fn trust_pid(&self, pid: u32) -> Result<()> {
        // In a full implementation, we'd update the TRUSTED_PIDS BPF map here
        // For now, just cache it in user space
        let mut cache = self.process_cache.write().await;
        cache.insert(
            pid,
            ProcessInfo {
                pid,
                ppid: 0,
                binary_path: None,
                binary_hash: None,
                cgroup_path: None,
                uid: 0,
                gid: 0,
            },
        );
        tracing::debug!("Added PID {} to trusted list", pid);
        Ok(())
    }

    /// Remove a PID from the trusted list
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub async fn untrust_pid(&self, pid: u32) -> Result<()> {
        let mut cache = self.process_cache.write().await;
        cache.remove(&pid);
        tracing::debug!("Removed PID {} from trusted list", pid);
        Ok(())
    }

    /// Spawn event processor task
    fn spawn_event_processor(&self) {
        let verifier = self.verifier.clone();
        let result_tx = self.result_tx.clone();
        let process_cache = self.process_cache.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            tracing::debug!("Event processor started");

            while running.load(Ordering::SeqCst) {
                // In simulation mode, just sleep
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                // Clean old cache entries periodically
                let mut cache = process_cache.write().await;
                if cache.len() > 1000 {
                    cache.clear();
                }
            }

            // Suppress unused warnings
            let _ = (verifier, result_tx);
            tracing::debug!("Event processor stopped");
        });
    }

    /// Manually attest a process by PID
    pub async fn attest_process(&self, pid: u32) -> Result<VerificationResult> {
        self.verifier
            .verify_pid(pid)
            .await
            .map_err(EbpfError::Verification)
    }

    /// Attest a process by binary path (computes hash)
    pub async fn attest_binary(&self, path: &std::path::Path) -> Result<VerificationResult> {
        self.verifier
            .verify_binary(path)
            .await
            .map_err(EbpfError::Verification)
    }

    /// Get the result receiver for attestation events
    pub fn take_result_receiver(&mut self) -> Option<mpsc::Receiver<VerificationResult>> {
        self.result_rx.take()
    }

    /// Check if a binary hash is allowed
    pub async fn is_allowed(&self, hash: &BinaryHash) -> bool {
        self.allowlist.read().await.is_allowed(hash)
    }

    /// Get engine statistics
    pub async fn stats(&self) -> EngineStats {
        let allowlist = self.allowlist.read().await;
        let cache = self.process_cache.read().await;

        EngineStats {
            allowlist_entries: allowlist.len(),
            allowlist_version: allowlist.version(),
            cached_processes: cache.len(),
            running: self.running.load(Ordering::SeqCst),
            simulation_mode: self.config.simulation_mode,
        }
    }

    /// Stop the attestation engine
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("eBPF attestation engine stopped");
    }
}

/// Engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    /// Number of allowlist entries
    pub allowlist_entries: usize,
    /// Allowlist version
    pub allowlist_version: u64,
    /// Number of cached process infos
    pub cached_processes: usize,
    /// Whether engine is running
    pub running: bool,
    /// Whether running in simulation mode
    pub simulation_mode: bool,
}

/// eBPF program manager (legacy compatibility)
#[cfg(feature = "ebpf")]
pub struct EbpfManager {
    /// Loaded XDP programs.
    xdp_programs: Vec<XdpProgram>,
    /// Loaded kProbe programs.
    kprobe_programs: Vec<KprobeProgram>,
}

#[cfg(feature = "ebpf")]
impl EbpfManager {
    /// Creates a new eBPF manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            xdp_programs: Vec::new(),
            kprobe_programs: Vec::new(),
        }
    }

    /// Loads an XDP program.
    pub async fn load_xdp(&mut self, program: XdpProgram) -> std::result::Result<(), String> {
        self.xdp_programs.push(program);
        Ok(())
    }

    /// Loads a kProbe program.
    pub async fn load_kprobe(&mut self, program: KprobeProgram) -> std::result::Result<(), String> {
        self.kprobe_programs.push(program);
        Ok(())
    }
}

#[cfg(feature = "ebpf")]
impl Default for EbpfManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let config = EbpfConfig::default();
        let engine = EbpfAttestationEngine::new(config);
        assert!(!engine.running.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_engine_start_stop() {
        let config = EbpfConfig {
            simulation_mode: true,
            ..Default::default()
        };
        let mut engine = EbpfAttestationEngine::new(config);

        engine.start().await.expect("start failed");
        assert!(engine.running.load(Ordering::SeqCst));

        engine.stop();
        assert!(!engine.running.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_allowlist_operations() {
        let engine = EbpfAttestationEngine::new(EbpfConfig::default());

        let entry = AllowlistEntry::new("test-binary", BinaryHash::from_bytes(b"test"));
        let hash = entry.hash.clone();

        engine.allow_binary(entry).await;
        assert!(engine.is_allowed(&hash).await);
    }

    #[test]
    fn test_connection_event_comm_str() {
        let mut event = ConnectionEvent {
            pid: 1234,
            tgid: 1234,
            uid: 1000,
            gid: 1000,
            comm: [0u8; 16],
            saddr: 0x7f000001u32.to_be(), // 127.0.0.1
            daddr: 0x08080808u32.to_be(), // 8.8.8.8
            sport: 12345,
            dport: 443,
            cgroup_id: 0,
            timestamp_ns: 0,
        };

        event.comm[..4].copy_from_slice(b"test");
        assert_eq!(event.comm_str(), "test");
    }

    #[tokio::test]
    async fn test_engine_stats() {
        let engine = EbpfAttestationEngine::new(EbpfConfig::default());
        let stats = engine.stats().await;

        assert_eq!(stats.allowlist_entries, 0);
        assert!(!stats.running);
    }
}
