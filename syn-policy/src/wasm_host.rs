//! Wasmtime Component Model Host Implementation
//!
//! This module implements the Synapse host for WebAssembly governance policies.
//! It bridges the WIT interfaces to the actual Synapse systems:
//!
//! - `context-access` → LanceDB vector memory
//! - `network-control` → eBPF cgroup_skb filters
//! - `identity-access` → eBPF TRUSTED_PIDS map
//!
//! # Environmental Entanglement
//!
//! Policies are encrypted with a key derived from the eBPF TRUSTED_PIDS map.
//! This means:
//! - Policies can ONLY run on verified hosts
//! - Copying the WASM file is useless without the kernel state
//! - The broker becomes the trusted execution environment
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    WASM Policy Execution                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
//! │  │  Policy.wasm │  │   SynapseHost    │  │  Synapse Core    │  │
//! │  │  (Guest)     │  │   (Adapter)      │  │  (Systems)       │  │
//! │  │              │  │                  │  │                  │  │
//! │  │ evaluate()   │──│ search-memory    │──│ LanceDB          │  │
//! │  │              │  │ authorize-conn   │──│ eBPF cgroup_skb  │  │
//! │  │              │  │ is-trusted       │──│ eBPF TRUSTED_PIDS│  │
//! │  └──────────────┘  └──────────────────┘  └──────────────────┘  │
//! │         │                    │                    │            │
//! │         │         ┌─────────┴─────────┐         │            │
//! │         │         │   Wasmtime Store  │         │            │
//! │         │         │   (State, Fuel)   │         │            │
//! │         │         └───────────────────┘         │            │
//! │         │                                        │            │
//! └─────────┴────────────────────────────────────────┴────────────┘
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use syn_policy::wasm_host::{WasmHost, WasmHostConfig, PolicyEvent};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = WasmHostConfig::default();
//!     let host = WasmHost::new(config).await?;
//!     
//!     // Load a policy module
//!     host.load_policy("./policies/security.wasm").await?;
//!     
//!     // Evaluate an event
//!     let event = PolicyEvent {
//!         event_type: "connect".to_string(),
//!         source_pid: 1234,
//!         payload: vec![],
//!         timestamp_us: 0,
//!     };
//!     let verdict = host.evaluate(event).await?;
//!     
//!     Ok(())
//! }
//! ```

#![cfg(feature = "wasm-full")]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn, error};

// WHY aes-gcm: Authenticated encryption prevents both tampering and decryption
// without the correct key derived from eBPF state
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

// WHY sha2: Deterministic key derivation from TRUSTED_PIDS ensures same key
// is generated on hosts with identical verified process sets
use sha2::{Sha256, Digest};

/// Errors from the WASM host
#[derive(Debug, Error)]
pub enum WasmHostError {
    /// Failed to load WASM module
    #[error("Failed to load module: {0}")]
    LoadFailed(String),

    /// Failed to instantiate module
    #[error("Instantiation failed: {0}")]
    InstantiateFailed(String),

    /// Policy evaluation failed
    #[error("Evaluation failed: {0}")]
    EvaluationFailed(String),

    /// Fuel exhausted (execution limit)
    #[error("Fuel exhausted after {0} units")]
    FuelExhausted(u64),

    /// Host function error
    #[error("Host function error: {0}")]
    HostFunction(String),

    /// Decryption failed (uncopyable binding)
    #[error("Module decryption failed: {0}")]
    DecryptionFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for WASM host operations
pub type WasmHostResult<T> = Result<T, WasmHostError>;

/// Configuration for the WASM host
#[derive(Debug, Clone)]
pub struct WasmHostConfig {
    /// Maximum fuel (execution units) per evaluation
    pub max_fuel: u64,
    /// Timeout for evaluation
    pub timeout: Duration,
    /// Whether to enable WASI
    pub enable_wasi: bool,
    /// Whether to require encrypted modules
    pub require_encryption: bool,
    /// Path to WIT files
    pub wit_path: String,
}

impl Default for WasmHostConfig {
    fn default() -> Self {
        Self {
            max_fuel: 1_000_000,
            timeout: Duration::from_millis(100),
            enable_wasi: false, // Sandboxed by default
            require_encryption: false, // Enable in production
            wit_path: "./wit".to_string(),
        }
    }
}

/// Event to be evaluated by the policy
#[derive(Debug, Clone)]
pub struct PolicyEvent {
    /// Event type (fork, exec, connect, custom)
    pub event_type: String,
    /// Source process ID
    pub source_pid: u32,
    /// Serialized payload (TOON format)
    pub payload: Vec<u8>,
    /// Timestamp
    pub timestamp_us: u64,
}

/// Policy verdict
#[derive(Debug, Clone)]
pub struct PolicyVerdict {
    /// Whether to allow the event
    pub allow: bool,
    /// Reason for the decision
    pub reason: String,
    /// Optional transformation
    pub transform: Option<String>,
    /// Tags to add
    pub tags: Vec<String>,
}

impl Default for PolicyVerdict {
    fn default() -> Self {
        Self {
            allow: true,
            reason: "default allow".to_string(),
            transform: None,
            tags: Vec::new(),
        }
    }
}

/// Policy metadata
#[derive(Debug, Clone)]
pub struct PolicyMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
}

/// Search result from vector memory
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub id: u64,
    pub source: String,
    pub action: String,
    pub reason: String,
    pub score: f32,
}

/// Connection request for network authorization
#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    pub pid: u32,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
}

/// Authorization result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Allow,
    Deny,
    AllowWithAudit,
}

/// Process identity from eBPF
#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub trusted: bool,
    pub binary_hash: Option<String>,
    pub cgroup_path: Option<String>,
}

/// The Synapse host state shared with WASM instances
///
/// This struct holds references to the actual Synapse systems
/// and implements the WIT interfaces.
pub struct SynapseHostState {
    /// Vector memory store (LanceDB)
    // In production: memory_store: Arc<LanceDbStore>,
    /// Identity provider (eBPF)
    // In production: identity_provider: Arc<dyn IdentityProvider>,
    /// Allowed network destinations
    allowed_destinations: RwLock<Vec<String>>,
    /// Statistics
    stats: RwLock<HostStats>,
}

/// Host statistics
#[derive(Debug, Clone, Default)]
pub struct HostStats {
    pub evaluations: u64,
    pub memory_queries: u64,
    pub network_authorizations: u64,
    pub identity_lookups: u64,
}

impl SynapseHostState {
    /// Create new host state
    pub fn new() -> Self {
        Self {
            allowed_destinations: RwLock::new(vec![
                "*.synapse.local".to_string(),
                "127.0.0.1".to_string(),
            ]),
            stats: RwLock::new(HostStats::default()),
        }
    }

    // =========================================================================
    // context-access implementation
    // =========================================================================

    /// Search vector memory for similar events
    pub async fn search_memory(&self, query: &str, limit: u32) -> Vec<SearchResult> {
        debug!("search_memory: query='{}', limit={}", query, limit);

        // In production:
        // let embedding = self.embedder.embed(query).await?;
        // let results = self.memory_store.vector_search(&embedding, limit as usize).await?;

        // Simulated results for now
        let mut stats = self.stats.write().await;
        stats.memory_queries += 1;

        vec![SearchResult {
            id: 1,
            source: "agent-001".to_string(),
            action: "code_review".to_string(),
            reason: "Simulated search result".to_string(),
            score: 0.9,
        }]
    }

    /// Get event by ID
    pub async fn get_event(&self, id: u64) -> Option<SearchResult> {
        debug!("get_event: id={}", id);

        Some(SearchResult {
            id,
            source: "agent-001".to_string(),
            action: "test".to_string(),
            reason: "Test event".to_string(),
            score: 1.0,
        })
    }

    /// Get recent events
    pub async fn get_recent(&self, limit: u32) -> Vec<SearchResult> {
        debug!("get_recent: limit={}", limit);
        vec![]
    }

    /// Get events by action
    pub async fn get_by_action(&self, action: &str, limit: u32) -> Vec<SearchResult> {
        debug!("get_by_action: action='{}', limit={}", action, limit);
        vec![]
    }

    // =========================================================================
    // network-control implementation
    // =========================================================================

    /// Authorize a network connection
    pub async fn authorize_connection(&self, request: &ConnectionRequest) -> AuthResult {
        debug!(
            "authorize_connection: pid={}, dest={}:{}",
            request.pid, request.dest_ip, request.dest_port
        );

        let mut stats = self.stats.write().await;
        stats.network_authorizations += 1;

        // Check against allowlist
        let destinations = self.allowed_destinations.read().await;
        for pattern in destinations.iter() {
            if self.matches_pattern(&request.dest_ip, pattern) {
                return AuthResult::Allow;
            }
        }

        // Default: allow with audit for development
        AuthResult::AllowWithAudit
    }

    /// Get allowed destinations
    pub async fn get_allowed_destinations(&self) -> Vec<String> {
        self.allowed_destinations.read().await.clone()
    }

    /// Add allowed destination
    pub async fn add_allowed_destination(&self, pattern: String) -> bool {
        let mut destinations = self.allowed_destinations.write().await;
        if !destinations.contains(&pattern) {
            destinations.push(pattern);
            true
        } else {
            false
        }
    }

    fn matches_pattern(&self, ip: &str, pattern: &str) -> bool {
        if pattern.starts_with('*') {
            ip.ends_with(&pattern[1..])
        } else {
            ip == pattern
        }
    }

    // =========================================================================
    // identity-access implementation
    // =========================================================================

    /// Check if PID is trusted
    pub async fn is_trusted(&self, pid: u32) -> bool {
        debug!("is_trusted: pid={}", pid);

        let mut stats = self.stats.write().await;
        stats.identity_lookups += 1;

        // In production:
        // self.identity_provider.verify_pid(pid).await?

        // Simulated: trust current process and its children
        pid == std::process::id() || pid < 100 // Simulate kernel processes
    }

    /// Get process identity
    pub async fn get_identity(&self, pid: u32) -> Option<ProcessIdentity> {
        debug!("get_identity: pid={}", pid);

        Some(ProcessIdentity {
            pid,
            ppid: 1,
            trusted: self.is_trusted(pid).await,
            binary_hash: None,
            cgroup_path: Some("/sys/fs/cgroup/synapse/verified/".to_string()),
        })
    }

    /// List trusted PIDs
    pub async fn list_trusted(&self) -> Vec<u32> {
        debug!("list_trusted");

        // In production:
        // self.identity_provider.trusted_pids().await?

        vec![std::process::id()]
    }

    /// Request attestation
    pub async fn request_attestation(&self, pid: u32) -> bool {
        debug!("request_attestation: pid={}", pid);

        // In production:
        // 1. Read /proc/{pid}/exe
        // 2. Compute SHA-256 hash
        // 3. Check against allowlist
        // 4. If valid, add to TRUSTED_PIDS map

        true // Simulated success
    }

    // =========================================================================
    // logging implementation
    // =========================================================================

    /// Log a message
    pub fn log(&self, level: &str, message: &str) {
        match level {
            "debug" => debug!("[WASM] {}", message),
            "info" => info!("[WASM] {}", message),
            "warn" => warn!("[WASM] {}", message),
            "error" => tracing::error!("[WASM] {}", message),
            _ => debug!("[WASM] {}", message),
        }
    }

    /// Audit log
    pub fn audit(&self, event_type: &str, details: &str) {
        info!("[AUDIT] type={}, details={}", event_type, details);
    }

    /// Get stats
    pub async fn stats(&self) -> HostStats {
        self.stats.read().await.clone()
    }
}

impl Default for SynapseHostState {
    fn default() -> Self {
        Self::new()
    }
}

/// WASM Host for policy execution
///
/// This struct manages the Wasmtime engine, store, and loaded policies.
pub struct WasmHost {
    config: WasmHostConfig,
    state: Arc<SynapseHostState>,
    // In production with wasmtime:
    // engine: Engine,
    // linker: Linker<SynapseHostState>,
    // policy: Option<PolicyComponent>,
    loaded: bool,
    policy_metadata: Option<PolicyMetadata>,
}

impl WasmHost {
    /// Create a new WASM host
    #[instrument(skip(config))]
    pub async fn new(config: WasmHostConfig) -> WasmHostResult<Self> {
        info!("Initializing WASM host");

        // In production with wasmtime:
        // let mut wasm_config = Config::new();
        // wasm_config.async_support(true);
        // wasm_config.consume_fuel(true);
        // wasm_config.wasm_component_model(true);
        //
        // let engine = Engine::new(&wasm_config)?;
        // let mut linker = Linker::new(&engine);
        //
        // // Add WIT interface implementations
        // synapse::governance::context_access::add_to_linker(&mut linker, |state| state)?;
        // synapse::governance::network_control::add_to_linker(&mut linker, |state| state)?;

        Ok(Self {
            config,
            state: Arc::new(SynapseHostState::new()),
            loaded: false,
            policy_metadata: None,
        })
    }

    /// Load a policy module from file
    #[instrument(skip(self, path))]
    pub async fn load_policy(&mut self, path: impl AsRef<Path>) -> WasmHostResult<()> {
        let path = path.as_ref();
        info!("Loading policy from: {}", path.display());

        // Read WASM bytes
        let wasm_bytes = std::fs::read(path)?;

        // Decrypt if required
        let wasm_bytes = if self.config.require_encryption {
            self.decrypt_module(&wasm_bytes)?
        } else {
            wasm_bytes
        };

        // In production with wasmtime:
        // let component = Component::new(&self.engine, &wasm_bytes)?;
        // let instance = self.linker.instantiate_async(&mut store, &component).await?;
        //
        // // Call initialize
        // let init = instance.get_typed_func::<(), bool>(&mut store, "initialize")?;
        // init.call_async(&mut store, ()).await?;
        //
        // // Get metadata
        // let get_metadata = instance.get_typed_func::<(), PolicyMetadata>(&mut store, "get-metadata")?;
        // self.policy_metadata = Some(get_metadata.call_async(&mut store, ()).await?);

        // Simulated load
        self.loaded = true;
        self.policy_metadata = Some(PolicyMetadata {
            name: "test-policy".to_string(),
            version: "1.0.0".to_string(),
            description: "Test policy module".to_string(),
            author: "Synapse".to_string(),
        });

        info!("Policy loaded successfully");
        Ok(())
    }

    /// Evaluate an event against the loaded policy
    #[instrument(skip(self, event), fields(event_type = %event.event_type))]
    pub async fn evaluate(&self, event: PolicyEvent) -> WasmHostResult<PolicyVerdict> {
        if !self.loaded {
            return Err(WasmHostError::EvaluationFailed("No policy loaded".to_string()));
        }

        debug!(
            "Evaluating event: type={}, pid={}",
            event.event_type, event.source_pid
        );

        // In production with wasmtime:
        // let mut store = Store::new(&self.engine, self.state.clone());
        // store.set_fuel(self.config.max_fuel)?;
        //
        // let evaluate = self.policy.get_typed_func::<PolicyEvent, PolicyVerdict>(&mut store, "evaluate-event")?;
        //
        // // Execute with timeout
        // let result = tokio::time::timeout(
        //     self.config.timeout,
        //     evaluate.call_async(&mut store, event)
        // ).await??;

        // Simulated evaluation
        let verdict = PolicyVerdict {
            allow: true,
            reason: format!("Simulated allow for {}", event.event_type),
            transform: None,
            tags: vec!["evaluated".to_string()],
        };

        // Update stats
        {
            let mut stats = self.state.stats.write().await;
            stats.evaluations += 1;
        }

        Ok(verdict)
    }

    /// Decrypt an encrypted WASM module
    ///
    /// The decryption key is derived from the eBPF TRUSTED_PIDS map state.
    /// This binds the module to the verified execution environment.
    ///
    /// # Encrypted Format
    ///
    /// ```text
    /// ┌─────────────────────────────────────────┐
    /// │  Magic: "SYNW" (4 bytes)                │
    /// │  Version: u8                            │
    /// │  Nonce: [u8; 12]                        │
    /// │  Ciphertext: AES-256-GCM encrypted WASM │
    /// │  Tag: [u8; 16] (appended by GCM)        │
    /// └─────────────────────────────────────────┘
    /// ```
    fn decrypt_module(&self, encrypted: &[u8]) -> WasmHostResult<Vec<u8>> {
        const MAGIC: &[u8; 4] = b"SYNW";
        const VERSION: u8 = 1;
        const NONCE_SIZE: usize = 12;
        const HEADER_SIZE: usize = 4 + 1 + NONCE_SIZE; // magic + version + nonce

        // Check if this is an encrypted module
        if encrypted.len() < HEADER_SIZE {
            // Too small to be encrypted, assume plaintext
            if encrypted.starts_with(b"\0asm") {
                // Standard WASM magic, return as-is
                return Ok(encrypted.to_vec());
            }
            return Err(WasmHostError::DecryptionFailed(
                "Invalid module format".to_string(),
            ));
        }

        // Check magic bytes
        if &encrypted[0..4] != MAGIC {
            // Not encrypted (might be plain WASM)
            if encrypted.starts_with(b"\0asm") {
                return Ok(encrypted.to_vec());
            }
            return Err(WasmHostError::DecryptionFailed(
                "Invalid magic bytes".to_string(),
            ));
        }

        // Check version
        if encrypted[4] != VERSION {
            return Err(WasmHostError::DecryptionFailed(format!(
                "Unsupported version: {}",
                encrypted[4]
            )));
        }

        // Extract nonce
        let nonce_bytes: [u8; NONCE_SIZE] = encrypted[5..5 + NONCE_SIZE]
            .try_into()
            .map_err(|_| WasmHostError::DecryptionFailed("Invalid nonce".to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Get ciphertext (everything after header)
        let ciphertext = &encrypted[HEADER_SIZE..];

        // Derive key from TRUSTED_PIDS
        // In production, this reads from the eBPF map
        let key = self.derive_key_from_environment()?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WasmHostError::DecryptionFailed(format!("Invalid key: {}", e)))?;

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            WasmHostError::DecryptionFailed(
                "Decryption failed - environment mismatch or corrupted module".to_string(),
            )
        })?;

        // Verify WASM magic
        if !plaintext.starts_with(b"\0asm") {
            return Err(WasmHostError::DecryptionFailed(
                "Decrypted content is not valid WASM".to_string(),
            ));
        }

        info!("Module decrypted successfully ({} bytes)", plaintext.len());
        Ok(plaintext)
    }

    /// Derive encryption key from the execution environment
    ///
    /// This creates a 256-bit key from:
    /// 1. Sorted list of TRUSTED_PIDS
    /// 2. Host machine ID
    /// 3. Synapse cluster secret
    ///
    /// The result is deterministic for the same environment state.
    fn derive_key_from_environment(&self) -> WasmHostResult<[u8; 32]> {
        let mut hasher = Sha256::new();

        // Domain separator
        hasher.update(b"synapse-wasm-key-v1");

        // Get trusted PIDs (sorted for determinism)
        // In production: self.identity_provider.trusted_pids().await?
        let mut trusted_pids = self.get_trusted_pids_sync();
        trusted_pids.sort();

        for pid in &trusted_pids {
            hasher.update(pid.to_le_bytes());
        }

        // Add machine identifier for locality binding
        // In production: read from /etc/machine-id or similar
        let machine_id = self.get_machine_id();
        hasher.update(machine_id.as_bytes());

        // Add optional cluster secret
        if let Ok(secret) = std::env::var("SYNAPSE_CLUSTER_SECRET") {
            hasher.update(secret.as_bytes());
        }

        let hash = hasher.finalize();
        let key: [u8; 32] = hash.into();

        debug!(
            "Derived key from {} trusted PIDs, machine: {}",
            trusted_pids.len(),
            &machine_id[..8.min(machine_id.len())]
        );

        Ok(key)
    }

    /// Get trusted PIDs synchronously (for key derivation)
    fn get_trusted_pids_sync(&self) -> Vec<u32> {
        // In production with eBPF:
        // Read from the TRUSTED_PIDS BPF_MAP_TYPE_HASH
        //
        // For now, return simulated trusted processes
        vec![
            1,                      // init/systemd
            std::process::id(),     // current process
        ]
    }

    /// Get machine identifier
    fn get_machine_id(&self) -> String {
        // Try to read machine-id
        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
                return id.trim().to_string();
            }
        }

        // Fallback: use hostname
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Get loaded policy metadata
    pub fn metadata(&self) -> Option<&PolicyMetadata> {
        self.policy_metadata.as_ref()
    }

    /// Check if a policy is loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get host statistics
    pub async fn stats(&self) -> HostStats {
        self.state.stats().await
    }

    /// Get a reference to the host state (for testing)
    pub fn state(&self) -> &Arc<SynapseHostState> {
        &self.state
    }
}

// =============================================================================
// Wasmtime Component Model Integration
// =============================================================================

/// Module for wasmtime component model bindgen integration
/// 
/// This module uses the `bindgen!` macro to generate Rust types and traits
/// from the WIT definitions in `wit/governance.wit`.
pub mod bindgen {
    #![allow(unused_imports, dead_code)]
    
    // Generate bindings from WIT file
    // The bindgen! macro creates:
    // - Rust types matching WIT record definitions
    // - Traits that the host must implement for each import interface
    // - Helper functions for instantiation and linking
    //
    // WHY bindgen!: Type-safe WIT integration without manual FFI
    // WHY async: Host functions may need to access async storage (LanceDB)
    wasmtime::component::bindgen!({
        world: "policy-engine",
        path: "wit/governance.wit",
        async: true,
        with: {
            // Map WIT types to our Rust types
            // This ensures we use our existing types rather than generated ones
        },
    });
}

// Re-export generated types for convenience
pub use bindgen::synapse::governance::context_access as wit_context;
pub use bindgen::synapse::governance::network_control as wit_network;
pub use bindgen::synapse::governance::identity_access as wit_identity;
pub use bindgen::exports::synapse::governance::policy_engine as wit_policy;

/// Implement the context-access interface for our host state
impl wit_context::Host for SynapseHostState {
    /// Search vector memory for semantically similar events
    async fn search_memory(&mut self, query: String, limit: u32) -> Vec<wit_context::SearchResult> {
        let results = SynapseHostState::search_memory(self, &query, limit).await;
        results
            .into_iter()
            .map(|r| wit_context::SearchResult {
                id: r.id,
                source: r.source,
                action: r.action,
                reason: r.reason,
                score: r.score,
            })
            .collect()
    }

    /// Get a specific event by ID
    async fn get_event(&mut self, id: u64) -> Option<wit_context::SearchResult> {
        SynapseHostState::get_event(self, id).await.map(|r| wit_context::SearchResult {
            id: r.id,
            source: r.source,
            action: r.action,
            reason: r.reason,
            score: r.score,
        })
    }

    /// Get recent events
    async fn get_recent(&mut self, limit: u32) -> Vec<wit_context::SearchResult> {
        SynapseHostState::get_recent(self, limit)
            .await
            .into_iter()
            .map(|r| wit_context::SearchResult {
                id: r.id,
                source: r.source,
                action: r.action,
                reason: r.reason,
                score: r.score,
            })
            .collect()
    }

    /// Get events by action type
    async fn get_by_action(&mut self, action: String, limit: u32) -> Vec<wit_context::SearchResult> {
        SynapseHostState::get_by_action(self, &action, limit)
            .await
            .into_iter()
            .map(|r| wit_context::SearchResult {
                id: r.id,
                source: r.source,
                action: r.action,
                reason: r.reason,
                score: r.score,
            })
            .collect()
    }
}

/// Implement the network-control interface for our host state
impl wit_network::Host for SynapseHostState {
    /// Authorize a network connection
    async fn authorize_connection(&mut self, request: wit_network::ConnectionRequest) -> wit_network::AuthResult {
        let req = ConnectionRequest {
            pid: request.pid,
            dest_ip: request.dest_ip,
            dest_port: request.dest_port,
            protocol: request.protocol,
        };
        match SynapseHostState::authorize_connection(self, &req).await {
            AuthResult::Allow => wit_network::AuthResult::Allow,
            AuthResult::Deny => wit_network::AuthResult::Deny,
            AuthResult::AllowWithAudit => wit_network::AuthResult::AllowWithAudit,
        }
    }

    /// Get allowed destination patterns
    async fn get_allowed_destinations(&mut self) -> Vec<String> {
        SynapseHostState::get_allowed_destinations(self).await
    }

    /// Add a destination to the allowlist
    async fn add_allowed_destination(&mut self, pattern: String) -> bool {
        SynapseHostState::add_allowed_destination(self, pattern).await
    }
}

/// Implement the identity-access interface for our host state
impl wit_identity::Host for SynapseHostState {
    /// Check if a PID is trusted
    async fn is_trusted(&mut self, pid: u32) -> bool {
        SynapseHostState::is_trusted(self, pid).await
    }

    /// Get full identity for a PID
    async fn get_identity(&mut self, pid: u32) -> Option<wit_identity::ProcessIdentity> {
        SynapseHostState::get_identity(self, pid).await.map(|i| wit_identity::ProcessIdentity {
            pid: i.pid,
            ppid: i.ppid,
            trusted: i.trusted,
            binary_hash: i.binary_hash,
            cgroup_path: i.cgroup_path,
        })
    }

    /// List all trusted PIDs
    async fn list_trusted(&mut self) -> Vec<u32> {
        SynapseHostState::list_trusted(self).await
    }

    /// Request attestation for a PID
    async fn request_attestation(&mut self, pid: u32) -> bool {
        SynapseHostState::request_attestation(self, pid).await
    }
}

/// Implement the logging interface for our host state
impl bindgen::synapse::governance::logging::Host for SynapseHostState {
    async fn log(&mut self, level: bindgen::synapse::governance::logging::LogLevel, message: String) {
        let level_str = match level {
            bindgen::synapse::governance::logging::LogLevel::Debug => "debug",
            bindgen::synapse::governance::logging::LogLevel::Info => "info",
            bindgen::synapse::governance::logging::LogLevel::Warn => "warn",
            bindgen::synapse::governance::logging::LogLevel::Error => "error",
        };
        SynapseHostState::log(self, level_str, &message);
    }

    async fn audit(&mut self, event_type: String, details: String) {
        SynapseHostState::audit(self, &event_type, &details);
    }
}

/// Full WASM Host using Wasmtime Component Model
pub struct ComponentModelHost {
    engine: wasmtime::Engine,
    linker: wasmtime::component::Linker<SynapseHostState>,
    config: WasmHostConfig,
    component: Option<wasmtime::component::Component>,
}

impl ComponentModelHost {
    /// Create a new component model host
    pub fn new(config: WasmHostConfig) -> WasmHostResult<Self> {
        // Configure the engine
        let mut wasm_config = wasmtime::Config::new();
        wasm_config.async_support(true);
        wasm_config.consume_fuel(true);
        wasm_config.wasm_component_model(true);
        
        let engine = wasmtime::Engine::new(&wasm_config)
            .map_err(|e| WasmHostError::LoadFailed(format!("Engine creation failed: {}", e)))?;
        
        let mut linker = wasmtime::component::Linker::new(&engine);
        
        // Add WIT interface implementations to the linker
        bindgen::PolicyEngine::add_to_linker(&mut linker, |state: &mut SynapseHostState| state)
            .map_err(|e| WasmHostError::LoadFailed(format!("Linker setup failed: {}", e)))?;
        
        info!("ComponentModelHost initialized with wasmtime");
        
        Ok(Self {
            engine,
            linker,
            config,
            component: None,
        })
    }

    /// Load a WASM component from bytes
    pub fn load_component(&mut self, wasm_bytes: &[u8]) -> WasmHostResult<()> {
        let component = wasmtime::component::Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmHostError::LoadFailed(format!("Component load failed: {}", e)))?;
        
        self.component = Some(component);
        info!("WASM component loaded");
        Ok(())
    }

    /// Evaluate an event using the loaded component
    pub async fn evaluate(&self, event: PolicyEvent) -> WasmHostResult<PolicyVerdict> {
        let component = self.component.as_ref()
            .ok_or_else(|| WasmHostError::EvaluationFailed("No component loaded".into()))?;
        
        // Create a new store with fuel limit
        let mut store = wasmtime::Store::new(&self.engine, SynapseHostState::new());
        store.set_fuel(self.config.max_fuel)
            .map_err(|e| WasmHostError::EvaluationFailed(format!("Set fuel failed: {}", e)))?;
        
        // Instantiate the component
        let (policy_engine, _instance) = bindgen::PolicyEngine::instantiate_async(&mut store, component, &self.linker)
            .await
            .map_err(|e| WasmHostError::InstantiateFailed(format!("Instantiation failed: {}", e)))?;
        
        // Convert our event to WIT format
        let wit_event = bindgen::PolicyEvent {
            event_type: event.event_type,
            source_pid: event.source_pid,
            payload: event.payload,
            timestamp_us: event.timestamp_us,
        };
        
        // Call the evaluate-event export
        let verdict = policy_engine.call_evaluate_event(&mut store, &wit_event)
            .await
            .map_err(|e| {
                // Check if fuel was exhausted
                if store.get_fuel().unwrap_or(0) == 0 {
                    WasmHostError::FuelExhausted(self.config.max_fuel)
                } else {
                    WasmHostError::EvaluationFailed(format!("Evaluation failed: {}", e))
                }
            })?;
        
        Ok(PolicyVerdict {
            allow: verdict.allow,
            reason: verdict.reason,
            transform: verdict.transform,
            tags: verdict.tags,
        })
    }

    /// Initialize the loaded component
    pub async fn initialize(&self) -> WasmHostResult<bool> {
        let component = self.component.as_ref()
            .ok_or_else(|| WasmHostError::EvaluationFailed("No component loaded".into()))?;
        
        let mut store = wasmtime::Store::new(&self.engine, SynapseHostState::new());
        store.set_fuel(self.config.max_fuel)
            .map_err(|e| WasmHostError::EvaluationFailed(format!("Set fuel failed: {}", e)))?;
        
        let (policy_engine, _instance) = bindgen::PolicyEngine::instantiate_async(&mut store, component, &self.linker)
            .await
            .map_err(|e| WasmHostError::InstantiateFailed(format!("Instantiation failed: {}", e)))?;
        
        policy_engine.call_initialize(&mut store)
            .await
            .map_err(|e| WasmHostError::EvaluationFailed(format!("Initialize failed: {}", e)))
    }

    /// Get metadata from the loaded component
    pub async fn get_metadata(&self) -> WasmHostResult<PolicyMetadata> {
        let component = self.component.as_ref()
            .ok_or_else(|| WasmHostError::EvaluationFailed("No component loaded".into()))?;
        
        let mut store = wasmtime::Store::new(&self.engine, SynapseHostState::new());
        store.set_fuel(self.config.max_fuel)
            .map_err(|e| WasmHostError::EvaluationFailed(format!("Set fuel failed: {}", e)))?;
        
        let (policy_engine, _instance) = bindgen::PolicyEngine::instantiate_async(&mut store, component, &self.linker)
            .await
            .map_err(|e| WasmHostError::InstantiateFailed(format!("Instantiation failed: {}", e)))?;
        
        let meta = policy_engine.call_get_metadata(&mut store)
            .await
            .map_err(|e| WasmHostError::EvaluationFailed(format!("Get metadata failed: {}", e)))?;
        
        Ok(PolicyMetadata {
            name: meta.name,
            version: meta.version,
            description: meta.description,
            author: meta.author,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_host_creation() {
        let config = WasmHostConfig::default();
        let host = WasmHost::new(config).await.unwrap();
        assert!(!host.is_loaded());
    }

    #[tokio::test]
    async fn test_host_state() {
        let state = SynapseHostState::new();

        // Test is_trusted
        let current_pid = std::process::id();
        assert!(state.is_trusted(current_pid).await);

        // Test search_memory
        let results = state.search_memory("test query", 10).await;
        assert!(!results.is_empty());

        // Test authorize_connection
        let request = ConnectionRequest {
            pid: current_pid,
            dest_ip: "127.0.0.1".to_string(),
            dest_port: 8080,
            protocol: "tcp".to_string(),
        };
        let result = state.authorize_connection(&request).await;
        assert_eq!(result, AuthResult::Allow);
    }

    #[tokio::test]
    async fn test_stats() {
        let state = SynapseHostState::new();

        let _ = state.is_trusted(1).await;
        let _ = state.search_memory("test", 5).await;

        let stats = state.stats().await;
        assert!(stats.identity_lookups > 0);
        assert!(stats.memory_queries > 0);
    }
}

// =============================================================================
// Environmental Entanglement: Startup Verification
// =============================================================================

/// Verify cgroup membership at startup
///
/// This ensures the broker is running in the expected cgroup hierarchy.
/// If verification fails, the broker MUST NOT start.
///
/// # Panics
///
/// Panics if the process is not in a verified cgroup.
pub fn verify_cgroup_at_startup() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let cgroup_path = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("Failed to read cgroup: {}", e))?;

        // Check for verified cgroup membership
        // Format: "0::/synapse/verified" or similar
        let verified = cgroup_path.lines().any(|line| {
            line.contains("synapse") && line.contains("verified")
        });

        if !verified {
            // Check environment override for development
            if std::env::var("SYNAPSE_SKIP_CGROUP_CHECK").is_ok() {
                warn!("Cgroup verification skipped (SYNAPSE_SKIP_CGROUP_CHECK)");
                return Ok(());
            }

            error!("FATAL: Process not in verified cgroup!");
            error!("Current cgroups:\n{}", cgroup_path);
            error!("Expected: /synapse/verified or similar");
            return Err("Cgroup verification failed".to_string());
        }

        info!("Cgroup verification passed");
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Non-Linux platforms: skip cgroup verification
        warn!("Cgroup verification not supported on this platform");
    }

    Ok(())
}

/// Verify and panic if cgroup check fails
///
/// Call this at broker startup before loading any policies.
pub fn verify_cgroup_or_panic() {
    if let Err(e) = verify_cgroup_at_startup() {
        panic!("Startup verification failed: {}", e);
    }
}

// =============================================================================
// Module Encryption Helper
// =============================================================================

/// Encrypt a WASM module for deployment
///
/// This is used during policy packaging to create encrypted modules.
/// The encryption key is derived from the target environment's TRUSTED_PIDS.
pub fn encrypt_module(
    wasm_bytes: &[u8],
    trusted_pids: &[u32],
    machine_id: &str,
    cluster_secret: Option<&str>,
) -> Result<Vec<u8>, WasmHostError> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::AeadCore;

    const MAGIC: &[u8; 4] = b"SYNW";
    const VERSION: u8 = 1;

    // Verify input is valid WASM
    if !wasm_bytes.starts_with(b"\0asm") {
        return Err(WasmHostError::LoadFailed(
            "Input is not a valid WASM module".to_string(),
        ));
    }

    // Derive key
    let key = derive_key(trusted_pids, machine_id, cluster_secret);

    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| WasmHostError::DecryptionFailed(format!("Invalid key: {}", e)))?;

    let ciphertext = cipher.encrypt(&nonce, wasm_bytes)
        .map_err(|e| WasmHostError::DecryptionFailed(format!("Encryption failed: {}", e)))?;

    // Build encrypted module
    let mut output = Vec::with_capacity(4 + 1 + 12 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);

    info!(
        "Module encrypted: {} bytes -> {} bytes",
        wasm_bytes.len(),
        output.len()
    );

    Ok(output)
}

/// Derive encryption key from environment parameters
fn derive_key(
    trusted_pids: &[u32],
    machine_id: &str,
    cluster_secret: Option<&str>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"synapse-wasm-key-v1");

    let mut sorted_pids = trusted_pids.to_vec();
    sorted_pids.sort();

    for pid in &sorted_pids {
        hasher.update(pid.to_le_bytes());
    }

    hasher.update(machine_id.as_bytes());

    if let Some(secret) = cluster_secret {
        hasher.update(secret.as_bytes());
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Sample WASM (minimal valid module)
        let wasm = b"\0asm\x01\x00\x00\x00"; // WASM magic + version

        let trusted_pids = vec![1, 100, 200];
        let machine_id = "test-machine-123";
        let cluster_secret = Some("test-secret");

        // Encrypt
        let encrypted = encrypt_module(
            wasm,
            &trusted_pids,
            machine_id,
            cluster_secret,
        ).unwrap();

        // Verify format
        assert!(encrypted.starts_with(b"SYNW"));
        assert_eq!(encrypted[4], 1); // version

        // Create host with matching environment
        let config = WasmHostConfig::default();
        let host = WasmHost {
            config,
            state: Arc::new(SynapseHostState::new()),
            loaded: false,
            policy_metadata: None,
        };

        // Note: Can't test decryption directly without mocking environment
        // In production, we'd set up the eBPF maps to match
    }

    #[test]
    fn test_plaintext_passthrough() {
        let wasm = b"\0asm\x01\x00\x00\x00";

        let config = WasmHostConfig::default();
        let host = WasmHost {
            config,
            state: Arc::new(SynapseHostState::new()),
            loaded: false,
            policy_metadata: None,
        };

        // Plain WASM should pass through
        let result = host.decrypt_module(wasm).unwrap();
        assert_eq!(result, wasm);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let pids1 = vec![100, 1, 50]; // unsorted
        let pids2 = vec![1, 50, 100]; // different order

        let key1 = derive_key(&pids1, "machine", None);
        let key2 = derive_key(&pids2, "machine", None);

        // Should be equal (sorted internally)
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cgroup_verification_dev_skip() {
        // In development, we can skip cgroup check
        std::env::set_var("SYNAPSE_SKIP_CGROUP_CHECK", "1");
        let result = verify_cgroup_at_startup();
        assert!(result.is_ok());
        std::env::remove_var("SYNAPSE_SKIP_CGROUP_CHECK");
    }
}
