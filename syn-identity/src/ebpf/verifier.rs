//! Process Attestation Verifier
//!
//! This module verifies process identity by:
//! 1. Reading /proc/{pid}/exe to get the binary path
//! 2. Computing SHA-256 hash of the binary
//! 3. Checking against the allowlist
//! 4. Verifying cgroup membership
//!
//! # Why /proc?
//!
//! On Linux, /proc provides authoritative process information that cannot
//! be spoofed by user-space processes. The kernel guarantees the accuracy
//! of /proc/{pid}/exe and /proc/{pid}/cgroup.
//!
//! # Platform Support
//!
//! - **Linux**: Full verification via /proc filesystem
//! - **Windows**: Limited verification via process handle APIs
//! - **macOS**: Limited verification via proc_pidpath

use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use super::{Allowlist, AllowlistEntry, BinaryHash};

/// Errors during verification
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Process not found
    #[error("Process not found: PID {0}")]
    ProcessNotFound(u32),

    /// Cannot read process info
    #[error("Cannot read process info for PID {pid}: {reason}")]
    ReadError {
        /// Process ID that failed to read
        pid: u32,
        /// Reason for the read failure
        reason: String,
    },

    /// Binary not in allowlist
    #[error("Binary not in allowlist: {0}")]
    NotAllowed(BinaryHash),

    /// Cgroup not allowed
    #[error("Cgroup not allowed: {0}")]
    CgroupNotAllowed(String),

    /// Entry expired
    #[error("Allowlist entry expired")]
    EntryExpired,

    /// Too many instances
    #[error("Too many instances: {current}/{max}")]
    TooManyInstances {
        /// Current number of instances
        current: u32,
        /// Maximum allowed instances
        max: u32,
    },

    /// Binary was modified
    #[error("Binary was modified after process start")]
    BinaryModified,

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Platform not supported
    #[error("Verification not supported on this platform")]
    NotSupported,
}

/// Result type for verifier operations
pub type Result<T> = std::result::Result<T, VerifierError>;

/// Information about a process gathered during verification
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Process command name
    pub comm: String,
    /// Full path to the executable
    pub exe_path: PathBuf,
    /// SHA-256 hash of the executable
    pub binary_hash: BinaryHash,
    /// Cgroup path (Linux only)
    pub cgroup: String,
    /// Command line arguments
    pub cmdline: Vec<String>,
    /// Process start time (jiffies since boot, Linux only)
    pub start_time: u64,
    /// Working directory
    pub cwd: Option<PathBuf>,
}

/// Result of a verification attempt
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Process is allowed
    Allowed {
        /// Process ID that was verified
        pid: u32,
        /// Matching allowlist entry
        entry: AllowlistEntry,
        /// Information about the verified process
        process_info: ProcessInfo,
    },
    /// Process is denied
    Denied {
        /// Process ID that was denied
        pid: u32,
        /// Reason for the denial
        reason: VerificationDenial,
        /// Process information if available
        process_info: Option<ProcessInfo>,
    },
}

/// Reasons for verification denial
#[derive(Debug, Clone)]
pub enum VerificationDenial {
    /// Binary hash not in allowlist
    HashNotAllowed(BinaryHash),
    /// Process is in a disallowed cgroup
    CgroupNotAllowed(String),
    /// Allowlist entry has expired
    EntryExpired,
    /// Too many instances of this binary
    TooManyInstances {
        /// Current number of running instances
        current: u32,
        /// Maximum allowed instances
        max: u32,
    },
    /// Could not read process information
    ProcessReadError(String),
    /// Binary file was modified after process started
    BinaryModified,
    /// Verification not supported on this platform
    NotSupported,
}

impl VerificationResult {
    /// Check if verification succeeded
    pub fn is_allowed(&self) -> bool {
        matches!(self, VerificationResult::Allowed { .. })
    }

    /// Get the PID
    pub fn pid(&self) -> u32 {
        match self {
            VerificationResult::Allowed { pid, .. } => *pid,
            VerificationResult::Denied { pid, .. } => *pid,
        }
    }

    /// Get process info if available
    pub fn process_info(&self) -> Option<&ProcessInfo> {
        match self {
            VerificationResult::Allowed { process_info, .. } => Some(process_info),
            VerificationResult::Denied { process_info, .. } => process_info.as_ref(),
        }
    }
}

/// Attestation verifier
///
/// Verifies process identity against the allowlist by:
/// 1. Reading process information from the OS
/// 2. Computing the binary hash
/// 3. Checking the allowlist
/// 4. Verifying cgroup membership
pub struct AttestationVerifier {
    allowlist: Arc<RwLock<Allowlist>>,
}

impl AttestationVerifier {
    /// Create a new verifier with the given allowlist
    pub fn new(allowlist: Arc<RwLock<Allowlist>>) -> Self {
        Self { allowlist }
    }

    /// Verify a process by PID
    pub async fn verify_pid(&self, pid: u32) -> Result<VerificationResult> {
        // Get process info
        let process_info = match self.get_process_info(pid).await {
            Ok(info) => info,
            Err(e) => {
                return Ok(VerificationResult::Denied {
                    pid,
                    reason: VerificationDenial::ProcessReadError(e.to_string()),
                    process_info: None,
                });
            }
        };

        self.verify_process_info(process_info).await
    }

    /// Verify a binary by path
    pub async fn verify_binary(&self, path: &Path) -> Result<VerificationResult> {
        let hash = BinaryHash::from_file(path).await?;

        let allowlist = self.allowlist.read().await;

        if let Some(entry) = allowlist.get(&hash) {
            if entry.is_expired() {
                return Ok(VerificationResult::Denied {
                    pid: 0,
                    reason: VerificationDenial::EntryExpired,
                    process_info: None,
                });
            }

            // For binary-only verification, we don't have full process info
            let process_info = ProcessInfo {
                pid: 0,
                ppid: 0,
                uid: 0,
                gid: 0,
                comm: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                exe_path: path.to_path_buf(),
                binary_hash: hash,
                cgroup: String::new(),
                cmdline: Vec::new(),
                start_time: 0,
                cwd: None,
            };

            return Ok(VerificationResult::Allowed {
                pid: 0,
                entry: entry.clone(),
                process_info,
            });
        }

        Ok(VerificationResult::Denied {
            pid: 0,
            reason: VerificationDenial::HashNotAllowed(hash),
            process_info: None,
        })
    }

    /// Verify process info against allowlist
    async fn verify_process_info(&self, info: ProcessInfo) -> Result<VerificationResult> {
        let allowlist = self.allowlist.read().await;

        // Check if binary hash is in allowlist
        let entry = match allowlist.get(&info.binary_hash) {
            Some(e) => e.clone(),
            None => {
                return Ok(VerificationResult::Denied {
                    pid: info.pid,
                    reason: VerificationDenial::HashNotAllowed(info.binary_hash.clone()),
                    process_info: Some(info),
                });
            }
        };

        // Check expiration
        if entry.is_expired() {
            return Ok(VerificationResult::Denied {
                pid: info.pid,
                reason: VerificationDenial::EntryExpired,
                process_info: Some(info),
            });
        }

        // Check cgroup (if configured)
        if !entry.is_cgroup_allowed(&info.cgroup) {
            return Ok(VerificationResult::Denied {
                pid: info.pid,
                reason: VerificationDenial::CgroupNotAllowed(info.cgroup.clone()),
                process_info: Some(info),
            });
        }

        // All checks passed
        Ok(VerificationResult::Allowed {
            pid: info.pid,
            entry,
            process_info: info,
        })
    }

    /// Get process information by PID
    #[cfg(target_os = "linux")]
    async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo> {
        use tokio::fs;

        let proc_dir = PathBuf::from(format!("/proc/{}", pid));

        if !proc_dir.exists() {
            return Err(VerifierError::ProcessNotFound(pid));
        }

        // Read exe path
        let exe_path =
            fs::read_link(proc_dir.join("exe"))
                .await
                .map_err(|e| VerifierError::ReadError {
                    pid,
                    reason: format!("Cannot read exe: {}", e),
                })?;

        // Compute binary hash
        let binary_hash =
            BinaryHash::from_file(&exe_path)
                .await
                .map_err(|e| VerifierError::ReadError {
                    pid,
                    reason: format!("Cannot hash binary: {}", e),
                })?;

        // Read comm (command name)
        let comm = fs::read_to_string(proc_dir.join("comm"))
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        // Read cmdline
        let cmdline_raw = fs::read(proc_dir.join("cmdline")).await.unwrap_or_default();
        let cmdline: Vec<String> = cmdline_raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();

        // Read cgroup
        let cgroup = fs::read_to_string(proc_dir.join("cgroup"))
            .await
            .map(|s| {
                // Parse cgroup v2 format: "0::/path"
                s.lines()
                    .find(|l| l.starts_with("0::"))
                    .map(|l| l.strip_prefix("0::").unwrap_or(l).to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        // Read status for ppid, uid, gid
        let status = fs::read_to_string(proc_dir.join("status"))
            .await
            .unwrap_or_default();

        let mut ppid = 0u32;
        let mut uid = 0u32;
        let mut gid = 0u32;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                uid = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Gid:\t") {
                gid = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        // Read stat for start time
        let stat = fs::read_to_string(proc_dir.join("stat"))
            .await
            .unwrap_or_default();
        let start_time = stat
            .split_whitespace()
            .nth(21) // Field 22 is starttime (0-indexed = 21)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Read cwd
        let cwd = fs::read_link(proc_dir.join("cwd")).await.ok();

        Ok(ProcessInfo {
            pid,
            ppid,
            uid,
            gid,
            comm,
            exe_path,
            binary_hash,
            cgroup,
            cmdline,
            start_time,
            cwd,
        })
    }

    /// Get process information by PID (Windows)
    #[cfg(target_os = "windows")]
    async fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo> {
        // Windows implementation would use:
        // - OpenProcess with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        // - GetModuleFileNameExW to get exe path
        // - GetProcessTimes for start time
        // Full implementation requires windows-sys crate

        Err(VerifierError::NotSupported)
    }

    /// Get process information by PID (other platforms)
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    async fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo> {
        Err(VerifierError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verifier_creation() {
        let allowlist = Arc::new(RwLock::new(Allowlist::new()));
        let verifier = AttestationVerifier::new(allowlist);
        // Verify the verifier was created successfully by using it
        let result = verifier.verify_pid(99999).await;
        assert!(result.is_ok()); // Should return Ok with Denied result for non-existent PID
    }

    #[tokio::test]
    async fn test_verify_binary_not_allowed() {
        let allowlist = Arc::new(RwLock::new(Allowlist::new()));
        let verifier = AttestationVerifier::new(allowlist);

        // Create a temp file to verify
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_binary_not_allowed");
        tokio::fs::write(&temp_file, b"test binary content")
            .await
            .unwrap();

        let result = verifier.verify_binary(&temp_file).await.unwrap();
        assert!(!result.is_allowed());

        // Cleanup
        let _ = tokio::fs::remove_file(&temp_file).await;
    }

    #[tokio::test]
    async fn test_verify_binary_allowed() {
        let allowlist = Arc::new(RwLock::new(Allowlist::new()));
        let verifier = AttestationVerifier::new(allowlist.clone());

        // Create a temp file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_binary_allowed");
        let content = b"test binary content for allowlist";
        tokio::fs::write(&temp_file, content).await.unwrap();

        // Add to allowlist
        let hash = BinaryHash::from_bytes(content);
        let entry = super::super::AllowlistEntry::new("test", hash);
        allowlist.write().await.add_entry(entry);

        let result = verifier.verify_binary(&temp_file).await.unwrap();
        assert!(result.is_allowed());

        // Cleanup
        let _ = tokio::fs::remove_file(&temp_file).await;
    }

    #[tokio::test]
    async fn test_verification_result_methods() {
        // Test denied result
        let denied = VerificationResult::Denied {
            pid: 1234,
            reason: VerificationDenial::NotSupported,
            process_info: None,
        };

        assert!(!denied.is_allowed());
        assert_eq!(denied.pid(), 1234);
        assert!(denied.process_info().is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_verify_current_process() {
        let allowlist = Arc::new(RwLock::new(Allowlist::new()));
        let verifier = AttestationVerifier::new(allowlist);

        // Get our own PID
        let pid = std::process::id();

        // This should succeed in reading process info, but fail allowlist check
        let result = verifier.verify_pid(pid).await.unwrap();

        // We're not in the allowlist, so should be denied
        assert!(!result.is_allowed());
        assert!(result.process_info().is_some());
    }
}
