//! kProbe instrumentation for function tracing.
//!
//! kProbes allow attaching eBPF programs to kernel functions, enabling
//! low-overhead latency measurement and function call tracing.

use thiserror::Error;

/// Errors that can occur during kProbe operations.
#[derive(Debug, Error)]
pub enum KprobeError {
    /// Failed to load kProbe program.
    #[error("Failed to load kProbe program: {0}")]
    LoadFailed(String),

    /// Failed to attach kProbe to function.
    #[error("Failed to attach kProbe to function {function}: {0}")]
    AttachFailed { function: String, error: String },

    /// Failed to detach kProbe.
    #[error("Failed to detach kProbe: {0}")]
    DetachFailed(String),

    /// Function not found.
    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    /// Insufficient permissions.
    #[error("Insufficient permissions: {0}")]
    PermissionDenied(String),
}

/// kProbe program for function tracing.
///
/// This is a simplified abstraction. In production, you would use
/// Aya to compile and load actual eBPF programs.
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct KprobeProgram {
    /// Program name.
    pub name: String,
    /// Target function name.
    pub function: String,
    /// Program bytecode (compiled eBPF).
    pub bytecode: Vec<u8>,
    /// Whether this is a kretprobe (return probe).
    pub is_return_probe: bool,
}

#[cfg(feature = "ebpf")]
impl KprobeProgram {
    /// Creates a new kProbe program.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        function: impl Into<String>,
        bytecode: Vec<u8>,
        is_return_probe: bool,
    ) -> Self {
        Self {
            name: name.into(),
            function: function.into(),
            bytecode,
            is_return_probe,
        }
    }

    /// Attaches the program to the target function.
    ///
    /// # Errors
    ///
    /// Returns an error if attachment fails.
    pub async fn attach(&self) -> Result<(), KprobeError> {
        // In a real implementation, this would use Aya to:
        // 1. Load the eBPF program into the kernel
        // 2. Attach it to the kProbe hook for the specified function
        Err(KprobeError::LoadFailed(
            "kProbe program loading not yet implemented. Requires Aya integration.".to_string(),
        ))
    }

    /// Detaches the program from the target function.
    ///
    /// # Errors
    ///
    /// Returns an error if detachment fails.
    pub async fn detach(&self) -> Result<(), KprobeError> {
        Err(KprobeError::DetachFailed(
            "kProbe program detachment not yet implemented.".to_string(),
        ))
    }
}

/// kProbe statistics.
#[derive(Debug, Clone, Default)]
pub struct KprobeStats {
    /// Number of function calls traced.
    pub calls_traced: u64,
    /// Total latency in nanoseconds.
    pub total_latency_ns: u64,
    /// Minimum latency in nanoseconds.
    pub min_latency_ns: u64,
    /// Maximum latency in nanoseconds.
    pub max_latency_ns: u64,
}

impl KprobeStats {
    /// Calculates the average latency in nanoseconds.
    #[must_use]
    pub fn avg_latency_ns(&self) -> u64 {
        if self.calls_traced > 0 {
            self.total_latency_ns / self.calls_traced
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kprobe_program_creation() {
        let program =
            KprobeProgram::new("test_probe", "do_sys_open", vec![0x01, 0x02, 0x03], false);
        assert_eq!(program.name, "test_probe");
        assert_eq!(program.function, "do_sys_open");
        assert!(!program.is_return_probe);
    }

    #[test]
    fn kprobe_stats_avg_latency() {
        let mut stats = KprobeStats::default();
        stats.calls_traced = 10;
        stats.total_latency_ns = 1000;
        assert_eq!(stats.avg_latency_ns(), 100);
    }
}
