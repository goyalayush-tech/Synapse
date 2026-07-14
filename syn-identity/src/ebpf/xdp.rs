//! XDP (eXpress Data Path) programs for packet processing.
//!
//! XDP programs run in the kernel's network stack, allowing for high-performance
//! packet filtering, counting, and processing without copying data to user space.

use thiserror::Error;

/// Errors that can occur during XDP program operations.
#[derive(Debug, Error)]
pub enum XdpError {
    /// Failed to load XDP program.
    #[error("Failed to load XDP program: {0}")]
    LoadFailed(String),

    /// Failed to attach XDP program to interface.
    #[error("Failed to attach XDP program to interface {interface}: {0}")]
    AttachFailed { interface: String, error: String },

    /// Failed to detach XDP program.
    #[error("Failed to detach XDP program: {0}")]
    DetachFailed(String),

    /// Interface not found.
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    /// Insufficient permissions.
    #[error("Insufficient permissions: {0}")]
    PermissionDenied(String),
}

/// XDP program for packet processing.
///
/// This is a simplified abstraction. In production, you would use
/// Aya to compile and load actual eBPF programs.
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct XdpProgram {
    /// Program name.
    pub name: String,
    /// Interface to attach to.
    pub interface: String,
    /// Program bytecode (compiled eBPF).
    pub bytecode: Vec<u8>,
}

#[cfg(feature = "ebpf")]
impl XdpProgram {
    /// Creates a new XDP program.
    #[must_use]
    pub fn new(name: impl Into<String>, interface: impl Into<String>, bytecode: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            interface: interface.into(),
            bytecode,
        }
    }

    /// Attaches the program to the network interface.
    ///
    /// # Errors
    ///
    /// Returns an error if attachment fails.
    pub async fn attach(&self) -> Result<(), XdpError> {
        // In a real implementation, this would use Aya to:
        // 1. Load the eBPF program into the kernel
        // 2. Attach it to the XDP hook on the specified interface
        Err(XdpError::LoadFailed(
            "XDP program loading not yet implemented. Requires Aya integration.".to_string(),
        ))
    }

    /// Detaches the program from the network interface.
    ///
    /// # Errors
    ///
    /// Returns an error if detachment fails.
    pub async fn detach(&self) -> Result<(), XdpError> {
        Err(XdpError::DetachFailed(
            "XDP program detachment not yet implemented.".to_string(),
        ))
    }
}

/// XDP program statistics.
#[derive(Debug, Clone, Default)]
pub struct XdpStats {
    /// Number of packets processed.
    pub packets_processed: u64,
    /// Number of packets dropped.
    pub packets_dropped: u64,
    /// Number of packets passed through.
    pub packets_passed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_program_creation() {
        let program = XdpProgram::new("test_program", "eth0", vec![0x01, 0x02, 0x03]);
        assert_eq!(program.name, "test_program");
        assert_eq!(program.interface, "eth0");
    }
}
