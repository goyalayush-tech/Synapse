//! Control plane protocol definitions.
//!
//! These messages are used for management operations between the CLI and proxy.
//! They use Serde for JSON compatibility, prioritizing debuggability over
//! raw performance (control operations are infrequent).

use serde::{Deserialize, Serialize};

/// Commands sent from the CLI to control a running proxy instance.
///
/// These commands are serialized as JSON and sent over the control socket
/// (Named Pipe on Windows, Unix socket on Linux/macOS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlCommand {
    /// Request the proxy to reload its configuration file.
    ///
    /// The proxy will re-read the config and apply changes without
    /// dropping existing connections.
    Reload,

    /// Request a graceful shutdown.
    ///
    /// The proxy will stop accepting new connections and drain
    /// existing ones before exiting.
    Shutdown,

    /// Request the current status of the proxy.
    ///
    /// Returns connection counts, uptime, and health metrics.
    GetStatus,

    /// Request detailed metrics for monitoring systems.
    GetMetrics,

    /// Ping to verify the control channel is working.
    Ping,
}

/// Response from the proxy to a control command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    /// Command was acknowledged and executed successfully.
    Ok,

    /// Detailed status information.
    Status(ProxyStatus),

    /// Metrics payload.
    Metrics(MetricsPayload),

    /// Pong response to a ping.
    Pong,

    /// Command failed with an error message.
    Error {
        /// The error message describing what went wrong.
        message: String,
    },
}

/// Status information about the running proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStatus {
    /// Number of seconds since the proxy started.
    pub uptime_secs: u64,

    /// Current number of active connections.
    pub active_connections: u64,

    /// Total connections handled since startup.
    pub total_connections: u64,

    /// Whether the proxy is accepting new connections.
    pub accepting: bool,

    /// Version string of the running proxy.
    pub version: String,
}

/// Metrics payload for monitoring systems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsPayload {
    /// Prometheus-compatible metrics text.
    pub prometheus: String,
}

impl ControlCommand {
    /// Serializes the command to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (should not happen for valid commands).
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes a command from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid JSON or don't match the schema.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl ControlResponse {
    /// Serializes the response to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes a response from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrip() {
        let commands = vec![
            ControlCommand::Reload,
            ControlCommand::Shutdown,
            ControlCommand::GetStatus,
            ControlCommand::Ping,
        ];

        for cmd in commands {
            let json = cmd.to_json().expect("serialize");
            let recovered = ControlCommand::from_json(&json).expect("deserialize");
            assert_eq!(cmd, recovered);
        }
    }

    #[test]
    fn command_json_format() {
        let cmd = ControlCommand::Reload;
        let json = String::from_utf8(cmd.to_json().unwrap()).unwrap();
        assert!(json.contains("\"type\":\"reload\""));
    }

    #[test]
    fn status_serialization() {
        let status = ProxyStatus {
            uptime_secs: 3600,
            active_connections: 42,
            total_connections: 1000,
            accepting: true,
            version: "0.1.0".to_string(),
        };

        let response = ControlResponse::Status(status);
        let json = response.to_json().unwrap();
        let recovered = ControlResponse::from_json(&json).unwrap();
        assert_eq!(response, recovered);
    }
}
