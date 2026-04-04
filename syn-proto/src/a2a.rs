//! Agent2Agent (A2A) protocol definitions.
//!
//! A2A is a standardized protocol for agent-to-agent communication developed
//! by Google and the Linux Foundation. This module provides types for A2A
//! message formats, enabling Synapse to participate in A2A-based agent ecosystems.

use serde::{Deserialize, Serialize};

/// A2A protocol version.
pub const A2A_VERSION: &str = "1.0";

/// A2A message envelope.
///
/// All A2A messages are wrapped in an envelope that provides routing and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AEnvelope {
    /// Message version.
    pub version: String,
    /// Message ID for correlation.
    pub message_id: String,
    /// Source agent identifier.
    pub source: String,
    /// Destination agent identifier (optional for broadcasts).
    #[serde(default)]
    pub destination: Option<String>,
    /// Message timestamp (Unix epoch in milliseconds).
    pub timestamp_ms: u64,
    /// Message type.
    #[serde(flatten)]
    pub message: A2AMessage,
}

/// A2A message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum A2AMessage {
    /// Discovery request - find available agents.
    Discovery {
        /// Capabilities to search for.
        #[serde(default)]
        capabilities: Vec<String>,
    },
    /// Discovery response - list of available agents.
    DiscoveryResponse {
        /// Available agents.
        agents: Vec<A2AAgentInfo>,
    },
    /// Capability advertisement.
    CapabilityAdvertisement {
        /// Agent capabilities.
        capabilities: Vec<A2ACapability>,
    },
    /// Request to invoke a capability.
    InvokeCapability {
        /// Capability name.
        capability: String,
        /// Invocation parameters.
        params: serde_json::Value,
    },
    /// Response from capability invocation.
    InvokeCapabilityResponse {
        /// Result data.
        result: serde_json::Value,
        /// Whether the invocation was successful.
        success: bool,
        /// Error message if unsuccessful.
        #[serde(default)]
        error: Option<String>,
    },
    /// Task delegation request.
    DelegateTask {
        /// Task description.
        task: A2ATask,
    },
    /// Task delegation response.
    DelegateTaskResponse {
        /// Whether the task was accepted.
        accepted: bool,
        /// Task ID if accepted.
        #[serde(default)]
        task_id: Option<String>,
        /// Rejection reason if not accepted.
        #[serde(default)]
        reason: Option<String>,
    },
    /// Task status update.
    TaskStatus {
        /// Task ID.
        task_id: String,
        /// Task status.
        status: A2ATaskStatus,
        /// Progress percentage (0-100).
        #[serde(default)]
        progress: Option<u8>,
    },
    /// Heartbeat message for liveness.
    Heartbeat,
    /// Heartbeat response.
    HeartbeatResponse,
}

/// A2A agent information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AAgentInfo {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent name.
    pub name: String,
    /// Agent version.
    pub version: String,
    /// Agent capabilities.
    pub capabilities: Vec<String>,
    /// Agent endpoint (URI).
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// A2A capability definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ACapability {
    /// Capability name.
    pub name: String,
    /// Capability description.
    pub description: String,
    /// Capability version.
    pub version: String,
    /// Input schema (JSON Schema).
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// Output schema (JSON Schema).
    #[serde(default)]
    pub output_schema: serde_json::Value,
}

/// A2A task definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ATask {
    /// Task identifier.
    pub task_id: String,
    /// Task type.
    pub task_type: String,
    /// Task description.
    pub description: String,
    /// Task parameters.
    #[serde(default)]
    pub parameters: serde_json::Value,
    /// Task priority (higher = more important).
    #[serde(default)]
    pub priority: u8,
    /// Task deadline (Unix epoch in milliseconds).
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

/// A2A task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2ATaskStatus {
    /// Task is pending.
    Pending,
    /// Task is in progress.
    InProgress,
    /// Task completed successfully.
    Completed,
    /// Task failed.
    Failed,
    /// Task was cancelled.
    Cancelled,
}

impl A2AEnvelope {
    /// Creates a new envelope with the given message.
    #[must_use]
    pub fn new(source: impl Into<String>, message: A2AMessage) -> Self {
        Self {
            version: A2A_VERSION.to_string(),
            message_id: generate_message_id(),
            source: source.into(),
            destination: None,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            message,
        }
    }

    /// Serializes the envelope to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes an envelope from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Generates a unique message ID.
fn generate_message_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2a_envelope_roundtrip() {
        let envelope = A2AEnvelope::new(
            "agent-1",
            A2AMessage::Heartbeat,
        );

        let json = envelope.to_json().unwrap();
        let recovered = A2AEnvelope::from_json(&json).unwrap();
        
        assert_eq!(envelope.version, recovered.version);
        assert_eq!(envelope.source, recovered.source);
        assert_eq!(envelope.message, recovered.message);
    }

    #[test]
    fn a2a_discovery_roundtrip() {
        let envelope = A2AEnvelope::new(
            "agent-1",
            A2AMessage::Discovery {
                capabilities: vec!["compute".to_string(), "storage".to_string()],
            },
        );

        let json = envelope.to_json().unwrap();
        let recovered = A2AEnvelope::from_json(&json).unwrap();
        
        if let (A2AMessage::Discovery { capabilities: c1 }, A2AMessage::Discovery { capabilities: c2 }) = 
            (envelope.message, recovered.message) {
            assert_eq!(c1, c2);
        } else {
            panic!("Message type mismatch");
        }
    }
}

