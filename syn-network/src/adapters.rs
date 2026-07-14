//! Protocol adapters for agent-to-agent communication.
//!
//! This module provides adapters that bridge between different agent protocols:
//! - MCP (Model Context Protocol) via gRPC or HTTP/3
//! - A2A (Agent2Agent) via gRPC or HTTP/3
//! - Protocol negotiation and conversion

#[cfg(feature = "quic")]
use crate::quic::{QuicBiStream, QuicError};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

/// Errors that can occur during protocol adapter operations.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Protocol negotiation failed.
    #[error("Protocol negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Unsupported protocol.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// Message conversion failed.
    #[error("Message conversion failed: {0}")]
    ConversionFailed(String),

    /// QUIC error.
    #[error("QUIC error: {0}")]
    Quic(#[from] QuicError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Supported agent protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Model Context Protocol (MCP).
    Mcp,
    /// Agent2Agent (A2A).
    A2A,
    /// Custom protocol.
    Custom(&'static str),
}

impl Protocol {
    /// Returns the protocol name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Mcp => "mcp",
            Self::A2A => "a2a",
            Self::Custom(name) => name,
        }
    }
}

/// Protocol adapter trait.
///
/// Adapters convert between different protocol formats and transport layers.
#[async_trait::async_trait]
pub trait ProtocolAdapter: Send + Sync {
    /// Returns the protocol this adapter handles.
    fn protocol(&self) -> Protocol;

    /// Negotiates the protocol with the remote peer.
    ///
    /// # Errors
    ///
    /// Returns an error if negotiation fails.
    async fn negotiate(&mut self, stream: &mut QuicBiStream) -> Result<(), AdapterError>;

    /// Encodes a message for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn encode(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError>;

    /// Decodes a received message.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, AdapterError>;
}

/// gRPC protocol adapter.
///
/// Adapts agent protocols to gRPC for transport over QUIC or HTTP/2.
#[cfg(feature = "grpc")]
pub struct GrpcAdapter {
    /// Protocol being adapted.
    protocol: Protocol,
}

#[cfg(feature = "grpc")]
impl GrpcAdapter {
    /// Creates a new gRPC adapter for the given protocol.
    #[must_use]
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

#[cfg(feature = "grpc")]
#[async_trait::async_trait]
impl ProtocolAdapter for GrpcAdapter {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    async fn negotiate(&mut self, _stream: &mut QuicBiStream) -> Result<(), AdapterError> {
        // gRPC negotiation would happen here
        Ok(())
    }

    fn encode(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // In a real implementation, this would encode as gRPC
        Ok(message.to_vec())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // In a real implementation, this would decode from gRPC
        Ok(data.to_vec())
    }
}

/// HTTP/3 protocol adapter.
///
/// Adapts agent protocols to HTTP/3 for transport over QUIC.
#[cfg(feature = "http3")]
pub struct Http3Adapter {
    /// Protocol being adapted.
    protocol: Protocol,
}

#[cfg(feature = "http3")]
impl Http3Adapter {
    /// Creates a new HTTP/3 adapter for the given protocol.
    #[must_use]
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

#[cfg(feature = "http3")]
#[async_trait::async_trait]
impl ProtocolAdapter for Http3Adapter {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    async fn negotiate(&mut self, _stream: &mut QuicBiStream) -> Result<(), AdapterError> {
        // HTTP/3 negotiation would happen here
        Ok(())
    }

    fn encode(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // In a real implementation, this would encode as HTTP/3
        Ok(message.to_vec())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // In a real implementation, this would decode from HTTP/3
        Ok(data.to_vec())
    }
}

/// Protocol adapter factory.
pub struct AdapterFactory;

impl AdapterFactory {
    /// Creates an adapter for the given protocol and transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter cannot be created.
    pub fn create(
        protocol: Protocol,
        transport: &str,
    ) -> Result<Box<dyn ProtocolAdapter>, AdapterError> {
        match transport {
            #[cfg(feature = "grpc")]
            "grpc" => Ok(Box::new(GrpcAdapter::new(protocol))),
            #[cfg(feature = "http3")]
            "http3" => Ok(Box::new(Http3Adapter::new(protocol))),
            "mcp" => Ok(Box::new(McpAdapter::new())),
            "a2a" => Ok(Box::new(A2aAdapter::new())),
            _ => Err(AdapterError::UnsupportedProtocol(format!(
                "Unsupported transport: {}",
                transport
            ))),
        }
    }
}

// =============================================================================
// MCP Adapter
// =============================================================================

/// Model Context Protocol (MCP) adapter.
///
/// Implements the MCP server interface, allowing agents to "mount" Synapse
/// as a memory and tool provider.
pub struct McpAdapter {
    /// Server information
    server_info: McpServerInfo,
    /// Server capabilities
    capabilities: McpServerCapabilities,
    /// Registered tools
    tools: Vec<McpTool>,
    /// Registered resources
    resources: Vec<McpResource>,
}

/// MCP server info (matching syn-proto types)
#[derive(Debug, Clone)]
pub struct McpServerInfo {
    pub name: String,
    pub version: String,
}

/// MCP server capabilities
#[derive(Debug, Clone)]
pub struct McpServerCapabilities {
    pub tools_enabled: bool,
    pub resources_enabled: bool,
}

/// MCP tool definition
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// MCP resource definition
#[derive(Debug, Clone)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: Option<String>,
}

impl McpAdapter {
    /// Create a new MCP adapter with default Synapse capabilities.
    #[must_use]
    pub fn new() -> Self {
        Self {
            server_info: McpServerInfo {
                name: "synapse".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: McpServerCapabilities {
                tools_enabled: true,
                resources_enabled: true,
            },
            tools: vec![
                McpTool {
                    name: "recall".to_string(),
                    description: "Search semantic memory for relevant context".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Natural language search query"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results to return",
                                "default": 10
                            }
                        },
                        "required": ["query"]
                    }),
                },
                McpTool {
                    name: "store".to_string(),
                    description: "Store an event in semantic memory".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "Content to store"
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional metadata"
                            }
                        },
                        "required": ["content"]
                    }),
                },
            ],
            resources: vec![McpResource {
                uri: "synapse://events/recent".to_string(),
                name: "Recent Events".to_string(),
                description: "List of recent events in the system".to_string(),
                mime_type: Some("application/json".to_string()),
            }],
        }
    }

    /// Register a custom tool.
    pub fn register_tool(&mut self, tool: McpTool) {
        self.tools.push(tool);
    }

    /// Register a custom resource.
    pub fn register_resource(&mut self, resource: McpResource) {
        self.resources.push(resource);
    }

    /// Handle an MCP initialize request.
    #[instrument(skip(self))]
    pub fn handle_initialize(&self, _client_info: &str) -> serde_json::Value {
        info!("MCP client connected");
        serde_json::json!({
            "type": "initialize_result",
            "server_capabilities": {
                "tools": {
                    "enabled": self.capabilities.tools_enabled
                },
                "resources": {
                    "enabled": self.capabilities.resources_enabled
                }
            },
            "server_info": {
                "name": self.server_info.name,
                "version": self.server_info.version
            }
        })
    }

    /// Handle list_tools request.
    pub fn handle_list_tools(&self) -> serde_json::Value {
        let tools: Vec<serde_json::Value> = self
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema
                })
            })
            .collect();

        serde_json::json!({
            "type": "list_tools_result",
            "tools": tools
        })
    }

    /// Handle list_resources request.
    pub fn handle_list_resources(&self) -> serde_json::Value {
        let resources: Vec<serde_json::Value> = self
            .resources
            .iter()
            .map(|r| {
                serde_json::json!({
                    "uri": r.uri,
                    "name": r.name,
                    "description": r.description,
                    "mime_type": r.mime_type
                })
            })
            .collect();

        serde_json::json!({
            "type": "list_resources_result",
            "resources": resources
        })
    }

    /// Process an incoming MCP message.
    #[instrument(skip(self, message))]
    pub fn process_message(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        let msg: serde_json::Value = serde_json::from_slice(message)
            .map_err(|e| AdapterError::Deserialization(e.to_string()))?;

        let msg_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        debug!("Processing MCP message: {}", msg_type);

        let response = match msg_type {
            "initialize" => self.handle_initialize(
                msg.get("client_info")
                    .map(|v| v.to_string())
                    .as_deref()
                    .unwrap_or(""),
            ),
            "list_tools" => self.handle_list_tools(),
            "list_resources" => self.handle_list_resources(),
            "call_tool" => {
                // Extract tool name and arguments
                let name = msg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = msg
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                self.handle_call_tool(name, args)
            }
            "read_resource" => {
                let uri = msg.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                self.handle_read_resource(uri)
            }
            _ => serde_json::json!({
                "type": "error",
                "error": format!("Unknown message type: {}", msg_type)
            }),
        };

        serde_json::to_vec(&response).map_err(|e| AdapterError::Serialization(e.to_string()))
    }

    /// Handle call_tool request.
    fn handle_call_tool(&self, name: &str, args: serde_json::Value) -> serde_json::Value {
        debug!("Calling tool: {} with args: {:?}", name, args);

        match name {
            "recall" => {
                let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

                // TODO: Connect to actual vector memory
                serde_json::json!({
                    "type": "call_tool_result",
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Tool 'recall' is not available: vector memory backend is not connected yet (query: '{}', limit: {})",
                            query, limit
                        )
                    }],
                    "is_error": true
                })
            }
            "store" => {
                let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
                // Char-boundary-safe truncation: slicing a `&str` by raw byte
                // index panics if the index lands mid-character, so collect
                // the first N chars instead of indexing bytes directly.
                let preview: String = content.chars().take(50).collect();

                // TODO: Connect to actual vector memory
                serde_json::json!({
                    "type": "call_tool_result",
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Tool 'store' is not available: vector memory backend is not connected yet (content preview: '{}')",
                            preview
                        )
                    }],
                    "is_error": true
                })
            }
            _ => serde_json::json!({
                "type": "call_tool_result",
                "content": [{
                    "type": "text",
                    "text": format!("Unknown tool: {}", name)
                }],
                "is_error": true
            }),
        }
    }

    /// Handle read_resource request.
    fn handle_read_resource(&self, uri: &str) -> serde_json::Value {
        debug!("Reading resource: {}", uri);

        // TODO: Connect to actual resources
        serde_json::json!({
            "type": "error",
            "error": format!("Resource '{}' is not available: resource backend is not connected yet", uri)
        })
    }
}

impl Default for McpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolAdapter for McpAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::Mcp
    }

    async fn negotiate(&mut self, stream: &mut QuicBiStream) -> Result<(), AdapterError> {
        // MCP uses JSON-RPC style messages, no separate negotiation needed
        debug!("MCP adapter ready");
        Ok(())
    }

    fn encode(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // MCP uses JSON, pass through
        Ok(message.to_vec())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // Process and generate response
        self.process_message(data)
    }
}

// =============================================================================
// A2A Adapter
// =============================================================================

/// Agent2Agent (A2A) protocol adapter.
///
/// Implements the A2A protocol for multi-agent task delegation and coordination.
pub struct A2aAdapter {
    /// Local agent information
    agent_info: A2aAgentInfo,
    /// Registered capabilities
    capabilities: Vec<A2aCapability>,
    /// Active tasks
    tasks: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, A2aTaskState>>>,
}

/// A2A agent info (matching syn-proto types)
#[derive(Debug, Clone)]
pub struct A2aAgentInfo {
    pub agent_id: String,
    pub name: String,
    pub version: String,
}

/// A2A capability definition
#[derive(Debug, Clone)]
pub struct A2aCapability {
    pub name: String,
    pub description: String,
    pub version: String,
}

/// Internal task state
#[derive(Debug, Clone)]
pub struct A2aTaskState {
    pub task_id: String,
    pub status: String,
    pub progress: u8,
}

impl A2aAdapter {
    /// Create a new A2A adapter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent_info: A2aAgentInfo {
                agent_id: uuid_simple(),
                name: "synapse-node".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: vec![
                A2aCapability {
                    name: "semantic_memory".to_string(),
                    description: "Query and store semantic memory".to_string(),
                    version: "1.0".to_string(),
                },
                A2aCapability {
                    name: "policy_evaluation".to_string(),
                    description: "Evaluate governance policies".to_string(),
                    version: "1.0".to_string(),
                },
            ],
            tasks: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a capability.
    pub fn register_capability(&mut self, capability: A2aCapability) {
        self.capabilities.push(capability);
    }

    /// Handle a discovery request.
    pub fn handle_discovery(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "discovery_response",
            "agents": [{
                "agent_id": self.agent_info.agent_id,
                "name": self.agent_info.name,
                "version": self.agent_info.version,
                "capabilities": self.capabilities.iter().map(|c| &c.name).collect::<Vec<_>>()
            }]
        })
    }

    /// Handle capability advertisement.
    pub fn handle_capability_advertisement(&self) -> serde_json::Value {
        let caps: Vec<serde_json::Value> = self
            .capabilities
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "description": c.description,
                    "version": c.version
                })
            })
            .collect();

        serde_json::json!({
            "type": "capability_advertisement",
            "capabilities": caps
        })
    }

    /// Handle task delegation.
    pub async fn handle_delegate_task(&self, task: serde_json::Value) -> serde_json::Value {
        let task_id = task
            .get("task_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&uuid_simple())
            .to_string();

        // Accept the task
        let mut tasks = self.tasks.write().await;
        tasks.insert(
            task_id.clone(),
            A2aTaskState {
                task_id: task_id.clone(),
                status: "accepted".to_string(),
                progress: 0,
            },
        );

        serde_json::json!({
            "type": "delegate_task_response",
            "accepted": true,
            "task_id": task_id
        })
    }

    /// Process an incoming A2A message.
    #[instrument(skip(self, message))]
    pub async fn process_message(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        let msg: serde_json::Value = serde_json::from_slice(message)
            .map_err(|e| AdapterError::Deserialization(e.to_string()))?;

        let msg_type = msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        debug!("Processing A2A message: {}", msg_type);

        let response = match msg_type {
            "discovery" => self.handle_discovery(),
            "capability_advertisement" => self.handle_capability_advertisement(),
            "delegate_task" => {
                let task = msg.get("task").cloned().unwrap_or(serde_json::Value::Null);
                self.handle_delegate_task(task).await
            }
            "heartbeat" => serde_json::json!({
                "type": "heartbeat_response"
            }),
            "invoke_capability" => {
                let capability = msg.get("capability").and_then(|v| v.as_str()).unwrap_or("");
                let params = msg
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                self.handle_invoke_capability(capability, params)
            }
            _ => serde_json::json!({
                "type": "error",
                "error": format!("Unknown message type: {}", msg_type)
            }),
        };

        serde_json::to_vec(&response).map_err(|e| AdapterError::Serialization(e.to_string()))
    }

    /// Handle capability invocation.
    fn handle_invoke_capability(
        &self,
        capability: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        debug!(
            "Invoking capability: {} with params: {:?}",
            capability, params
        );

        // TODO: Connect to actual capability implementations
        serde_json::json!({
            "type": "invoke_capability_response",
            "result": {
                "message": format!("Capability '{}' is not available: capability backend is not connected yet", capability)
            },
            "success": false
        })
    }
}

impl Default for A2aAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolAdapter for A2aAdapter {
    fn protocol(&self) -> Protocol {
        Protocol::A2A
    }

    async fn negotiate(&mut self, stream: &mut QuicBiStream) -> Result<(), AdapterError> {
        // A2A uses envelope-based messages, no separate negotiation
        debug!("A2A adapter ready");
        Ok(())
    }

    fn encode(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // A2A uses JSON envelopes, pass through
        Ok(message.to_vec())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, AdapterError> {
        // Note: This is sync but we need async. In practice, use process_message
        // For the trait, just return the raw data
        Ok(data.to_vec())
    }
}

/// Generate a simple UUID-like string
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_as_str() {
        assert_eq!(Protocol::Mcp.as_str(), "mcp");
        assert_eq!(Protocol::A2A.as_str(), "a2a");
        assert_eq!(Protocol::Custom("custom").as_str(), "custom");
    }
}
