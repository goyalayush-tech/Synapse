//! Model Context Protocol (MCP) compatibility layer.
//!
//! MCP is a standardized protocol for agent-to-agent communication developed by Anthropic.
//! This module provides types and adapters for MCP message formats, enabling Synapse
//! to participate in MCP-based agent ecosystems.

use serde::{Deserialize, Serialize};

/// MCP protocol version.
pub const MCP_VERSION: &str = "2024-11-05";

/// MCP message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpMessage {
    /// Initialize connection with capabilities.
    Initialize {
        /// Protocol version.
        protocol_version: String,
        /// Client capabilities.
        capabilities: McpCapabilities,
        /// Client information.
        client_info: McpClientInfo,
    },
    /// Response to initialization.
    InitializeResult {
        /// Server capabilities.
        server_capabilities: McpServerCapabilities,
        /// Server information.
        server_info: McpServerInfo,
    },
    /// Request to list available tools/resources.
    ListTools,
    /// Response with available tools.
    ListToolsResult {
        /// Available tools.
        tools: Vec<McpTool>,
    },
    /// Request to call a tool.
    CallTool {
        /// Tool name.
        name: String,
        /// Tool arguments.
        arguments: serde_json::Value,
    },
    /// Response from tool call.
    CallToolResult {
        /// Tool output.
        content: Vec<McpContent>,
        /// Whether the tool call was successful.
        is_error: bool,
    },
    /// Request to list available resources.
    ListResources,
    /// Response with available resources.
    ListResourcesResult {
        /// Available resources.
        resources: Vec<McpResource>,
    },
    /// Request to read a resource.
    ReadResource {
        /// Resource URI.
        uri: String,
    },
    /// Response with resource content.
    ReadResourceResult {
        /// Resource contents.
        contents: Vec<McpContent>,
    },
    /// Notification message (no response expected).
    Notification {
        /// Notification method.
        method: String,
        /// Notification parameters.
        params: serde_json::Value,
    },
}

/// MCP client capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpCapabilities {
    /// Experimental features supported.
    #[serde(default)]
    pub experimental: serde_json::Value,
}

/// MCP client information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpClientInfo {
    /// Client name.
    pub name: String,
    /// Client version.
    pub version: String,
}

/// MCP server capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerCapabilities {
    /// Experimental features supported.
    #[serde(default)]
    pub experimental: serde_json::Value,
    /// Tools available on the server.
    #[serde(default)]
    pub tools: Option<McpToolsCapability>,
    /// Resources available on the server.
    #[serde(default)]
    pub resources: Option<McpResourcesCapability>,
}

/// MCP tools capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolsCapability {
    /// Whether tools are supported.
    pub enabled: bool,
}

/// MCP resources capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResourcesCapability {
    /// Whether resources are supported.
    pub enabled: bool,
}

/// MCP server information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// MCP tool definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTool {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Tool input schema (JSON Schema).
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

/// MCP resource definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResource {
    /// Resource URI.
    pub uri: String,
    /// Resource name.
    pub name: String,
    /// Resource description.
    #[serde(default)]
    pub description: String,
    /// Resource MIME type.
    #[serde(default)]
    pub mime_type: Option<String>,
}

/// MCP content (text or resource reference).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpContent {
    /// Text content.
    Text {
        /// Text content.
        text: String,
    },
    /// Resource reference.
    Resource {
        /// Resource URI.
        uri: String,
        /// Resource MIME type.
        #[serde(default)]
        mime_type: Option<String>,
        /// Resource text preview.
        #[serde(default)]
        text: Option<String>,
    },
}

impl McpMessage {
    /// Serializes the message to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes a message from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_initialize_roundtrip() {
        let msg = McpMessage::Initialize {
            protocol_version: MCP_VERSION.to_string(),
            capabilities: McpCapabilities {
                experimental: serde_json::json!({}),
            },
            client_info: McpClientInfo {
                name: "synapse".to_string(),
                version: "0.1.0".to_string(),
            },
        };

        let json = msg.to_json().unwrap();
        let recovered = McpMessage::from_json(&json).unwrap();
        assert_eq!(msg, recovered);
    }
}
