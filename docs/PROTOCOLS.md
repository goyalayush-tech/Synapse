# Protocol Documentation

This document describes the agent-to-agent protocols supported by Synapse.

## Model Context Protocol (MCP)

MCP is a standardized protocol for agent-to-agent communication developed by Anthropic.

### Message Types

- `Initialize`: Establish connection with capabilities
- `ListTools`: Discover available tools
- `CallTool`: Invoke a tool
- `ListResources`: Discover available resources
- `ReadResource`: Read a resource

### Example

```rust
use syn_proto::mcp::*;

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

let json = msg.to_json()?;
```

## Agent2Agent (A2A)

A2A is a standardized protocol developed by Google and the Linux Foundation.

### Message Types

- `Discovery`: Find available agents
- `CapabilityAdvertisement`: Advertise capabilities
- `InvokeCapability`: Invoke a capability
- `DelegateTask`: Delegate a task to another agent
- `TaskStatus`: Update task status

### Example

```rust
use syn_proto::a2a::*;

let envelope = A2AEnvelope::new(
    "agent-1",
    A2AMessage::Discovery {
        capabilities: vec!["compute".to_string()],
    },
);

let json = envelope.to_json()?;
```

## Protocol Adapters

Synapse provides adapters to bridge protocols over different transports:

### gRPC Adapter

```rust
use syn_network::{AdapterFactory, Protocol};

let adapter = AdapterFactory::create(Protocol::Mcp, "grpc")?;
```

### HTTP/3 Adapter

```rust
let adapter = AdapterFactory::create(Protocol::A2A, "http3")?;
```

## Transport Layers

Protocols can be transported over:

- **QUIC**: High-performance, multiplexed connections
- **gRPC**: Standard RPC framework
- **HTTP/3**: HTTP over QUIC

## Protocol Negotiation

Agents negotiate protocols during connection establishment:

1. Client sends protocol preference
2. Server responds with supported protocols
3. Both sides agree on a protocol
4. Communication proceeds using the agreed protocol

## Serialization

Protocol messages use JSON for human readability, but can be converted to:

- **TOON**: For LLM interactions (token-efficient)
- **Rkyv**: For high-performance data plane

