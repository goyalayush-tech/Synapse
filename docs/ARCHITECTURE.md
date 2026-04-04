# Synapse Architecture

This document describes the complete architecture of the Synapse project, including all crates, their responsibilities, and how they interact.

## Overview

Synapse is a distributed semantic event ledger designed for autonomous agents. It provides:

- **Token-efficient communication**: TOON format for LLM interactions
- **Secure identity**: SPIFFE/SPIRE integration for ephemeral workload identity
- **Advanced networking**: QUIC transport with protocol adapters
- **Event sourcing**: Immutable event log for full auditability
- **Knowledge graph**: Queryable graph of agents, tasks, and resources
- **Vector memory**: Semantic similarity search on embeddings

## Crate Structure

### syn-core

**Purpose**: Domain logic and shared infrastructure

**Responsibilities**:
- Domain types (SessionId, PortNumber)
- Error definitions
- Telemetry setup

**Dependencies**: Minimal (serde, thiserror, tracing)

### syn-proto

**Purpose**: Wire formats and protocol definitions

**Responsibilities**:
- Control plane messages (Serde/JSON)
- Data plane messages (Rkyv zero-copy)
- TOON serialization
- MCP/A2A protocol definitions
- Serialization adapters

**Features**:
- `toon`: TOON serialization support
- `mcp`: Model Context Protocol support
- `a2a`: Agent2Agent protocol support

### syn-proxy

**Purpose**: Async proxy engine

**Responsibilities**:
- Network abstraction (NetProvider trait)
- Connection management
- Control plane handling
- Event emission (when memory feature enabled)

**Features**:
- `mock-windows`: Mock provider for cross-platform testing
- `spiffe`: SPIFFE identity integration
- `quic`: QUIC transport support
- `memory`: Event sourcing integration

### syn-cli

**Purpose**: Command-line management interface

**Responsibilities**:
- CLI argument parsing
- Control command execution
- Status reporting

### syn-identity

**Purpose**: Secure workload identity and attestation

**Responsibilities**:
- SPIFFE/SPIRE integration
- X.509 SVID management
- Mutual TLS configuration
- Process attestation
- eBPF instrumentation

**Features**:
- `spiffe`: SPIFFE/SPIRE support
- `ebpf`: eBPF instrumentation (Linux only)

### syn-network

**Purpose**: Advanced network transport and protocol adapters

**Responsibilities**:
- QUIC transport implementation
- Protocol adapters (gRPC, HTTP/3)
- MASQUE tunnel support

**Features**:
- `quic`: QUIC transport
- `grpc`: gRPC protocol adapter
- `http3`: HTTP/3 support
- `masque`: MASQUE tunnel support

### syn-memory

**Purpose**: Event sourcing, knowledge graph, and vector memory

**Responsibilities**:
- Event store (append-only log)
- Knowledge graph (entity-relationship)
- Vector memory (embeddings)
- Consensus protocols

**Features**:
- `event-sourcing`: Event store support
- `graph`: Knowledge graph support
- `vector`: Vector memory support

## Data Flow

```
┌─────────┐
│ syn-cli │───Control Commands───┐
└─────────┘                       │
                                   ▼
                            ┌──────────────┐
                            │  syn-proxy   │
                            └──────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
            ┌─────────────┐ ┌──────────┐ ┌─────────────┐
            │ syn-network │ │syn-identity│ │ syn-memory  │
            └─────────────┘ └──────────┘ └─────────────┘
                    │              │              │
                    ▼              ▼              ▼
            ┌─────────────┐ ┌──────────┐ ┌─────────────┐
            │   QUIC      │ │  SPIFFE   │ │ Event Store │
            │  Adapters   │ │   SVIDs   │ │ Graph/Vector│
            └─────────────┘ └──────────┘ └─────────────┘
```

## Network Abstraction

The `NetProvider` trait provides platform-agnostic networking:

- **Windows**: Named Pipes
- **Unix**: Unix Domain Sockets
- **QUIC**: High-performance transport (when enabled)
- **Mock**: In-memory channels for testing

## Serialization Strategy

| Context | Format | Technology | Why |
|---------|--------|------------|-----|
| Control Plane | JSON | Serde | Human-readable, debuggable |
| Data Plane | Binary | Rkyv | Zero-copy, no allocation |
| LLM Interactions | TOON | Custom | Token-efficient (60% savings) |

## Security Model

- **SPIFFE Identity**: Ephemeral X.509 certificates from SPIRE
- **Mutual TLS**: All connections authenticated via SPIFFE
- **Process Attestation**: eBPF verification of workload identity
- **Zero-Trust**: No static API keys

## Event Sourcing

All significant actions are recorded as immutable events:

1. Event is appended to the log
2. Event updates the knowledge graph
3. Event may generate vector embeddings
4. State is reconstructed by replaying events

## Extension Points

The architecture supports extension through:

- **Feature Flags**: Conditional compilation for optional features
- **Trait Abstractions**: NetProvider, EventStore, KnowledgeGraph
- **Protocol Adapters**: Bridge between different agent protocols
- **Storage Backends**: Pluggable event stores and graph databases

