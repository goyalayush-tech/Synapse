# Synapse - Complete Technical Documentation

> **Version**: 0.4.0 (Enterprise)  
> **Last Updated**: December 2025  
> **Status**: Enterprise Ready  

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Philosophy & Design Principles](#philosophy--design-principles)
3. [The Iron Stack](#the-iron-stack)
4. [v2.0 Agentic Mesh Architecture](#v20-agentic-mesh-architecture)
5. [Architecture Overview](#architecture-overview)
6. [Workspace Structure](#workspace-structure)
7. [Crate Documentation](#crate-documentation)
   - [syn-core](#syn-core)
   - [syn-proto](#syn-proto)
   - [syn-identity](#syn-identity)
   - [syn-network](#syn-network)
   - [syn-memory](#syn-memory)
   - [syn-policy](#syn-policy)
   - [syn-proxy](#syn-proxy)
   - [syn-cli](#syn-cli)
   - [syn-admin](#syn-admin)
8. [Feature Flags](#feature-flags)
9. [Serialization Strategy](#serialization-strategy)
10. [Testing](#testing)
11. [Development Guide](#development-guide)
12. [Roadmap](#roadmap)

---

## Project Overview

**Synapse** is a distributed semantic event ledger designed to replace Apache Kafka for the Agentic AI economy. It serves as the "Nervous System" for autonomous agents, providing infrastructure built specifically for machine-to-machine communication rather than human operators.

### Key Differentiators

| Traditional Stack | Synapse Approach |
|-------------------|------------------|
| JSON everywhere | TOON (Token-Oriented Object Notation) |
| Static API keys | Zero-trust eBPF process attestation |
| Opaque byte streams | Semantic intent storage (LanceDB) |
| External policy engines | Inline WebAssembly + Cedar policies |
| Human-readable logs | Machine-queryable knowledge |
| Single-agent state | CRDT-based multi-agent collaboration |
| Manual coordination | Autonomous swarm via Blackboard pattern |

---

## Philosophy & Design Principles

### Core Tenets

1. **Token Efficiency**: Every byte costs money in the AI economy
2. **Semantic Memory**: Query by intent, not by byte offset
3. **Zero-Trust Identity**: Process attestation over static secrets
4. **Sub-millisecond Latency**: Zero-copy everywhere it matters
5. **Type Safety**: Rust's type system as the first line of defense

### Architectural Patterns

- **Hexagonal Architecture**: Ports & Adapters for testability
- **Trait-based Abstractions**: Mock anything, test everything
- **Feature-gated Compilation**: Only compile what you need
- **Error Handling Convention**: `thiserror` for libraries, `anyhow` for binaries

---

## The Iron Stack

Synapse adheres to the "Iron Stack" - a set of non-negotiable technical choices:

### 1. Language: 100% Rust
- Memory safety without garbage collection
- Zero-cost abstractions
- Thread-per-core architecture compatibility
- No JVM, no Python in the core broker

### 2. Economics: TOON over JSON (The Syntax Tax)
- 30-50% token cost savings
- Schema-embedded format for LLM drift protection
- Indentation-based, bracket-free syntax

### 3. Identity: Zero Trust via eBPF
- Process identity from the kernel (PID, Cgroup, Binary Hash)
- Ephemeral SPIFFE IDs
- No static API keys

### 4. Memory: Semantic Persistence (Lance)
- Store "Intent" not opaque bytes
- Every log segment is a vector index
- Columnar storage for ML workloads

### 5. Logic: WebAssembly Reflexes
- Governance policies run inside the stream
- Wasmtime for sandboxed execution
- Hot-reloadable without restart

---

## v2.0 Agentic Mesh Architecture

Synapse v2.0 introduces the "Agentic Mesh" - a complete nervous system for autonomous AI agents with four integrated planes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SYNAPSE v2.0: AGENTIC MESH                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   SHIELD    │  │   ROUTER    │  │   STATE     │  │      JUDGE          ││
│  │   Plane     │  │   Plane     │  │   Plane     │  │      Plane          ││
│  │             │  │             │  │             │  │                     ││
│  │ eBPF/Aya    │  │ QUIC/Quinn  │  │ LanceDB +   │  │ Wasmtime +          ││
│  │ Kernel ID   │  │ MCP/A2A     │  │ Automerge   │  │ Cedar               ││
│  │ Zero Trust  │  │ Protocols   │  │ CRDTs       │  │ ABAC Policies       ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                │                    │           │
│         └────────────────┴────────────────┴────────────────────┘           │
│                                   │                                         │
│                          ┌────────┴────────┐                               │
│                          │  SynapseNode    │                               │
│                          │  (Integration)  │                               │
│                          └─────────────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Four Planes

| Plane | Crate | Technology | Purpose |
|-------|-------|------------|--------|
| **Shield** | syn-identity | Aya eBPF | Kernel-anchored process attestation, SPIFFE IDs |
| **Router** | syn-network | Quinn QUIC | MCP/A2A protocol multiplexing, connection pooling |
| **State** | syn-memory | LanceDB + Automerge | Vector memory + CRDT "Blackboard" for collaboration |
| **Judge** | syn-policy | Wasmtime + Cedar | WASM reflexes + Cedar ABAC authorization |

### HyperState: The Agent Blackboard

The `HyperState` combines two memory paradigms:

```rust
pub struct HyperState {
    /// Vector memory for semantic search (long-term)
    pub vectors: LanceStore,
    /// CRDT blackboard for live collaboration (short-term)
    pub blackboard: CrdtBlackboard,
}
```

- **Vector Memory** (LanceDB): Persistent semantic storage with IVF-PQ indices for sub-10ms ANN queries
- **CRDT Blackboard** (Automerge): Conflict-free collaborative state for multi-agent "swarm" coordination

### SynapseNode Integration

The `SynapseNode` (in `syn-proxy/src/node.rs`) orchestrates all four planes:

```rust
let node = SynapseNode::new(NodeConfig {
    bind_addr: "0.0.0.0:4433".parse()?,
    data_dir: PathBuf::from("./synapse_data"),
    require_attestation: true,
}).await?;

node.run().await?; // Event loop with graceful shutdown
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SYNAPSE SYSTEM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Control Plane                                 │    │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │    │
│  │  │ syn-cli  │──▶│syn-proxy │──▶│syn-proto │──▶│    syn-core      │ │    │
│  │  │ Commands │   │  Server  │   │ Protocol │   │  Domain Types    │ │    │
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Data Plane                                   │    │
│  │  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐  │    │
│  │  │ syn-network  │──▶│ syn-identity │──▶│      syn-memory        │  │    │
│  │  │    QUIC      │   │ eBPF/SPIFFE  │   │    Lance Storage       │  │    │
│  │  └──────────────┘   └──────────────┘   └────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Policy Layer                                  │    │
│  │  ┌────────────────────────────────────────────────────────────────┐ │    │
│  │  │                        syn-policy                               │ │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│ │    │
│  │  │  │   Engine    │  │   Verdict   │  │    Wasm Runtime         ││ │    │
│  │  │  │  Registry   │  │  Allow/Deny │  │   (Wasmtime)            ││ │    │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘│ │    │
│  │  └────────────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Workspace Structure

```
Synapse/
├── Cargo.toml              # Workspace root with shared dependencies
├── Cargo.lock              # Locked dependency versions
├── rust-toolchain.toml     # Rust version pinning (1.75+)
├── README.md               # Project overview
├── VERIFICATION.md         # Verification procedures
├── ARCHITECTURE_DETAILED.md # This file
│
├── synapse-ebpf/           # Kernel-space eBPF programs (built separately)
│   ├── Cargo.toml          # #![no_std] eBPF crate config
│   ├── .cargo/config.toml  # bpf-linker configuration
│   └── src/
│       └── main.rs         # LSM hooks, kprobes, cgroup filters
│
├── xtask/                  # Build automation
│   └── src/
│       └── main.rs         # Docker-based cross-platform eBPF compilation
│
├── wit/                    # WebAssembly Interface Types
│   └── governance.wit      # WIT definitions for WASM Component Model
│
├── syn-core/               # Core domain types and infrastructure
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── error.rs        # SynapseError enum
│       ├── telemetry.rs    # Tracing configuration
│       ├── types.rs        # Domain newtypes (SessionId)
│       └── uncopyable.rs   # UncopyableRuntime orchestration
│
├── syn-proto/              # Wire protocol definitions
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── control.rs      # Control plane messages
│       ├── data.rs         # Data plane packets
│       ├── error.rs        # Protocol errors
│       ├── toon.rs         # TOON serialization
│       ├── mcp.rs          # Model Context Protocol
│       ├── a2a.rs          # Agent-to-Agent protocol
│       ├── serde.rs        # Serde configuration
│       └── rkyv.rs         # Rkyv zero-copy serialization
│
├── syn-identity/           # Workload identity and attestation
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── attestation.rs  # Process attribute verification
│       ├── spiffe.rs       # SPIFFE/SPIRE client
│       ├── tls.rs          # TLS configuration
│       ├── provider.rs     # IdentityProvider trait (platform abstraction)
│       └── ebpf/
│           ├── mod.rs      # eBPF attestation engine
│           ├── allowlist.rs # Binary hash allowlist
│           ├── verifier.rs  # Process verification
│           ├── kprobe.rs    # Connection kprobe
│           └── xdp.rs       # XDP packet programs
│
├── syn-network/            # Network transport layer
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── quic.rs         # Quinn QUIC implementation
│       ├── adapters.rs     # Protocol adapters
│       └── masque.rs       # MASQUE tunnel support
│
├── syn-memory/             # Event sourcing and semantic storage
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── event_store.rs  # Append-only event log
│       ├── consensus.rs    # LLM-mediated consensus
│       ├── graph.rs        # Knowledge graph
│       ├── vector.rs       # Vector embeddings
│       ├── lance.rs        # Lance-lite columnar storage
│       ├── lancedb.rs      # Production LanceDB integration
│       ├── embedder.rs     # Candle ML embedding engine
│       └── crdt.rs         # Automerge CRDT blackboard (v2.0)
│
├── syn-policy/             # Governance policy engine
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── engine.rs       # Policy evaluation engine
│       ├── policy.rs       # Policy trait and implementations
│       ├── verdict.rs      # Allow/Deny/Transform verdicts
│       ├── wasm_host.rs    # Wasmtime Component Model host (encrypted modules)
│       └── cedar.rs        # Cedar ABAC policy engine (v2.0)
│
├── syn-proxy/              # Async proxy server
│   └── src/
│       ├── lib.rs          # Library exports
│       ├── main.rs         # Binary entry point
│       ├── server.rs       # Server implementation
│       ├── node.rs         # SynapseNode v2.0 integration runtime
│       ├── net/            # Network abstraction layer
│       └── windows/        # Windows-specific (Named Pipes)
│
├── policies/               # Cedar policy files (v2.0)
│   └── guardrails.cedar    # Default agent governance rules
│
├── syn-cli/                # Command-line interface
│   └── src/
│       └── main.rs         # CLI implementation
│
├── docs/                   # Additional documentation
│   ├── ARCHITECTURE.md
│   ├── EVENT_SOURCING.md
│   ├── IDENTITY.md
│   └── PROTOCOLS.md
│
├── examples/               # Example code
└── tools/                  # Development tools
```

---

## Crate Documentation

### syn-core

**Purpose**: Foundation crate containing domain types, error handling, and telemetry.

**Design Principle**: "Pure" - no I/O logic, minimal dependencies. All workspace crates depend on `syn-core`, but it depends on none of them.

#### Key Types

| Type | Description |
|------|-------------|
| `SessionId` | Newtype for session identification (prevents primitive obsession) |
| `SynapseError` | Unified error enum with proper error codes |
| `Result<T>` | Type alias for `Result<T, SynapseError>` |

#### Modules

- **`error.rs`**: Centralized error handling with `thiserror`
- **`telemetry.rs`**: Tracing configuration (env-filter, JSON output)
- **`types.rs`**: Domain newtypes with validation
- **`uncopyable.rs`**: UncopyableRuntime for Environmental Entanglement

```rust
use syn_core::{SessionId, SynapseError, Result};
use syn_core::{UncopyableRuntime, EbpfEvent, PolicyVerdict, IntentRecord};
```

#### UncopyableRuntime

The `UncopyableRuntime` orchestrates the three pillars of Environmental Entanglement:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Environmental Entanglement Flow                       │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   eBPF       │    │   WASM       │    │   Vector     │              │
│  │   Events     │───▶│   Policy     │───▶│   Memory     │              │
│  │              │    │   Evaluate   │    │   (LanceDB)  │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                       │
│         ▼                   ▼                   ▼                       │
│  TRUSTED_PIDS map   Key derivation      Semantic indexing              │
│  Binary hashes      Encrypted modules   Intent capture                 │
│  Cgroup filters     Fuel metering       Vector search                  │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Enterprise Module

The `enterprise` module provides production-grade features for multi-tenant deployments:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENTERPRISE LAYER                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │  Tenancy   │  │   Audit    │  │   Rate     │  │    Geo     │        │
│  │  Manager   │  │   Chain    │  │  Limiter   │  │   Repl     │        │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘        │
│        │               │               │               │               │
│        └───────────────┴───────────────┴───────────────┘               │
│                               │                                         │
│                    ┌──────────┴──────────┐                             │
│                    │  EnterpriseContext  │                             │
│                    └─────────────────────┘                             │
│                               │                                         │
│                    ┌──────────┴──────────┐                             │
│                    │   BackupManager     │                             │
│                    └─────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────┘
```

**Components:**

| Component | Description |
|-----------|-------------|
| `TenantManager` | Tenant lifecycle, namespace isolation, resource quotas |
| `AuditChain` | Tamper-proof SHA-256 hash chain for compliance |
| `RateLimiter` | Token bucket + sliding window rate limiting |
| `GeoRegion` | Multi-region replication with conflict resolution |
| `BackupManager` | Point-in-time recovery and automated backups |

**Usage:**

```rust
use syn_core::enterprise::{
    EnterpriseContext, EnterpriseConfig,
    TenantId, AuditEvent, AuditSeverity,
};

// Initialize enterprise features
let config = EnterpriseConfig {
    tenancy_enabled: true,
    audit_enabled: true,
    ..Default::default()
};
let ctx = EnterpriseContext::new(config).await;

// Validate request
ctx.check_request(&TenantId::new("tenant-123"), 1).await?;

// Record audit event
ctx.audit(AuditEvent::new(
    AuditSeverity::Info,
    "user.login",
    "User authenticated successfully",
)).await?;
```

---

### syn-proto

**Purpose**: Wire protocol definitions and serialization for inter-component communication.

**Design Principle**: Hybrid serialization - Serde/JSON for control plane (human-readable), Rkyv for data plane (zero-copy).

#### Serialization Strategy

| Context | Format | Use Case |
|---------|--------|----------|
| Control Plane | Serde/JSON | Configuration, CLI commands |
| Data Plane | Rkyv | Event streaming, high throughput |
| LLM Communication | TOON | Token-efficient structured data |

#### Key Types

| Type | Description |
|------|-------------|
| `ControlCommand` | CLI to proxy commands (Ping, Status, Reload, Shutdown) |
| `ControlResponse` | Proxy responses with status and metrics |
| `PacketHeader` | Zero-copy data plane header (via Rkyv) |
| `PacketFlags` | Bitflags for packet properties (COMPRESSED, ENCRYPTED, etc.) |
| `IntentEvent` | Semantic event with action/reason/payload |

#### Features

- **`toon`**: TOON serialization (Token-Oriented Object Notation)
- **`mcp`**: Model Context Protocol support
- **`a2a`**: Agent-to-Agent protocol support

#### TOON Format Example

```
// JSON (24 tokens):
{"users":[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]}

// TOON (12 tokens):
users2{id,name}:
  1 Alice
  2 Bob
```

---

### syn-identity

**Purpose**: Secure workload identity via SPIFFE/SPIRE and eBPF process attestation.

**Design Principle**: Zero-trust - identity derived from kernel, not static secrets.

#### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         syn-identity                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   SPIFFE    │  │    eBPF     │  │    Attestation          │ │
│  │   Client    │  │   Engine    │  │    Provider             │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                     │               │
│         ▼                ▼                     ▼               │
│  ┌────────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │  X.509 SVIDs   │  │   Allowlist   │  │ ProcessAttributes │ │
│  │  (mTLS certs)  │  │ (binary hash) │  │  (pid, exe, etc)  │ │
│  └────────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Types

| Type | Description |
|------|-------------|
| `SpiffeClient` | Client for SPIFFE workload API |
| `SpiffeIdentity` | X.509 SVID with certificate chain |
| `EbpfAttestationEngine` | Kernel-level process attestation |
| `Allowlist` | SHA-256 binary hash allowlist |
| `BinaryHash` | 32-byte SHA-256 hash with hex encoding |
| `ProcessInfo` | Process attributes (pid, uid, exe_path, cgroup) |
| `VerificationResult` | Allowed/Denied with reason |
| `IdentityProvider` | Platform-abstracted identity verification trait |
| `EbpfIdentityProvider` | Linux implementation using aya-rs |
| `MockIdentityProvider` | Windows/macOS mock implementation |

#### Features

- **`spiffe`**: SPIFFE workload API client
- **`ebpf`**: eBPF programs via aya-rs (Linux only)

#### Platform Support

| Platform | eBPF | SPIFFE | Attestation |
|----------|------|--------|-------------|
| Linux | ✅ Full | ✅ Full | ✅ /proc-based |
| Windows | ❌ Stub | ✅ Full | ⚠️ Mock |
| macOS | ❌ Stub | ✅ Full | ⚠️ Mock |

---

### syn-network

**Purpose**: High-performance network transport via QUIC with horizontal scaling.

**Design Principle**: Multiplexed, encrypted connections with connection pooling and consistent hashing for cluster distribution.

#### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      QUIC Transport Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ QuicServer  │  │ QuicClient  │  │   ConnectionPool        │ │
│  │  (accept)   │  │  (connect)  │  │  (LRU reuse)            │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                     │               │
│         └────────────────┼─────────────────────┘               │
│                          │                                      │
│                    ┌─────┴──────┐                               │
│                    │QuicConnection│                             │
│                    │  + Metadata  │                             │
│                    └─────┬──────┘                               │
│         ┌────────────────┼─────────────────┐                   │
│         │                │                 │                   │
│   ┌─────┴─────┐   ┌─────┴─────┐   ┌──────┴──────┐             │
│   │BiStream   │   │SendStream │   │RecvStream   │             │
│   └───────────┘   └───────────┘   └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   Consistent Hash Ring (v0.3.0)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                      ╭──────────╮                               │
│                 ╭────│  VNode1  │────╮                          │
│            ╭────│    ╰──────────╯    │────╮                     │
│       ╭────│    │       Node A       │    │────╮                │
│  VNode6    │    ╰────────────────────╯    │    VNode2           │
│  Node C    │                              │    Node A           │
│       ╰────│    ╭────────────────────╮    │────╯                │
│            ╰────│       Node B       │────╯                     │
│                 │    ╭──────────╮    │                          │
│                 ╰────│  VNode3  │────╯                          │
│                      ╰──────────╯                               │
│                                                                  │
│  Features:                                                       │
│  • Virtual nodes for even distribution (default: 150 per node)  │
│  • Bounded loads to prevent hot spots (1.25x factor)            │
│  • Preference lists for N-way replication                       │
│  • Rack-aware placement (datacenter affinity)                   │
│  • SipHash-2-4 for consistent, secure hashing                   │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Types

| Type | Description |
|------|-------------|
| `QuicServer` | Accept incoming QUIC connections |
| `QuicClient` | Establish outgoing QUIC connections |
| `QuicConnection` | Multiplexed connection with metadata |
| `ConnectionPool` | LRU connection pool with eviction |
| `QuicBiStream` | Bidirectional stream (read + write) |
| `ConnectionMetadata` | Tracks creation time, bytes transferred |
| `HashRing` | Consistent hashing ring for horizontal scaling |
| `ClusterNode` | Physical node in the cluster |
| `ConsistentRouter` | Routes keys to nodes via hash ring |
| `HashRingBuilder` | Fluent builder for hash ring configuration |

#### Hash Ring Usage (v0.3.0)

```rust
use syn_network::{HashRingBuilder, ClusterNode};

// Build a hash ring for a 3-node cluster
let ring = HashRingBuilder::new()
    .virtual_nodes(150)
    .replication_factor(3)
    .bounded_loads(true)
    .add_node(ClusterNode::new("node-east", "10.0.1.10:9090".parse()?))
    .add_node(ClusterNode::new("node-west", "10.0.2.10:9090".parse()?))
    .add_node(ClusterNode::new("node-central", "10.0.3.10:9090".parse()?))
    .build()?;

// Route a key to its primary node
let primary = ring.get_node_for_key("user:12345")?;

// Get preference list for replication (3 distinct nodes)
let replicas = ring.get_preference_list_bounded(b"user:12345")?;
```

#### Configuration

```rust
let config = QuicConfig {
    max_concurrent_bidi_streams: 100,
    max_concurrent_uni_streams: 100,
    stream_receive_window: 1_000_000,
    idle_timeout_ms: 30_000,
    keep_alive_interval_ms: 10_000,
    allow_insecure: false,  // true for development
};
```

#### ALPN Protocols

Synapse uses ALPN for protocol negotiation:
- `synapse/1` - Primary Synapse protocol
- `h3` - HTTP/3 compatibility

#### Features

- **`quic`**: Quinn QUIC implementation
- **`masque`**: MASQUE tunnel support
- **`hash-ring`**: Consistent hashing for horizontal scaling (v0.3.0)

---

### syn-memory

**Purpose**: Semantic event storage with vector indices, CRDT state, and distributed consensus.

**Design Principle**: Store "Intent" not opaque bytes. Every log segment becomes a vector index. Distributed state via CRDTs and Raft consensus.

#### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Lance Storage Engine                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │   MemTable   │  │  WAL Buffer  │  │    Lance Segments      ││
│  │ (Red-Black)  │  │ (in-memory)  │  │    (.lance files)      ││
│  │   im::OrdMap │  │              │  │                        ││
│  │  O(log n)    │──│  Durability  │──│ Cold storage with      ││
│  │              │  │  guarantee   │  │ IVF-PQ vector index    ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
│         │                                      │                │
│         └──────────────────┬───────────────────┘                │
│                            │                                    │
│                    ┌───────┴───────┐                           │
│                    │ Query Engine  │                           │
│                    │ - Point lookup│                           │
│                    │ - Range scan  │                           │
│                    │ - Vector ANN  │                           │
│                    └───────────────┘                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│               Distributed Consensus (v0.3.0)                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐│
│  │   RaftNode     │◄──▶│   RaftNode     │◄──▶│   RaftNode     ││
│  │   (Leader)     │    │   (Follower)   │    │   (Follower)   ││
│  │                │    │                │    │                ││
│  │  Log Index: N  │    │  Log Index: N  │    │  Log Index: N  ││
│  │  Term: T       │    │  Term: T       │    │  Term: T       ││
│  └────────────────┘    └────────────────┘    └────────────────┘│
│          │                                           │          │
│          └───────────────────┬───────────────────────┘          │
│                              │                                  │
│                    ┌─────────┴─────────┐                       │
│                    │  CrdtSyncProtocol │                       │
│                    │  (P2P Broadcast)   │                       │
│                    └───────────────────┘                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Types

| Type | Description |
|------|-------------|
| `LanceStore` | Main storage engine with semantic search |
| `LanceConfig` | Configuration (data_dir, vector_dimension, etc.) |
| `IntentEvent` | Event with source, action, reason, payload, embedding |
| `SearchResult` | Query result with relevance score |
| `FileEventStore` | Append-only file-based event store |
| `InMemoryEventStore` | In-memory event store for testing |
| `ConsensusProtocol` | LLM-mediated conflict resolution |
| `CrdtBlackboard` | Automerge-based collaborative state (v2.0) |
| `BlackboardConfig` | CRDT configuration (data_dir, agent_id) |
| `Embedder` | Candle ML embedding generator |
| `EmbedderConfig` | Embedding model configuration |
| `RaftNode` | Raft consensus implementation (v0.3.0) |
| `RaftState` | Leader/Follower/Candidate state machine |
| `CrdtSyncProtocol` | P2P CRDT synchronization (v0.3.0) |
| `ReplicationManager` | Manages replication across cluster |

#### IntentEvent Structure

```rust
pub struct IntentEvent {
    pub id: u64,                    // Unique event ID
    pub source: String,             // Agent/process ID
    pub timestamp_us: u64,          // Microseconds since epoch
    pub action: String,             // Action type
    pub reason: String,             // Human-readable intent
    pub payload: String,            // TOON-serialized data
    pub parent_id: Option<u64>,     // Causal parent (for DAG)
    pub embedding: Option<Vec<f32>>, // Vector embedding
    pub tags: Vec<String>,          // Filtering tags
}
```

#### Features

- **`event-sourcing`**: Append-only event log
- **`graph`**: Knowledge graph support
- **`vector`**: Candle embeddings (all-MiniLM-L6-v2, 384 dimensions)
- **`lance`**: Lance-lite columnar storage (no cmake required)
- **`lance-full`**: Production LanceDB with IVF-PQ vector indices
- **`zero-copy`**: Rkyv zero-copy for WASM host-guest data sharing
- **`crdt`**: Automerge CRDT for multi-agent collaboration (v2.0)
- **`distributed`**: Raft consensus and P2P sync (v0.3.0)

#### Embedder

The `Embedder` provides local embedding generation using Candle ML:

```rust
let config = EmbedderConfig::default(); // all-MiniLM-L6-v2
let embedder = Embedder::new(config).await?;
let embedding = embedder.embed("Who modified the auth logic?").await?;
// Returns Vec<f32> with 384 dimensions
```

#### CRDT Blackboard (v2.0)

The `CrdtBlackboard` provides conflict-free collaborative state for multi-agent systems:

```rust
use syn_memory::crdt::{CrdtBlackboard, BlackboardConfig};

// Create a new blackboard
let config = BlackboardConfig {
    data_dir: PathBuf::from("./blackboard"),
    agent_id: "agent-001".to_string(),
};
let blackboard = CrdtBlackboard::new(config).await?;

// Create a document for a task
let doc_id = blackboard.new_document("task-123").await?;

// Set values (conflict-free across agents)
blackboard.set(&doc_id, &["status"], "in_progress").await?;
blackboard.set(&doc_id, &["assignee"], "agent-002").await?;

// Get values
let status: Option<String> = blackboard.get(&doc_id, &["status"]).await?;

// Sync with another agent
let sync_message = blackboard.generate_sync_message(&doc_id).await?;
// Send sync_message to peer...
blackboard.receive_sync_message(&doc_id, &peer_message).await?;

// Persist to disk
blackboard.save_document(&doc_id).await?;
```

**Key Features:**
- **Multi-agent collaboration**: Multiple agents can modify the same document simultaneously
- **Conflict-free merging**: Automerge automatically resolves concurrent edits
- **Persistence**: Documents saved as `.automerge` files for recovery
- **Sync protocol**: Generate and receive sync messages for distributed state

#### Distributed CRDT Sync (v0.3.0)

The `CrdtSyncProtocol` enables peer-to-peer synchronization across nodes:

```rust
use syn_memory::crdt::{CrdtSyncProtocol, ReplicationMode};

// Initialize with the blackboard and network sender
let sync = CrdtSyncProtocol::new(
    blackboard.clone(),
    network_sender,
    ReplicationMode::SemiSync,  // Semi-synchronous replication
);

// Broadcast a change to all peers
sync.broadcast_change(&doc_id, &change).await?;

// Handle incoming sync from a peer
sync.receive_from_peer(peer_id, &sync_message).await?;

// Start the sync protocol (background task)
sync.start().await;
```

**Replication Modes:**
- **Async**: Fire-and-forget, best performance
- **SemiSync**: Wait for at least one replica
- **Sync**: Wait for all replicas (strongest consistency)

#### Raft Consensus (v0.3.0)

The `RaftNode` provides distributed consensus for cluster coordination:

```rust
use syn_memory::consensus::{RaftNode, RaftConfig, RaftCommand};

// Create a Raft node
let config = RaftConfig {
    node_id: "node-east".to_string(),
    peers: vec!["node-west", "node-central"],
    election_timeout_ms: 150..300,
    heartbeat_interval_ms: 50,
};
let raft = RaftNode::new(config);

// Propose a command (will replicate to followers if leader)
raft.propose(RaftCommand::UpdateConfig { 
    key: "policy.timeout".into(), 
    value: "30".into() 
}).await?;

// Handle incoming Raft messages
raft.handle_message(peer_id, message).await?;

// Get current state
let state = raft.state(); // Leader, Follower, or Candidate
```

---

### syn-policy

**Purpose**: Inline governance policies via WebAssembly with hot-reload support.

**Design Principle**: Policies run *inside* the stream, not as external services. Zero-downtime updates via file watching.

#### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Event Stream                                 │
│  ┌─────────┐    ┌─────────────┐    ┌─────────┐                 │
│  │ Ingress │───▶│  Policy VM  │───▶│ Egress  │                 │
│  │ (QUIC)  │    │   (Wasm)    │    │ (Lance) │                 │
│  └─────────┘    └─────────────┘    └─────────┘                 │
│                        │                                        │
│                  ┌─────┴─────┐                                  │
│                  │  Verdict  │                                  │
│                  │  Allow/   │                                  │
│                  │  Deny/    │                                  │
│                  │  Transform│                                  │
│                  └───────────┘                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  Policy Hot-Reload (v0.3.0)                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌────────────┐     ┌────────────┐     ┌────────────────────┐  │
│  │  File      │────▶│  Debounce  │────▶│  Policy Reload     │  │
│  │  Watcher   │     │  (500ms)   │     │  (atomic swap)     │  │
│  └────────────┘     └────────────┘     └────────────────────┘  │
│        │                                        │               │
│        ▼                                        ▼               │
│  ┌────────────┐                          ┌────────────────┐    │
│  │ inotify/   │                          │ Validation &   │    │
│  │ FSEvents   │                          │ Compilation    │    │
│  └────────────┘                          └────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

#### Key Types

| Type | Description |
|------|-------------|
| `PolicyEngine` | Central registry and evaluation engine |
| `PolicyConfig` | Engine configuration (timeout, concurrency) |
| `Policy` | Trait for policy implementations |
| `PolicyMetadata` | Policy info (id, version, priority, timeout) |
| `PolicyContext` | Event context for evaluation |
| `Verdict` | Allow / Deny(reason) / Transform(action) |
| `VerdictReason` | Code + message for denial |
| `TransformAction` | Modify payload, set/remove fields |
| `CedarEngine` | Cedar ABAC policy evaluator (v2.0) |
| `CedarConfig` | Cedar configuration (policies_dir) |
| `AgentContext` | Agent action context for Cedar evaluation |
| `WasmHost` | Wasmtime Component Model host |
| `PolicyWatcher` | File watcher for hot-reload (v0.3.0) |
| `HotReloadConfig` | Hot-reload configuration (debounce, extensions) |

#### Built-in Policies

| Policy | Description |
|--------|-------------|
| `AllowAllPolicy` | Passes all events |
| `DenyAllPolicy` | Blocks all events with reason |
| `ActionFilterPolicy` | Filter by action type |
| `SourceFilterPolicy` | Filter by source prefix |
| `PolicyChain` | Composite policy chain |

#### Verdict Types

```rust
pub enum Verdict {
    Allow,                      // Event proceeds unchanged
    Deny(VerdictReason),       // Event rejected with code/message
    Transform(TransformAction), // Event modified before proceeding
}
```

#### Features

- **`wasm-lite`**: Lightweight native policies (default)
- **`wasm-full`**: Full Wasmtime Component Model with encrypted modules
- **`cedar`**: Cedar ABAC policy engine for fine-grained authorization (v2.0)
- **`hot-reload`**: File watching for zero-downtime policy updates (v0.3.0)

#### Policy Hot-Reload (v0.3.0)

The `PolicyWatcher` enables zero-downtime policy updates:

```rust
use syn_policy::hot_reload::{PolicyWatcherBuilder, HotReloadConfig};
use std::time::Duration;

// Build a policy watcher with custom configuration
let mut watcher = PolicyWatcherBuilder::new()
    .debounce(Duration::from_millis(500))  // Wait after last change
    .extensions(vec![".cedar".to_string()])  // Watch .cedar files
    .recursive(true)  // Watch subdirectories
    .build();

// Start watching with a reload callback
watcher.start(|content, path| {
    println!("Reloading policy: {}", path.display());
    // Validate and apply the new policy
    cedar_engine.load_policies(content)?;
    Ok(())
}).await?;

// Watch a directory
watcher.watch("./policies")?;

// Get statistics
let stats = watcher.stats();
println!("Successful reloads: {}", stats.successful_reloads);
println!("Failed reloads: {}", stats.failed_reloads);
```

**Integration with Cedar:**

```rust
use syn_policy::{CedarPolicy, CedarHotReload};
use std::sync::Arc;

// Create a Cedar policy wrapped in Arc for shared ownership
let policy = Arc::new(CedarPolicy::new()?);
policy.load_policies(SYNAPSE_DEFAULT_POLICIES)?;

// Start watching a directory (policies are auto-reloaded)
let watcher = policy.watch_directory("./policies").await?;
```

**Key Features:**
- **Debounced events**: Multiple rapid saves trigger single reload
- **Atomic swap**: New policies validated before replacing old ones  
- **Error isolation**: Invalid policies don't affect running system
- **Metrics**: Track reload success/failure counts and timestamps

#### Cedar Policy Engine (v2.0)

The `CedarEngine` provides attribute-based access control using AWS Cedar:

```rust
use syn_policy::cedar::{CedarEngine, CedarConfig, AgentContext};

// Create Cedar engine with default Synapse policies
let config = CedarConfig {
    policies_dir: Some(PathBuf::from("./policies")),
    ..Default::default()
};
let engine = CedarEngine::new(config)?;

// Add Synapse default policies (guardrails)
engine.add_default_synapse_policies()?;

// Evaluate an agent action
let context = AgentContext {
    principal: "agent:assistant-001".to_string(),
    action: "synapse:action:write_memory".to_string(),
    resource: "memory:blackboard:task-123".to_string(),
    attributes: HashMap::from([
        ("trust_level".to_string(), "high".to_string()),
        ("source_verified".to_string(), "true".to_string()),
    ]),
};

let decision = engine.evaluate_context(&context)?;
match decision {
    cedar_policy::Decision::Allow => { /* proceed */ }
    cedar_policy::Decision::Deny => { /* reject with reason */ }
}
```

**Cedar Policy Example** (`policies/guardrails.cedar`):

```cedar
// Allow verified agents to write to memory
permit(
    principal,
    action == synapse::action::"write_memory",
    resource
) when {
    principal.trust_level == "high" &&
    context.source_verified == true
};

// Deny external network access for untrusted agents
forbid(
    principal,
    action == synapse::action::"network_request",
    resource
) when {
    principal.trust_level == "low"
};
```

**Key Features:**
- **ABAC (Attribute-Based Access Control)**: Policies based on agent attributes
- **Compile-time validation**: Cedar validates policies at load time
- **Fast evaluation**: Sub-millisecond policy decisions
- **Entity management**: Track agents, resources, and their relationships

#### WasmHost (Environmental Entanglement)

The `WasmHost` implements "Uncopyable" WASM execution:

```rust
let config = WasmHostConfig {
    require_encryption: true,  // Policies must be encrypted
    ..Default::default()
};
let mut host = WasmHost::new(config).await?;

// Encrypted modules can ONLY decrypt on verified hosts
host.load_policy("./policies/security.wasm.enc").await?;

let verdict = host.evaluate(event).await?;
```

#### Encrypted Module Format

```
┌─────────────────────────────────────────┐
│  Magic: "SYNW" (4 bytes)                │
│  Version: u8                            │
│  Nonce: [u8; 12]                        │
│  Ciphertext: AES-256-GCM encrypted WASM │
│  Tag: [u8; 16] (appended by GCM)        │
└─────────────────────────────────────────┘
```

The decryption key is derived from:
1. Sorted TRUSTED_PIDS from eBPF map
2. Machine ID (`/etc/machine-id` or hostname)
3. Optional cluster secret (`SYNAPSE_CLUSTER_SECRET`)

#### WIT Interface (wit/governance.wit)

```wit
interface context-access {
    record search-result { id: u64, source: string, score: f32 }
    search-memory: func(query: string, limit: u32) -> list<search-result>
}

interface network-control {
    enum auth-result { allow, deny, allow-with-audit }
    authorize-connection: func(request: connection-request) -> auth-result
}

interface identity-access {
    is-trusted: func(pid: u32) -> bool
}

world policy-engine {
    import context-access
    import network-control
    import identity-access
    export evaluate-event: func(event: policy-event) -> policy-verdict
}
```

---

### synapse-ebpf

**Purpose**: Kernel-space eBPF programs for Environmental Entanglement.

**Design Principle**: Identity verification at the kernel level - processes must be attested before they can interact with Synapse.

#### Programs

| Program | Hook | Purpose |
|---------|------|--------|
| `task_alloc` | LSM | Track process creation, inherit trust from parent |
| `cgroup_skb_egress` | Cgroup | Filter network traffic from untrusted processes |
| `tcp_connect` | Kprobe | Log connection attempts for audit |

#### Maps

| Map | Type | Purpose |
|-----|------|--------|
| `TRUSTED_PIDS` | HashMap | Set of verified process IDs |
| `EVENTS` | PerfEventArray | Stream events to userspace |

#### Building

```bash
# On Linux (native)
cargo xtask build-ebpf

# On Windows/macOS (via Docker)
cargo xtask build-ebpf  # Automatically uses Docker fallback
```

---

### syn-proxy

**Purpose**: Async proxy server with platform-abstracted networking and v2.0 Agentic Mesh runtime.

**Design Principle**: Hexagonal Architecture with `NetProvider` trait for testability.

#### NetProvider Abstraction

```rust
pub trait NetProvider: Send + Sync {
    type Listener: AsyncRead + AsyncWrite + Send + Unpin;
    type Stream: AsyncRead + AsyncWrite + Send + Unpin;
    
    async fn bind(&self) -> Result<Self::Listener>;
    async fn accept(&self, listener: &mut Self::Listener) -> Result<Self::Stream>;
}
```

#### Platform Implementations

| Platform | Provider | Socket Path |
|----------|----------|-------------|
| Windows | `WindowsProvider` | `\\.\pipe\synapse_ctl` |
| Unix | `UnixProvider` | `/tmp/synapse_ctl.sock` |
| Testing | `MockProvider` | In-memory channels |

#### SynapseNode (v2.0 Agentic Mesh Runtime)

The `SynapseNode` integrates all four planes into a unified runtime:

```rust
use syn_proxy::{SynapseNode, NodeConfig};

let config = NodeConfig {
    bind_addr: "0.0.0.0:4433".parse()?,
    data_dir: PathBuf::from("./synapse_data"),
    require_attestation: true,
    enable_cedar: true,
};

let node = SynapseNode::new(config).await?;

// HyperState provides vector + CRDT memory
let hyper_state = node.hyper_state();

// Store semantic event
hyper_state.store_event(event).await?;

// Update collaborative blackboard
hyper_state.update_blackboard("task-123", "status", "complete").await?;

// Run the event loop (handles QUIC connections, policy evaluation)
node.run().await?;
```

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                        SynapseNode                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    HyperState                            │   │
│  │  ┌───────────────────┐  ┌────────────────────────────┐  │   │
│  │  │  Vector Memory    │  │   CRDT Blackboard          │  │   │
│  │  │  (LanceDB)        │  │   (Automerge)              │  │   │
│  │  │                   │  │                            │  │   │
│  │  │  - Semantic search│  │  - Multi-agent state       │  │   │
│  │  │  - Event history  │  │  - Conflict-free merge     │  │   │
│  │  │  - Embeddings     │  │  - Sync protocol           │  │   │
│  │  └───────────────────┘  └────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────┐  ┌───────┴────────┐  ┌────────────────┐    │
│  │ Identity      │  │ QUIC Server    │  │ Policy Engine  │    │
│  │ Provider      │  │ (Quinn)        │  │ (Cedar/WASM)   │    │
│  │ (eBPF/Mock)   │  │                │  │                │    │
│  └───────────────┘  └────────────────┘  └────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

#### Features

- **`mock-windows`**: Enable mock provider on Windows
- **`agentic-mesh`**: Full v2.0 runtime with all four planes
- **`quic`**: QUIC transport support
- **`memory`**: Event sourcing and storage
- **`policy`**: Cedar/WASM governance engine

---

### syn-cli

**Purpose**: Command-line management interface.

#### Available Commands

| Command | Description |
|---------|-------------|
| `syn up` | Start the proxy daemon |
| `syn status` | Get proxy status |
| `syn reload` | Reload configuration |
| `syn stop` | Graceful shutdown |
| `syn ping` | Check proxy connectivity |
| `syn blame <query>` | Visualize causal chain of agent decisions |

#### Blame Command

The `blame` command performs semantic search across the event store:

```bash
# Search for authentication-related events
syn blame "Who modified the auth logic?" --data-dir ./synapse_events

# With demo data for testing
syn blame "test query" --demo

# Show full payloads
syn blame "deployment" --full --limit 20
```

---

### syn-admin

**Purpose**: Enterprise administration web dashboard for cluster management.

#### Architecture

```
syn-admin/
├── src/
│   ├── main.rs           # Server entrypoint (Axum router)
│   ├── lib.rs            # Module declarations
│   ├── config.rs         # AdminConfig (port, host, env vars)
│   ├── error.rs          # AdminError with IntoResponse
│   ├── state.rs          # AppState with EnterpriseContext
│   ├── handlers.rs       # Page handlers (Askama templates)
│   └── api/              # REST API endpoints
│       ├── health.rs     # Health checks
│       ├── cluster.rs    # Node/metrics management
│       ├── tenants.rs    # Tenant CRUD
│       ├── audit.rs      # Audit log queries
│       ├── backups.rs    # Backup management
│       └── rate_limits.rs # Rate limit config
├── templates/            # Askama HTML templates
│   ├── base.html         # Layout with header/nav
│   ├── dashboard.html    # Overview metrics
│   ├── tenants.html      # Tenant table
│   ├── audit.html        # Audit log viewer
│   ├── backups.html      # Backup list
│   └── settings.html     # Configuration
└── static/               # Static assets
    ├── css/style.css     # Tailwind-inspired styling
    └── js/htmx.min.js    # Dynamic updates
```

#### Running the Admin UI

```bash
# Start with default settings (http://localhost:3000)
cargo run --bin syn-admin

# Custom configuration via environment variables
SYN_ADMIN_PORT=8080 SYN_ADMIN_HOST=0.0.0.0 cargo run --bin syn-admin
```

#### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Liveness/readiness check |
| GET | `/api/cluster/nodes` | List all cluster nodes |
| GET | `/api/cluster/metrics` | Cluster-wide metrics |
| GET | `/api/tenants` | List all tenants |
| POST | `/api/tenants` | Create new tenant |
| GET | `/api/tenants/:id` | Get tenant details |
| DELETE | `/api/tenants/:id` | Delete tenant |
| PUT | `/api/tenants/:id/quota` | Update tenant quota |
| GET | `/api/audit` | List audit entries |
| GET | `/api/audit/export` | Export audit log |
| POST | `/api/audit/verify` | Verify chain integrity |
| GET | `/api/backups` | List recovery points |
| POST | `/api/backups` | Start new backup |
| POST | `/api/backups/:id/restore` | Restore from backup |
| GET | `/api/rate-limits` | Get rate limit config |
| PUT | `/api/rate-limits` | Update rate limits |

#### HTMX Integration

The dashboard uses HTMX for seamless updates without full page reloads:

```html
<!-- Refresh metrics every 5 seconds -->
<div hx-get="/api/cluster/metrics" 
     hx-trigger="every 5s"
     hx-swap="innerHTML">
  Loading metrics...
</div>

<!-- Create tenant with form submission -->
<form hx-post="/api/tenants" hx-target="#tenant-list">
  <input name="name" required>
  <select name="tier">
    <option>Free</option>
    <option>Starter</option>
    <option>Professional</option>
    <option>Enterprise</option>
  </select>
  <button type="submit">Create</button>
</form>
```

---

## Feature Flags

### Workspace-Level Features

| Feature | Crate | Description |
|---------|-------|-------------|
| `toon` | syn-proto | TOON serialization |
| `mcp` | syn-proto | Model Context Protocol |
| `a2a` | syn-proto | Agent-to-Agent protocol |
| `spiffe` | syn-identity | SPIFFE workload API |
| `ebpf` | syn-identity | eBPF programs (Linux) |
| `quic` | syn-network | QUIC transport |
| `masque` | syn-network | MASQUE tunnels |
| `event-sourcing` | syn-memory | Event store |
| `graph` | syn-memory | Knowledge graph |
| `vector` | syn-memory | Vector embeddings |
| `lance` | syn-memory | Lance-lite storage |
| `lance-full` | syn-memory | Production LanceDB (requires cmake) |
| `crdt` | syn-memory | Automerge CRDT blackboard (v2.0) |
| `zero-copy` | syn-memory | Rkyv zero-copy for WASM host-guest |
| `wasm-lite` | syn-policy | Native policies (default) |
| `wasm-full` | syn-policy | Wasmtime Component Model + encrypted modules |
| `cedar` | syn-policy | Cedar ABAC authorization (v2.0) |
| `mock-windows` | syn-proxy | Mock network provider |
| `agentic-mesh` | syn-proxy | Full v2.0 Agentic Mesh runtime |
| `policy` | syn-proxy | Enable Cedar/WASM governance |

### v2.0 Feature Combinations

```bash
# Development (minimal dependencies)
cargo build --workspace

# Full Agentic Mesh (v2.0)
cargo build --workspace --features agentic-mesh

# With Cedar policies
cargo build -p syn-policy --features cedar

# With CRDT blackboard
cargo build -p syn-memory --features crdt

# Production deployment (Linux)
cargo build --workspace --features agentic-mesh,ebpf,lance-full --release
```

---

## Serialization Strategy

### Control Plane (Serde/JSON)

Used for human-readable, debuggable communication:

```rust
// Command serialization
let cmd = ControlCommand::GetStatus;
let json = serde_json::to_string(&cmd)?; // {"GetStatus":null}
```

### Data Plane (Rkyv)

Zero-copy deserialization for high-throughput data:

```rust
// Zero-copy access
let archived = rkyv::access::<ArchivedPacketHeader, _>(&bytes)?;
let flags = archived.flags; // No heap allocation!
```

### LLM Communication (TOON)

Token-efficient format for AI interactions:

```rust
let serializer = ToonSerializer;
let toon = serializer.serialize(&data)?;
// users2{id,name}:
//   1 Alice
//   2 Bob
```

---

## Testing

### Running Tests

```bash
# All workspace tests
cargo test --workspace

# Specific crate
cargo test -p syn-memory --features lance

# With verbose output
cargo test --workspace -- --nocapture

# Specific test
cargo test test_append_and_get
```

### Test Counts

| Crate | Unit Tests | Doc Tests |
|-------|------------|-----------|
| syn-core | 6 | 1 |
| syn-proto | 7 | 1 |
| syn-identity | 21 | 3 |
| syn-network | 0 | 0 |
| syn-memory | 9 | 1 |
| syn-memory (crdt) | 3 | 0 |
| syn-policy | 19 | 1 |
| syn-policy (cedar) | 4 | 0 |
| syn-proxy | 1 | 0 |
| syn-core (uncopyable) | 4 | 0 |
| syn-policy (wasm_host) | 7 | 0 |
| **Total** | **81** | **7** |

---

## Development Guide

### Prerequisites

- Rust 1.75+ (see `rust-toolchain.toml`)
- Windows, Linux, or macOS

### Quick Start

```bash
# Build entire workspace
cargo build --workspace

# Build with v2.0 Agentic Mesh features
cargo build --workspace --features agentic-mesh# Run proxy (mock mode)
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# Check status (another terminal)
cargo run --bin syn -- status
```

### Code Quality

```bash
# Formatting
cargo fmt --check

# Linting (note: unwrap() is denied!)
cargo clippy --workspace -- -D warnings

# Documentation
cargo doc --workspace --no-deps --open
```

### Adding a New Feature

1. Define types in `syn-core` if shared
2. Define protocol in `syn-proto`
3. Implement behind feature flag
4. Add tests with >80% coverage
5. Update documentation

---

## Roadmap

### Phase 1: Foundation ✅
- [x] Workspace scaffolding
- [x] Control plane protocol
- [x] Proxy with NetProvider abstraction
- [x] CLI with basic commands
- [x] Windows mock for cross-platform dev

### Phase 2: Transport ✅
- [x] QUIC transport via Quinn
- [x] Connection pooling (LRU)
- [x] ALPN protocol negotiation
- [x] Connection metadata tracking

### Phase 3: Identity ✅
- [x] eBPF attestation engine
- [x] Binary hash verification
- [x] Allowlist management
- [x] Process verification
- [x] SPIFFE client

### Phase 4: Storage ✅
- [x] Lance columnar storage
- [x] MemTable (Red-Black tree)
- [x] Semantic search
- [x] Causal chain tracking
- [x] Event persistence

### Phase 5: Policy ✅
- [x] Policy engine
- [x] Verdict types
- [x] Built-in policies
- [x] Policy chaining
- [x] Metrics collection

### Phase 6: Uncopyable Infrastructure ✅
- [x] synapse-ebpf kernel programs (task_alloc LSM, cgroup_skb, tcp_connect kprobe)
- [x] xtask build automation with Docker cross-compilation
- [x] IdentityProvider trait with platform abstraction
- [x] LanceDB production storage upgrade
- [x] Candle embedding integration (all-MiniLM-L6-v2)
- [x] WIT interface definitions for WASM Component Model
- [x] Wasmtime SynapseHost with encrypted module support
- [x] UncopyableRuntime orchestration (eBPF→WASM→VectorMemory flow)
- [x] AES-256-GCM encrypted WASM modules with eBPF-derived keys
- [x] Startup cgroup verification

### Phase 7: Agentic Mesh v2.0 ✅
- [x] Automerge CRDT integration (`syn-memory/src/crdt.rs`)
- [x] CrdtBlackboard for multi-agent collaboration
- [x] Cedar ABAC policy engine (`syn-policy/src/cedar.rs`)
- [x] Default Synapse guardrail policies (`policies/guardrails.cedar`)
- [x] SynapseNode integration runtime (`syn-proxy/src/node.rs`)
- [x] HyperState (Vector + CRDT memory fusion)
- [x] MCP/A2A protocol adapter foundations
- [x] Cross-platform identity provider (Mock for Windows/macOS)

### Phase 8: Production ✅
- [x] Distributed CRDT synchronization (`syn-memory/src/crdt.rs` - CrdtSyncProtocol)
- [x] Multi-node clustering with Raft consensus (`syn-memory/src/consensus.rs`)
- [x] Production observability with OpenTelemetry (`syn-core/src/telemetry.rs` - MetricsRegistry)
- [x] Horizontal scaling with consistent hashing (`syn-network/src/hash_ring.rs`)
- [x] Cedar policy hot-reload (`syn-policy/src/hot_reload.rs`)
- [x] CRDT conflict visualization (`syn-cli` - `syn conflicts` command)
- [x] Cluster status monitoring (`syn-cli` - `syn cluster` command)

### Phase 9: Enterprise ✅
- [x] Multi-tenancy with namespace isolation (`syn-core/src/enterprise/tenancy.rs`)
  - TenantManager with tenant lifecycle management
  - Cryptographic namespace isolation
  - Per-tenant resource quotas (CPU, memory, storage, RPS)
  - Tenant tiers (Free, Starter, Professional, Enterprise, Custom)
- [x] Tamper-proof audit logging (`syn-core/src/enterprise/audit.rs`)
  - Cryptographic hash chain (SHA-256)
  - Audit severity levels and categories
  - Retention policies and chain verification
  - Compliance-ready event tracking
- [x] Rate limiting and quotas (`syn-core/src/enterprise/rate_limit.rs`)
  - Token bucket algorithm for burst handling
  - Sliding window for smooth rate limiting
  - Per-tenant and per-user limits
  - Quota management with period reset
- [x] Geographic replication (`syn-core/src/enterprise/geo_replication.rs`)
  - Multi-region data replication
  - Conflict resolution strategies (LWW, merge, custom)
  - Consistency models (eventual, strong, bounded staleness)
  - Region health monitoring and latency tracking
- [x] Backup and disaster recovery (`syn-core/src/enterprise/backup.rs`)
  - Automated backup scheduling (daily, weekly, monthly, cron)
  - Point-in-time recovery with incremental backups
  - Multi-destination storage (Local, S3, Azure Blob, GCS)
  - Retention policies and backup verification
- [x] EnterpriseContext orchestration (`syn-core/src/enterprise/mod.rs`)
  - Unified enterprise feature access
  - Configuration-driven feature enablement
  - Request validation with tenant and rate limit checks

### Phase 10: Admin Web UI ✅
- [x] Server-rendered admin dashboard (`syn-admin` crate)
  - Axum-based async HTTP server
  - Askama type-safe templates
  - HTMX for dynamic updates
  - Tailwind-inspired CSS styling
- [x] REST API endpoints
  - `/api/health` - Cluster health checks
  - `/api/cluster/*` - Node and metrics management
  - `/api/tenants/*` - Tenant CRUD operations
  - `/api/audit/*` - Audit log queries and verification
  - `/api/backups/*` - Backup management and restore
  - `/api/rate-limits/*` - Rate limit configuration
- [x] Dashboard pages
  - Dashboard overview with cluster status
  - Tenant management with quota editing
  - Audit log viewer with chain verification
  - Backup management with point-in-time recovery
  - Settings and configuration
- [x] Enterprise integration
  - Full EnterpriseContext integration
  - Real-time metrics from RateLimiter
  - Tenant management via TenantManager
  - Audit chain verification via AuditChain
  - Backup scheduling via BackupManager

### Phase 11: Cloud & Operations (Planned)
- [ ] Kubernetes Operator for deployment
- [ ] Prometheus/Grafana dashboards
- [ ] Compliance certification (SOC2, GDPR, HIPAA)
- [ ] Performance benchmarking suite
- [ ] SDK generators (Python, TypeScript, Go)

---

## License

MIT OR Apache-2.0

---

*Generated for Synapse v0.4.0 (Enterprise) - December 2025*
