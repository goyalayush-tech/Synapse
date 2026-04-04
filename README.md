# Synapse

> **The Nervous System for Autonomous Agents**

A distributed semantic event ledger designed to replace Apache Kafka for the Agentic AI economy. Built for machines, not humans.

## Philosophy

Current infrastructure (Kafka, JSON, API Keys) is built for human operators. Synapse is built for autonomous agents that need:

- **Token Efficiency**: No JSON tax on LLM communications
- **Semantic Memory**: Query by intent, not by offset
- **Zero-Trust Identity**: Process attestation, not API keys
- **Sub-millisecond Latency**: Zero-copy everywhere it matters

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SYNAPSE                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │
│   │ syn-cli  │   │syn-proxy │   │syn-proto │   │ syn-core │    │
│   │          │   │          │   │          │   │          │    │
│   │ Commands │──▶│  Server  │──▶│ Protocol │──▶│  Domain  │    │
│   │          │   │          │   │          │   │          │    │
│   └──────────┘   └──────────┘   └──────────┘   └──────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Type | Description |
|-------|------|-------------|
| `syn-core` | Library | Domain types, error handling, telemetry |
| `syn-proto` | Library | Wire protocol (Serde + Rkyv hybrid) |
| `syn-proxy` | Binary | Async proxy engine with `NetProvider` abstraction |
| `syn-cli` | Binary | Management CLI (`syn up`, `syn status`, `syn blame`) |

## Quick Start

```bash
# Build the workspace
cargo build --workspace

# Run the proxy (mock mode for development)
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# In another terminal, check status
cargo run --bin syn -- status

# Or use the ping command
cargo run --bin syn -- ping
```

## Development

### Prerequisites

- Rust 1.75+ (see `rust-toolchain.toml`)
- Windows, Linux, or macOS

### Cross-Platform Development

The proxy uses a **Hexagonal Architecture** with the `NetProvider` trait to abstract platform-specific networking:

- **Windows**: Named Pipes (`\\.\pipe\synapse_ctl`)
- **Unix**: Unix Domain Sockets (`/tmp/synapse_ctl.sock`)
- **Mock**: In-memory channels for testing

Enable mock mode for development:

```bash
# Via environment variable
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# Or via feature flag
cargo run --bin syn-proxy --features mock-windows
```
### Testing

```bash
# Run all tests
cargo test --workspace

# Run with mock provider
cargo test --workspace --features mock-windows
```

### Linting

```bash
# Check formatting
cargo fmt --check

# Run Clippy (note: unwrap() is denied!)
cargo clippy --workspace -- -D warnings
```

## Serialization Strategy

| Context | Format | Why |
|---------|--------|-----|
| Control Plane | Serde/JSON | Human readable, debuggable, schema flexible |
| Data Plane | Rkyv | Zero-copy deserialization, no heap allocation |

## Roadmap

### Phase 1: Foundation (Current)
- [x] Workspace scaffolding
- [x] Control plane protocol
- [x] Proxy with `NetProvider` abstraction
- [x] CLI with basic commands
- [x] Windows mock for cross-platform dev

### Phase 2: Transport
- [ ] QUIC transport via `quinn`
- [ ] Connection multiplexing
- [ ] Backpressure handling

### Phase 3: Identity (Linux)
- [ ] eBPF process attestation via `aya`
- [ ] SPIFFE ID generation
- [ ] X.509 certificate issuance

### Phase 4: Semantic Storage
- [ ] Lance columnar storage
- [ ] IntentEvent indexing
- [ ] Candle embedding generation
- [ ] Semantic query (`syn blame`)

### Phase 5: Policy Engine
- [ ] Wasmtime integration
- [ ] Policy hot-reloading
- [ ] Governance rules

## License

MIT OR Apache-2.0
