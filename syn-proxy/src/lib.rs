//! # syn-proxy
//!
//! The asynchronous proxy engine for Synapse - the operational heart of the system.
//!
//! ## Architecture
//!
//! This crate implements the **Hexagonal Architecture** (Ports & Adapters) pattern:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        ProxyServer                          │
//! │  ┌──────────────────────────────────────────────────────┐  │
//! │  │                   Business Logic                      │  │
//! │  │   (Connection handling, protocol dispatch, routing)   │  │
//! │  └────────────────────────┬─────────────────────────────┘  │
//! │                           │                                 │
//! │              ┌────────────┴────────────┐                   │
//! │              │      NetProvider        │ ← Port (Trait)    │
//! │              └────────────┬────────────┘                   │
//! │         ┌─────────────────┼─────────────────┐              │
//! │         ▼                 ▼                 ▼              │
//! │  ┌────────────┐   ┌────────────┐   ┌────────────┐         │
//! │  │ RealNet    │   │ WindowsMock│   │ (Future:   │         │
//! │  │ Provider   │   │ Provider   │   │  eBPF)     │         │
//! │  └────────────┘   └────────────┘   └────────────┘         │
//! │     Adapters                                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## v2.0 Agentic Mesh
//!
//! The `node` module implements the full v2.0 architecture with four planes:
//! - **Shield**: Kernel-anchored identity (eBPF)
//! - **Router**: QUIC transport with MCP/A2A protocols
//! - **State**: LanceDB vectors + Automerge CRDTs
//! - **Judge**: Wasmtime + Cedar policy engine
//!
//! ## Cross-Platform Strategy
//!
//! The `NetProvider` trait abstracts OS-specific networking:
//! - **Windows**: Named Pipes (`\\.\pipe\synapse`)
//! - **Unix**: Unix Domain Sockets (`/tmp/synapse.sock`)
//! - **Mock**: In-memory channels for deterministic testing
//!
//! Enable the `mock-windows` feature or set `SYNAPSE_MOCK=1` to use
//! the mock provider on any platform.

pub mod net;
pub mod server;
pub mod windows;

#[cfg(feature = "agentic-mesh")]
pub mod node;

pub use server::ProxyServer;

#[cfg(feature = "agentic-mesh")]
pub use node::{NodeConfig, NodeMetrics, SynapseNode};

