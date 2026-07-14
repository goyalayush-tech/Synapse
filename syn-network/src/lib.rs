//! # syn-network
//!
//! Advanced network transport and protocol adapters for Synapse.
//!
//! This crate provides:
//! - QUIC transport via Quinn for high-performance, multiplexed connections
//! - Protocol adapters for MCP/A2A (gRPC, HTTP/3)
//! - MASQUE tunnel support for secure proxying
//! - Consistent hashing ring for horizontal scaling
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        syn-network                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐   │
//! │  │ QUIC Module  │  │ Protocol      │  │ MASQUE Tunnel      │   │
//! │  │              │  │ Adapters      │  │                    │   │
//! │  │ • Server     │  │ • gRPC        │  │ • UDP-over-QUIC    │   │
//! │  │ • Client     │  │ • HTTP/3      │  │ • TCP-over-QUIC    │   │
//! │  │ • Pool       │  │ • WebSocket   │  │ • IP-over-QUIC     │   │
//! │  └──────────────┘  └───────────────┘  └────────────────────┘   │
//! │  ┌────────────────────────────────────────────────────────┐    │
//! │  │                 Hash Ring (Consistent Hashing)          │    │
//! │  │  • Virtual Nodes    • Bounded Loads    • Rack-Aware    │    │
//! │  └────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **QUIC Transport**: Next-generation transport protocol with built-in encryption
//! - **Connection Pooling**: Reuse expensive QUIC connections
//! - **Protocol Adapters**: Bridge between different agent protocols
//! - **Connection Multiplexing**: Multiple streams over a single connection
//! - **MASQUE Tunnels**: Secure proxy tunnels over QUIC
//! - **Consistent Hashing**: Horizontal scaling with minimal data movement

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "quic")]
pub mod adapters;

#[cfg(feature = "masque")]
pub mod masque;

#[cfg(feature = "hash-ring")]
pub mod hash_ring;

#[cfg(feature = "quic")]
pub use quic::{
    QuicBiStream, QuicClient, QuicConfig, QuicConnection, QuicError, QuicRecvStream, QuicResult,
    QuicSendStream, QuicServer, TlsCerts,
};

#[cfg(feature = "quic")]
pub use quic::{ConnectionPool, PoolStats};

#[cfg(feature = "quic")]
pub use adapters::{AdapterError, ProtocolAdapter};

#[cfg(feature = "masque")]
pub use masque::{MasqueError, MasqueTunnel};

#[cfg(feature = "hash-ring")]
pub use hash_ring::{
    ClusterNode, ConsistentRouter, HashRing, HashRingBuilder, HashRingConfig, HashRingError,
    HashRingResult, HashRingStats,
};
