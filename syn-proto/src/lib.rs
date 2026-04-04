//! # syn-proto
//!
//! Wire protocol definitions and serialization for the Synapse event ledger.
//!
//! This crate defines the grammar of inter-component communication, implementing
//! a hybrid serialization strategy optimized for different use cases:
//!
//! ## Serialization Strategy
//!
//! | Context       | Technology | Rationale |
//! |---------------|------------|-----------|
//! | Control Plane | Serde/JSON | Human readability, schema flexibility, debugging |
//! | Data Plane    | Rkyv       | Zero-copy, minimal latency, no heap allocation |
//!
//! ## Design Philosophy
//!
//! This crate is intentionally "pure" - it contains no I/O logic and has
//! minimal dependencies. This ensures:
//! - Fast compilation times
//! - Easy fuzz testing
//! - Reuse across all workspace crates
//!
//! ## Example
//!
//! ```
//! use syn_proto::{ControlCommand, PacketHeader, PacketFlags};
//!
//! // Control plane: JSON serialization
//! let cmd = ControlCommand::Reload;
//! let json = serde_json::to_string(&cmd).unwrap();
//!
//! // Data plane: Zero-copy with Rkyv
//! let header = PacketHeader::new(42, 1024, PacketFlags::COMPRESSED);
//! ```

pub mod control;
pub mod data;
pub mod error;

#[cfg(feature = "toon")]
pub mod toon;

#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(feature = "a2a")]
pub mod a2a;

pub mod serde;
pub mod rkyv;

// Re-export primary types
pub use control::{ControlCommand, ControlResponse, MetricsPayload, ProxyStatus};
pub use data::{PacketFlags, PacketHeader, IntentEvent};
pub use error::{ProtoError, ProtoResult};

#[cfg(feature = "toon")]
pub use toon::{ToonError, ToonParser, ToonResult, ToonSchema, ToonSerializer};

#[cfg(feature = "mcp")]
pub use mcp::*;

#[cfg(feature = "a2a")]
pub use a2a::*;
