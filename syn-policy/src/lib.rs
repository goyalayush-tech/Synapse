//! # syn-policy
//!
//! WebAssembly-based governance policy engine for Synapse.
//!
//! This crate provides the "Reflexes" layer of Synapse - governance policies
//! that run inline with the event stream as WebAssembly modules.
//!
//! ## Design Philosophy
//!
//! Traditional policy engines operate as external services, adding latency
//! and complexity. Synapse policies run *inside* the stream:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Event Stream                                 │
//! │                                                                  │
//! │   ┌─────────┐    ┌─────────────┐    ┌─────────┐                │
//! │   │ Ingress │───▶│  Policy VM  │───▶│ Egress  │                │
//! │   │ (QUIC)  │    │   (Wasm)    │    │ (Lance) │                │
//! │   └─────────┘    └─────────────┘    └─────────┘                │
//! │                        │                                        │
//! │                  ┌─────┴─────┐                                  │
//! │                  │  Verdict  │                                  │
//! │                  │  Allow/   │                                  │
//! │                  │  Deny/    │                                  │
//! │                  │  Transform│                                  │
//! │                  └───────────┘                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **wasm-full**: Full wasmtime integration with JIT compilation
//! - **wasm-lite**: Lightweight policy engine for testing (default)
//!
//! ## Example
//!
//! ```
//! use syn_policy::{
//!     PolicyEngine, PolicyConfig, Verdict,
//!     policy::{AllowAllPolicy, PolicyContext},
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create policy engine
//! let config = PolicyConfig::default();
//! let engine = PolicyEngine::new(config);
//!
//! // Register a policy
//! engine.register(AllowAllPolicy::new()).await?;
//!
//! // Evaluate an event
//! let ctx = PolicyContext::new(1, "agent-001").with_action("read");
//! let verdict = engine.evaluate("allow-all", &ctx).await?;
//!
//! match verdict {
//!     Verdict::Allow => println!("Event allowed"),
//!     Verdict::Deny(reason) => println!("Denied: {}", reason),
//!     Verdict::Transform(_) => println!("Event transformed"),
//! }
//! # Ok(())
//! # }
//! ```

pub mod engine;
pub mod policy;
pub mod verdict;

// WHY wasm_host: Component Model host for "Uncopyable" WASM governance
// Implements Environmental Entanglement - policies only decrypt on trusted hosts
#[cfg(feature = "wasm-full")]
pub mod wasm_host;

// WHY cedar: Fine-grained authorization using Cedar policy language
// Zero Trust governance - every agent action evaluated against Cedar policies
#[cfg(feature = "cedar")]
pub mod cedar;

// WHY hot_reload: Zero-downtime policy updates via file watching
// Enables atomic policy swaps without broker restart
#[cfg(feature = "hot-reload")]
pub mod hot_reload;

pub use engine::{PolicyConfig, PolicyEngine, PolicyEngineError, PolicyEngineResult};
pub use policy::{Policy, PolicyId, PolicyMetadata};
pub use verdict::{TransformAction, Verdict, VerdictReason};

// Re-export wasm_host types when feature is enabled
//
// `WasmHost` does NOT actually execute WASM policies (see
// `WasmHost::evaluate`, which always fails closed). `ComponentModelHost` is
// the real evaluation path: it actually instantiates and runs the loaded
// WASM component via wasmtime. Callers who need real policy enforcement
// should use `ComponentModelHost`, not `WasmHost`.
#[cfg(feature = "wasm-full")]
pub use wasm_host::{ComponentModelHost, PolicyVerdict, WasmHost, WasmHostConfig, WasmHostError};

// Re-export cedar types when feature is enabled
#[cfg(feature = "cedar")]
pub use cedar::{
    create_default_policy, CedarConfig, CedarEngine, CedarError, CedarPolicy, CedarStats,
    SYNAPSE_CEDAR_SCHEMA, SYNAPSE_DEFAULT_POLICIES,
};

// Re-export hot-reload types when feature is enabled
#[cfg(feature = "hot-reload")]
pub use hot_reload::{
    HotReloadConfig, HotReloadError, HotReloadResult, HotReloadStats, PolicyWatcher,
    PolicyWatcherBuilder,
};

// Re-export Cedar + hot-reload integration
#[cfg(all(feature = "cedar", feature = "hot-reload"))]
pub use hot_reload::cedar_integration::{cedar_reload_callback, CedarHotReload};
