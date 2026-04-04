//! # syn-identity
//!
//! Secure workload identity and attestation for Synapse.
//!
//! This crate provides SPIFFE/SPIRE integration for ephemeral agent identity,
//! enabling zero-trust authentication without static API keys. Each agent/process
//! can obtain short-lived X.509 SVIDs from a SPIRE server, bootstrapping mutual
//! TLS at the kernel level.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         syn-identity                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
//! │  │   SPIFFE    │  │    eBPF     │  │    Attestation          │ │
//! │  │   Client    │  │   Engine    │  │    Provider             │ │
//! │  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
//! │         │                │                     │               │
//! │         │      ┌─────────┴─────────┐          │               │
//! │         │      │                   │          │               │
//! │         ▼      ▼                   ▼          ▼               │
//! │  ┌────────────────┐  ┌───────────────┐  ┌──────────────────┐ │
//! │  │  X.509 SVIDs   │  │   Allowlist   │  │ ProcessAttributes │ │
//! │  │  (mTLS certs)  │  │ (binary hash) │  │  (pid, exe, etc) │ │
//! │  └────────────────┘  └───────────────┘  └──────────────────┘ │
//! │                                                                │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **SPIFFE Integration**: Fetch and manage X.509 SVIDs from SPIRE servers
//! - **Mutual TLS**: Secure connections using SPIFFE-derived certificates
//! - **Process Attestation**: Verify workload identity via eBPF (Linux)
//! - **Ephemeral Identity**: Short-lived certificates for milliseconds-scale agents
//! - **Binary Hash Verification**: Zero-trust based on cryptographic identity
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(feature = "spiffe")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use syn_identity::{SpiffeClient, ToTlsConfig};
//!
//! let client = SpiffeClient::new("spire-server:8081");
//! let identity = client.fetch_svid("spiffe://example.org/workload/agent-1").await?;
//! let tls_config = identity.to_tls_config(true)?; // true = client mode
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "spiffe")]
pub mod spiffe;

#[cfg(feature = "spiffe")]
pub mod tls;

pub mod attestation;
pub mod ebpf;
pub mod provider;

#[cfg(feature = "spiffe")]
pub use spiffe::{SpiffeClient, SpiffeEndpoint, SpiffeError, SpiffeIdentity, SpiffeResult, SpiffeBundle, SpiffeId, ParsedSpiffeId};
#[cfg(feature = "spiffe")]
pub use tls::{TlsConfig, TlsError};
#[cfg(feature = "spiffe")]
pub use tls::ToTlsConfig;

pub use attestation::{AttestationError, AttestationProvider, AttestationResult, ProcessAttributes};
pub use ebpf::{Allowlist, AllowlistEntry, BinaryHash, AttestationVerifier, ProcessInfo, VerificationResult, VerificationDenial};
pub use ebpf::{EbpfAttestationEngine, EbpfConfig, EbpfError, ConnectionEvent, EngineStats};

// Identity Provider trait - the core abstraction for kernel-level attestation
pub use provider::{
    IdentityProvider, IdentityProviderConfig, IdentityProviderError, IdentityProviderResult,
    AttestationEvent, AttestationEventType, ProviderStats, get_identity_provider,
};

