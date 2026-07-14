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
//!
//! // NOTE: `to_tls_config` currently ALWAYS returns
//! // `Err(TlsError::NotImplemented)`. This crate does not yet build a real
//! // rustls::ClientConfig/ServerConfig or install a certificate verifier,
//! // so it cannot be used to establish real TLS/mTLS. Wire up rustls (or
//! // another TLS library) directly for real TLS.
//! let tls_config = identity.to_tls_config(true); // true = client mode
//! assert!(tls_config.is_err());
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
pub use spiffe::{
    ParsedSpiffeId, SpiffeBundle, SpiffeClient, SpiffeEndpoint, SpiffeError, SpiffeId,
    SpiffeIdentity, SpiffeResult,
};
#[cfg(feature = "spiffe")]
pub use tls::ToTlsConfig;
#[cfg(feature = "spiffe")]
pub use tls::{TlsConfig, TlsError};

pub use attestation::{
    AttestationError, AttestationProvider, AttestationResult, ProcessAttributes,
};
pub use ebpf::{
    Allowlist, AllowlistEntry, AttestationVerifier, BinaryHash, ProcessInfo, VerificationDenial,
    VerificationResult,
};
pub use ebpf::{ConnectionEvent, EbpfAttestationEngine, EbpfConfig, EbpfError, EngineStats};

// Identity Provider trait - the core abstraction for kernel-level attestation
pub use provider::{
    get_identity_provider, AttestationEvent, AttestationEventType, IdentityProvider,
    IdentityProviderConfig, IdentityProviderError, IdentityProviderResult, ProviderStats,
};
