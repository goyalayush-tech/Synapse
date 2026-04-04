//! SPIFFE (Secure Production Identity Framework for Everyone) integration.
//!
//! SPIFFE provides a standardized way to identify workloads in distributed systems.
//! This module implements client functionality to fetch X.509 SVIDs (SPIFFE Verifiable
//! Identity Documents) from a SPIRE server.
//!
//! ## Architecture
//!
//! The SPIRE Workload API uses a Unix domain socket (Linux) or named pipe (Windows)
//! to provide workload identity attestation. This module provides:
//!
//! - `SpiffeClient`: Connect to SPIRE Workload API and fetch SVIDs
//! - `SpiffeIdentity`: Wrapper around X.509 certificates with SPIFFE metadata
//! - `SpiffeWatcher`: Stream-based watching for certificate rotation
//!
//! ## Example
//!
//! ```no_run
//! use syn_identity::SpiffeClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to local SPIRE agent
//! let client = SpiffeClient::from_env()?;
//!
//! // Fetch the default SVID for this workload
//! let svids = client.fetch_all_svids().await?;
//! for svid in svids {
//!     println!("Got SVID: {}", svid.spiffe_id);
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Default SPIRE agent socket path (Linux).
pub const DEFAULT_UNIX_SOCKET_PATH: &str = "/tmp/spire-agent/public/api.sock";

/// Default SPIRE agent pipe name (Windows).
pub const DEFAULT_WINDOWS_PIPE_NAME: &str = r"\\.\pipe\spire-agent\public\api";

/// Environment variable for SPIRE agent address.
pub const SPIFFE_ENDPOINT_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

/// Errors that can occur during SPIFFE operations.
#[derive(Debug, Error)]
pub enum SpiffeError {
    /// Failed to connect to SPIRE server.
    #[error("Failed to connect to SPIRE server at {endpoint}: {message}")]
    ConnectionFailed {
        /// The endpoint that failed to connect.
        endpoint: String,
        /// Error message.
        message: String,
    },

    /// Failed to fetch SVID from SPIRE server.
    #[error("Failed to fetch SVID: {0}")]
    FetchFailed(String),

    /// Invalid SPIFFE ID format.
    #[error("Invalid SPIFFE ID format: {0}")]
    InvalidSpiffeId(String),

    /// Certificate parsing error.
    #[error("Certificate parsing error: {0}")]
    CertificateError(String),

    /// Certificate expired or not yet valid.
    #[error("Certificate validity error: {0}")]
    ValidityError(String),

    /// Socket path not found.
    #[error("SPIRE agent socket not found at {0}")]
    SocketNotFound(String),

    /// Environment variable error.
    #[error("Environment variable error: {0}")]
    EnvError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(String),

    /// Protocol error.
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

impl From<std::io::Error> for SpiffeError {
    fn from(err: std::io::Error) -> Self {
        SpiffeError::IoError(err.to_string())
    }
}

/// Result type for SPIFFE operations.
pub type SpiffeResult<T> = Result<T, SpiffeError>;

/// SPIFFE identity (SPIFFE ID + X.509 certificate).
#[derive(Debug, Clone)]
pub struct SpiffeIdentity {
    /// The SPIFFE ID (e.g., "spiffe://example.org/workload/agent-1").
    pub spiffe_id: String,
    /// X.509 certificate in DER format.
    pub certificate: Vec<u8>,
    /// Private key in PKCS#8 format.
    pub private_key: Vec<u8>,
    /// Certificate chain (intermediate CAs).
    pub certificate_chain: Vec<Vec<u8>>,
    /// Expiration time of the certificate.
    pub expires_at: SystemTime,
}

impl SpiffeIdentity {
    /// Creates a new SPIFFE identity.
    #[must_use]
    pub fn new(
        spiffe_id: String,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        certificate_chain: Vec<Vec<u8>>,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            spiffe_id,
            certificate,
            private_key,
            certificate_chain,
            expires_at,
        }
    }

    /// Checks if the identity is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Returns the time until expiration.
    #[must_use]
    pub fn time_until_expiration(&self) -> Option<Duration> {
        self.expires_at
            .duration_since(SystemTime::now())
            .ok()
    }

    /// Validates the SPIFFE ID format.
    ///
    /// # Errors
    ///
    /// Returns an error if the SPIFFE ID format is invalid.
    pub fn validate_spiffe_id(spiffe_id: &str) -> SpiffeResult<()> {
        // Basic validation: must start with spiffe://
        if !spiffe_id.starts_with("spiffe://") {
            return Err(SpiffeError::InvalidSpiffeId(
                "SPIFFE ID must start with 'spiffe://'".to_string(),
            ));
        }

        // Must have at least a trust domain
        let parts: Vec<&str> = spiffe_id[9..].split('/').collect();
        if parts.is_empty() || parts[0].is_empty() {
            return Err(SpiffeError::InvalidSpiffeId(
                "SPIFFE ID must include a trust domain".to_string(),
            ));
        }

        Ok(())
    }
}

/// SPIFFE client for fetching SVIDs from a SPIRE server.
///
/// Connects to the SPIRE Workload API via Unix domain socket (Linux)
/// or Named Pipe (Windows) to fetch X.509 SVIDs for workload identity.
///
/// ## Connection Methods
///
/// - **Unix Socket**: `/tmp/spire-agent/public/api.sock`
/// - **Named Pipe**: `\\.\pipe\spire-agent\public\api`
/// - **Environment**: Set `SPIFFE_ENDPOINT_SOCKET` to override
///
/// ## Example
///
/// ```no_run
/// use syn_identity::SpiffeClient;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SpiffeClient::from_env()?;
/// let svids = client.fetch_all_svids().await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "spiffe")]
pub struct SpiffeClient {
    /// SPIRE agent endpoint.
    endpoint: SpiffeEndpoint,
}

/// SPIRE agent endpoint type.
#[cfg(feature = "spiffe")]
#[derive(Debug, Clone)]
pub enum SpiffeEndpoint {
    /// Unix domain socket path.
    UnixSocket(PathBuf),
    /// Windows named pipe.
    NamedPipe(String),
    /// TCP address (for testing/development).
    Tcp(String),
}

#[cfg(feature = "spiffe")]
impl SpiffeClient {
    /// Creates a new SPIFFE client with a Unix socket endpoint.
    #[must_use]
    pub fn with_unix_socket(path: impl Into<PathBuf>) -> Self {
        Self {
            endpoint: SpiffeEndpoint::UnixSocket(path.into()),
        }
    }

    /// Creates a new SPIFFE client with a named pipe endpoint (Windows).
    #[must_use]
    pub fn with_named_pipe(name: impl Into<String>) -> Self {
        Self {
            endpoint: SpiffeEndpoint::NamedPipe(name.into()),
        }
    }

    /// Creates a new SPIFFE client with a TCP endpoint.
    #[must_use]
    pub fn with_tcp(addr: impl Into<String>) -> Self {
        Self {
            endpoint: SpiffeEndpoint::Tcp(addr.into()),
        }
    }

    /// Creates a client from the SPIFFE_ENDPOINT_SOCKET environment variable.
    ///
    /// Falls back to platform-specific defaults if not set.
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is malformed.
    pub fn from_env() -> SpiffeResult<Self> {
        if let Ok(endpoint) = std::env::var(SPIFFE_ENDPOINT_ENV) {
            Self::from_endpoint_string(&endpoint)
        } else {
            // Use platform-specific default
            Ok(Self::default_for_platform())
        }
    }

    /// Creates a client from an endpoint string.
    ///
    /// Formats:
    /// - `unix:///path/to/socket` - Unix domain socket
    /// - `npipe:///pipe/name` - Named pipe (Windows)
    /// - `tcp://host:port` - TCP connection
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint format is invalid.
    pub fn from_endpoint_string(endpoint: &str) -> SpiffeResult<Self> {
        if let Some(path) = endpoint.strip_prefix("unix://") {
            Ok(Self::with_unix_socket(path))
        } else if let Some(pipe) = endpoint.strip_prefix("npipe://") {
            Ok(Self::with_named_pipe(pipe))
        } else if let Some(addr) = endpoint.strip_prefix("tcp://") {
            Ok(Self::with_tcp(addr))
        } else {
            // Assume it's a path
            Ok(Self::with_unix_socket(endpoint))
        }
    }

    /// Returns the default client for the current platform.
    #[must_use]
    pub fn default_for_platform() -> Self {
        #[cfg(windows)]
        {
            Self::with_named_pipe(DEFAULT_WINDOWS_PIPE_NAME)
        }
        #[cfg(not(windows))]
        {
            Self::with_unix_socket(DEFAULT_UNIX_SOCKET_PATH)
        }
    }

    /// Creates a client with the legacy endpoint format.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - SPIRE server endpoint string.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        let endpoint_str = endpoint.into();
        Self::from_endpoint_string(&endpoint_str).unwrap_or_else(|_| {
            Self::with_unix_socket(&endpoint_str)
        })
    }

    /// Fetches an SVID for the given SPIFFE ID.
    ///
    /// Note: The SPIRE Workload API typically returns all SVIDs for the workload,
    /// not for a specific SPIFFE ID. This method fetches all and filters.
    ///
    /// # Errors
    ///
    /// Returns an error if the fetch fails or the SPIFFE ID is not found.
    pub async fn fetch_svid(&self, spiffe_id: &str) -> SpiffeResult<SpiffeIdentity> {
        SpiffeIdentity::validate_spiffe_id(spiffe_id)?;

        let svids = self.fetch_all_svids().await?;
        svids
            .into_iter()
            .find(|s| s.spiffe_id == spiffe_id)
            .ok_or_else(|| SpiffeError::FetchFailed(format!(
                "SVID not found for SPIFFE ID: {spiffe_id}"
            )))
    }

    /// Fetches all available SVIDs for the current workload.
    ///
    /// This connects to the SPIRE Workload API and fetches all X.509 SVIDs
    /// that the workload is entitled to.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or fetch fails.
    pub async fn fetch_all_svids(&self) -> SpiffeResult<Vec<SpiffeIdentity>> {
        // Connect to SPIRE agent
        let response = self.call_workload_api().await?;
        
        // Parse response
        self.parse_svid_response(&response)
    }

    /// Calls the SPIRE Workload API.
    async fn call_workload_api(&self) -> SpiffeResult<Vec<u8>> {
        match &self.endpoint {
            SpiffeEndpoint::UnixSocket(path) => {
                self.call_via_unix_socket(path).await
            }
            SpiffeEndpoint::NamedPipe(name) => {
                self.call_via_named_pipe(name).await
            }
            SpiffeEndpoint::Tcp(addr) => {
                self.call_via_tcp(addr).await
            }
        }
    }

    /// Calls SPIRE via Unix domain socket.
    #[cfg(unix)]
    async fn call_via_unix_socket(&self, path: &PathBuf) -> SpiffeResult<Vec<u8>> {
        use tokio::net::UnixStream;

        if !path.exists() {
            return Err(SpiffeError::SocketNotFound(
                path.display().to_string()
            ));
        }

        let mut stream = UnixStream::connect(path).await.map_err(|e| {
            SpiffeError::ConnectionFailed {
                endpoint: path.display().to_string(),
                message: e.to_string(),
            }
        })?;

        // Send gRPC request for FetchX509SVID
        // Note: In production, this would use proper gRPC framing
        let request = self.build_fetch_request();
        stream.write_all(&request).await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        Ok(response)
    }

    /// Stub for Unix socket on Windows.
    #[cfg(not(unix))]
    async fn call_via_unix_socket(&self, path: &PathBuf) -> SpiffeResult<Vec<u8>> {
        Err(SpiffeError::ConnectionFailed {
            endpoint: path.display().to_string(),
            message: "Unix sockets are not supported on Windows".to_string(),
        })
    }

    /// Calls SPIRE via Windows named pipe.
    #[cfg(windows)]
    async fn call_via_named_pipe(&self, name: &str) -> SpiffeResult<Vec<u8>> {
        // Windows named pipe implementation
        // In production, use tokio::net::windows::named_pipe
        Err(SpiffeError::ConnectionFailed {
            endpoint: name.to_string(),
            message: "Named pipe support requires tokio windows features".to_string(),
        })
    }

    /// Stub for named pipe on non-Windows.
    #[cfg(not(windows))]
    async fn call_via_named_pipe(&self, name: &str) -> SpiffeResult<Vec<u8>> {
        Err(SpiffeError::ConnectionFailed {
            endpoint: name.to_string(),
            message: "Named pipes are only supported on Windows".to_string(),
        })
    }

    /// Calls SPIRE via TCP (for development/testing).
    async fn call_via_tcp(&self, addr: &str) -> SpiffeResult<Vec<u8>> {
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(addr).await.map_err(|e| {
            SpiffeError::ConnectionFailed {
                endpoint: addr.to_string(),
                message: e.to_string(),
            }
        })?;

        let request = self.build_fetch_request();
        stream.write_all(&request).await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        Ok(response)
    }

    /// Builds the gRPC request for FetchX509SVID.
    fn build_fetch_request(&self) -> Vec<u8> {
        // Simplified request - in production use proper protobuf encoding
        // The SPIRE Workload API uses gRPC with the following service:
        // service SpiffeWorkloadAPI {
        //   rpc FetchX509SVID(X509SVIDRequest) returns (stream X509SVIDResponse);
        // }
        Vec::new()
    }

    /// Parses the SVID response from the Workload API.
    fn parse_svid_response(&self, _response: &[u8]) -> SpiffeResult<Vec<SpiffeIdentity>> {
        // In production, parse the protobuf response
        // The response contains:
        // - svids: list of X509SVID messages
        //   - spiffe_id: string
        //   - x509_svid: bytes (DER-encoded certificate)
        //   - x509_svid_key: bytes (PKCS#8 private key)
        //   - bundle: bytes (trust bundle)
        
        // For now, return empty - real implementation needs protobuf
        tracing::warn!(
            "SPIRE Workload API integration requires protobuf. \
             Install spiffe-rs crate for full support."
        );
        
        Err(SpiffeError::ProtocolError(
            "Protobuf parsing not implemented. Use spiffe-rs crate for production.".to_string()
        ))
    }

    /// Returns the endpoint configuration.
    #[must_use]
    pub fn endpoint(&self) -> &SpiffeEndpoint {
        &self.endpoint
    }
}

/// SPIFFE bundle (trust bundle for certificate validation).
#[derive(Debug, Clone)]
pub struct SpiffeBundle {
    /// Trust domain this bundle is for.
    pub trust_domain: String,
    /// Root CA certificates (DER-encoded).
    pub root_cas: Vec<Vec<u8>>,
}

impl SpiffeBundle {
    /// Creates a new SPIFFE bundle.
    #[must_use]
    pub fn new(trust_domain: impl Into<String>, root_cas: Vec<Vec<u8>>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            root_cas,
        }
    }
}

/// SPIFFE ID parser and validator.
pub struct SpiffeId;

impl SpiffeId {
    /// Parses and validates a SPIFFE ID string.
    ///
    /// Format: `spiffe://<trust-domain>/<path>`
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid.
    pub fn parse(spiffe_id: &str) -> SpiffeResult<ParsedSpiffeId> {
        SpiffeIdentity::validate_spiffe_id(spiffe_id)?;

        let without_prefix = &spiffe_id[9..]; // Remove "spiffe://"
        let parts: Vec<&str> = without_prefix.split('/').collect();

        if parts.is_empty() {
            return Err(SpiffeError::InvalidSpiffeId(
                "SPIFFE ID must include a trust domain".to_string(),
            ));
        }

        let trust_domain = parts[0].to_string();
        let path = if parts.len() > 1 {
            Some(parts[1..].join("/"))
        } else {
            None
        };

        Ok(ParsedSpiffeId {
            trust_domain,
            path,
            full_id: spiffe_id.to_string(),
        })
    }
}

/// Parsed SPIFFE ID components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpiffeId {
    /// Trust domain (e.g., "example.org").
    pub trust_domain: String,
    /// Optional path component.
    pub path: Option<String>,
    /// Full SPIFFE ID string.
    pub full_id: String,
}

impl ParsedSpiffeId {
    /// Returns the full SPIFFE ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_spiffe_id_valid() {
        assert!(SpiffeIdentity::validate_spiffe_id("spiffe://example.org/workload/agent-1").is_ok());
        assert!(SpiffeIdentity::validate_spiffe_id("spiffe://trust.domain/path/to/workload").is_ok());
    }

    #[test]
    fn validate_spiffe_id_invalid() {
        assert!(SpiffeIdentity::validate_spiffe_id("http://example.org").is_err());
        assert!(SpiffeIdentity::validate_spiffe_id("spiffe://").is_err());
        assert!(SpiffeIdentity::validate_spiffe_id("not-a-spiffe-id").is_err());
    }

    #[test]
    fn parse_spiffe_id() {
        let parsed = SpiffeId::parse("spiffe://example.org/workload/agent-1").expect("valid spiffe id");
        assert_eq!(parsed.trust_domain, "example.org");
        assert_eq!(parsed.path, Some("workload/agent-1".to_string()));
    }

    #[test]
    fn parse_spiffe_id_no_path() {
        let parsed = SpiffeId::parse("spiffe://example.org").expect("valid spiffe id");
        assert_eq!(parsed.trust_domain, "example.org");
        assert_eq!(parsed.path, None);
    }

    #[test]
    fn spiffe_identity_expiration() {
        let future = SystemTime::now() + Duration::from_secs(3600);
        let past = SystemTime::now() - Duration::from_secs(1);

        let valid = SpiffeIdentity::new(
            "spiffe://test.org/workload".to_string(),
            vec![],
            vec![],
            vec![],
            future,
        );
        assert!(!valid.is_expired());
        assert!(valid.time_until_expiration().is_some());

        let expired = SpiffeIdentity::new(
            "spiffe://test.org/workload".to_string(),
            vec![],
            vec![],
            vec![],
            past,
        );
        assert!(expired.is_expired());
        assert!(expired.time_until_expiration().is_none());
    }

    #[test]
    fn spiffe_bundle_creation() {
        let bundle = SpiffeBundle::new("example.org", vec![vec![1, 2, 3]]);
        assert_eq!(bundle.trust_domain, "example.org");
        assert_eq!(bundle.root_cas.len(), 1);
    }

    #[cfg(feature = "spiffe")]
    #[test]
    fn spiffe_client_from_endpoint_string() {
        let unix = SpiffeClient::from_endpoint_string("unix:///tmp/spire.sock")
            .expect("valid unix endpoint");
        assert!(matches!(unix.endpoint(), SpiffeEndpoint::UnixSocket(_)));

        let tcp = SpiffeClient::from_endpoint_string("tcp://localhost:8081")
            .expect("valid tcp endpoint");
        assert!(matches!(tcp.endpoint(), SpiffeEndpoint::Tcp(_)));

        let npipe = SpiffeClient::from_endpoint_string("npipe:///pipe/test")
            .expect("valid npipe endpoint");
        assert!(matches!(npipe.endpoint(), SpiffeEndpoint::NamedPipe(_)));
    }

    #[cfg(feature = "spiffe")]
    #[test]
    fn spiffe_client_default() {
        let client = SpiffeClient::default_for_platform();
        #[cfg(windows)]
        assert!(matches!(client.endpoint(), SpiffeEndpoint::NamedPipe(_)));
        #[cfg(not(windows))]
        assert!(matches!(client.endpoint(), SpiffeEndpoint::UnixSocket(_)));
    }
}

