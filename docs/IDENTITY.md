# Identity & Security

This document describes the identity and security architecture of Synapse, focusing on SPIFFE/SPIRE integration and eBPF attestation.

## SPIFFE Integration

SPIFFE (Secure Production Identity Framework for Everyone) provides a standardized way to identify workloads in distributed systems.

### Architecture

```
┌─────────────┐
│ SPIRE Server│───Issues SVIDs───┐
└─────────────┘                   │
                                  ▼
                          ┌──────────────┐
                          │ syn-identity │
                          └──────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
            ┌──────────┐   ┌──────────┐   ┌──────────┐
            │ syn-proxy│   │ syn-cli  │   │  Agents  │
            └──────────┘   └──────────┘   └──────────┘
```

### SPIFFE IDs

SPIFFE IDs follow the format: `spiffe://<trust-domain>/<path>`

Example: `spiffe://example.org/workload/agent-1`

### SVID Management

SVIDs (SPIFFE Verifiable Identity Documents) are short-lived X.509 certificates:

- **Lifetime**: Typically minutes to hours
- **Renewal**: Automatic via SPIRE Workload API
- **Storage**: In-memory, never persisted

### Usage

```rust
use syn_identity::{SpiffeClient, ToTlsConfig};

// Create SPIFFE client
let client = SpiffeClient::new("spire-server:8081").await?;

// Fetch SVID
let identity = client.fetch_svid("spiffe://example.org/workload/agent-1").await?;

// Create TLS configuration
let tls_config = identity.to_tls_config(true)?; // true = client mode
```

## Mutual TLS

All connections use mutual TLS with SPIFFE identities:

1. Client presents SPIFFE SVID
2. Server verifies SPIFFE ID against policy
3. Server presents its own SVID
4. Client verifies server identity

## Process Attestation

On Linux, eBPF can verify process attributes:

- **Executable path**: Verify the process is running the expected binary
- **Command line**: Verify process arguments
- **Parent process**: Verify process hierarchy

### eBPF Programs

- **XDP**: Packet filtering and counting
- **kProbe**: Function latency measurement
- **Tracepoints**: Process lifecycle tracking

## Security Benefits

1. **No Static Secrets**: All identity is ephemeral
2. **Automatic Rotation**: SVIDs expire and renew automatically
3. **Kernel-Level Verification**: eBPF provides strong guarantees
4. **Zero-Trust**: Every connection is authenticated

## Configuration

Enable SPIFFE support via feature flag:

```toml
[dependencies]
syn-identity = { path = "../syn-identity", features = ["spiffe"] }
syn-proxy = { path = "../syn-proxy", features = ["spiffe"] }
```

## SPIRE Server Setup

Synapse requires a running SPIRE server. See the [SPIRE documentation](https://spiffe.io/docs/latest/spire/) for setup instructions.

