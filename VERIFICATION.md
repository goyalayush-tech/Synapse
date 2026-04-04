# Synapse Verification Guide

This guide shows you how to verify that Synapse is working correctly.

## Quick Verification (5 minutes)

### Step 1: Check Compilation

```bash
# Build the entire workspace
cargo build --workspace

# If successful, you should see:
# "Finished dev [unoptimized + debuginfo] target(s)"
```

**Expected Output:**
```
   Compiling syn-core v0.1.0 (...)
   Compiling syn-proto v0.1.0 (...)
   Compiling syn-proxy v0.1.0 (...)
   Compiling syn-cli v0.1.0 (...)
   Finished dev [unoptimized + debuginfo] target(s)
```

### Step 2: Run Unit Tests

```bash
# Run all tests
cargo test --workspace

# Expected: All tests should pass
```

**Expected Output:**
```
running X tests
test result: ok. X passed; 0 failed; 0 ignored
```

### Step 3: Test Basic Functionality

#### Terminal 1: Start the Proxy (Mock Mode)

```bash
# On Windows (PowerShell)
$env:SYNAPSE_MOCK=1; cargo run --bin syn-proxy

# On Linux/macOS
SYNAPSE_MOCK=1 cargo run --bin syn-proxy
```

**Expected Output:**
```
2024-XX-XX INFO syn_proxy::server: Creating ProxyServer
2024-XX-XX INFO syn_proxy::server: Control plane listening addr="..."
2024-XX-XX INFO syn_proxy::main: Synapse Proxy starting event loop
```

#### Terminal 2: Test CLI Commands

```bash
# Ping the proxy
cargo run --bin syn -- ping

# Check status
cargo run --bin syn -- status

# Expected output for ping:
# ✓ Pong! Proxy is responsive.

# Expected output for status:
# ╔══════════════════════════════════════╗
# ║         SYNAPSE PROXY STATUS         ║
# ╠══════════════════════════════════════╣
# ║ Version:      0.1.0                   ║
# ║ Uptime:       5s                      ║
# ║ Active Conns: 1                       ║
# ║ Total Conns:  1                       ║
# ║ Accepting:    yes                     ║
# ╚══════════════════════════════════════╝
```

## Detailed Verification

### 1. Verify Individual Crates

#### Test syn-core

```bash
cargo test -p syn-core
```

**What to check:**
- SessionId generation works
- PortNumber type works
- Error types are correct

#### Test syn-proto

```bash
cargo test -p syn-proto

# Test with TOON feature
cargo test -p syn-proto --features toon
```

**What to check:**
- Control command serialization/deserialization
- Packet header Rkyv serialization
- TOON parsing (if feature enabled)

#### Test syn-proxy

```bash
cargo test -p syn-proxy

# Test with mock provider
cargo test -p syn-proxy --features mock-windows
```

**What to check:**
- Network provider selection
- Connection handling
- Control command processing

### 2. Verify Feature Flags

#### Test TOON Serialization

```bash
# Build with TOON feature
cargo build -p syn-proto --features toon

# Run the example
cargo run --example toon_serialize --features toon
```

**Expected Output:**
```
TOON format:
users2{id,name}:
  1 Alice
  2 Bob

Parsed schema: ToonSchema { name: "users", row_count: 2, columns: ["id", "name"] }
Parsed rows: [["1", "Alice"], ["2", "Bob"]]
```

#### Test MCP Protocol

```bash
# Build with MCP feature
cargo build -p syn-proto --features mcp

# Run MCP tests
cargo test -p syn-proto --features mcp
```

#### Test A2A Protocol

```bash
# Build with A2A feature
cargo build -p syn-proto --features a2a

# Run A2A tests
cargo test -p syn-proto --features a2a
```

### 3. Verify Network Providers

#### Test Real Network Provider

```bash
# On Windows: Should use Named Pipes
cargo run --bin syn-proxy

# On Linux/macOS: Should use Unix Domain Sockets
cargo run --bin syn-proxy
```

**Check logs for:**
- "Using real network provider"
- Platform-specific socket binding

#### Test Mock Provider

```bash
# Cross-platform mock provider
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# Or with feature flag
cargo run --bin syn-proxy --features mock-windows
```

**Check logs for:**
- "Using MOCK network provider - not for production!"

### 4. Verify Event Sourcing (if enabled)

```bash
# Build with memory feature
cargo build -p syn-proxy --features memory

# Run tests
cargo test -p syn-memory
```

**What to check:**
- Event store append works
- Event replay works
- Snapshot creation works

### 5. Verify Identity Features (if enabled)

```bash
# Build with SPIFFE feature
cargo build -p syn-identity --features spiffe

# Run tests
cargo test -p syn-identity --features spiffe
```

**Note:** Full SPIFFE integration requires a running SPIRE server.

### 6. Verify Network Features (if enabled)

```bash
# Build with QUIC feature
cargo build -p syn-network --features quic

# Run tests
cargo test -p syn-network --features quic
```

**Note:** Full QUIC integration requires Quinn library and proper TLS setup.

## Integration Testing

### End-to-End Test

```bash
# Terminal 1: Start proxy
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# Terminal 2: Run multiple CLI commands
cargo run --bin syn -- ping
cargo run --bin syn -- status
cargo run --bin syn -- reload
cargo run --bin syn -- status
```

**Expected:** All commands should succeed and show appropriate output.

### Stress Test

```bash
# Start proxy
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# In another terminal, run multiple pings
for i in {1..10}; do
    cargo run --bin syn -- ping
    sleep 0.1
done
```

**Expected:** All pings should succeed, connection count should increase.

## Checking Logs

### Enable Verbose Logging

```bash
# Set log level
export RUST_LOG=debug  # Linux/macOS
$env:RUST_LOG="debug"  # Windows PowerShell

# Run proxy
SYNAPSE_MOCK=1 cargo run --bin syn-proxy
```

**What to look for:**
- Connection acceptance logs
- Command processing logs
- Event emission logs (if memory feature enabled)

### Check for Errors

Look for these in logs:
- ❌ "ERROR" level messages
- ❌ "Failed to" messages
- ❌ Panic messages

## Platform-Specific Verification

### Windows

```bash
# Verify Named Pipe support
cargo run --bin syn-proxy
# Should create: \\.\pipe\synapse_ctl

# Test CLI connection
cargo run --bin syn -- ping
```

### Linux/macOS

```bash
# Verify Unix Domain Socket support
cargo run --bin syn-proxy
# Should create: /tmp/synapse_ctl.sock

# Test CLI connection
cargo run --bin syn -- ping
```

## Troubleshooting

### Issue: "Failed to connect to proxy"

**Solutions:**
1. Make sure proxy is running
2. Check socket/pipe permissions
3. Try mock mode: `SYNAPSE_MOCK=1`

### Issue: Compilation Errors

**Solutions:**
1. Update Rust: `rustup update stable`
2. Clean build: `cargo clean && cargo build`
3. Check feature flags match dependencies

### Issue: Tests Fail

**Solutions:**
1. Run tests individually: `cargo test -p <crate-name>`
2. Check feature flags: `cargo test --features <feature>`
3. Check platform compatibility

### Issue: Mock Provider Not Working

**Solutions:**
1. Use environment variable: `SYNAPSE_MOCK=1`
2. Or feature flag: `--features mock-windows`
3. Check both are set correctly

## Performance Verification

### Check Build Time

```bash
# Clean build
cargo clean
time cargo build --workspace --release
```

**Expected:** Should complete in reasonable time (< 5 minutes on modern hardware)

### Check Binary Size

```bash
# Check release binary sizes
ls -lh target/release/syn-proxy
ls -lh target/release/syn
```

**Expected:** Reasonable sizes (< 10MB for release builds)

## Advanced Verification

### Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzz tests
cd tools/fuzz
cargo fuzz run protocol_parse
cargo fuzz run toon_parse
```

### Linting

```bash
# Format check
cargo fmt --check

# Clippy
cargo clippy --workspace -- -D warnings
```

**Expected:** No errors or warnings

### Security Audit

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

**Expected:** No critical vulnerabilities

## Success Criteria

✅ **Project is working if:**

1. ✅ All crates compile without errors
2. ✅ All unit tests pass
3. ✅ Proxy starts and accepts connections
4. ✅ CLI can communicate with proxy
5. ✅ Basic commands (ping, status) work
6. ✅ No critical errors in logs
7. ✅ Cross-platform networking works (or mock mode works)

## Next Steps

Once basic verification passes:

1. **Enable Advanced Features:**
   - Test with `--features quic,spiffe,memory`
   - Verify event sourcing works
   - Test knowledge graph queries

2. **Production Readiness:**
   - Set up SPIRE server for SPIFFE
   - Configure persistent storage
   - Set up monitoring

3. **Development:**
   - Add custom features
   - Extend protocols
   - Integrate with your agents

## Quick Reference

```bash
# Build everything
cargo build --workspace

# Test everything
cargo test --workspace

# Run proxy (mock mode)
SYNAPSE_MOCK=1 cargo run --bin syn-proxy

# Test CLI
cargo run --bin syn -- ping
cargo run --bin syn -- status

# Check logs
RUST_LOG=debug cargo run --bin syn-proxy
```

