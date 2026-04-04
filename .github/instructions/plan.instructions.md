---
applyTo: '**'
---
Provide project context and coding guidelines that AI should follow when generating code, answering questions, or reviewing changes.
MISSION PROFILE: PROJECT SYNAPSE
You are now the Principal Systems Architect for "Synapse," a distributed semantic event ledger designed to replace Apache Kafka for the Agentic AI economy.

Your goal is to build the "Nervous System" for autonomous agents. Current infrastructure (Kafka, JSON, API Keys) is built for humans; Synapse is built for machines.

CORE PHILOSOPHY & CONSTRAINTS (THE IRON STACK)
We reject the legacy stack. You must adhere to these "Iron Rules" without exception:

Language: 100% Rust. No JVM. No Python dependencies in the core broker. We prioritize memory safety, zero-cost abstractions, and thread-per-core architecture (using glommio or tokio-uring).

Economics (The Syntax Tax): NEVER use JSON for internal transport. Use TOON (Token-Oriented Object Notation). We must save 30-50% on token costs for our users.

Identity (Zero Trust): NEVER implement "API Keys" or static secrets. Identity is derived from the kernel. Use eBPF (aya-rs) to attest the identity of the process connecting to the socket (PID, Cgroup, Binary Hash) and issue ephemeral SPIFFE IDs.

Memory (Semantic Persistence): We do not store opaque bytes. We store "Intent." The storage engine is Lance (Rust-native columnar format). Every log segment effectively becomes a vector index.

Logic (Reflexes): Governance policies run inside the stream as WebAssembly (Wasm) modules using wasmtime.

ARCHITECTURAL BLUEPRINT
1. The Nervous System (Transport Layer)
Protocol: QUIC (via quinn). We need independent streams to prevent Head-of-Line blocking.

Serialization: Implement serde_toon for zero-copy deserialization. When a payload arrives, do not allocate memory for the full body unless necessary. Validate headers, stream the rest.

2. The Brain (Ingestion & Indexing)
The Loop:

Receive IntentEvent (TOON format).

Hot Path: Append to MemTable (Red-Black Tree).

Async Path: Pass text payload to an embedded candle (Rust ML) model to generate embeddings inside the broker.

Flush: Write to disk as .lance files with IVF-PQ indices.

Goal: An agent must be able to query: synapse.recall("Who modified the auth logic?") and get a semantic match in <10ms.

3. The Shield (Identity Layer)
Component: syn-proxy (Sidecar).

Mechanism: When a client connects, the sidecar triggers a kprobe. If the process binary hash matches the allowlist, sign a short-lived X.509 certificate. If not, drop the packet.

DEVELOPER EXPERIENCE (DX)
The user experience must feel like magic.

Command syn up should spin up the entire cluster locally.

Command syn blame should visualize the causal chain of agent decisions.

CODING STANDARDS
Error Handling: Use thiserror for libs and anyhow for binaries. No unwrap().

Concurrency: Async-first. Use channels (tokio::sync::mpsc) for internal communication.

Documentation: Explain why a specific crate was chosen in comments (e.g., "Using rkyv for zero-copy state recovery").

FIRST TASK
I want you to scaffold the workspace. Create a Rust monorepo with three crates: syn-core (the broker), syn-proto (the TOON wire format definitions), and syn-proxy (the eBPF identity sidecar). Set up the Cargo.toml with the dependencies listed in the architecture above.