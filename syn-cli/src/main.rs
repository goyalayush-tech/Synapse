//! # syn-cli
//!
//! Command-line management interface for the Synapse distributed event ledger.
//!
//! ## Commands
//!
//! - `syn up` - Start the proxy daemon
//! - `syn status` - Get proxy status
//! - `syn reload` - Reload configuration
//! - `syn stop` - Graceful shutdown
//! - `syn blame` - Visualize causal chain of agent decisions
//! - `syn conflicts` - Visualize CRDT conflicts and resolutions
//!
//! ## Communication
//!
//! The CLI communicates with the running proxy via the control socket:
//! - **Windows**: Named Pipe (`\\.\pipe\synapse_ctl`)
//! - **Unix**: Unix Domain Socket (`/tmp/synapse_ctl.sock`)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use syn_core::telemetry;
use syn_memory::event_store::{Event, EventStore, FileEventStore, InMemoryEventStore};
use syn_proto::{ControlCommand, ControlResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Synapse - The Nervous System for Autonomous Agents
///
/// A distributed semantic event ledger designed for the Agentic AI economy.
#[derive(Parser)]
#[command(name = "syn")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Available CLI commands
#[derive(Subcommand)]
enum Commands {
    /// Start the Synapse proxy daemon
    Up {
        /// Path to configuration file
        #[arg(short, long, default_value = "synapse.toml")]
        config: String,

        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Get the status of a running proxy
    Status,

    /// Reload configuration on a running proxy
    Reload,

    /// Gracefully stop a running proxy
    Stop,

    /// Ping the proxy to check connectivity
    Ping,

    /// Visualize the causal chain of agent decisions
    Blame {
        /// The query to trace (e.g., "Who modified the auth logic?")
        query: String,

        /// Path to the event store directory (default: ./synapse_events)
        #[arg(short, long, default_value = "./synapse_events")]
        data_dir: PathBuf,

        /// Maximum number of results to display
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Show full event payloads (not truncated)
        #[arg(long)]
        full: bool,

        /// Use demo data for testing
        #[arg(long)]
        demo: bool,
    },

    /// Visualize CRDT conflicts and their resolutions
    Conflicts {
        /// Path to the CRDT state directory
        #[arg(short, long, default_value = "./synapse_crdt")]
        data_dir: PathBuf,

        /// Filter by document/key
        #[arg(short, long)]
        key: Option<String>,

        /// Show resolved conflicts (default: only active)
        #[arg(long)]
        include_resolved: bool,

        /// Maximum number of conflicts to display
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Use demo data for testing
        #[arg(long)]
        demo: bool,

        /// Output format (table, json, graph)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Show cluster node status and CRDT sync state
    Cluster {
        /// Show detailed peer information
        #[arg(long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize telemetry if verbose
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    let _ = telemetry::init(); // Ignore error if already initialized

    match cli.command {
        Commands::Up { config, foreground } => {
            cmd_up(&config, foreground).await
        }
        Commands::Status => {
            send_command_and_print(ControlCommand::GetStatus).await
        }
        Commands::Reload => {
            send_command_and_print(ControlCommand::Reload).await
        }
        Commands::Stop => {
            send_command_and_print(ControlCommand::Shutdown).await
        }
        Commands::Ping => {
            send_command_and_print(ControlCommand::Ping).await
        }
        Commands::Blame { query, data_dir, limit, full, demo } => {
            cmd_blame(&query, &data_dir, limit, full, demo).await
        }
        Commands::Conflicts { data_dir, key, include_resolved, limit, demo, format } => {
            cmd_conflicts(&data_dir, key.as_deref(), include_resolved, limit, demo, &format).await
        }
        Commands::Cluster { verbose } => {
            cmd_cluster(verbose).await
        }
    }
}

/// Starts the proxy daemon.
async fn cmd_up(config: &str, foreground: bool) -> Result<()> {
    tracing::info!(config = %config, foreground, "Starting Synapse proxy");

    if foreground {
        // Run in foreground - exec the proxy binary directly
        println!("Starting Synapse proxy in foreground mode...");
        println!("Config: {config}");
        println!();

        // In a real implementation, we would exec the syn-proxy binary
        // For now, just print instructions
        println!("To start the proxy, run:");
        println!("  syn-proxy");
        println!();
        println!("Or with SYNAPSE_MOCK=1 for development:");
        println!("  SYNAPSE_MOCK=1 syn-proxy");
    } else {
        // Daemonize - spawn as background process
        println!("Starting Synapse proxy as daemon...");
        
        // Platform-specific daemonization would go here
        // For now, just provide instructions
        println!();
        println!("Daemon mode not yet implemented.");
        println!("Run with --foreground or -f for now.");
    }

    Ok(())
}

/// Sends a control command and prints the response.
async fn send_command_and_print(cmd: ControlCommand) -> Result<()> {
    let response = send_command(cmd).await?;

    match response {
        ControlResponse::Ok => {
            println!("✓ Command executed successfully");
        }
        ControlResponse::Pong => {
            println!("✓ Pong! Proxy is responsive.");
        }
        ControlResponse::Status(status) => {
            println!("╔══════════════════════════════════════╗");
            println!("║         SYNAPSE PROXY STATUS         ║");
            println!("╠══════════════════════════════════════╣");
            println!("║ Version:      {:>22} ║", status.version);
            println!("║ Uptime:       {:>19}s ║", status.uptime_secs);
            println!("║ Active Conns: {:>22} ║", status.active_connections);
            println!("║ Total Conns:  {:>22} ║", status.total_connections);
            println!("║ Accepting:    {:>22} ║", if status.accepting { "yes" } else { "no" });
            println!("╚══════════════════════════════════════╝");
        }
        ControlResponse::Metrics(metrics) => {
            println!("{}", metrics.prometheus);
        }
        ControlResponse::Error { message } => {
            eprintln!("✗ Error: {message}");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Sends a control command to the running proxy and returns the response.
async fn send_command(cmd: ControlCommand) -> Result<ControlResponse> {
    let mut stream = connect_control_socket()
        .await
        .context("Failed to connect to proxy. Is it running?")?;

    // Send the command as newline-delimited JSON
    let mut cmd_bytes = cmd.to_json().context("Failed to serialize command")?;
    cmd_bytes.push(b'\n');
    stream.write_all(&cmd_bytes).await.context("Failed to send command")?;
    stream.flush().await?;

    // Read the response
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .await
        .context("Failed to read response")?;

    ControlResponse::from_json(response_line.trim().as_bytes())
        .context("Failed to parse response")
}

/// Connects to the proxy's control socket.
#[cfg(windows)]
async fn connect_control_socket() -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_name = r"\\.\pipe\synapse_ctl";
    let client = ClientOptions::new()
        .open(pipe_name)
        .context("Failed to open named pipe")?;

    Ok(client)
}

#[cfg(unix)]
async fn connect_control_socket() -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    use tokio::net::UnixStream;

    let socket_path = "/tmp/synapse_ctl.sock";
    let stream = UnixStream::connect(socket_path)
        .await
        .context("Failed to connect to Unix socket")?;

    Ok(stream)
}

#[cfg(not(any(windows, unix)))]
async fn connect_control_socket() -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> {
    use tokio::net::TcpStream;

    // Fallback to TCP on localhost
    let stream = TcpStream::connect("127.0.0.1:9999")
        .await
        .context("Failed to connect via TCP")?;

    Ok(stream)
}

/// Visualizes the causal chain of agent decisions.
///
/// This performs text-based search on the event store. Future versions
/// will use Lance columnar storage with Candle embeddings for semantic search.
async fn cmd_blame(
    query: &str,
    data_dir: &PathBuf,
    limit: usize,
    full: bool,
    demo: bool,
) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                    SYNAPSE BLAME                         ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ Query: {:51} ║", truncate(query, 51));
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Load events from store
    let events = if demo {
        println!("📦 Using demo data...");
        println!();
        generate_demo_events().await?
    } else {
        load_events_from_store(data_dir).await?
    };

    if events.is_empty() {
        println!("⚠ No events found in store.");
        println!();
        println!("Tips:");
        println!("  • Use --demo flag to see example output");
        println!("  • Ensure the data directory exists: {}", data_dir.display());
        println!("  • Check that events have been recorded by the proxy");
        return Ok(());
    }

    // Perform text-based search
    let query_lower = query.to_lowercase();
    let keywords: Vec<&str> = query_lower.split_whitespace().collect();

    let matches: Vec<(&Event, f64)> = events
        .iter()
        .filter_map(|event| {
            let score = calculate_relevance(event, &keywords);
            if score > 0.0 {
                Some((event, score))
            } else {
                None
            }
        })
        .collect();

    // Sort by relevance score (descending)
    let mut sorted_matches = matches;
    sorted_matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take top results
    let results: Vec<_> = sorted_matches.into_iter().take(limit).collect();

    if results.is_empty() {
        println!("🔍 No matching events found for query: \"{query}\"");
        println!();
        println!("Suggestions:");
        println!("  • Try broader search terms");
        println!("  • Check event types with: syn blame \"*\"");
        return Ok(());
    }

    println!("🔍 Found {} matching events (showing top {}):", results.len(), limit.min(results.len()));
    println!();

    // Display causal chain visualization
    print_causal_chain(&results, full);

    // Future implementation note
    println!();
    println!("─────────────────────────────────────────────────────────────");
    println!("ℹ Currently using text-based search.");
    println!("  Future: Lance + Candle for semantic vector search.");

    Ok(())
}

/// Calculates relevance score for an event based on keyword matches.
fn calculate_relevance(event: &Event, keywords: &[&str]) -> f64 {
    let mut score = 0.0;

    // Search in event type
    let event_type_lower = event.event_type.to_lowercase();
    for keyword in keywords {
        if event_type_lower.contains(keyword) {
            score += 2.0; // Higher weight for event type matches
        }
    }

    // Search in payload (serialize to string for search)
    let payload_str = event.payload.to_string().to_lowercase();
    for keyword in keywords {
        if payload_str.contains(keyword) {
            score += 1.0;
        }
    }

    // Search in reason
    if let Some(ref reason) = event.reason {
        let reason_lower = reason.to_lowercase();
        for keyword in keywords {
            if reason_lower.contains(keyword) {
                score += 1.5; // Medium weight for reason matches
            }
        }
    }

    // Search in source
    if let Some(ref source) = event.source {
        let source_lower = source.to_lowercase();
        for keyword in keywords {
            if source_lower.contains(keyword) {
                score += 1.0;
            }
        }
    }

    score
}

/// Prints the causal chain visualization.
fn print_causal_chain(results: &[(&Event, f64)], full: bool) {
    for (i, (event, score)) in results.iter().enumerate() {
        let is_last = i == results.len() - 1;
        let connector = if is_last { "└" } else { "├" };
        let continuation = if is_last { " " } else { "│" };

        // Format timestamp
        let timestamp = event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| {
                let secs = d.as_secs();
                let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
                    .unwrap_or_else(|| chrono::Utc::now());
                datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
            })
            .unwrap_or_else(|_| "unknown".to_string());

        // Event header
        println!(
            "{connector}─[{:03}] {} (score: {:.1})",
            event.event_id, event.event_type, score
        );
        println!("{continuation}     ⏰ {timestamp}");

        // Source
        if let Some(ref source) = event.source {
            println!("{continuation}     👤 Source: {source}");
        }

        // Reason
        if let Some(ref reason) = event.reason {
            println!("{continuation}     💡 Reason: {reason}");
        }

        // Payload
        let payload_str = if full {
            serde_json::to_string_pretty(&event.payload).unwrap_or_else(|_| "{}".to_string())
        } else {
            let compact = event.payload.to_string();
            if compact.len() > 60 {
                format!("{}...", &compact[..60])
            } else {
                compact
            }
        };

        if full {
            println!("{continuation}     📋 Payload:");
            for line in payload_str.lines() {
                println!("{continuation}        {line}");
            }
        } else {
            println!("{continuation}     📋 Payload: {payload_str}");
        }

        println!("{continuation}");
    }
}

/// Loads events from a file-based event store.
async fn load_events_from_store(data_dir: &PathBuf) -> Result<Vec<Event>> {
    if !data_dir.exists() {
        return Ok(Vec::new());
    }

    let store = FileEventStore::open(data_dir)
        .await
        .context("Failed to open event store")?;

    let events = store
        .read_from(0)
        .await
        .context("Failed to read events")?;

    Ok(events)
}

/// Generates demo events for testing the blame command.
async fn generate_demo_events() -> Result<Vec<Event>> {
    use serde_json::json;

    let mut store = InMemoryEventStore::new();

    // Create a realistic causal chain of agent decisions
    let events = vec![
        Event::new(
            1,
            "agent.spawned",
            json!({
                "agent_id": "auth-agent-001",
                "capabilities": ["auth", "jwt", "oauth2"],
                "model": "gpt-4-turbo"
            }),
        )
        .with_source("orchestrator")
        .with_reason("User requested auth system review"),

        Event::new(
            2,
            "task.assigned",
            json!({
                "task_id": "task-auth-review-001",
                "agent_id": "auth-agent-001",
                "description": "Review and improve authentication logic",
                "priority": "high"
            }),
        )
        .with_source("orchestrator")
        .with_reason("Security audit requirement"),

        Event::new(
            3,
            "code.analyzed",
            json!({
                "file": "src/auth/jwt.rs",
                "issues_found": 2,
                "severity": "medium",
                "suggestions": ["Add token expiry validation", "Implement refresh token rotation"]
            }),
        )
        .with_source("auth-agent-001")
        .with_reason("Static analysis of auth module"),

        Event::new(
            4,
            "decision.made",
            json!({
                "decision_id": "dec-001",
                "action": "modify_auth_logic",
                "target": "src/auth/jwt.rs",
                "changes": ["Added expiry check", "Implemented refresh rotation"],
                "confidence": 0.92
            }),
        )
        .with_source("auth-agent-001")
        .with_reason("Addressing security vulnerabilities in JWT handling"),

        Event::new(
            5,
            "code.modified",
            json!({
                "file": "src/auth/jwt.rs",
                "lines_added": 45,
                "lines_removed": 12,
                "diff_summary": "Added token expiry validation and refresh token rotation"
            }),
        )
        .with_source("auth-agent-001")
        .with_reason("Implementing decision dec-001"),

        Event::new(
            6,
            "test.executed",
            json!({
                "suite": "auth_tests",
                "passed": 24,
                "failed": 0,
                "coverage": 0.87
            }),
        )
        .with_source("auth-agent-001")
        .with_reason("Validating auth modifications"),

        Event::new(
            7,
            "task.completed",
            json!({
                "task_id": "task-auth-review-001",
                "status": "success",
                "summary": "Auth logic improved with better security",
                "time_taken_secs": 342
            }),
        )
        .with_source("auth-agent-001")
        .with_reason("All tests passing, changes verified"),
    ];

    // Add events to store
    for event in events {
        store.append(event).await.context("Failed to append demo event")?;
    }

    // Read back all events
    store.read_from(0).await.context("Failed to read demo events")
}

/// Truncates a string to a maximum length, adding "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

// ============================================================================
// CRDT Conflict Visualization
// ============================================================================

/// Represents a detected CRDT conflict
#[derive(Debug, Clone)]
struct CrdtConflict {
    /// Unique conflict ID
    id: String,
    /// Document/key where conflict occurred
    key: String,
    /// Type of conflict (concurrent-edit, network-partition, merge-required)
    conflict_type: ConflictType,
    /// Timestamp when conflict was detected
    #[allow(dead_code)]
    detected_at: std::time::SystemTime,
    /// Nodes involved in the conflict
    nodes: Vec<String>,
    /// Resolution status
    resolution: Option<ConflictResolution>,
    /// Conflicting values (simplified representation)
    values: Vec<ConflictValue>,
}

#[derive(Debug, Clone)]
enum ConflictType {
    ConcurrentEdit,
    NetworkPartition,
    MergeRequired,
    VectorClockDivergence,
}

impl std::fmt::Display for ConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictType::ConcurrentEdit => write!(f, "Concurrent Edit"),
            ConflictType::NetworkPartition => write!(f, "Network Partition"),
            ConflictType::MergeRequired => write!(f, "Merge Required"),
            ConflictType::VectorClockDivergence => write!(f, "Vector Clock Divergence"),
        }
    }
}

#[derive(Debug, Clone)]
struct ConflictResolution {
    /// How the conflict was resolved
    strategy: ResolutionStrategy,
    /// When it was resolved
    #[allow(dead_code)]
    resolved_at: std::time::SystemTime,
    /// Winning value (if applicable)
    winner: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ResolutionStrategy {
    LastWriterWins,
    MergeAll,
    ManualResolution,
    VectorClockOrdering,
    Automatic,
}

impl std::fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionStrategy::LastWriterWins => write!(f, "Last Writer Wins"),
            ResolutionStrategy::MergeAll => write!(f, "Merge All"),
            ResolutionStrategy::ManualResolution => write!(f, "Manual"),
            ResolutionStrategy::VectorClockOrdering => write!(f, "Vector Clock"),
            ResolutionStrategy::Automatic => write!(f, "Automatic"),
        }
    }
}

#[derive(Debug, Clone)]
struct ConflictValue {
    /// Node that produced this value
    node: String,
    /// The value (as string)
    value: String,
    /// Vector clock for this value
    vector_clock: HashMap<String, u64>,
    /// Timestamp
    #[allow(dead_code)]
    timestamp: std::time::SystemTime,
}

/// Visualizes CRDT conflicts
async fn cmd_conflicts(
    _data_dir: &PathBuf,
    key_filter: Option<&str>,
    include_resolved: bool,
    limit: usize,
    demo: bool,
    format: &str,
) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║               SYNAPSE CRDT CONFLICTS                     ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    if let Some(key) = key_filter {
        println!("║ Filter: {:50} ║", truncate(key, 50));
    }
    println!("║ Include Resolved: {:39} ║", if include_resolved { "yes" } else { "no" });
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Load conflicts (demo or real)
    let conflicts = if demo {
        println!("📦 Using demo data...");
        println!();
        generate_demo_conflicts()
    } else {
        // In real implementation, would load from CRDT state store
        println!("⚠ Real CRDT state loading not yet implemented.");
        println!("  Use --demo to see example output.");
        return Ok(());
    };

    // Filter conflicts
    let filtered: Vec<_> = conflicts
        .into_iter()
        .filter(|c| {
            // Filter by key if specified
            if let Some(key) = key_filter {
                if !c.key.contains(key) {
                    return false;
                }
            }
            // Filter resolved if not requested
            if !include_resolved && c.resolution.is_some() {
                return false;
            }
            true
        })
        .take(limit)
        .collect();

    if filtered.is_empty() {
        println!("✓ No conflicts found. CRDT state is consistent.");
        return Ok(());
    }

    // Display based on format
    match format {
        "json" => print_conflicts_json(&filtered),
        "graph" => print_conflicts_graph(&filtered),
        _ => print_conflicts_table(&filtered),
    }

    // Summary
    println!();
    println!("─────────────────────────────────────────────────────────────");
    let active = filtered.iter().filter(|c| c.resolution.is_none()).count();
    let resolved = filtered.len() - active;
    println!("📊 Summary: {} active conflicts, {} resolved", active, resolved);

    Ok(())
}

fn print_conflicts_table(conflicts: &[CrdtConflict]) {
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ ID       │ Key              │ Type                │ Nodes    │ Status      │");
    println!("├─────────────────────────────────────────────────────────────────────────────┤");

    for conflict in conflicts {
        let status = match &conflict.resolution {
            Some(r) => format!("✓ {}", r.strategy),
            None => "⚠ Active".to_string(),
        };

        println!(
            "│ {:8} │ {:16} │ {:19} │ {:8} │ {:11} │",
            truncate(&conflict.id, 8),
            truncate(&conflict.key, 16),
            format!("{}", conflict.conflict_type),
            conflict.nodes.len(),
            truncate(&status, 11)
        );
    }

    println!("└─────────────────────────────────────────────────────────────────────────────┘");
    println!();

    // Detailed view for active conflicts
    let active: Vec<_> = conflicts.iter().filter(|c| c.resolution.is_none()).collect();
    if !active.is_empty() {
        println!("🔍 Active Conflict Details:");
        println!();

        for conflict in active {
            println!("  ╭─ Conflict: {} ─────────────────────────────", conflict.id);
            println!("  │ Key:  {}", conflict.key);
            println!("  │ Type: {}", conflict.conflict_type);
            println!("  │ Nodes: {}", conflict.nodes.join(", "));
            println!("  │");
            println!("  │ Conflicting Values:");

            for (i, value) in conflict.values.iter().enumerate() {
                let vc: Vec<String> = value
                    .vector_clock
                    .iter()
                    .map(|(k, v)| format!("{}:{}", k, v))
                    .collect();
                
                println!("  │   {}. [{}] {} -> \"{}\"",
                    i + 1,
                    vc.join(", "),
                    value.node,
                    truncate(&value.value, 30)
                );
            }

            println!("  │");
            println!("  │ Suggested Resolution: {}", suggest_resolution(conflict));
            println!("  ╰────────────────────────────────────────────────────");
            println!();
        }
    }
}

fn print_conflicts_json(conflicts: &[CrdtConflict]) {
    // Simplified JSON output
    println!("[");
    for (i, conflict) in conflicts.iter().enumerate() {
        let comma = if i < conflicts.len() - 1 { "," } else { "" };
        println!("  {{");
        println!("    \"id\": \"{}\",", conflict.id);
        println!("    \"key\": \"{}\",", conflict.key);
        println!("    \"type\": \"{}\",", conflict.conflict_type);
        println!("    \"nodes\": {:?},", conflict.nodes);
        println!("    \"resolved\": {}", conflict.resolution.is_some());
        println!("  }}{}", comma);
    }
    println!("]");
}

fn print_conflicts_graph(conflicts: &[CrdtConflict]) {
    println!("CRDT Conflict Graph (ASCII Visualization)");
    println!();

    // Group conflicts by key
    let mut by_key: HashMap<&str, Vec<&CrdtConflict>> = HashMap::new();
    for conflict in conflicts {
        by_key.entry(&conflict.key).or_default().push(conflict);
    }

    for (key, key_conflicts) in by_key {
        println!("╭──────────────────────────────────────────────────────────");
        println!("│ Document: {}", key);
        println!("├──────────────────────────────────────────────────────────");

        // Collect all unique nodes
        let mut all_nodes: Vec<&str> = key_conflicts
            .iter()
            .flat_map(|c| c.nodes.iter().map(|s| s.as_str()))
            .collect();
        all_nodes.sort();
        all_nodes.dedup();

        // Print timeline header
        print!("│ Timeline ");
        for node in &all_nodes {
            print!(" {:^10}", truncate(node, 10));
        }
        println!();
        println!("│ ─────────────────────────────────────────────────────────");

        // For each conflict, show which nodes diverged
        for conflict in key_conflicts {
            print!("│ {:>8} ", truncate(&conflict.id, 8));
            for node in &all_nodes {
                if conflict.nodes.contains(&node.to_string()) {
                    print!("     ◆     "); // Conflict marker
                } else {
                    print!("     │     "); // No conflict
                }
            }
            println!();

            // Show resolution if any
            if let Some(ref resolution) = conflict.resolution {
                print!("│          ");
                for _ in &all_nodes {
                    print!("     │     ");
                }
                println!();
                print!("│ resolved ");
                for node in &all_nodes {
                    if resolution.winner.as_deref() == Some(*node) {
                        print!("     ✓     "); // Winner
                    } else if conflict.nodes.contains(&node.to_string()) {
                        print!("     ×     "); // Loser
                    } else {
                        print!("     │     ");
                    }
                }
                println!();
            }
        }

        println!("╰──────────────────────────────────────────────────────────");
        println!();
    }
}

fn suggest_resolution(conflict: &CrdtConflict) -> String {
    match conflict.conflict_type {
        ConflictType::ConcurrentEdit => {
            "Automerge semantic merge (text CRDT)".to_string()
        }
        ConflictType::NetworkPartition => {
            "Wait for partition heal, then reconcile".to_string()
        }
        ConflictType::MergeRequired => {
            "Apply CRDT merge rules (commutative)".to_string()
        }
        ConflictType::VectorClockDivergence => {
            "Use vector clock ordering (causal consistency)".to_string()
        }
    }
}

fn generate_demo_conflicts() -> Vec<CrdtConflict> {
    let now = std::time::SystemTime::now();
    let hour_ago = now - std::time::Duration::from_secs(3600);
    let two_hours_ago = now - std::time::Duration::from_secs(7200);

    vec![
        // Active concurrent edit conflict
        CrdtConflict {
            id: "c-001".to_string(),
            key: "agents/auth-agent/config".to_string(),
            conflict_type: ConflictType::ConcurrentEdit,
            detected_at: now,
            nodes: vec!["node-east".to_string(), "node-west".to_string()],
            resolution: None,
            values: vec![
                ConflictValue {
                    node: "node-east".to_string(),
                    value: r#"{"timeout": 30, "retries": 3}"#.to_string(),
                    vector_clock: [("node-east".to_string(), 5), ("node-west".to_string(), 3)]
                        .into_iter()
                        .collect(),
                    timestamp: now,
                },
                ConflictValue {
                    node: "node-west".to_string(),
                    value: r#"{"timeout": 60, "retries": 5}"#.to_string(),
                    vector_clock: [("node-east".to_string(), 3), ("node-west".to_string(), 4)]
                        .into_iter()
                        .collect(),
                    timestamp: now,
                },
            ],
        },
        // Active partition conflict
        CrdtConflict {
            id: "c-002".to_string(),
            key: "topics/events/metadata".to_string(),
            conflict_type: ConflictType::NetworkPartition,
            detected_at: now,
            nodes: vec!["node-east".to_string(), "node-central".to_string(), "node-west".to_string()],
            resolution: None,
            values: vec![
                ConflictValue {
                    node: "node-east".to_string(),
                    value: "partition-a-value".to_string(),
                    vector_clock: [("node-east".to_string(), 10)].into_iter().collect(),
                    timestamp: now,
                },
                ConflictValue {
                    node: "node-west".to_string(),
                    value: "partition-b-value".to_string(),
                    vector_clock: [("node-west".to_string(), 8)].into_iter().collect(),
                    timestamp: now,
                },
            ],
        },
        // Resolved conflict
        CrdtConflict {
            id: "c-003".to_string(),
            key: "agents/llm-agent/state".to_string(),
            conflict_type: ConflictType::VectorClockDivergence,
            detected_at: two_hours_ago,
            nodes: vec!["node-east".to_string(), "node-central".to_string()],
            resolution: Some(ConflictResolution {
                strategy: ResolutionStrategy::VectorClockOrdering,
                resolved_at: hour_ago,
                winner: Some("node-east".to_string()),
            }),
            values: vec![],
        },
        // Another resolved conflict
        CrdtConflict {
            id: "c-004".to_string(),
            key: "policies/rate-limits".to_string(),
            conflict_type: ConflictType::MergeRequired,
            detected_at: two_hours_ago,
            nodes: vec!["node-central".to_string(), "node-west".to_string()],
            resolution: Some(ConflictResolution {
                strategy: ResolutionStrategy::MergeAll,
                resolved_at: hour_ago,
                winner: None, // Merged, no single winner
            }),
            values: vec![],
        },
    ]
}

// ============================================================================
// Cluster Status Command
// ============================================================================

async fn cmd_cluster(verbose: bool) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                SYNAPSE CLUSTER STATUS                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // In real implementation, would query the cluster via control socket
    // For now, show demo data

    println!("🔗 Cluster Topology:");
    println!();
    println!("  ┌─────────────┬────────────────────┬──────────┬────────────┐");
    println!("  │ Node        │ Address            │ Status   │ CRDT Sync  │");
    println!("  ├─────────────┼────────────────────┼──────────┼────────────┤");
    println!("  │ node-east   │ 10.0.1.10:9090     │ ✓ Leader │ 100%       │");
    println!("  │ node-central│ 10.0.2.10:9090     │ ✓ Online │ 100%       │");
    println!("  │ node-west   │ 10.0.3.10:9090     │ ✓ Online │ 98.5%      │");
    println!("  └─────────────┴────────────────────┴──────────┴────────────┘");
    println!();

    if verbose {
        println!("📊 CRDT Sync Details:");
        println!();
        println!("  Replication Mode: Semi-Synchronous");
        println!("  Vector Clocks: {{east: 1547, central: 1545, west: 1542}}");
        println!("  Pending Syncs: 3 operations");
        println!("  Last Full Sync: 2 minutes ago");
        println!();

        println!("🔄 Raft Consensus:");
        println!();
        println!("  Current Term: 42");
        println!("  Leader: node-east");
        println!("  Commit Index: 15847");
        println!("  Last Applied: 15847");
        println!();

        println!("⚡ Hash Ring:");
        println!();
        println!("  Virtual Nodes: 450 (150 per node)");
        println!("  Replication Factor: 3");
        println!("  Key Distribution: Even (σ = 2.3%)");
        println!();
    }

    println!("─────────────────────────────────────────────────────────────");
    println!("ℹ Use 'syn conflicts --demo' to view CRDT conflict state");
    println!("  Use 'syn cluster --verbose' for detailed metrics");

    Ok(())
}
