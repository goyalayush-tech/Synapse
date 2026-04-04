# Event Sourcing

This document describes the event sourcing architecture in Synapse.

## Overview

Event sourcing persists each state change as an immutable event log rather than overwriting current state. This enables:

- **Full auditability**: Every decision is recorded
- **Time-travel debugging**: Replay events to any point in time
- **Resilience**: Agents can replay their log to restore state after crashes

## Event Structure

```rust
pub struct Event {
    pub event_id: u64,
    pub event_type: String,
    pub timestamp: SystemTime,
    pub payload: serde_json::Value,
    pub reason: Option<String>,
    pub source: Option<String>,
}
```

## Event Store

The event store maintains an append-only log:

```rust
use syn_memory::{Event, EventStore, InMemoryEventStore};

let mut store = InMemoryEventStore::new();

let event = Event::new(
    0,
    "agent.decided",
    serde_json::json!({"decision": "accept"}),
)
.with_reason("Policy check passed")
.with_source("agent-1");

store.append(event).await?;
```

## Replay

Reconstruct state by replaying events:

```rust
let final_state = store
    .replay(1, None, initial_state, |state, event| {
        // Apply event to state
        match event.event_type.as_str() {
            "agent.decided" => {
                // Update state based on decision
            }
            _ => state,
        }
    })
    .await?;
```

## Snapshots

Snapshots allow efficient state reconstruction:

```rust
// Create snapshot
let snapshot = store.create_snapshot(current_state).await?;

// Load snapshot and replay from that point
if let Some(snapshot) = store.load_snapshot().await? {
    let state = deserialize_state(&snapshot.state)?;
    let final_state = store
        .replay(snapshot.event_id + 1, None, state, apply_event)
        .await?;
}
```

## Knowledge Graph Integration

Events automatically populate the knowledge graph:

```rust
use syn_memory::{Node, Relationship, KnowledgeGraph};

// Event creates a node
let node = Node::new("task-123", "Task");
graph.add_node(node).await?;

// Event creates a relationship
let rel = Relationship::new(
    "rel-1",
    "agent-1",
    "task-123",
    "Assigned_To",
);
graph.add_relationship(rel).await?;
```

## Vector Memory Integration

Events can generate vector embeddings:

```rust
use syn_memory::{VectorEmbedding, VectorMemory};

// Generate embedding from event
let embedding = generate_embedding(&event).await?;
let vector = VectorEmbedding::new(
    format!("emb-{}", event.event_id),
    embedding,
    768, // dimension
)?
.with_event_id(event.event_id)
.with_metadata(serde_json::json!({
    "event_type": event.event_type
}));

memory.store(vector).await?;
```

## Query Patterns

### Find all events of a type

```rust
let events = store.read_from(0).await?;
let filtered: Vec<_> = events
    .iter()
    .filter(|e| e.event_type == "agent.decided")
    .collect();
```

### Find events in time range

```rust
let events = store.read_range(from_id, to_id).await?;
let in_range: Vec<_> = events
    .iter()
    .filter(|e| e.timestamp >= start && e.timestamp <= end)
    .collect();
```

### Semantic search

```rust
let query_vector = generate_embedding("agent decision").await?;
let results = memory.search(&query_vector, 10, 0.7).await?;

for result in results {
    if let Some(event_id) = result.embedding.event_id {
        let event = find_event_by_id(event_id).await?;
        // Process similar event
    }
}
```

## Best Practices

1. **Event Granularity**: Record meaningful state changes, not every operation
2. **Event Size**: Keep payloads small; reference external data if needed
3. **Snapshots**: Create snapshots periodically to bound replay time
4. **Retention**: Implement retention policies to manage log size
5. **Idempotency**: Ensure event application is idempotent

## Production Considerations

For production deployments:

- Use persistent storage (database, distributed log)
- Implement compaction to remove old events
- Add replication for high availability
- Monitor event log growth
- Consider event schema versioning

