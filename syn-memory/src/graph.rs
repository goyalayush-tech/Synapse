//! Knowledge graph implementation.
//!
//! The knowledge graph maintains a graph of entities (agents, tasks, resources)
//! and their relationships, with temporal tracking. This enables:
//! - Context retrieval: "Is order 101 shipped?"
//! - Relationship queries: "What tasks is agent-1 working on?"
//! - Temporal queries: "What happened between time X and Y?"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can occur during graph operations.
#[derive(Debug, Error)]
pub enum GraphError {
    /// Node not found.
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Relationship not found.
    #[error("Relationship not found: {0}")]
    RelationshipNotFound(String),

    /// Query failed.
    #[error("Query failed: {0}")]
    QueryFailed(String),
}

/// Result type for graph operations.
pub type GraphResult<T> = Result<T, GraphError>;

/// A node in the knowledge graph.
///
/// Nodes represent entities such as agents, tasks, or resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Node identifier.
    pub id: String,
    /// Node type (e.g., "Agent", "Task", "Resource").
    pub node_type: String,
    /// Node properties.
    pub properties: HashMap<String, serde_json::Value>,
    /// Timestamp when the node was created.
    pub created_at: SystemTime,
}

impl Node {
    /// Creates a new node.
    #[must_use]
    pub fn new(id: impl Into<String>, node_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            node_type: node_type.into(),
            properties: HashMap::new(),
            created_at: SystemTime::now(),
        }
    }

    /// Sets a property on the node.
    pub fn set_property(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.properties.insert(key.into(), value);
    }
}

/// A relationship between nodes.
///
/// Relationships represent connections between entities, with optional
/// temporal information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    /// Relationship identifier.
    pub id: String,
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
    /// Relationship type (e.g., "Assigned_To", "Completed_At").
    pub rel_type: String,
    /// Relationship properties.
    pub properties: HashMap<String, serde_json::Value>,
    /// Timestamp when the relationship was created.
    pub created_at: SystemTime,
}

impl Relationship {
    /// Creates a new relationship.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        rel_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            from: from.into(),
            to: to.into(),
            rel_type: rel_type.into(),
            properties: HashMap::new(),
            created_at: SystemTime::now(),
        }
    }

    /// Sets a property on the relationship.
    pub fn set_property(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.properties.insert(key.into(), value);
    }
}

/// Graph query for retrieving nodes and relationships.
#[derive(Debug, Clone)]
pub struct GraphQuery {
    /// Node IDs to start from (optional).
    pub start_nodes: Option<Vec<String>>,
    /// Relationship types to traverse (optional).
    pub relationship_types: Option<Vec<String>>,
    /// Node types to filter (optional).
    pub node_types: Option<Vec<String>>,
    /// Maximum depth for traversal.
    pub max_depth: Option<usize>,
}

impl GraphQuery {
    /// Creates a new graph query.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_nodes: None,
            relationship_types: None,
            node_types: None,
            max_depth: None,
        }
    }

    /// Sets the starting nodes.
    #[must_use]
    pub fn with_start_nodes(mut self, nodes: Vec<String>) -> Self {
        self.start_nodes = Some(nodes);
        self
    }

    /// Sets the relationship types to traverse.
    #[must_use]
    pub fn with_relationship_types(mut self, types: Vec<String>) -> Self {
        self.relationship_types = Some(types);
        self
    }

    /// Sets the maximum traversal depth.
    #[must_use]
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }
}

impl Default for GraphQuery {
    fn default() -> Self {
        Self::new()
    }
}

/// Knowledge graph interface.
///
/// The knowledge graph maintains nodes and relationships, enabling
/// complex queries for context retrieval.
#[async_trait::async_trait]
pub trait KnowledgeGraph: Send + Sync {
    /// Adds a node to the graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the node cannot be added.
    async fn add_node(&mut self, node: Node) -> GraphResult<()>;

    /// Gets a node by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is not found.
    async fn get_node(&self, id: &str) -> GraphResult<Node>;

    /// Adds a relationship to the graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the relationship cannot be added.
    async fn add_relationship(&mut self, relationship: Relationship) -> GraphResult<()>;

    /// Executes a graph query.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    async fn query(&self, query: &GraphQuery) -> GraphResult<Vec<Node>>;
}

/// In-memory knowledge graph implementation.
///
/// This is a simple implementation for development and testing.
/// Production implementations would use a graph database (Neo4j, Dgraph).
#[derive(Debug, Default)]
pub struct InMemoryKnowledgeGraph {
    nodes: HashMap<String, Node>,
    relationships: HashMap<String, Relationship>,
}

impl InMemoryKnowledgeGraph {
    /// Creates a new in-memory knowledge graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            relationships: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl KnowledgeGraph for InMemoryKnowledgeGraph {
    async fn add_node(&mut self, node: Node) -> GraphResult<()> {
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    async fn get_node(&self, id: &str) -> GraphResult<Node> {
        self.nodes
            .get(id)
            .cloned()
            .ok_or_else(|| GraphError::NodeNotFound(id.to_string()))
    }

    async fn add_relationship(&mut self, relationship: Relationship) -> GraphResult<()> {
        // Verify that both nodes exist
        if !self.nodes.contains_key(&relationship.from) {
            return Err(GraphError::NodeNotFound(relationship.from.clone()));
        }
        if !self.nodes.contains_key(&relationship.to) {
            return Err(GraphError::NodeNotFound(relationship.to.clone()));
        }

        self.relationships.insert(relationship.id.clone(), relationship);
        Ok(())
    }

    async fn query(&self, query: &GraphQuery) -> GraphResult<Vec<Node>> {
        let mut results = Vec::new();

        if let Some(start_nodes) = &query.start_nodes {
            for node_id in start_nodes {
                if let Ok(node) = self.get_node(node_id).await {
                    results.push(node);
                }
            }
        } else {
            // Return all nodes if no start nodes specified
            results.extend(self.nodes.values().cloned());
        }

        // Filter by node types if specified
        if let Some(node_types) = &query.node_types {
            results.retain(|node| node_types.contains(&node.node_type));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn graph_add_and_get_node() {
        let mut graph = InMemoryKnowledgeGraph::new();
        let node = Node::new("node-1", "Agent");
        graph.add_node(node.clone()).await.unwrap();

        let retrieved = graph.get_node("node-1").await.unwrap();
        assert_eq!(retrieved.id, "node-1");
    }

    #[tokio::test]
    async fn graph_add_relationship() {
        let mut graph = InMemoryKnowledgeGraph::new();
        
        let node1 = Node::new("node-1", "Agent");
        let node2 = Node::new("node-2", "Task");
        
        graph.add_node(node1).await.unwrap();
        graph.add_node(node2).await.unwrap();

        let rel = Relationship::new("rel-1", "node-1", "node-2", "Assigned_To");
        graph.add_relationship(rel).await.unwrap();
    }
}

