//! # Consistent Hashing Ring for Horizontal Scaling
//!
//! Implements a consistent hashing ring with virtual nodes for distributing
//! events across a cluster of Synapse nodes. This enables horizontal scaling
//! with minimal data movement during cluster topology changes.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Consistent Hash Ring                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │                      ╭──────────╮                               │
//! │                 ╭────│  VNode1  │────╮                          │
//! │            ╭────│    ╰──────────╯    │────╮                     │
//! │       ╭────│    │       Node A       │    │────╮                │
//! │  VNode6    │    ╰────────────────────╯    │    VNode2           │
//! │  Node C    │                              │    Node A           │
//! │       ╰────│    ╭────────────────────╮    │────╯                │
//! │            ╰────│       Node B       │────╯                     │
//! │                 │    ╭──────────╮    │                          │
//! │                 ╰────│  VNode3  │────╯                          │
//! │                      ╰──────────╯                               │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Virtual Nodes**: Configurable vnodes for even distribution
//! - **Bounded Loads**: Prevents hot spots with load balancing
//! - **Preference Lists**: N-way replication across distinct nodes
//! - **Zero-Copy Keys**: Efficient key hashing without allocation

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use siphasher::sip::SipHasher24;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur in hash ring operations.
#[derive(Debug, Error)]
pub enum HashRingError {
    #[error("No nodes available in the ring")]
    EmptyRing,

    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Insufficient nodes for replication factor {requested}, have {available}")]
    InsufficientNodes { requested: usize, available: usize },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type HashRingResult<T> = Result<T, HashRingError>;

/// Configuration for the consistent hash ring.
#[derive(Debug, Clone)]
pub struct HashRingConfig {
    /// Number of virtual nodes per physical node (default: 150).
    /// Higher values provide better distribution but use more memory.
    pub virtual_nodes: usize,

    /// Replication factor - number of nodes to replicate data to (default: 3).
    pub replication_factor: usize,

    /// Enable bounded loads to prevent hot spots (default: true).
    /// When enabled, nodes exceeding 1.25x average load are skipped.
    pub bounded_loads: bool,

    /// Load bound factor (default: 1.25).
    /// Maximum load = average_load * load_bound_factor.
    pub load_bound_factor: f64,
}

impl Default for HashRingConfig {
    fn default() -> Self {
        Self {
            virtual_nodes: 150,
            replication_factor: 3,
            bounded_loads: true,
            load_bound_factor: 1.25,
        }
    }
}

/// A node in the Synapse cluster.
#[derive(Debug, Clone)]
pub struct ClusterNode {
    /// Unique identifier for this node.
    pub id: String,

    /// Network address of the node.
    pub addr: SocketAddr,

    /// Node weight for weighted distribution (default: 1.0).
    /// Higher weights result in more virtual nodes.
    pub weight: f64,

    /// Current load on this node (number of assigned keys).
    pub load: usize,

    /// Whether this node is healthy and accepting traffic.
    pub healthy: bool,

    /// Datacenter or availability zone (for rack-aware placement).
    pub datacenter: Option<String>,

    /// Additional metadata about the node.
    pub metadata: HashMap<String, String>,
}

impl ClusterNode {
    /// Create a new cluster node with default settings.
    pub fn new(id: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            id: id.into(),
            addr,
            weight: 1.0,
            load: 0,
            healthy: true,
            datacenter: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the weight for this node.
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    /// Set the datacenter for rack-aware placement.
    pub fn with_datacenter(mut self, dc: impl Into<String>) -> Self {
        self.datacenter = Some(dc.into());
        self
    }
}

/// Virtual node on the hash ring.
#[derive(Debug, Clone)]
struct VirtualNode {
    /// Hash position on the ring.
    hash: u64,
    /// Physical node ID this virtual node belongs to.
    node_id: String,
    /// Virtual node index (0..virtual_nodes).
    index: usize,
}

/// Thread-safe consistent hash ring implementation.
///
/// Uses SipHash-2-4 for consistent, secure hashing and a BTreeMap
/// for O(log n) lookups on the ring.
pub struct HashRing {
    /// Configuration for the ring.
    config: HashRingConfig,

    /// Ring of virtual nodes, sorted by hash position.
    /// Using BTreeMap for O(log n) ceiling lookup.
    ring: RwLock<BTreeMap<u64, VirtualNode>>,

    /// Physical nodes in the cluster.
    nodes: RwLock<HashMap<String, ClusterNode>>,

    /// Total number of keys assigned (for load calculation).
    total_keys: RwLock<usize>,
}

impl HashRing {
    /// Create a new hash ring with the given configuration.
    pub fn new(config: HashRingConfig) -> HashRingResult<Self> {
        if config.virtual_nodes == 0 {
            return Err(HashRingError::InvalidConfig(
                "virtual_nodes must be > 0".into(),
            ));
        }

        if config.replication_factor == 0 {
            return Err(HashRingError::InvalidConfig(
                "replication_factor must be > 0".into(),
            ));
        }

        if config.load_bound_factor <= 1.0 {
            return Err(HashRingError::InvalidConfig(
                "load_bound_factor must be > 1.0".into(),
            ));
        }

        Ok(Self {
            config,
            ring: RwLock::new(BTreeMap::new()),
            nodes: RwLock::new(HashMap::new()),
            total_keys: RwLock::new(0),
        })
    }

    /// Create a hash ring with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HashRingConfig::default()).expect("default config is valid")
    }

    /// Add a node to the hash ring.
    ///
    /// This will create `virtual_nodes * weight` virtual nodes on the ring.
    pub fn add_node(&self, node: ClusterNode) {
        let node_id = node.id.clone();
        let effective_vnodes = (self.config.virtual_nodes as f64 * node.weight) as usize;

        // Add physical node
        {
            let mut nodes = self.nodes.write();
            nodes.insert(node_id.clone(), node);
        }

        // Add virtual nodes to the ring
        {
            let mut ring = self.ring.write();
            for i in 0..effective_vnodes {
                let vnode_key = format!("{}#{}", node_id, i);
                let hash = self.hash_key(&vnode_key);

                ring.insert(
                    hash,
                    VirtualNode {
                        hash,
                        node_id: node_id.clone(),
                        index: i,
                    },
                );
            }
        }

        info!(
            node_id = %node_id,
            vnodes = effective_vnodes,
            "Added node to hash ring"
        );
    }

    /// Remove a node from the hash ring.
    pub fn remove_node(&self, node_id: &str) -> HashRingResult<ClusterNode> {
        // Remove physical node
        let node = {
            let mut nodes = self.nodes.write();
            nodes
                .remove(node_id)
                .ok_or_else(|| HashRingError::NodeNotFound(node_id.to_string()))?
        };

        let effective_vnodes = (self.config.virtual_nodes as f64 * node.weight) as usize;

        // Remove virtual nodes from the ring
        {
            let mut ring = self.ring.write();
            for i in 0..effective_vnodes {
                let vnode_key = format!("{}#{}", node_id, i);
                let hash = self.hash_key(&vnode_key);
                ring.remove(&hash);
            }
        }

        info!(
            node_id = %node_id,
            vnodes = effective_vnodes,
            "Removed node from hash ring"
        );

        Ok(node)
    }

    /// Mark a node as unhealthy (it will be skipped during lookups).
    pub fn mark_unhealthy(&self, node_id: &str) -> HashRingResult<()> {
        let mut nodes = self.nodes.write();
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| HashRingError::NodeNotFound(node_id.to_string()))?;

        node.healthy = false;
        warn!(node_id = %node_id, "Marked node as unhealthy");
        Ok(())
    }

    /// Mark a node as healthy.
    pub fn mark_healthy(&self, node_id: &str) -> HashRingResult<()> {
        let mut nodes = self.nodes.write();
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| HashRingError::NodeNotFound(node_id.to_string()))?;

        node.healthy = true;
        info!(node_id = %node_id, "Marked node as healthy");
        Ok(())
    }

    /// Get the primary node for a key.
    ///
    /// Returns the node responsible for this key based on consistent hashing.
    pub fn get_node(&self, key: &[u8]) -> HashRingResult<String> {
        let hash = self.hash_key_bytes(key);
        self.get_node_by_hash(hash)
    }

    /// Get the primary node for a string key.
    pub fn get_node_for_key(&self, key: &str) -> HashRingResult<String> {
        self.get_node(key.as_bytes())
    }

    /// Get the preference list for a key (for replication).
    ///
    /// Returns up to `replication_factor` distinct physical nodes,
    /// optionally respecting datacenter diversity.
    pub fn get_preference_list(&self, key: &[u8]) -> HashRingResult<Vec<String>> {
        let hash = self.hash_key_bytes(key);
        self.get_preference_list_by_hash(hash)
    }

    /// Get preference list with bounded loads.
    ///
    /// This version respects the bounded loads setting and will skip
    /// overloaded nodes.
    pub fn get_preference_list_bounded(&self, key: &[u8]) -> HashRingResult<Vec<String>> {
        if !self.config.bounded_loads {
            return self.get_preference_list(key);
        }

        let hash = self.hash_key_bytes(key);
        let ring = self.ring.read();
        let nodes = self.nodes.read();

        if ring.is_empty() {
            return Err(HashRingError::EmptyRing);
        }

        let average_load = self.calculate_average_load();
        let max_load = (average_load * self.config.load_bound_factor) as usize;

        let mut result = Vec::with_capacity(self.config.replication_factor);
        let mut seen_nodes = HashSet::new();
        let mut seen_dcs = HashSet::new();

        // Start from the key's position and walk clockwise
        let start_iter = ring.range(hash..).chain(ring.range(..hash));

        for (_, vnode) in start_iter {
            if result.len() >= self.config.replication_factor {
                break;
            }

            // Skip if we've already added this physical node
            if seen_nodes.contains(&vnode.node_id) {
                continue;
            }

            // Check if node exists and is healthy
            if let Some(node) = nodes.get(&vnode.node_id) {
                if !node.healthy {
                    continue;
                }

                // Check bounded load
                if node.load >= max_load {
                    debug!(
                        node_id = %vnode.node_id,
                        load = node.load,
                        max_load = max_load,
                        "Skipping overloaded node"
                    );
                    continue;
                }

                // For rack-aware placement, prefer diverse datacenters
                if let Some(dc) = &node.datacenter {
                    if seen_dcs.contains(dc) && result.len() < self.config.replication_factor - 1 {
                        // Try to find a node in a different DC first
                        continue;
                    }
                    seen_dcs.insert(dc.clone());
                }

                seen_nodes.insert(vnode.node_id.clone());
                result.push(vnode.node_id.clone());
            }
        }

        if result.is_empty() {
            return Err(HashRingError::EmptyRing);
        }

        // The walk above can exhaust every healthy virtual node (e.g. all
        // remaining healthy physical nodes belong to datacenters we've
        // already used, or are over the bounded-load limit) without ever
        // filling `replication_factor` slots. Silently returning a shorter
        // list hides an under-replication condition from callers, so surface
        // it explicitly instead.
        if result.len() < self.config.replication_factor {
            warn!(
                requested = self.config.replication_factor,
                available = result.len(),
                "Preference list has fewer healthy nodes than the replication factor"
            );
            return Err(HashRingError::InsufficientNodes {
                requested: self.config.replication_factor,
                available: result.len(),
            });
        }

        Ok(result)
    }

    /// Increment the load counter for a node.
    pub fn increment_load(&self, node_id: &str) -> HashRingResult<usize> {
        let mut nodes = self.nodes.write();
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| HashRingError::NodeNotFound(node_id.to_string()))?;

        node.load += 1;

        let mut total = self.total_keys.write();
        *total += 1;

        Ok(node.load)
    }

    /// Decrement the load counter for a node.
    pub fn decrement_load(&self, node_id: &str) -> HashRingResult<usize> {
        let mut nodes = self.nodes.write();
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| HashRingError::NodeNotFound(node_id.to_string()))?;

        node.load = node.load.saturating_sub(1);

        let mut total = self.total_keys.write();
        *total = total.saturating_sub(1);

        Ok(node.load)
    }

    /// Get the number of physical nodes in the ring.
    pub fn node_count(&self) -> usize {
        self.nodes.read().len()
    }

    /// Get the number of virtual nodes in the ring.
    pub fn vnode_count(&self) -> usize {
        self.ring.read().len()
    }

    /// Get statistics about the hash ring.
    pub fn stats(&self) -> HashRingStats {
        let nodes = self.nodes.read();
        let ring = self.ring.read();

        let healthy_nodes = nodes.values().filter(|n| n.healthy).count();
        let total_load: usize = nodes.values().map(|n| n.load).sum();

        let (min_load, max_load) = if nodes.is_empty() {
            (0, 0)
        } else {
            let loads: Vec<_> = nodes
                .values()
                .filter(|n| n.healthy)
                .map(|n| n.load)
                .collect();
            (
                *loads.iter().min().unwrap_or(&0),
                *loads.iter().max().unwrap_or(&0),
            )
        };

        HashRingStats {
            physical_nodes: nodes.len(),
            healthy_nodes,
            virtual_nodes: ring.len(),
            total_keys: total_load,
            average_load: if healthy_nodes > 0 {
                total_load as f64 / healthy_nodes as f64
            } else {
                0.0
            },
            min_load,
            max_load,
            replication_factor: self.config.replication_factor,
        }
    }

    /// Get the list of keys that would be affected by adding a new node.
    ///
    /// This is useful for planning data migration during scale-out.
    pub fn get_affected_ranges(&self, new_node_id: &str, weight: f64) -> Vec<(u64, u64)> {
        let effective_vnodes = (self.config.virtual_nodes as f64 * weight) as usize;
        let ring = self.ring.read();

        let mut affected = Vec::new();

        for i in 0..effective_vnodes {
            let vnode_key = format!("{}#{}", new_node_id, i);
            let new_hash = self.hash_key(&vnode_key);

            // Find the predecessor and successor
            if let Some((&succ_hash, _)) = ring.range(new_hash..).next() {
                if let Some((&pred_hash, _)) = ring.range(..new_hash).next_back() {
                    // Keys in (pred_hash, new_hash] will move to the new node
                    affected.push((pred_hash, new_hash));
                }
            }
        }

        affected
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Hash a key using SipHash-2-4.
    /// Using SipHash for its balance of speed and collision resistance.
    fn hash_key(&self, key: &str) -> u64 {
        self.hash_key_bytes(key.as_bytes())
    }

    fn hash_key_bytes(&self, key: &[u8]) -> u64 {
        // Using a fixed seed for deterministic hashing across nodes
        let mut hasher = SipHasher24::new_with_keys(0x0706050403020100, 0x0f0e0d0c0b0a0908);
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn get_node_by_hash(&self, hash: u64) -> HashRingResult<String> {
        let ring = self.ring.read();
        let nodes = self.nodes.read();

        if ring.is_empty() {
            return Err(HashRingError::EmptyRing);
        }

        // Find the first virtual node with hash >= key hash (clockwise)
        let vnode = ring
            .range(hash..)
            .next()
            .or_else(|| ring.iter().next()) // Wrap around
            .map(|(_, v)| v);

        if let Some(vnode) = vnode {
            // Check if node is healthy
            if let Some(node) = nodes.get(&vnode.node_id) {
                if node.healthy {
                    return Ok(vnode.node_id.clone());
                }

                // Node is unhealthy, find the next healthy node
                return self.find_next_healthy_node(hash);
            }
        }

        Err(HashRingError::EmptyRing)
    }

    fn find_next_healthy_node(&self, hash: u64) -> HashRingResult<String> {
        let ring = self.ring.read();
        let nodes = self.nodes.read();

        let mut seen = HashSet::new();

        for (_, vnode) in ring.range(hash..).chain(ring.range(..hash)) {
            if seen.contains(&vnode.node_id) {
                continue;
            }
            seen.insert(vnode.node_id.clone());

            if let Some(node) = nodes.get(&vnode.node_id) {
                if node.healthy {
                    return Ok(vnode.node_id.clone());
                }
            }
        }

        Err(HashRingError::EmptyRing)
    }

    fn get_preference_list_by_hash(&self, hash: u64) -> HashRingResult<Vec<String>> {
        let ring = self.ring.read();
        let nodes = self.nodes.read();

        if ring.is_empty() {
            return Err(HashRingError::EmptyRing);
        }

        let mut result = Vec::with_capacity(self.config.replication_factor);
        let mut seen = HashSet::new();

        // Walk clockwise from the key's position
        for (_, vnode) in ring.range(hash..).chain(ring.range(..hash)) {
            if result.len() >= self.config.replication_factor {
                break;
            }

            // Skip if we've already added this physical node
            if seen.contains(&vnode.node_id) {
                continue;
            }

            // Check if node is healthy
            if let Some(node) = nodes.get(&vnode.node_id) {
                if node.healthy {
                    seen.insert(vnode.node_id.clone());
                    result.push(vnode.node_id.clone());
                }
            }
        }

        if result.is_empty() {
            return Err(HashRingError::EmptyRing);
        }

        Ok(result)
    }

    fn calculate_average_load(&self) -> f64 {
        let nodes = self.nodes.read();
        let healthy_count = nodes.values().filter(|n| n.healthy).count();

        if healthy_count == 0 {
            return 0.0;
        }

        let total_keys = *self.total_keys.read();
        total_keys as f64 / healthy_count as f64
    }
}

/// Statistics about the hash ring.
#[derive(Debug, Clone)]
pub struct HashRingStats {
    /// Number of physical nodes.
    pub physical_nodes: usize,
    /// Number of healthy nodes.
    pub healthy_nodes: usize,
    /// Number of virtual nodes.
    pub virtual_nodes: usize,
    /// Total number of keys assigned.
    pub total_keys: usize,
    /// Average load per node.
    pub average_load: f64,
    /// Minimum load on any node.
    pub min_load: usize,
    /// Maximum load on any node.
    pub max_load: usize,
    /// Configured replication factor.
    pub replication_factor: usize,
}

/// Builder for creating a hash ring with nodes.
pub struct HashRingBuilder {
    config: HashRingConfig,
    nodes: Vec<ClusterNode>,
}

impl HashRingBuilder {
    pub fn new() -> Self {
        Self {
            config: HashRingConfig::default(),
            nodes: Vec::new(),
        }
    }

    pub fn with_config(mut self, config: HashRingConfig) -> Self {
        self.config = config;
        self
    }

    pub fn virtual_nodes(mut self, count: usize) -> Self {
        self.config.virtual_nodes = count;
        self
    }

    pub fn replication_factor(mut self, factor: usize) -> Self {
        self.config.replication_factor = factor;
        self
    }

    pub fn bounded_loads(mut self, enabled: bool) -> Self {
        self.config.bounded_loads = enabled;
        self
    }

    pub fn add_node(mut self, node: ClusterNode) -> Self {
        self.nodes.push(node);
        self
    }

    pub fn build(self) -> HashRingResult<HashRing> {
        let ring = HashRing::new(self.config)?;

        for node in self.nodes {
            ring.add_node(node);
        }

        Ok(ring)
    }
}

impl Default for HashRingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Router that uses consistent hashing to route requests.
pub struct ConsistentRouter {
    ring: Arc<HashRing>,
}

impl ConsistentRouter {
    /// Create a new router backed by a hash ring.
    pub fn new(ring: Arc<HashRing>) -> Self {
        Self { ring }
    }

    /// Route a key to its primary node.
    pub fn route(&self, key: &[u8]) -> HashRingResult<String> {
        self.ring.get_node(key)
    }

    /// Route a key to all replica nodes.
    pub fn route_replicated(&self, key: &[u8]) -> HashRingResult<Vec<String>> {
        self.ring.get_preference_list_bounded(key)
    }

    /// Get the hash ring statistics.
    pub fn stats(&self) -> HashRingStats {
        self.ring.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_add_remove_nodes() {
        let ring = HashRing::with_defaults();

        ring.add_node(ClusterNode::new("node1", make_addr(8001)));
        ring.add_node(ClusterNode::new("node2", make_addr(8002)));
        ring.add_node(ClusterNode::new("node3", make_addr(8003)));

        assert_eq!(ring.node_count(), 3);
        assert_eq!(ring.vnode_count(), 450); // 3 * 150

        ring.remove_node("node2").unwrap();
        assert_eq!(ring.node_count(), 2);
        assert_eq!(ring.vnode_count(), 300);
    }

    #[test]
    fn test_consistent_routing() {
        let ring = HashRing::with_defaults();

        ring.add_node(ClusterNode::new("node1", make_addr(8001)));
        ring.add_node(ClusterNode::new("node2", make_addr(8002)));
        ring.add_node(ClusterNode::new("node3", make_addr(8003)));

        // Same key should always route to the same node
        let key = b"test-key-123";
        let node1 = ring.get_node(key).unwrap();
        let node2 = ring.get_node(key).unwrap();
        assert_eq!(node1, node2);
    }

    #[test]
    fn test_preference_list() {
        let ring = HashRingBuilder::new()
            .replication_factor(3)
            .add_node(ClusterNode::new("node1", make_addr(8001)))
            .add_node(ClusterNode::new("node2", make_addr(8002)))
            .add_node(ClusterNode::new("node3", make_addr(8003)))
            .add_node(ClusterNode::new("node4", make_addr(8004)))
            .build()
            .unwrap();

        let prefs = ring.get_preference_list(b"some-key").unwrap();
        assert_eq!(prefs.len(), 3);

        // All nodes in preference list should be unique
        let unique: HashSet<_> = prefs.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_unhealthy_node_skip() {
        let ring = HashRing::with_defaults();

        ring.add_node(ClusterNode::new("node1", make_addr(8001)));
        ring.add_node(ClusterNode::new("node2", make_addr(8002)));

        let key = b"test-key";
        let original = ring.get_node(key).unwrap();

        // Mark the original node as unhealthy
        ring.mark_unhealthy(&original).unwrap();

        // Should now route to the other node
        let new = ring.get_node(key).unwrap();
        assert_ne!(original, new);
    }

    #[test]
    fn test_weighted_nodes() {
        let ring = HashRingBuilder::new()
            .virtual_nodes(100)
            .add_node(ClusterNode::new("node1", make_addr(8001)).with_weight(2.0))
            .add_node(ClusterNode::new("node2", make_addr(8002)).with_weight(1.0))
            .build()
            .unwrap();

        // node1 should have 2x the virtual nodes
        assert_eq!(ring.vnode_count(), 300); // 200 + 100
    }

    #[test]
    fn test_builder() {
        let ring = HashRingBuilder::new()
            .virtual_nodes(50)
            .replication_factor(2)
            .bounded_loads(false)
            .add_node(ClusterNode::new("node1", make_addr(8001)))
            .add_node(ClusterNode::new("node2", make_addr(8002)))
            .build()
            .unwrap();

        assert_eq!(ring.node_count(), 2);
        assert_eq!(ring.vnode_count(), 100);
    }

    #[test]
    fn test_stats() {
        let ring = HashRing::with_defaults();

        ring.add_node(ClusterNode::new("node1", make_addr(8001)));
        ring.add_node(ClusterNode::new("node2", make_addr(8002)));

        ring.increment_load("node1").unwrap();
        ring.increment_load("node1").unwrap();
        ring.increment_load("node2").unwrap();

        let stats = ring.stats();
        assert_eq!(stats.physical_nodes, 2);
        assert_eq!(stats.healthy_nodes, 2);
        assert_eq!(stats.total_keys, 3);
        assert_eq!(stats.min_load, 1);
        assert_eq!(stats.max_load, 2);
    }
}
