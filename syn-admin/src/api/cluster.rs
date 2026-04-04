//! Cluster status API.

use std::sync::Arc;
use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::{AppState, NodeStatus};

/// Cluster status response.
#[derive(Serialize)]
pub struct ClusterStatus {
    /// Cluster name
    pub name: String,
    /// Total nodes
    pub total_nodes: usize,
    /// Healthy nodes
    pub healthy_nodes: usize,
    /// Node details
    pub nodes: Vec<NodeInfo>,
}

/// Node info for API.
#[derive(Serialize)]
pub struct NodeInfo {
    /// Node ID
    pub id: String,
    /// Node address
    pub address: String,
    /// Node status
    pub status: String,
    /// Last heartbeat (ISO timestamp)
    pub last_heartbeat: String,
}

/// Metrics response.
#[derive(Serialize)]
pub struct MetricsResponse {
    /// Events processed
    pub events_processed: u64,
    /// Events per second
    pub events_per_second: f64,
    /// Active connections
    pub active_connections: u64,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Storage used in bytes
    pub storage_bytes: u64,
}

/// Get cluster status.
pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Json<ClusterStatus> {
    let nodes = state.nodes.read().await;
    let healthy = nodes.iter().filter(|n| n.status == NodeStatus::Healthy).count();
    
    let node_info: Vec<NodeInfo> = nodes.iter().map(|n| {
        NodeInfo {
            id: n.id.clone(),
            address: n.address.clone(),
            status: format!("{:?}", n.status),
            last_heartbeat: format_time(n.last_heartbeat),
        }
    }).collect();
    
    Json(ClusterStatus {
        name: "synapse-cluster".to_string(),
        total_nodes: nodes.len(),
        healthy_nodes: healthy,
        nodes: node_info,
    })
}

/// Get cluster metrics.
pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> Json<MetricsResponse> {
    let metrics = state.metrics.read().await;
    
    Json(MetricsResponse {
        events_processed: metrics.events_processed,
        events_per_second: metrics.events_per_second,
        active_connections: metrics.active_connections,
        memory_bytes: metrics.memory_bytes,
        cpu_percent: metrics.cpu_percent,
        storage_bytes: metrics.storage_bytes,
    })
}

fn format_time(time: std::time::SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
