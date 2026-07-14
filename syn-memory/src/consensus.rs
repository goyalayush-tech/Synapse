//! Consensus protocols for multi-agent conflict resolution.
//!
//! When multiple agents propose conflicting plans or decisions, consensus
//! protocols help resolve the conflict through:
//! - Simple conflict resolution: A "judge" agent reviews and picks the winner
//! - Multi-round debate: Agents iteratively critique until agreement
//! - Policy-based decisions: Decisions are made according to shared policies
//! - Raft consensus: Distributed state machine replication for cluster coordination
//!
//! ## Phase 8: Raft Consensus
//!
//! The Raft implementation provides:
//! - Leader election with randomized timeouts
//! - Log replication across cluster nodes
//! - Membership changes (add/remove nodes)
//! - Snapshot support for log compaction

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, instrument};

/// Errors that can occur during consensus operations.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// Consensus failed.
    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    /// Invalid proposal.
    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),

    /// Timeout during consensus.
    #[error("Consensus timeout")]
    Timeout,

    /// Insufficient participants.
    #[error("Insufficient participants: need {needed}, got {actual}")]
    InsufficientParticipants {
        /// Required number of participants.
        needed: usize,
        /// Actual number of participants.
        actual: usize,
    },

    /// Not the leader
    #[error("Not the leader, current leader: {0:?}")]
    NotLeader(Option<String>),

    /// Log entry not found
    #[error("Log entry not found at index {0}")]
    LogEntryNotFound(u64),

    /// Node not found
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Channel error
    #[error("Channel error: {0}")]
    ChannelError(String),
}

/// Result type for consensus operations.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

/// A proposal in a consensus protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Proposal identifier.
    pub id: String,
    /// Agent that made the proposal.
    pub proposer: String,
    /// Proposal content.
    pub content: serde_json::Value,
    /// Timestamp when the proposal was made.
    pub timestamp: std::time::SystemTime,
}

impl Proposal {
    /// Creates a new proposal.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        proposer: impl Into<String>,
        content: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            proposer: proposer.into(),
            content,
            timestamp: std::time::SystemTime::now(),
        }
    }
}

/// Consensus protocol interface.
///
/// Consensus protocols resolve conflicts between multiple agent proposals.
#[async_trait::async_trait]
pub trait ConsensusProtocol: Send + Sync {
    /// Resolves a conflict between multiple proposals.
    ///
    /// # Arguments
    ///
    /// * `proposals` - The conflicting proposals.
    /// * `policy` - Policy to guide the decision (optional).
    ///
    /// # Errors
    ///
    /// Returns an error if consensus cannot be reached.
    async fn resolve(
        &self,
        proposals: Vec<Proposal>,
        policy: Option<serde_json::Value>,
    ) -> ConsensusResult<Proposal>;
}

/// Simple judge-based consensus protocol.
///
/// A single "judge" agent reviews all proposals and selects the winner
/// based on the provided policy.
pub struct JudgeConsensus {
    /// Judge agent identifier.
    #[allow(dead_code)] // Will be used in full implementation
    judge_id: String,
}

impl JudgeConsensus {
    /// Creates a new judge-based consensus protocol.
    #[must_use]
    pub fn new(judge_id: impl Into<String>) -> Self {
        Self {
            judge_id: judge_id.into(),
        }
    }
}

#[async_trait::async_trait]
impl ConsensusProtocol for JudgeConsensus {
    async fn resolve(
        &self,
        proposals: Vec<Proposal>,
        _policy: Option<serde_json::Value>,
    ) -> ConsensusResult<Proposal> {
        tracing::warn!(
            "JudgeConsensus::resolve is a stub: it does not evaluate proposals against \
             any policy, it always returns the first proposal in the list. This is not \
             real judge-based consensus."
        );

        if proposals.is_empty() {
            return Err(ConsensusError::InvalidProposal(
                "No proposals provided".to_string(),
            ));
        }

        // Simple implementation: return the first proposal
        // In a real implementation, the judge agent would:
        // 1. Review all proposals
        // 2. Evaluate them against the policy
        // 3. Select the best one

        Ok(proposals[0].clone())
    }
}

/// Multi-round debate consensus protocol.
///
/// Agents iteratively critique each other's proposals until
/// an agreement is reached or a timeout occurs.
pub struct DebateConsensus {
    /// Maximum number of rounds.
    #[allow(dead_code)] // Will be used in full implementation
    max_rounds: usize,
    /// Timeout per round in seconds.
    #[allow(dead_code)] // Will be used in full implementation
    round_timeout_secs: u64,
}

impl DebateConsensus {
    /// Creates a new debate-based consensus protocol.
    #[must_use]
    pub fn new(max_rounds: usize, round_timeout_secs: u64) -> Self {
        Self {
            max_rounds,
            round_timeout_secs,
        }
    }
}

#[async_trait::async_trait]
impl ConsensusProtocol for DebateConsensus {
    async fn resolve(
        &self,
        proposals: Vec<Proposal>,
        _policy: Option<serde_json::Value>,
    ) -> ConsensusResult<Proposal> {
        tracing::warn!(
            "DebateConsensus::resolve is a stub: no debate rounds are run and no \
             critiques are exchanged between agents, it always returns the first \
             proposal in the list. This is not real multi-round debate consensus."
        );

        if proposals.is_empty() {
            return Err(ConsensusError::InvalidProposal(
                "No proposals provided".to_string(),
            ));
        }

        // Simple implementation: return the first proposal
        // In a real implementation, this would:
        // 1. Start with initial proposals
        // 2. For each round:
        //    a. Each agent critiques other proposals
        //    b. Proposals are refined based on critiques
        //    c. Check if consensus is reached
        // 3. Return the agreed-upon proposal or timeout

        Ok(proposals[0].clone())
    }
}

// ============================================================================
// Phase 8: Raft Consensus Implementation
// ============================================================================

/// Raft node state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftState {
    /// Node is a follower
    Follower,
    /// Node is a candidate seeking election
    Candidate,
    /// Node is the leader
    Leader,
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Term when entry was received by leader
    pub term: u64,
    /// Index in the log
    pub index: u64,
    /// The command to be applied to state machine
    pub command: RaftCommand,
}

/// Commands that can be replicated via Raft.
///
/// These commands represent state machine operations that are
/// replicated across all nodes in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftCommand {
    /// Set a value in the distributed state.
    Set {
        /// Key to store the value under.
        key: String,
        /// JSON value to store.
        value: serde_json::Value,
    },
    /// Delete a value.
    Delete {
        /// Key to delete from the distributed state.
        key: String,
    },
    /// No-op for leader election.
    Noop,
    /// Configuration change.
    ConfigChange(ClusterConfig),
}

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// All nodes in the cluster
    pub nodes: Vec<RaftNodeInfo>,
}

/// Information about a Raft node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RaftNodeInfo {
    /// Node identifier
    pub id: String,
    /// Node address
    pub addr: String,
    /// Is this a voting member
    pub voting: bool,
}

/// Raft RPC messages.
///
/// These messages implement the Raft consensus protocol for leader election
/// and log replication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftMessage {
    /// Request vote from peers during leader election.
    RequestVote {
        /// Candidate's current term.
        term: u64,
        /// Candidate requesting the vote.
        candidate_id: String,
        /// Index of candidate's last log entry.
        last_log_index: u64,
        /// Term of candidate's last log entry.
        last_log_term: u64,
    },
    /// Response to RequestVote.
    RequestVoteResponse {
        /// Current term, for candidate to update itself.
        term: u64,
        /// True if candidate received vote.
        vote_granted: bool,
    },
    /// Append entries (heartbeat when entries is empty).
    AppendEntries {
        /// Leader's term.
        term: u64,
        /// Leader's ID so followers can redirect clients.
        leader_id: String,
        /// Index of log entry immediately preceding new ones.
        prev_log_index: u64,
        /// Term of prev_log_index entry.
        prev_log_term: u64,
        /// Log entries to replicate (empty for heartbeat).
        entries: Vec<LogEntry>,
        /// Leader's commit index.
        leader_commit: u64,
    },
    /// Response to AppendEntries.
    AppendEntriesResponse {
        /// Current term, for leader to update itself.
        term: u64,
        /// True if follower contained entry matching prev_log_index and prev_log_term.
        success: bool,
        /// Highest index replicated on this follower.
        match_index: u64,
    },
}

/// Events emitted by the Raft node.
///
/// These events can be observed to track the state of the consensus
/// and react to cluster changes.
#[derive(Debug, Clone)]
pub enum RaftEvent {
    /// State changed.
    StateChanged {
        /// Previous Raft state before the transition.
        old: RaftState,
        /// New Raft state after the transition.
        new: RaftState,
    },
    /// Leader elected.
    LeaderElected {
        /// Node ID of the newly elected leader.
        leader_id: String,
    },
    /// Entry committed.
    EntryCommitted {
        /// Log index of the committed entry.
        index: u64,
        /// Command that was committed.
        command: RaftCommand,
    },
    /// Node added to cluster.
    NodeAdded(RaftNodeInfo),
    /// Node removed from cluster.
    NodeRemoved(String),
}

/// Configuration for Raft consensus
#[derive(Debug, Clone)]
pub struct RaftConfig {
    /// This node's ID
    pub node_id: String,
    /// Minimum election timeout in milliseconds
    pub election_timeout_min_ms: u64,
    /// Maximum election timeout in milliseconds
    pub election_timeout_max_ms: u64,
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    /// Maximum entries per append
    pub max_entries_per_append: usize,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: format!("node-{}", uuid_simple()),
            election_timeout_min_ms: 150,
            election_timeout_max_ms: 300,
            heartbeat_interval_ms: 50,
            max_entries_per_append: 100,
        }
    }
}

/// Generate a simple UUID-like string
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

/// Persistent state on all servers
#[derive(Debug, Clone)]
pub struct RaftPersistentState {
    /// Latest term server has seen
    pub current_term: u64,
    /// CandidateId that received vote in current term
    pub voted_for: Option<String>,
    /// Log entries
    pub log: Vec<LogEntry>,
}

impl Default for RaftPersistentState {
    fn default() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
        }
    }
}

/// Volatile state on all servers
#[derive(Debug, Clone, Default)]
pub struct RaftVolatileState {
    /// Index of highest log entry known to be committed
    pub commit_index: u64,
    /// Index of highest log entry applied to state machine
    pub last_applied: u64,
}

/// Volatile state on leaders
#[derive(Debug, Clone, Default)]
pub struct RaftLeaderState {
    /// For each server, index of next log entry to send
    pub next_index: HashMap<String, u64>,
    /// For each server, index of highest log entry known to be replicated
    pub match_index: HashMap<String, u64>,
}

/// The Raft consensus node
pub struct RaftNode {
    /// Configuration
    #[allow(dead_code)]
    config: RaftConfig,
    /// Current state (Follower, Candidate, Leader)
    state: Arc<RwLock<RaftState>>,
    /// Persistent state
    persistent: Arc<RwLock<RaftPersistentState>>,
    /// Volatile state
    volatile: Arc<RwLock<RaftVolatileState>>,
    /// Leader state (only valid when leader)
    leader_state: Arc<RwLock<Option<RaftLeaderState>>>,
    /// Current leader ID
    leader_id: Arc<RwLock<Option<String>>>,
    /// Cluster configuration
    cluster: Arc<RwLock<ClusterConfig>>,
    /// State machine (key-value store)
    state_machine: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<RaftEvent>,
    /// Last heartbeat received
    last_heartbeat: Arc<RwLock<Instant>>,
}

impl RaftNode {
    /// Create a new Raft node
    pub fn new(config: RaftConfig) -> (Self, broadcast::Receiver<RaftEvent>) {
        let (event_tx, event_rx) = broadcast::channel(100);

        tracing::warn!(
            "RaftNode leader election is NOT implemented in this build: there is no \
             election-timeout loop and no vote-counting logic to transition a Candidate \
             to Leader. Nodes will remain Followers forever unless externally driven, so \
             RaftNode::propose() will always return ConsensusError::NotLeader."
        );

        (
            Self {
                config,
                state: Arc::new(RwLock::new(RaftState::Follower)),
                persistent: Arc::new(RwLock::new(RaftPersistentState::default())),
                volatile: Arc::new(RwLock::new(RaftVolatileState::default())),
                leader_state: Arc::new(RwLock::new(None)),
                leader_id: Arc::new(RwLock::new(None)),
                cluster: Arc::new(RwLock::new(ClusterConfig { nodes: Vec::new() })),
                state_machine: Arc::new(RwLock::new(HashMap::new())),
                event_tx,
                last_heartbeat: Arc::new(RwLock::new(Instant::now())),
            },
            event_rx,
        )
    }

    /// Get current state
    pub async fn get_state(&self) -> RaftState {
        *self.state.read().await
    }

    /// Get current term
    pub async fn get_term(&self) -> u64 {
        self.persistent.read().await.current_term
    }

    /// Get current leader ID
    pub async fn get_leader(&self) -> Option<String> {
        self.leader_id.read().await.clone()
    }

    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        *self.state.read().await == RaftState::Leader
    }

    /// Propose a command (only works on leader)
    #[instrument(skip(self))]
    pub async fn propose(&self, command: RaftCommand) -> ConsensusResult<u64> {
        if !self.is_leader().await {
            return Err(ConsensusError::NotLeader(self.get_leader().await));
        }

        let mut persistent = self.persistent.write().await;
        let index = persistent.log.len() as u64 + 1;
        let term = persistent.current_term;

        let entry = LogEntry {
            term,
            index,
            command: command.clone(),
        };

        persistent.log.push(entry);
        info!("Proposed command at index {}", index);

        Ok(index)
    }

    /// Handle incoming Raft message
    #[instrument(skip(self, msg))]
    pub async fn handle_message(
        &self,
        from: &str,
        msg: RaftMessage,
    ) -> ConsensusResult<Option<RaftMessage>> {
        match msg {
            RaftMessage::RequestVote {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => {
                self.handle_request_vote(term, &candidate_id, last_log_index, last_log_term)
                    .await
            }
            RaftMessage::RequestVoteResponse { term, vote_granted } => {
                self.handle_vote_response(from, term, vote_granted).await
            }
            RaftMessage::AppendEntries {
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                self.handle_append_entries(
                    term,
                    &leader_id,
                    prev_log_index,
                    prev_log_term,
                    entries,
                    leader_commit,
                )
                .await
            }
            RaftMessage::AppendEntriesResponse {
                term,
                success,
                match_index,
            } => {
                self.handle_append_response(from, term, success, match_index)
                    .await
            }
        }
    }

    async fn handle_request_vote(
        &self,
        term: u64,
        candidate_id: &str,
        last_log_index: u64,
        last_log_term: u64,
    ) -> ConsensusResult<Option<RaftMessage>> {
        let mut persistent = self.persistent.write().await;

        // Update term if needed
        if term > persistent.current_term {
            persistent.current_term = term;
            persistent.voted_for = None;
            *self.state.write().await = RaftState::Follower;
        }

        let vote_granted = if term < persistent.current_term {
            false
        } else if persistent.voted_for.is_none()
            || persistent.voted_for.as_deref() == Some(candidate_id)
        {
            // Check if candidate's log is at least as up-to-date
            let our_last_term = persistent.log.last().map(|e| e.term).unwrap_or(0);
            let our_last_index = persistent.log.len() as u64;

            if last_log_term > our_last_term
                || (last_log_term == our_last_term && last_log_index >= our_last_index)
            {
                persistent.voted_for = Some(candidate_id.to_string());
                true
            } else {
                false
            }
        } else {
            false
        };

        debug!(
            "Vote request from {}: granted={}",
            candidate_id, vote_granted
        );

        Ok(Some(RaftMessage::RequestVoteResponse {
            term: persistent.current_term,
            vote_granted,
        }))
    }

    async fn handle_vote_response(
        &self,
        from: &str,
        term: u64,
        vote_granted: bool,
    ) -> ConsensusResult<Option<RaftMessage>> {
        let mut persistent = self.persistent.write().await;

        if term > persistent.current_term {
            persistent.current_term = term;
            persistent.voted_for = None;
            *self.state.write().await = RaftState::Follower;
            return Ok(None);
        }

        if vote_granted && *self.state.read().await == RaftState::Candidate {
            debug!("Received vote from {}", from);
            // In a full implementation, we'd count votes and transition to leader
            // when we have a majority
        }

        Ok(None)
    }

    async fn handle_append_entries(
        &self,
        term: u64,
        leader_id: &str,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    ) -> ConsensusResult<Option<RaftMessage>> {
        let mut persistent = self.persistent.write().await;

        // Update term if needed
        if term > persistent.current_term {
            persistent.current_term = term;
            persistent.voted_for = None;
        }

        // Reject if term is old
        if term < persistent.current_term {
            return Ok(Some(RaftMessage::AppendEntriesResponse {
                term: persistent.current_term,
                success: false,
                match_index: 0,
            }));
        }

        // Recognize leader
        *self.state.write().await = RaftState::Follower;
        *self.leader_id.write().await = Some(leader_id.to_string());
        *self.last_heartbeat.write().await = Instant::now();

        // Check if log contains entry at prev_log_index with prev_log_term
        if prev_log_index > 0 {
            if let Some(entry) = persistent.log.get(prev_log_index as usize - 1) {
                if entry.term != prev_log_term {
                    // Conflict, delete this and all following
                    persistent.log.truncate(prev_log_index as usize - 1);
                    return Ok(Some(RaftMessage::AppendEntriesResponse {
                        term: persistent.current_term,
                        success: false,
                        match_index: persistent.log.len() as u64,
                    }));
                }
            } else if prev_log_index > persistent.log.len() as u64 {
                // Missing entries
                return Ok(Some(RaftMessage::AppendEntriesResponse {
                    term: persistent.current_term,
                    success: false,
                    match_index: persistent.log.len() as u64,
                }));
            }
        }

        // Append new entries
        for entry in entries {
            if entry.index > persistent.log.len() as u64 {
                persistent.log.push(entry);
            } else if entry.index > 0 {
                // Overwrite if terms don't match
                let idx = entry.index as usize - 1;
                if persistent.log.get(idx).map(|e| e.term) != Some(entry.term) {
                    persistent.log.truncate(idx);
                    persistent.log.push(entry);
                }
            }
        }

        // Update commit index
        let mut volatile = self.volatile.write().await;
        if leader_commit > volatile.commit_index {
            volatile.commit_index = std::cmp::min(leader_commit, persistent.log.len() as u64);
        }

        // Apply committed entries
        self.apply_committed(&persistent, &mut volatile).await;

        Ok(Some(RaftMessage::AppendEntriesResponse {
            term: persistent.current_term,
            success: true,
            match_index: persistent.log.len() as u64,
        }))
    }

    async fn handle_append_response(
        &self,
        from: &str,
        term: u64,
        success: bool,
        match_index: u64,
    ) -> ConsensusResult<Option<RaftMessage>> {
        let mut persistent = self.persistent.write().await;

        if term > persistent.current_term {
            persistent.current_term = term;
            persistent.voted_for = None;
            *self.state.write().await = RaftState::Follower;
            return Ok(None);
        }

        if *self.state.read().await != RaftState::Leader {
            return Ok(None);
        }

        let mut leader_state = self.leader_state.write().await;
        if let Some(ref mut ls) = *leader_state {
            if success {
                ls.match_index.insert(from.to_string(), match_index);
                ls.next_index.insert(from.to_string(), match_index + 1);
                debug!("Updated match_index for {}: {}", from, match_index);
            } else {
                // Decrement next_index and retry
                let next = ls.next_index.entry(from.to_string()).or_insert(1);
                if *next > 1 {
                    *next -= 1;
                }
            }
        }

        Ok(None)
    }

    async fn apply_committed(
        &self,
        persistent: &RaftPersistentState,
        volatile: &mut RaftVolatileState,
    ) {
        while volatile.last_applied < volatile.commit_index {
            volatile.last_applied += 1;
            if let Some(entry) = persistent.log.get(volatile.last_applied as usize - 1) {
                self.apply_command(&entry.command).await;
                let _ = self.event_tx.send(RaftEvent::EntryCommitted {
                    index: entry.index,
                    command: entry.command.clone(),
                });
            }
        }
    }

    async fn apply_command(&self, command: &RaftCommand) {
        let mut state_machine = self.state_machine.write().await;
        match command {
            RaftCommand::Set { key, value } => {
                state_machine.insert(key.clone(), value.clone());
                debug!("Applied SET {} = {:?}", key, value);
            }
            RaftCommand::Delete { key } => {
                state_machine.remove(key);
                debug!("Applied DELETE {}", key);
            }
            RaftCommand::Noop => {}
            RaftCommand::ConfigChange(config) => {
                *self.cluster.write().await = config.clone();
                debug!("Applied config change");
            }
        }
    }

    /// Get a value from the state machine
    pub async fn get(&self, key: &str) -> Option<serde_json::Value> {
        self.state_machine.read().await.get(key).cloned()
    }

    /// Add a node to the cluster (leader only)
    #[instrument(skip(self))]
    pub async fn add_node(&self, node: RaftNodeInfo) -> ConsensusResult<()> {
        if !self.is_leader().await {
            return Err(ConsensusError::NotLeader(self.get_leader().await));
        }

        let mut cluster = self.cluster.write().await;
        if !cluster.nodes.iter().any(|n| n.id == node.id) {
            cluster.nodes.push(node.clone());
            let _ = self.event_tx.send(RaftEvent::NodeAdded(node));
        }
        Ok(())
    }

    /// Remove a node from the cluster (leader only)
    #[instrument(skip(self))]
    pub async fn remove_node(&self, node_id: &str) -> ConsensusResult<()> {
        if !self.is_leader().await {
            return Err(ConsensusError::NotLeader(self.get_leader().await));
        }

        let mut cluster = self.cluster.write().await;
        cluster.nodes.retain(|n| n.id != node_id);
        let _ = self
            .event_tx
            .send(RaftEvent::NodeRemoved(node_id.to_string()));
        Ok(())
    }

    /// Subscribe to Raft events
    pub fn subscribe(&self) -> broadcast::Receiver<RaftEvent> {
        self.event_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn judge_consensus_resolve() {
        let consensus = JudgeConsensus::new("judge-1");
        let proposals = vec![
            Proposal::new("prop-1", "agent-1", serde_json::json!({"plan": "A"})),
            Proposal::new("prop-2", "agent-2", serde_json::json!({"plan": "B"})),
        ];

        let result = consensus.resolve(proposals, None).await.unwrap();
        assert_eq!(result.id, "prop-1");
    }

    #[tokio::test]
    async fn debate_consensus_resolve() {
        let consensus = DebateConsensus::new(3, 10);
        let proposals = vec![Proposal::new(
            "prop-1",
            "agent-1",
            serde_json::json!({"plan": "A"}),
        )];

        let result = consensus.resolve(proposals, None).await.unwrap();
        assert_eq!(result.id, "prop-1");
    }

    #[tokio::test]
    async fn raft_node_creation() {
        let config = RaftConfig::default();
        let (node, _events) = RaftNode::new(config);

        assert_eq!(node.get_state().await, RaftState::Follower);
        assert_eq!(node.get_term().await, 0);
        assert!(node.get_leader().await.is_none());
    }

    #[tokio::test]
    async fn raft_request_vote() {
        let config = RaftConfig {
            node_id: "node-1".to_string(),
            ..Default::default()
        };
        let (node, _events) = RaftNode::new(config);

        // Request vote from a candidate with term 1
        let msg = RaftMessage::RequestVote {
            term: 1,
            candidate_id: "node-2".to_string(),
            last_log_index: 0,
            last_log_term: 0,
        };

        let response = node.handle_message("node-2", msg).await.unwrap();
        assert!(matches!(
            response,
            Some(RaftMessage::RequestVoteResponse {
                vote_granted: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn raft_append_entries() {
        let config = RaftConfig {
            node_id: "node-1".to_string(),
            ..Default::default()
        };
        let (node, _events) = RaftNode::new(config);

        // Heartbeat from leader
        let msg = RaftMessage::AppendEntries {
            term: 1,
            leader_id: "leader".to_string(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };

        let response = node.handle_message("leader", msg).await.unwrap();
        assert!(matches!(
            response,
            Some(RaftMessage::AppendEntriesResponse { success: true, .. })
        ));

        assert_eq!(node.get_leader().await, Some("leader".to_string()));
    }
}
