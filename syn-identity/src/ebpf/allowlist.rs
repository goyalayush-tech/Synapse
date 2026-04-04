//! Binary Allowlist for eBPF Attestation
//!
//! This module manages the allowlist of trusted binaries that can connect
//! to Synapse. Each entry contains:
//! - SHA-256 hash of the binary
//! - Allowed cgroups (for container identity)
//! - Maximum concurrent instances
//! - Optional expiration time
//!
//! # Why Allowlist?
//!
//! Zero-trust means we don't trust process names or PIDs - they can be spoofed.
//! We only trust cryptographic hashes of the actual binary on disk. This is
//! verified at the kernel level via eBPF before any connection is allowed.
//!
//! # Example
//!
//! ```
//! use syn_identity::ebpf::{Allowlist, AllowlistEntry, BinaryHash};
//!
//! let mut allowlist = Allowlist::new();
//!
//! // Allow a specific binary by its SHA-256 hash
//! let entry = AllowlistEntry::new("my-agent", BinaryHash::from_bytes(b"binary content"))
//!     .with_cgroup("/system.slice")
//!     .with_max_instances(10);
//!
//! allowlist.add_entry(entry);
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// SHA-256 hash of a binary executable
///
/// This is the cryptographic identity of a binary. Even a single byte change
/// in the executable will produce a completely different hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryHash(#[serde(with = "hex_serde")] pub [u8; 32]);

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid hash length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl BinaryHash {
    /// Create a hash from a hex string
    ///
    /// # Example
    ///
    /// ```
    /// use syn_identity::ebpf::BinaryHash;
    ///
    /// let hash = BinaryHash::from_hex(
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// assert!(hash.is_some());
    /// ```
    pub fn from_hex(hex: &str) -> Option<Self> {
        let bytes = hex::decode(hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Compute hash of a file
    ///
    /// This reads the entire file and computes its SHA-256 hash.
    /// For large files, this may take some time.
    pub async fn from_file(path: &Path) -> std::io::Result<Self> {
        let data = tokio::fs::read(path).await?;
        Ok(Self::from_bytes(&data))
    }
    
    /// Compute hash of a file synchronously
    pub fn from_file_sync(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(Self::from_bytes(&data))
    }
    
    /// Compute hash of a byte slice
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for BinaryHash {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl std::fmt::Display for BinaryHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 8 and last 8 characters for readability
        let hex = self.to_hex();
        if f.alternate() {
            write!(f, "{}", hex)
        } else {
            write!(f, "{}...{}", &hex[..8], &hex[56..])
        }
    }
}

/// An entry in the binary allowlist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Human-readable name for this binary
    pub name: String,
    /// SHA-256 hash of the binary
    pub hash: BinaryHash,
    /// Description of what this binary does
    #[serde(default)]
    pub description: Option<String>,
    /// Cgroups where this binary is allowed to run
    /// Empty means any cgroup is allowed
    #[serde(default)]
    pub allowed_cgroups: Vec<String>,
    /// Maximum number of concurrent instances
    /// None means unlimited
    #[serde(default)]
    pub max_instances: Option<u32>,
    /// Expiration time for this entry
    /// None means never expires
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<SystemTime>,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// When this entry was added
    #[serde(default = "SystemTime::now")]
    pub added_at: SystemTime,
}

impl AllowlistEntry {
    /// Create a new allowlist entry
    pub fn new(name: impl Into<String>, hash: BinaryHash) -> Self {
        Self {
            name: name.into(),
            hash,
            description: None,
            allowed_cgroups: Vec::new(),
            max_instances: None,
            expires_at: None,
            tags: Vec::new(),
            added_at: SystemTime::now(),
        }
    }
    
    /// Set the description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
    
    /// Add an allowed cgroup
    pub fn with_cgroup(mut self, cgroup: impl Into<String>) -> Self {
        self.allowed_cgroups.push(cgroup.into());
        self
    }
    
    /// Set allowed cgroups
    pub fn with_cgroups(mut self, cgroups: Vec<String>) -> Self {
        self.allowed_cgroups = cgroups;
        self
    }
    
    /// Set maximum instances
    pub fn with_max_instances(mut self, max: u32) -> Self {
        self.max_instances = Some(max);
        self
    }
    
    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
    
    /// Set expiration from duration
    pub fn expires_in(mut self, duration: std::time::Duration) -> Self {
        self.expires_at = Some(SystemTime::now() + duration);
        self
    }
    
    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
    
    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => SystemTime::now() > expires,
            None => false,
        }
    }
    
    /// Check if a cgroup is allowed
    pub fn is_cgroup_allowed(&self, cgroup: &str) -> bool {
        if self.allowed_cgroups.is_empty() {
            return true;
        }
        self.allowed_cgroups.iter().any(|c| {
            // Support prefix matching for cgroup hierarchies
            cgroup.starts_with(c) || c == "*"
        })
    }
    
    /// Get time remaining until expiration
    pub fn time_remaining(&self) -> Option<std::time::Duration> {
        self.expires_at.and_then(|expires| {
            expires.duration_since(SystemTime::now()).ok()
        })
    }
}

/// The allowlist database
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Allowlist {
    /// Map from binary hash to entry
    entries: HashMap<BinaryHash, AllowlistEntry>,
    /// Version for cache invalidation
    version: u64,
    /// Description of this allowlist
    #[serde(default)]
    description: Option<String>,
}

impl Allowlist {
    /// Create a new empty allowlist
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            version: 0,
            description: None,
        }
    }
    
    /// Load allowlist from a file
    pub async fn from_file(path: &Path) -> std::io::Result<Self> {
        let data = tokio::fs::read_to_string(path).await?;
        Self::parse(&data, path)
    }
    
    /// Load allowlist from a file synchronously
    pub fn from_file_sync(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Self::parse(&data, path)
    }
    
    /// Parse allowlist from string
    fn parse(data: &str, path: &Path) -> std::io::Result<Self> {
        // Support both JSON and TOML formats
        let allowlist: Self = if path.extension().map_or(false, |e| e == "toml") {
            toml::from_str(data).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        } else {
            serde_json::from_str(data).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        };
        
        Ok(allowlist)
    }
    
    /// Save allowlist to a file
    pub async fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = if path.extension().map_or(false, |e| e == "toml") {
            toml::to_string_pretty(self).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        } else {
            serde_json::to_string_pretty(self).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?
        };
        tokio::fs::write(path, data).await
    }
    
    /// Add an entry to the allowlist
    pub fn add_entry(&mut self, entry: AllowlistEntry) {
        self.entries.insert(entry.hash.clone(), entry);
        self.version += 1;
    }
    
    /// Remove an entry by hash
    pub fn remove_entry(&mut self, hash: &BinaryHash) -> Option<AllowlistEntry> {
        let removed = self.entries.remove(hash);
        if removed.is_some() {
            self.version += 1;
        }
        removed
    }
    
    /// Remove an entry by name
    pub fn remove_by_name(&mut self, name: &str) -> Option<AllowlistEntry> {
        let hash = self.entries.iter()
            .find(|(_, e)| e.name == name)
            .map(|(h, _)| h.clone());
        
        hash.and_then(|h| self.remove_entry(&h))
    }
    
    /// Check if a binary hash is allowed
    pub fn is_allowed(&self, hash: &BinaryHash) -> bool {
        self.entries.get(hash)
            .map(|e| !e.is_expired())
            .unwrap_or(false)
    }
    
    /// Check if a binary hash is allowed in a specific cgroup
    pub fn is_allowed_in_cgroup(&self, hash: &BinaryHash, cgroup: &str) -> bool {
        self.entries.get(hash)
            .map(|e| !e.is_expired() && e.is_cgroup_allowed(cgroup))
            .unwrap_or(false)
    }
    
    /// Get an entry by hash
    pub fn get(&self, hash: &BinaryHash) -> Option<&AllowlistEntry> {
        self.entries.get(hash).filter(|e| !e.is_expired())
    }
    
    /// Get an entry by name
    pub fn get_by_name(&self, name: &str) -> Option<&AllowlistEntry> {
        self.entries.values()
            .find(|e| e.name == name && !e.is_expired())
    }
    
    /// Get all entries
    pub fn entries(&self) -> impl Iterator<Item = &AllowlistEntry> {
        self.entries.values().filter(|e| !e.is_expired())
    }
    
    /// Get all entries including expired
    pub fn all_entries(&self) -> impl Iterator<Item = &AllowlistEntry> {
        self.entries.values()
    }
    
    /// Get entries by tag
    pub fn get_by_tag(&self, tag: &str) -> Vec<&AllowlistEntry> {
        self.entries.values()
            .filter(|e| !e.is_expired() && e.tags.contains(&tag.to_string()))
            .collect()
    }
    
    /// Get the number of active entries
    pub fn len(&self) -> usize {
        self.entries.values().filter(|e| !e.is_expired()).count()
    }
    
    /// Check if the allowlist is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Get the version number
    pub fn version(&self) -> u64 {
        self.version
    }
    
    /// Prune expired entries
    pub fn prune_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired());
        let pruned = before - self.entries.len();
        if pruned > 0 {
            self.version += 1;
        }
        pruned
    }
    
    /// Merge another allowlist into this one
    pub fn merge(&mut self, other: Allowlist) {
        for (hash, entry) in other.entries {
            self.entries.insert(hash, entry);
        }
        self.version += 1;
    }
    
    /// Set description
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = Some(desc.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_binary_hash_hex_roundtrip() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = BinaryHash::from_hex(hex).expect("valid hex");
        assert_eq!(hash.to_hex(), hex);
    }
    
    #[test]
    fn test_binary_hash_from_bytes() {
        let data = b"hello world";
        let hash = BinaryHash::from_bytes(data);
        // SHA-256 of "hello world"
        assert_eq!(
            hash.to_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
    
    #[test]
    fn test_binary_hash_display() {
        let hash = BinaryHash::from_bytes(b"test");
        let short = format!("{}", hash);
        let full = format!("{:#}", hash);
        
        assert!(short.contains("..."));
        assert!(!full.contains("..."));
        assert_eq!(full.len(), 64);
    }
    
    #[test]
    fn test_allowlist_entry_cgroup() {
        let entry = AllowlistEntry::new("test", BinaryHash::default())
            .with_cgroup("/system.slice")
            .with_cgroup("/docker");
        
        assert!(entry.is_cgroup_allowed("/system.slice/test.service"));
        assert!(entry.is_cgroup_allowed("/docker/abc123"));
        assert!(!entry.is_cgroup_allowed("/user.slice"));
    }
    
    #[test]
    fn test_allowlist_entry_expiration() {
        // Test non-expired entry
        let entry = AllowlistEntry::new("test", BinaryHash::default())
            .expires_in(Duration::from_secs(3600));
        assert!(!entry.is_expired());
        assert!(entry.time_remaining().is_some());
        
        // Test expired entry (by setting expires_at to past)
        let mut expired = AllowlistEntry::new("test", BinaryHash::default());
        expired.expires_at = Some(SystemTime::UNIX_EPOCH);
        assert!(expired.is_expired());
    }
    
    #[test]
    fn test_allowlist_operations() {
        let mut allowlist = Allowlist::new();
        
        let entry = AllowlistEntry::new("test", BinaryHash::from_bytes(b"test"));
        let hash = entry.hash.clone();
        
        allowlist.add_entry(entry);
        assert!(allowlist.is_allowed(&hash));
        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist.version(), 1);
        
        allowlist.remove_entry(&hash);
        assert!(!allowlist.is_allowed(&hash));
        assert!(allowlist.is_empty());
        assert_eq!(allowlist.version(), 2);
    }
    
    #[test]
    fn test_allowlist_get_by_name() {
        let mut allowlist = Allowlist::new();
        
        allowlist.add_entry(
            AllowlistEntry::new("agent-1", BinaryHash::from_bytes(b"agent1"))
        );
        allowlist.add_entry(
            AllowlistEntry::new("agent-2", BinaryHash::from_bytes(b"agent2"))
        );
        
        let entry = allowlist.get_by_name("agent-1");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().name, "agent-1");
    }
    
    #[test]
    fn test_allowlist_tags() {
        let mut allowlist = Allowlist::new();
        
        allowlist.add_entry(
            AllowlistEntry::new("agent-1", BinaryHash::from_bytes(b"agent1"))
                .with_tag("production")
        );
        allowlist.add_entry(
            AllowlistEntry::new("agent-2", BinaryHash::from_bytes(b"agent2"))
                .with_tag("development")
        );
        
        let prod = allowlist.get_by_tag("production");
        assert_eq!(prod.len(), 1);
        assert_eq!(prod[0].name, "agent-1");
    }
    
    #[test]
    fn test_allowlist_cgroup_check() {
        let mut allowlist = Allowlist::new();
        
        let entry = AllowlistEntry::new("test", BinaryHash::from_bytes(b"test"))
            .with_cgroup("/docker");
        let hash = entry.hash.clone();
        
        allowlist.add_entry(entry);
        
        assert!(allowlist.is_allowed_in_cgroup(&hash, "/docker/container123"));
        assert!(!allowlist.is_allowed_in_cgroup(&hash, "/system.slice"));
    }
    
    #[test]
    fn test_allowlist_prune_expired() {
        let mut allowlist = Allowlist::new();
        
        // Add valid entry
        allowlist.add_entry(
            AllowlistEntry::new("valid", BinaryHash::from_bytes(b"valid"))
        );
        
        // Add expired entry
        let mut expired = AllowlistEntry::new("expired", BinaryHash::from_bytes(b"expired"));
        expired.expires_at = Some(SystemTime::UNIX_EPOCH);
        allowlist.add_entry(expired);
        
        assert_eq!(allowlist.len(), 1); // Only non-expired counted
        
        let pruned = allowlist.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(allowlist.entries.len(), 1);
    }
    
    #[test]
    fn test_allowlist_merge() {
        let mut list1 = Allowlist::new();
        list1.add_entry(AllowlistEntry::new("a", BinaryHash::from_bytes(b"a")));
        
        let mut list2 = Allowlist::new();
        list2.add_entry(AllowlistEntry::new("b", BinaryHash::from_bytes(b"b")));
        
        list1.merge(list2);
        assert_eq!(list1.len(), 2);
    }
}
