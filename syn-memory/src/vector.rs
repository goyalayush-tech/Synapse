//! Vector memory for semantic embeddings.
//!
//! Vector memory stores LLM embeddings alongside events, enabling:
//! - Semantic retrieval: "Have we seen a similar problem?"
//! - Anomaly detection: Embeddings outside safe clusters trigger alerts
//! - Context similarity: Find related past events

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can occur during vector memory operations.
#[derive(Debug, Error)]
pub enum VectorError {
    /// Failed to generate embedding.
    #[error("Failed to generate embedding: {0}")]
    EmbeddingFailed(String),

    /// Failed to store vector.
    #[error("Failed to store vector: {0}")]
    StoreFailed(String),

    /// Failed to search vectors.
    #[error("Failed to search vectors: {0}")]
    SearchFailed(String),

    /// Invalid vector dimension.
    #[error("Invalid vector dimension: expected {expected}, got {actual}")]
    InvalidDimension { expected: usize, actual: usize },
}

/// Result type for vector memory operations.
pub type VectorResult<T> = Result<T, VectorError>;

/// A vector embedding with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEmbedding {
    /// Unique identifier.
    pub id: String,
    /// The embedding vector.
    pub vector: Vec<f32>,
    /// Associated event ID (if any).
    pub event_id: Option<u64>,
    /// Metadata about the embedding.
    pub metadata: serde_json::Value,
    /// Timestamp when the embedding was created.
    pub created_at: SystemTime,
}

impl VectorEmbedding {
    /// Creates a new vector embedding.
    ///
    /// # Errors
    ///
    /// Returns an error if the vector dimension is invalid.
    pub fn new(id: impl Into<String>, vector: Vec<f32>, expected_dim: usize) -> VectorResult<Self> {
        if vector.len() != expected_dim {
            return Err(VectorError::InvalidDimension {
                expected: expected_dim,
                actual: vector.len(),
            });
        }

        Ok(Self {
            id: id.into(),
            vector,
            event_id: None,
            metadata: serde_json::json!({}),
            created_at: SystemTime::now(),
        })
    }

    /// Sets the associated event ID.
    #[must_use]
    pub fn with_event_id(mut self, event_id: u64) -> Self {
        self.event_id = Some(event_id);
        self
    }

    /// Sets metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Search result with similarity score.
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    /// The embedding that matched.
    pub embedding: VectorEmbedding,
    /// Similarity score (higher is more similar).
    pub similarity: f32,
}

/// Vector memory interface.
///
/// Vector memory stores embeddings and provides semantic search capabilities.
#[async_trait::async_trait]
pub trait VectorMemory: Send + Sync {
    /// Stores an embedding.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn store(&mut self, embedding: VectorEmbedding) -> VectorResult<()>;

    /// Searches for similar embeddings.
    ///
    /// # Arguments
    ///
    /// * `query_vector` - The query vector to search for.
    /// * `top_k` - Number of results to return.
    /// * `threshold` - Minimum similarity threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if search fails.
    async fn search(
        &self,
        query_vector: &[f32],
        top_k: usize,
        threshold: f32,
    ) -> VectorResult<Vec<VectorSearchResult>>;

    /// Gets an embedding by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedding is not found.
    async fn get(&self, id: &str) -> VectorResult<VectorEmbedding>;
}

/// In-memory vector memory implementation.
///
/// This is a simple implementation for development and testing.
/// Production implementations would use specialized vector databases.
#[derive(Debug)]
pub struct InMemoryVectorMemory {
    embeddings: Vec<VectorEmbedding>,
    dimension: usize,
}

impl InMemoryVectorMemory {
    /// Creates a new in-memory vector memory.
    ///
    /// # Arguments
    ///
    /// * `dimension` - Expected dimension for all vectors.
    #[must_use]
    pub fn new(dimension: usize) -> Self {
        Self {
            embeddings: Vec::new(),
            dimension,
        }
    }
}

#[async_trait::async_trait]
impl VectorMemory for InMemoryVectorMemory {
    async fn store(&mut self, embedding: VectorEmbedding) -> VectorResult<()> {
        if embedding.vector.len() != self.dimension {
            return Err(VectorError::InvalidDimension {
                expected: self.dimension,
                actual: embedding.vector.len(),
            });
        }

        self.embeddings.push(embedding);
        Ok(())
    }

    async fn search(
        &self,
        query_vector: &[f32],
        top_k: usize,
        threshold: f32,
    ) -> VectorResult<Vec<VectorSearchResult>> {
        if query_vector.len() != self.dimension {
            return Err(VectorError::InvalidDimension {
                expected: self.dimension,
                actual: query_vector.len(),
            });
        }

        // Simple cosine similarity search
        let mut results: Vec<VectorSearchResult> = self
            .embeddings
            .iter()
            .map(|emb| {
                let similarity = cosine_similarity(query_vector, &emb.vector);
                VectorSearchResult {
                    embedding: emb.clone(),
                    similarity,
                }
            })
            .filter(|r| r.similarity >= threshold)
            .collect();

        // Sort by similarity (descending) and take top_k
        results.sort_by(|a, b| b.similarity.total_cmp(&a.similarity));
        results.truncate(top_k);

        Ok(results)
    }

    async fn get(&self, id: &str) -> VectorResult<VectorEmbedding> {
        self.embeddings
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| VectorError::SearchFailed(format!("Embedding not found: {}", id)))
    }
}

/// Calculates cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot_product / (norm_a * norm_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn vector_memory_store_and_search() {
        let mut memory = InMemoryVectorMemory::new(3);

        let emb1 = VectorEmbedding::new("emb-1", vec![1.0, 0.0, 0.0], 3).unwrap();
        let emb2 = VectorEmbedding::new("emb-2", vec![0.0, 1.0, 0.0], 3).unwrap();

        memory.store(emb1).await.unwrap();
        memory.store(emb2).await.unwrap();

        let results = memory.search(&[1.0, 0.0, 0.0], 1, 0.0).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].embedding.id, "emb-1");
        assert!(results[0].similarity > 0.9);
    }

    #[test]
    fn cosine_similarity_test() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &c).abs() < 0.001);
    }
}
