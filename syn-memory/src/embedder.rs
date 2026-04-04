//! Embedding Engine using Candle
//!
//! This module provides local embedding generation using the Candle ML framework.
//! Embeddings are generated inside the Synapse binary without external API calls,
//! which is critical for the "Uncopyable" architecture - the embedding model
//! becomes part of the verified binary.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Embedding Engine                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
//! │  │  Tokenizer   │  │   Model Weights  │  │  Inference       │  │
//! │  │ (HF format)  │  │  (safetensors)   │  │  (spawn_blocking)│  │
//! │  │              │  │                  │  │                  │  │
//! │  │ Text → IDs   │──│ Memory-mapped    │──│ CPU/GPU forward  │  │
//! │  │              │  │ .safetensors     │  │ pass             │  │
//! │  └──────────────┘  └──────────────────┘  └──────────────────┘  │
//! │         │                    │                    │            │
//! │         └────────────────────┼────────────────────┘            │
//! │                              │                                  │
//! │                    ┌─────────┴─────────┐                       │
//! │                    │ Vec<f32> embedding│                       │
//! │                    │ (normalized)      │                       │
//! │                    └───────────────────┘                       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Why Local Embeddings?
//!
//! 1. **Uncopyable Binding**: The model weights are part of the verified binary
//! 2. **No API Dependencies**: Works offline, no OpenAI/Cohere required
//! 3. **Latency**: No network round-trip, sub-100ms inference
//! 4. **Cost**: Zero per-token costs for embeddings
//!
//! # Usage
//!
//! ```no_run
//! use syn_memory::embedder::{Embedder, EmbedderConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = EmbedderConfig::default();
//!     let embedder = Embedder::new(config).await?;
//!     
//!     let text = "Authenticate user with OAuth2";
//!     let embedding = embedder.embed(text).await?;
//!     
//!     println!("Embedding dimension: {}", embedding.len());
//!     Ok(())
//! }
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

/// Errors from the embedding engine
#[derive(Debug, Error)]
pub enum EmbedderError {
    /// Model loading failed
    #[error("Failed to load model: {0}")]
    ModelLoad(String),

    /// Tokenization failed
    #[error("Tokenization failed: {0}")]
    Tokenization(String),

    /// Inference failed
    #[error("Inference failed: {0}")]
    Inference(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for embedder operations
pub type EmbedderResult<T> = Result<T, EmbedderError>;

/// Embedding model type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// all-MiniLM-L6-v2 (384 dimensions, fast)
    MiniLmL6V2,
    /// all-MiniLM-L12-v2 (384 dimensions, more accurate)
    MiniLmL12V2,
    /// BGE-small-en (512 dimensions)
    BgeSmallEn,
    /// E5-small (384 dimensions)
    E5Small,
    /// Custom model path
    Custom,
}

impl ModelType {
    /// Get the output dimension for this model type
    pub fn dimension(&self) -> usize {
        match self {
            Self::MiniLmL6V2 | Self::MiniLmL12V2 | Self::E5Small => 384,
            Self::BgeSmallEn => 512,
            Self::Custom => 384, // Default, should be overridden
        }
    }

    /// Get the HuggingFace model ID
    pub fn hf_model_id(&self) -> &'static str {
        match self {
            Self::MiniLmL6V2 => "sentence-transformers/all-MiniLM-L6-v2",
            Self::MiniLmL12V2 => "sentence-transformers/all-MiniLM-L12-v2",
            Self::BgeSmallEn => "BAAI/bge-small-en",
            Self::E5Small => "intfloat/e5-small-v2",
            Self::Custom => "custom",
        }
    }
}

/// Configuration for the embedding engine
#[derive(Debug, Clone)]
pub struct EmbedderConfig {
    /// Model type to use
    pub model_type: ModelType,
    /// Custom model path (for ModelType::Custom)
    pub model_path: Option<PathBuf>,
    /// Maximum sequence length
    pub max_seq_length: usize,
    /// Whether to normalize output embeddings
    pub normalize: bool,
    /// Batch size for multiple texts
    pub batch_size: usize,
    /// Use GPU if available
    pub use_gpu: bool,
}

impl Default for EmbedderConfig {
    fn default() -> Self {
        Self {
            model_type: ModelType::MiniLmL6V2,
            model_path: None,
            max_seq_length: 512,
            normalize: true,
            batch_size: 32,
            use_gpu: false,
        }
    }
}

impl EmbedderConfig {
    /// Create config for MiniLM-L6-v2 (fast, good quality)
    pub fn mini_lm() -> Self {
        Self {
            model_type: ModelType::MiniLmL6V2,
            ..Default::default()
        }
    }

    /// Create config for BGE-small (better for retrieval)
    pub fn bge_small() -> Self {
        Self {
            model_type: ModelType::BgeSmallEn,
            ..Default::default()
        }
    }

    /// Set custom model path
    pub fn with_model_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.model_type = ModelType::Custom;
        self.model_path = Some(path.into());
        self
    }

    /// Enable GPU inference
    pub fn with_gpu(mut self) -> Self {
        self.use_gpu = true;
        self
    }
}

/// Embedding engine using Candle
///
/// This struct wraps the Candle ML framework for generating text embeddings.
/// Inference is offloaded to `spawn_blocking` to avoid blocking the async runtime.
pub struct Embedder {
    config: EmbedderConfig,
    /// Cached model state
    /// In a full implementation, this would hold:
    /// - tokenizer: tokenizers::Tokenizer
    /// - model: candle_transformers::models::bert::BertModel
    /// - device: candle_core::Device
    dimension: usize,
    /// Statistics
    stats: Arc<RwLock<EmbedderStats>>,
}

/// Embedding statistics
#[derive(Debug, Clone, Default)]
pub struct EmbedderStats {
    /// Number of texts embedded
    pub texts_embedded: u64,
    /// Total tokens processed
    pub tokens_processed: u64,
    /// Total inference time (milliseconds)
    pub inference_time_ms: u64,
}

impl Embedder {
    /// Create a new embedding engine
    #[instrument(skip(config), fields(model = %config.model_type.hf_model_id()))]
    pub async fn new(config: EmbedderConfig) -> EmbedderResult<Self> {
        info!(
            "Initializing embedder with model: {}",
            config.model_type.hf_model_id()
        );

        // In a full implementation, this would:
        // 1. Load tokenizer from HuggingFace Hub or local path
        // 2. Load model weights from .safetensors
        // 3. Initialize Candle device (CPU/CUDA/Metal)

        // For now, we create a simulated embedder
        let dimension = config.model_type.dimension();

        info!(
            "Embedder initialized: {} dimensions, normalize={}",
            dimension, config.normalize
        );

        Ok(Self {
            config,
            dimension,
            stats: Arc::new(RwLock::new(EmbedderStats::default())),
        })
    }

    /// Generate embedding for a single text
    #[instrument(skip(self, text))]
    pub async fn embed(&self, text: &str) -> EmbedderResult<Vec<f32>> {
        let text = text.to_string();
        let dimension = self.dimension;
        let normalize = self.config.normalize;
        let stats = self.stats.clone();

        // Offload inference to blocking thread pool
        // WHY spawn_blocking: ML inference is CPU-intensive and would block
        // the Tokio async runtime, causing network jitter
        let embedding = tokio::task::spawn_blocking(move || {
            let start = std::time::Instant::now();

            // In a full implementation with Candle:
            // let tokens = tokenizer.encode(text, true)?;
            // let input_ids = Tensor::new(tokens.get_ids(), &device)?;
            // let attention_mask = Tensor::new(tokens.get_attention_mask(), &device)?;
            // let embeddings = model.forward(&input_ids, &attention_mask)?;
            // let pooled = mean_pooling(&embeddings, &attention_mask)?;

            // Simulated embedding (deterministic based on text hash)
            let mut embedding = generate_simulated_embedding(&text, dimension);

            if normalize {
                normalize_vector(&mut embedding);
            }

            let elapsed = start.elapsed().as_millis() as u64;

            (embedding, elapsed, text.split_whitespace().count() as u64)
        })
        .await
        .map_err(|e| EmbedderError::Inference(format!("Task join error: {}", e)))?;

        // Update stats
        let (embedding, elapsed, token_count) = embedding;
        {
            let mut stats = stats.write().await;
            stats.texts_embedded += 1;
            stats.tokens_processed += token_count;
            stats.inference_time_ms += elapsed;
        }

        debug!(
            "Generated embedding: {} dims, {}ms",
            embedding.len(),
            elapsed
        );

        Ok(embedding)
    }

    /// Generate embeddings for multiple texts (batched)
    pub async fn embed_batch(&self, texts: &[&str]) -> EmbedderResult<Vec<Vec<f32>>> {
        let mut embeddings = Vec::with_capacity(texts.len());

        // In a full implementation, we'd batch these properly
        // For now, process sequentially
        for text in texts {
            embeddings.push(self.embed(text).await?);
        }

        Ok(embeddings)
    }

    /// Get the embedding dimension
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Get the model type
    pub fn model_type(&self) -> ModelType {
        self.config.model_type
    }

    /// Get statistics
    pub async fn stats(&self) -> EmbedderStats {
        self.stats.read().await.clone()
    }

    /// Calculate cosine similarity between two embeddings
    pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot / (norm_a * norm_b)
    }
}

/// Generate a simulated embedding based on text hash
/// This is deterministic for testing - same text always produces same embedding
fn generate_simulated_embedding(text: &str, dimension: usize) -> Vec<f32> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    let seed = hasher.finish();

    // Use seed to generate deterministic pseudo-random values
    let mut rng_state = seed;
    let mut embedding = Vec::with_capacity(dimension);

    for _ in 0..dimension {
        // Simple LCG for deterministic pseudo-random numbers
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let value = ((rng_state >> 33) as f32) / (u32::MAX as f32) * 2.0 - 1.0;
        embedding.push(value);
    }

    embedding
}

/// Normalize a vector to unit length (L2 normalization)
fn normalize_vector(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

// =============================================================================
// Candle Integration (feature-gated)
// =============================================================================

#[cfg(feature = "vector")]
pub mod candle_impl {
    //! Full Candle implementation for production use
    //!
    //! This module is compiled when the `vector` feature is enabled.
    //! It provides actual ML inference using Candle.

    use super::*;
    use candle_core::{DType, Device, Tensor};
    use candle_nn::VarBuilder;
    use candle_transformers::models::bert::{BertModel, Config as BertConfig, DTYPE};
    use hf_hub::{api::sync::Api, Repo, RepoType};
    use std::path::Path;
    use tokenizers::Tokenizer;

    /// Production embedder using Candle
    pub struct CandleEmbedder {
        model: BertModel,
        tokenizer: Tokenizer,
        device: Device,
        config: EmbedderConfig,
        normalize: bool,
    }

    impl CandleEmbedder {
        /// Load model from HuggingFace Hub
        #[instrument(skip_all)]
        pub fn from_hf(config: &EmbedderConfig) -> EmbedderResult<Self> {
            let model_id = config.model_type.hf_model_id();
            info!("Loading model from HuggingFace Hub: {}", model_id);

            // Initialize device
            let device = if config.use_gpu {
                Device::cuda_if_available(0)
                    .map_err(|e| EmbedderError::ModelLoad(format!("CUDA error: {}", e)))?
            } else {
                Device::Cpu
            };
            debug!("Using device: {:?}", device);

            // Download model files
            let api = Api::new()
                .map_err(|e| EmbedderError::ModelLoad(format!("HF API error: {}", e)))?;
            let repo = api.repo(Repo::new(model_id.to_string(), RepoType::Model));

            let tokenizer_file = repo
                .get("tokenizer.json")
                .map_err(|e| EmbedderError::ModelLoad(format!("Tokenizer download: {}", e)))?;
            let config_file = repo
                .get("config.json")
                .map_err(|e| EmbedderError::ModelLoad(format!("Config download: {}", e)))?;
            let weights_file = repo
                .get("model.safetensors")
                .map_err(|e| EmbedderError::ModelLoad(format!("Weights download: {}", e)))?;

            Self::from_files(&tokenizer_file, &config_file, &weights_file, config, device)
        }

        /// Load model from local files
        pub fn from_files(
            tokenizer_path: &Path,
            config_path: &Path,
            weights_path: &Path,
            config: &EmbedderConfig,
            device: Device,
        ) -> EmbedderResult<Self> {
            // Load tokenizer
            let tokenizer = Tokenizer::from_file(tokenizer_path)
                .map_err(|e| EmbedderError::Tokenization(format!("Load tokenizer: {}", e)))?;

            // Load model config
            let bert_config: BertConfig = serde_json::from_reader(std::fs::File::open(config_path)?)
                .map_err(|e| EmbedderError::ModelLoad(format!("Parse config: {}", e)))?;

            // Load weights using memory-mapped safetensors
            // WHY memory-map: Avoids loading entire model into RAM at startup
            let vb = unsafe {
                VarBuilder::from_mmaped_safetensors(&[weights_path], DTYPE, &device)
                    .map_err(|e| EmbedderError::ModelLoad(format!("Load weights: {}", e)))?
            };

            // Build model
            let model = BertModel::load(vb, &bert_config)
                .map_err(|e| EmbedderError::ModelLoad(format!("Build model: {}", e)))?;

            info!(
                "Model loaded: {} layers, {} hidden",
                bert_config.num_hidden_layers, bert_config.hidden_size
            );

            Ok(Self {
                model,
                tokenizer,
                device,
                config: config.clone(),
                normalize: config.normalize,
            })
        }

        /// Generate embedding for text
        pub fn embed(&self, text: &str) -> EmbedderResult<Vec<f32>> {
            let start = std::time::Instant::now();

            // Tokenize
            let encoding = self
                .tokenizer
                .encode(text, true)
                .map_err(|e| EmbedderError::Tokenization(e.to_string()))?;

            let input_ids = encoding.get_ids();
            let attention_mask = encoding.get_attention_mask();
            let token_type_ids = encoding.get_type_ids();

            // Truncate to max length
            let len = input_ids.len().min(self.config.max_seq_length);
            let input_ids = &input_ids[..len];
            let attention_mask = &attention_mask[..len];
            let token_type_ids = &token_type_ids[..len];

            // Convert to tensors (batch size = 1)
            let input_ids = Tensor::new(input_ids, &self.device)
                .map_err(|e| EmbedderError::Inference(format!("Input tensor: {}", e)))?
                .unsqueeze(0)
                .map_err(|e| EmbedderError::Inference(format!("Unsqueeze: {}", e)))?;

            let attention_mask = Tensor::new(attention_mask, &self.device)
                .map_err(|e| EmbedderError::Inference(format!("Attention tensor: {}", e)))?
                .unsqueeze(0)
                .map_err(|e| EmbedderError::Inference(format!("Unsqueeze: {}", e)))?;

            let token_type_ids = Tensor::new(token_type_ids, &self.device)
                .map_err(|e| EmbedderError::Inference(format!("Token type tensor: {}", e)))?
                .unsqueeze(0)
                .map_err(|e| EmbedderError::Inference(format!("Unsqueeze: {}", e)))?;

            // Forward pass
            let output = self
                .model
                .forward(&input_ids, &token_type_ids, Some(&attention_mask))
                .map_err(|e| EmbedderError::Inference(format!("Forward: {}", e)))?;

            // Mean pooling over sequence dimension
            let embedding = mean_pooling_tensor(&output, &attention_mask)?;

            // Convert to Vec<f32>
            let mut embedding: Vec<f32> = embedding
                .squeeze(0)
                .map_err(|e| EmbedderError::Inference(format!("Squeeze: {}", e)))?
                .to_vec1()
                .map_err(|e| EmbedderError::Inference(format!("To vec: {}", e)))?;

            // Normalize if configured
            if self.normalize {
                normalize_vector(&mut embedding);
            }

            debug!("Inference completed in {:?}", start.elapsed());
            Ok(embedding)
        }

        /// Get embedding dimension
        pub fn dimension(&self) -> usize {
            self.config.model_type.dimension()
        }
    }

    /// Mean pooling: weighted average over token embeddings using attention mask
    fn mean_pooling_tensor(embeddings: &Tensor, attention_mask: &Tensor) -> EmbedderResult<Tensor> {
        // Expand attention mask to match embedding dimensions
        let mask = attention_mask
            .unsqueeze(2)
            .map_err(|e| EmbedderError::Inference(format!("Unsqueeze mask: {}", e)))?
            .to_dtype(embeddings.dtype())
            .map_err(|e| EmbedderError::Inference(format!("Cast mask: {}", e)))?;

        // Apply mask and sum
        let masked = embeddings
            .broadcast_mul(&mask)
            .map_err(|e| EmbedderError::Inference(format!("Broadcast mul: {}", e)))?;

        let summed = masked
            .sum(1)
            .map_err(|e| EmbedderError::Inference(format!("Sum: {}", e)))?;

        // Divide by count of non-masked tokens
        let counts = mask
            .sum(1)
            .map_err(|e| EmbedderError::Inference(format!("Sum counts: {}", e)))?
            .clamp(1e-9, f64::MAX)
            .map_err(|e| EmbedderError::Inference(format!("Clamp: {}", e)))?;

        summed
            .broadcast_div(&counts)
            .map_err(|e| EmbedderError::Inference(format!("Div: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_embedder_creation() {
        let config = EmbedderConfig::default();
        let embedder = Embedder::new(config).await.unwrap();
        assert_eq!(embedder.dimension(), 384);
    }

    #[tokio::test]
    async fn test_embed_single() {
        let embedder = Embedder::new(EmbedderConfig::default()).await.unwrap();
        let embedding = embedder.embed("Hello world").await.unwrap();
        assert_eq!(embedding.len(), 384);

        // Check normalization (should be unit vector)
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_embed_deterministic() {
        let embedder = Embedder::new(EmbedderConfig::default()).await.unwrap();

        let text = "Deterministic embedding test";
        let emb1 = embedder.embed(text).await.unwrap();
        let emb2 = embedder.embed(text).await.unwrap();

        // Same text should produce same embedding
        assert_eq!(emb1, emb2);
    }

    #[tokio::test]
    async fn test_cosine_similarity() {
        let embedder = Embedder::new(EmbedderConfig::default()).await.unwrap();

        let emb1 = embedder.embed("Hello world").await.unwrap();
        let emb2 = embedder.embed("Hello world").await.unwrap();
        let emb3 = embedder.embed("Completely different text").await.unwrap();

        // Identical texts should have similarity 1.0
        let sim_same = Embedder::cosine_similarity(&emb1, &emb2);
        assert!((sim_same - 1.0).abs() < 0.001);

        // Different texts should have lower similarity
        let sim_diff = Embedder::cosine_similarity(&emb1, &emb3);
        assert!(sim_diff < 0.9);
    }

    #[tokio::test]
    async fn test_embed_batch() {
        let embedder = Embedder::new(EmbedderConfig::default()).await.unwrap();

        let texts = vec!["First text", "Second text", "Third text"];
        let embeddings = embedder.embed_batch(&texts).await.unwrap();

        assert_eq!(embeddings.len(), 3);
        for emb in &embeddings {
            assert_eq!(emb.len(), 384);
        }
    }

    #[tokio::test]
    async fn test_stats() {
        let embedder = Embedder::new(EmbedderConfig::default()).await.unwrap();

        let _ = embedder.embed("Test 1").await;
        let _ = embedder.embed("Test 2").await;

        let stats = embedder.stats().await;
        assert_eq!(stats.texts_embedded, 2);
    }
}
