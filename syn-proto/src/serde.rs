//! Serde serialization helpers and adapters.
//!
//! This module provides utilities for working with Serde-based serialization,
//! including format selection and conversion helpers.

use crate::error::{ProtoError, ProtoResult};

/// Serialization format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// JSON format (human-readable, debuggable).
    Json,
    /// TOML format (configuration files).
    Toml,
}

/// Serializes a value to the specified format.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize<T: serde::Serialize>(
    value: &T,
    format: SerializationFormat,
) -> ProtoResult<Vec<u8>> {
    match format {
        SerializationFormat::Json => {
            serde_json::to_vec(value).map_err(|e| ProtoError::Serialization(e.to_string()))
        }
        #[cfg(feature = "toml")]
        SerializationFormat::Toml => toml::to_string(value)
            .map(String::into_bytes)
            .map_err(|e| ProtoError::Serialization(e.to_string())),
        #[cfg(not(feature = "toml"))]
        SerializationFormat::Toml => Err(ProtoError::Serialization(
            "TOML support not enabled".to_string(),
        )),
    }
}

/// Deserializes a value from the specified format.
///
/// # Errors
///
/// Returns an error if deserialization fails.
pub fn deserialize<T: for<'de> serde::Deserialize<'de>>(
    bytes: &[u8],
    format: SerializationFormat,
) -> ProtoResult<T> {
    match format {
        SerializationFormat::Json => {
            serde_json::from_slice(bytes).map_err(|e| ProtoError::Deserialization(e.to_string()))
        }
        #[cfg(feature = "toml")]
        SerializationFormat::Toml => {
            let s = std::str::from_utf8(bytes)
                .map_err(|e| ProtoError::Deserialization(e.to_string()))?;
            toml::from_str(s).map_err(|e| ProtoError::Deserialization(e.to_string()))
        }
        #[cfg(not(feature = "toml"))]
        SerializationFormat::Toml => Err(ProtoError::Deserialization(
            "TOML support not enabled".to_string(),
        )),
    }
}

/// Helper trait for types that support multiple serialization formats.
pub trait MultiFormatSerialize: serde::Serialize + Sized {
    /// Serializes to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn to_json(&self) -> ProtoResult<Vec<u8>> {
        serialize(self, SerializationFormat::Json)
    }

    /// Serializes to TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn to_toml(&self) -> ProtoResult<Vec<u8>> {
        serialize(self, SerializationFormat::Toml)
    }
}

impl<T: serde::Serialize + Sized> MultiFormatSerialize for T {}

/// Helper trait for types that support multiple deserialization formats.
pub trait MultiFormatDeserialize: for<'de> serde::Deserialize<'de> {
    /// Deserializes from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn from_json(bytes: &[u8]) -> ProtoResult<Self>
    where
        Self: Sized,
    {
        deserialize(bytes, SerializationFormat::Json)
    }

    /// Deserializes from TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn from_toml(bytes: &[u8]) -> ProtoResult<Self>
    where
        Self: Sized,
    {
        deserialize(bytes, SerializationFormat::Toml)
    }
}

impl<T: for<'de> serde::Deserialize<'de>> MultiFormatDeserialize for T {}
