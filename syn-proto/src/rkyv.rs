//! Rkyv serialization helpers and utilities.
//!
//! This module provides utilities for working with Rkyv zero-copy serialization,
//! including validation, conversion, and helper functions.

use crate::error::{ProtoError, ProtoResult, MAX_MESSAGE_SIZE};
use rkyv::validation::validators::DefaultValidator;
use rkyv::{Archive, CheckBytes, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

/// Serializes a value using Rkyv for zero-copy deserialization.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn serialize<T>(value: &T) -> ProtoResult<Vec<u8>>
where
    T: RkyvSerialize<rkyv::ser::serializers::AllocSerializer<256>>,
{
    use rkyv::ser::serializers::AllocSerializer;
    use rkyv::ser::Serializer;

    let mut serializer = AllocSerializer::<256>::default();
    serializer
        .serialize_value(value)
        .map_err(|e| ProtoError::Serialization(e.to_string()))?;
    Ok(serializer.into_serializer().into_inner().to_vec())
}

/// Validates and returns an archived reference without deserialization.
///
/// This is the zero-copy path - the returned reference points directly
/// into the input bytes with no heap allocation.
///
/// # Errors
///
/// Returns [`ProtoError::MessageTooLarge`] if `bytes` exceeds
/// [`MAX_MESSAGE_SIZE`] (checked before any parsing/validation work), or
/// [`ProtoError::Validation`] if validation fails (checksum mismatch,
/// invalid format, etc.).
pub fn validate_archived<'a, T>(bytes: &'a [u8]) -> ProtoResult<&'a T::Archived>
where
    T: Archive,
    T::Archived: CheckBytes<DefaultValidator<'a>>,
{
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(ProtoError::MessageTooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    rkyv::check_archived_root::<T>(bytes).map_err(|e| ProtoError::Validation(e.to_string()))
}

/// Deserializes a value from Rkyv bytes.
///
/// This performs full deserialization (allocates memory). For zero-copy
/// access, use `validate_archived` instead.
///
/// # Errors
///
/// Returns [`ProtoError::MessageTooLarge`] if `bytes` exceeds
/// [`MAX_MESSAGE_SIZE`] (enforced by the underlying `validate_archived` call
/// before any parsing/validation work), or an error if deserialization fails.
pub fn deserialize<T>(bytes: &[u8]) -> ProtoResult<T>
where
    T: Archive,
    T::Archived: for<'a> CheckBytes<DefaultValidator<'a>> + RkyvDeserialize<T, rkyv::Infallible>,
{
    let archived = validate_archived::<T>(bytes)?;
    archived
        .deserialize(&mut rkyv::Infallible)
        .map_err(|e| ProtoError::Deserialization(e.to_string()))
}

/// Helper trait for types that support Rkyv serialization.
pub trait RkyvSerializeExt:
    RkyvSerialize<rkyv::ser::serializers::AllocSerializer<256>> + Sized
{
    /// Serializes to Rkyv bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn to_rkyv(&self) -> ProtoResult<Vec<u8>> {
        serialize(self)
    }
}

impl<T> RkyvSerializeExt for T where
    T: RkyvSerialize<rkyv::ser::serializers::AllocSerializer<256>> + Sized
{
}

/// Helper trait for types that support Rkyv deserialization.
pub trait RkyvDeserializeExt: Archive + Sized {
    /// Validates and returns an archived reference (zero-copy).
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    fn from_rkyv_archived<'a>(bytes: &'a [u8]) -> ProtoResult<&'a Self::Archived>
    where
        Self::Archived: CheckBytes<DefaultValidator<'a>>,
    {
        validate_archived::<Self>(bytes)
    }

    /// Deserializes from Rkyv bytes (full deserialization).
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    fn from_rkyv(bytes: &[u8]) -> ProtoResult<Self>
    where
        Self::Archived:
            for<'a> CheckBytes<DefaultValidator<'a>> + RkyvDeserialize<Self, rkyv::Infallible>,
    {
        deserialize::<Self>(bytes)
    }
}

impl<T> RkyvDeserializeExt for T where T: Archive + Sized {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::PacketHeader;

    #[test]
    fn rkyv_roundtrip() {
        let header =
            PacketHeader::new(12345, 1024, crate::data::PacketFlags::COMPRESSED).with_sequence(42);

        let bytes = serialize(&header).unwrap();

        // Use check_archived_root directly since PacketHeader has check_bytes
        let archived = rkyv::check_archived_root::<PacketHeader>(&bytes).unwrap();

        assert_eq!(archived.session_id, 12345);
        assert_eq!(archived.payload_len, 1024);
        assert_eq!(archived.sequence, 42);

        let deserialized: PacketHeader = deserialize(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn rejects_oversized_messages_before_parsing() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];

        // `ArchivedPacketHeader` doesn't implement `Debug`, so match directly
        // instead of using `unwrap_err` (which requires `T: Debug`).
        match validate_archived::<PacketHeader>(&oversized) {
            Err(ProtoError::MessageTooLarge { size, max }) => {
                assert_eq!(size, MAX_MESSAGE_SIZE + 1);
                assert_eq!(max, MAX_MESSAGE_SIZE);
            }
            other => panic!("expected Err(MessageTooLarge), got {}", other.is_ok()),
        }

        let err = deserialize::<PacketHeader>(&oversized).unwrap_err();
        assert!(matches!(err, ProtoError::MessageTooLarge { .. }));
    }
}
