//! Data plane protocol definitions with zero-copy serialization.
//!
//! These structures are used in the "hot path" of packet processing.
//! They use Rkyv for zero-copy deserialization - the serialized binary
//! representation is identical to the in-memory representation, making
//! "deserialization" a simple pointer cast with validation.
//!
//! ## Why Rkyv over Serde?
//!
//! For high-frequency packet headers:
//! - Serde/JSON: Parse bytes → Allocate memory → Populate struct
//! - Rkyv: Validate checksum → Cast pointer → Done (no allocation!)
//!
//! This eliminates GC pressure and memory fragmentation in the data plane.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

/// Flags for packet metadata.
///
/// Stored as a single byte for wire efficiency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, RkyvSerialize, RkyvDeserialize)]
#[archive(check_bytes)]
#[repr(transparent)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Payload is compressed (e.g., zstd).
    pub const COMPRESSED: Self = Self(1 << 0);

    /// Payload is encrypted.
    pub const ENCRYPTED: Self = Self(1 << 1);

    /// This is a continuation of a fragmented message.
    pub const FRAGMENT: Self = Self(1 << 2);

    /// This is the final fragment of a message.
    pub const FINAL_FRAGMENT: Self = Self(1 << 3);

    /// Requires acknowledgment.
    pub const REQUIRES_ACK: Self = Self(1 << 4);

    /// Creates flags from a raw byte.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw byte value.
    #[must_use]
    pub const fn as_raw(&self) -> u8 {
        self.0
    }

    /// Combines two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Checks if a specific flag is set.
    #[must_use]
    pub const fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// High-frequency packet header for the data plane.
///
/// This structure is designed for zero-copy access using Rkyv.
/// It contains the minimum metadata needed to route and process packets.
///
/// ## Wire Format (16 bytes with alignment)
///
/// ```text
/// ┌────────────────────────────────────────────────────────┐
/// │ session_id: u64 (8 bytes)                              │
/// ├────────────────────────────────────────────────────────┤
/// │ payload_len: u32 (4 bytes)                             │
/// ├────────────────────────────────────────────────────────┤
/// │ sequence: u8 │ flags: u8 │ _reserved: [u8; 2]          │
/// └────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, RkyvSerialize, RkyvDeserialize)]
#[archive(check_bytes)]
#[repr(C)] // Ensure predictable memory layout
pub struct PacketHeader {
    /// Session identifier (lower 64 bits of full SessionId for wire efficiency).
    pub session_id: u64,

    /// Length of the payload following this header.
    /// Using u32 for alignment and to support payloads up to 4GB.
    pub payload_len: u32,

    /// Sequence number for ordering within a session (wraps at 255).
    pub sequence: u8,

    /// Packet flags (compression, encryption, fragmentation).
    pub flags: PacketFlags,

    /// Reserved for future use (maintains 8-byte alignment).
    _reserved: [u8; 2],
}

impl PacketHeader {
    /// The size of the header in bytes.
    pub const SIZE: usize = 16;

    /// Creates a new packet header.
    #[must_use]
    pub const fn new(session_id: u64, payload_len: u32, flags: PacketFlags) -> Self {
        Self {
            session_id,
            payload_len,
            sequence: 0,
            flags,
            _reserved: [0; 2],
        }
    }

    /// Creates a header with a specific sequence number.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: u8) -> Self {
        self.sequence = sequence;
        self
    }

    /// Returns `true` if the payload is compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags.contains(PacketFlags::COMPRESSED)
    }

    /// Returns `true` if the payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.flags.contains(PacketFlags::ENCRYPTED)
    }

    /// Returns `true` if this is part of a fragmented message.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.flags.contains(PacketFlags::FRAGMENT)
    }
}

/// Intent event for semantic storage.
///
/// This is the primary unit of data in Synapse - not opaque bytes,
/// but structured "intent" that can be indexed and queried semantically.
#[derive(Debug, Clone, PartialEq, Eq, Archive, RkyvSerialize, RkyvDeserialize)]
#[archive(check_bytes)]
pub struct IntentEvent {
    /// Unique identifier for this event.
    pub event_id: u64,

    /// Session that produced this event.
    pub session_id: u64,

    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,

    /// The intent category (e.g., "auth.modify", "data.query").
    pub intent_type: String,

    /// Human-readable description of the intent.
    pub description: String,

    /// The raw payload data.
    pub payload: Vec<u8>,
}

impl IntentEvent {
    /// Creates a new intent event.
    #[must_use]
    pub fn new(
        event_id: u64,
        session_id: u64,
        intent_type: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event_id,
            session_id,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            intent_type: intent_type.into(),
            description: description.into(),
            payload: Vec::new(),
        }
    }

    /// Attaches a payload to the event.
    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_header_size() {
        // Verify our size constant matches reality
        assert_eq!(
            std::mem::size_of::<PacketHeader>(),
            PacketHeader::SIZE,
            "PacketHeader size mismatch"
        );
    }

    #[test]
    fn flags_operations() {
        let flags = PacketFlags::COMPRESSED.union(PacketFlags::ENCRYPTED);
        assert!(flags.contains(PacketFlags::COMPRESSED));
        assert!(flags.contains(PacketFlags::ENCRYPTED));
        assert!(!flags.contains(PacketFlags::FRAGMENT));
    }

    #[test]
    fn header_serialization_roundtrip() {
        use rkyv::ser::serializers::AllocSerializer;
        use rkyv::ser::Serializer;
        use rkyv::Deserialize;

        let header = PacketHeader::new(12345, 1024, PacketFlags::COMPRESSED).with_sequence(42);

        // Serialize
        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&header).expect("serialize");
        let bytes = serializer.into_serializer().into_inner();

        // Zero-copy access
        let archived = rkyv::check_archived_root::<PacketHeader>(&bytes).expect("validation");

        assert_eq!(archived.session_id, 12345);
        assert_eq!(archived.payload_len, 1024);
        assert_eq!(archived.sequence, 42);

        // Full deserialization (if needed)
        let deserialized: PacketHeader = archived
            .deserialize(&mut rkyv::Infallible)
            .expect("deserialize");
        assert_eq!(header, deserialized);
    }
}
