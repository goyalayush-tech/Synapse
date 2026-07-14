//! Domain types and newtypes for Synapse.
//!
//! In high-reliability systems, "primitive obsession" (using `String` or `u64` for
//! domain concepts) is a source of bugs. This module defines distinct types that
//! cannot be accidentally misused.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A unique identifier for a client connection session.
///
/// Wraps a `u128` to ensure sufficient entropy for distributed systems.
/// The 128-bit space prevents collisions even at massive scale without
/// requiring coordination between nodes.
///
/// # Example
///
/// ```
/// use syn_core::SessionId;
///
/// let session = SessionId::new();
/// println!("Session: {}", session);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(u128);

impl SessionId {
    /// Creates a new random session ID.
    ///
    /// Backed by a UUIDv4 (RFC 4122), which uses the operating system's CSPRNG
    /// for entropy - this avoids the collision risk of hashing a coarse
    /// timestamp.
    #[must_use]
    pub fn new() -> Self {
        Self(rand_u128())
    }

    /// Creates a session ID from a raw u128 value.
    ///
    /// Useful for deserialization or testing with known values.
    #[must_use]
    pub const fn from_raw(value: u128) -> Self {
        Self(value)
    }

    /// Returns the raw u128 value.
    #[must_use]
    pub const fn as_raw(&self) -> u128 {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as lowercase hex for readability
        write!(f, "{:032x}", self.0)
    }
}

/// Generates 128 bits of randomness backed by a UUIDv4.
///
/// Previously this hashed a nanosecond timestamp with `DefaultHasher`, which
/// is not a CSPRNG and could collide under concurrent calls within the same
/// clock tick. `uuid::Uuid::new_v4()` draws from the OS random number
/// generator, so it doesn't have that weakness.
fn rand_u128() -> u128 {
    uuid::Uuid::new_v4().as_u128()
}

/// A port number for network binding.
///
/// Distinct from other numeric types to prevent accidental misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortNumber(u16);

impl PortNumber {
    /// Creates a new port number.
    ///
    /// # Panics
    ///
    /// Does not panic, but port 0 typically means "let the OS choose".
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self(port)
    }

    /// Returns the raw port number.
    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for PortNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_display_is_hex() {
        let session = SessionId::from_raw(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0);
        assert_eq!(session.to_string(), "123456789abcdef0123456789abcdef0");
    }

    #[test]
    fn session_id_roundtrip() {
        let original = SessionId::new();
        let raw = original.as_raw();
        let recovered = SessionId::from_raw(raw);
        assert_eq!(original, recovered);
    }

    #[test]
    fn port_number_display() {
        let port = PortNumber::new(8080);
        assert_eq!(port.to_string(), "8080");
        assert_eq!(port.as_u16(), 8080);
    }
}
