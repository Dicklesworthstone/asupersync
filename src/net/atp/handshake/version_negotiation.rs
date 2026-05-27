//! QUIC Version Negotiation
//!
//! Implements QUIC version negotiation packet handling as specified in RFC 9000.

use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::net::atp::handshake::state_machine::{HandshakeError, QuicVersion};
use crate::types::outcome::Outcome;

/// Version negotiation packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNegotiationPacket {
    /// Source connection ID from server
    pub source_cid: Bytes,
    /// Destination connection ID from original client packet
    pub dest_cid: Bytes,
    /// List of supported versions
    pub supported_versions: Vec<u32>,
}

impl VersionNegotiationPacket {
    /// Create a new version negotiation packet
    pub fn new(source_cid: Bytes, dest_cid: Bytes, supported_versions: Vec<u32>) -> Self {
        Self {
            source_cid,
            dest_cid,
            supported_versions,
        }
    }

    /// Encode packet to wire format
    pub fn encode(&self) -> Outcome<Bytes, HandshakeError> {
        let mut buf = BytesMut::new();

        // Long header form with version = 0 for version negotiation
        let first_byte = 0x80; // Long header
        buf.put_u8(first_byte);
        buf.put_u32(0); // Version = 0 for version negotiation

        // Destination Connection ID
        if self.dest_cid.len() > 255 {
            return Outcome::err(HandshakeError::ConnectionIdError {
                reason: "destination CID too long".to_string(),
            });
        }
        buf.put_u8(self.dest_cid.len() as u8);
        buf.put_slice(&self.dest_cid);

        // Source Connection ID
        if self.source_cid.len() > 255 {
            return Outcome::err(HandshakeError::ConnectionIdError {
                reason: "source CID too long".to_string(),
            });
        }
        buf.put_u8(self.source_cid.len() as u8);
        buf.put_slice(&self.source_cid);

        // Supported versions (4 bytes each)
        for &version in &self.supported_versions {
            buf.put_u32(version);
        }

        Outcome::ok(buf.freeze())
    }

    /// Decode packet from wire format
    pub fn decode(data: &[u8]) -> Outcome<Self, HandshakeError> {
        if data.len() < 7 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "version negotiation packet too short".to_string(),
            });
        }

        let mut buf = data;

        // Check long header form
        let first_byte = buf.get_u8();
        if first_byte & 0x80 == 0 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "not a long header packet".to_string(),
            });
        }

        // Check version is 0
        let version = buf.get_u32();
        if version != 0 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "version negotiation must have version 0".to_string(),
            });
        }

        // Destination Connection ID
        let dest_cid_len = buf.get_u8() as usize;
        if buf.remaining() < dest_cid_len {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "insufficient data for destination CID".to_string(),
            });
        }
        let dest_cid = Bytes::copy_from_slice(&buf[..dest_cid_len]);
        buf.advance(dest_cid_len);

        // Source Connection ID
        if buf.is_empty() {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "missing source CID length".to_string(),
            });
        }
        let source_cid_len = buf.get_u8() as usize;
        if buf.remaining() < source_cid_len {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "insufficient data for source CID".to_string(),
            });
        }
        let source_cid = Bytes::copy_from_slice(&buf[..source_cid_len]);
        buf.advance(source_cid_len);

        // Supported versions
        if buf.remaining() % 4 != 0 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "invalid version list length".to_string(),
            });
        }

        let mut supported_versions = Vec::new();
        while buf.remaining() >= 4 {
            supported_versions.push(buf.get_u32());
        }

        if supported_versions.is_empty() {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "no supported versions".to_string(),
            });
        }

        Outcome::ok(Self {
            source_cid,
            dest_cid,
            supported_versions,
        })
    }

    /// Check if a version is supported
    pub fn supports_version(&self, version: u32) -> bool {
        self.supported_versions.contains(&version)
    }

    /// Select the best supported version from client's attempted version
    pub fn select_version(&self, attempted_version: u32) -> Option<u32> {
        // If the attempted version is supported, use it
        if self.supports_version(attempted_version) {
            return Some(attempted_version);
        }

        // Otherwise, select the highest supported version
        self.supported_versions.iter().max().copied()
    }
}

/// Version negotiation utilities
pub struct VersionNegotiation;

impl VersionNegotiation {
    /// Check if version negotiation is needed
    pub fn is_negotiation_needed(client_version: u32, server_versions: &[u32]) -> bool {
        !server_versions.contains(&client_version)
    }

    /// Create server response for unsupported client version
    pub fn create_server_response(
        client_dest_cid: Bytes,
        server_source_cid: Bytes,
    ) -> VersionNegotiationPacket {
        VersionNegotiationPacket::new(
            server_source_cid,
            client_dest_cid,
            QuicVersion::supported_versions(),
        )
    }

    /// Validate version negotiation packet from server
    pub fn validate_server_response(
        packet: &VersionNegotiationPacket,
        original_dest_cid: &[u8],
        original_source_cid: &[u8],
    ) -> Outcome<(), HandshakeError> {
        // Destination CID must match original source CID
        if packet.dest_cid.as_ref() != original_source_cid {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "version negotiation destination CID mismatch".to_string(),
            });
        }

        // Source CID must match original destination CID
        if packet.source_cid.as_ref() != original_dest_cid {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "version negotiation source CID mismatch".to_string(),
            });
        }

        // Must contain at least one supported version
        let has_supported = packet
            .supported_versions
            .iter()
            .any(|&v| QuicVersion::is_supported(v));

        if !has_supported {
            return Outcome::err(HandshakeError::UnsupportedVersion {
                version: 0, // No compatible version
            });
        }

        Outcome::ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_negotiation_packet_roundtrip() {
        let source_cid = Bytes::from_static(b"server_cid");
        let dest_cid = Bytes::from_static(b"client_cid");
        let supported_versions = vec![0x00000001, 0x12345678];

        let packet = VersionNegotiationPacket::new(
            source_cid.clone(),
            dest_cid.clone(),
            supported_versions.clone(),
        );

        let encoded = packet.encode().unwrap();
        let decoded = VersionNegotiationPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.source_cid, source_cid);
        assert_eq!(decoded.dest_cid, dest_cid);
        assert_eq!(decoded.supported_versions, supported_versions);
    }

    #[test]
    fn test_version_support_check() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![0x00000001, 0x12345678],
        );

        assert!(packet.supports_version(0x00000001));
        assert!(packet.supports_version(0x12345678));
        assert!(!packet.supports_version(0xabcdef00));
    }

    #[test]
    fn test_version_selection() {
        let packet = VersionNegotiationPacket::new(
            Bytes::from_static(b"src"),
            Bytes::from_static(b"dst"),
            vec![0x00000001, 0x12345678],
        );

        // Supported version should be selected
        assert_eq!(packet.select_version(0x00000001), Some(0x00000001));

        // Unsupported version should select highest supported
        assert_eq!(packet.select_version(0xabcdef00), Some(0x12345678));
    }

    #[test]
    fn test_negotiation_needed() {
        let server_versions = vec![0x00000001, 0x12345678];

        assert!(!VersionNegotiation::is_negotiation_needed(
            0x00000001,
            &server_versions
        ));
        assert!(VersionNegotiation::is_negotiation_needed(
            0xabcdef00,
            &server_versions
        ));
    }

    #[test]
    fn test_invalid_packet_decode() {
        // Too short
        let result = VersionNegotiationPacket::decode(&[0x80, 0x00]);
        assert!(result.is_err());

        // Short header (not long header)
        let result = VersionNegotiationPacket::decode(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(result.is_err());

        // Non-zero version
        let result = VersionNegotiationPacket::decode(&[0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
        assert!(result.is_err());
    }
}
