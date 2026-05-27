//! QUIC Retry Packet Implementation
//!
//! Implements QUIC retry packets for address validation and anti-amplification
//! protection as specified in RFC 9000.

use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::net::atp::handshake::state_machine::{HandshakeError, QuicVersion};
use crate::types::outcome::Outcome;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Retry packet structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPacket {
    /// QUIC version
    pub version: u32,
    /// Source connection ID from server
    pub source_cid: Bytes,
    /// Destination connection ID from client
    pub dest_cid: Bytes,
    /// Retry token for address validation
    pub retry_token: Bytes,
    /// Retry integrity tag
    pub integrity_tag: [u8; 16],
}

impl RetryPacket {
    /// Create a new retry packet
    pub fn new(version: u32, source_cid: Bytes, dest_cid: Bytes, retry_token: Bytes) -> Self {
        Self {
            version,
            source_cid,
            dest_cid,
            retry_token,
            integrity_tag: [0; 16],
        }
    }

    /// Encode packet to wire format
    pub fn encode(&self, retry_key: &[u8; 32]) -> Outcome<Bytes, HandshakeError> {
        let mut buf = BytesMut::new();

        // Long header with Retry packet type
        let first_byte = 0x80 | 0x40 | 0x30; // Long header | Fixed bit | Retry packet type
        buf.put_u8(first_byte);
        buf.put_u32(self.version);

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

        // Retry token
        buf.put_slice(&self.retry_token);

        // Calculate and append integrity tag
        let pseudo_packet = self.create_pseudo_retry_packet();
        let tag = match Self::calculate_integrity_tag(&buf, &pseudo_packet, retry_key) {
            Outcome::Ok(tag) => tag,
            Outcome::Err(e) => return Outcome::err(e),
            Outcome::Cancelled(reason) => return Outcome::cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::panicked(payload),
        };
        buf.put_slice(&tag);

        Outcome::ok(buf.freeze())
    }

    /// Decode packet from wire format
    pub fn decode(data: &[u8], retry_key: &[u8; 32]) -> Outcome<Self, HandshakeError> {
        if data.len() < 23 {
            // Minimum: header(1) + version(4) + dcid_len(1) + scid_len(1) + tag(16)
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "retry packet too short".to_string(),
            });
        }

        let mut buf = data;

        // Check packet type
        let first_byte = buf.get_u8();
        if first_byte & 0xF0 != 0xF0 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "not a retry packet".to_string(),
            });
        }

        let version = buf.get_u32();
        if !QuicVersion::is_supported(version) {
            return Outcome::err(HandshakeError::UnsupportedVersion { version });
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

        // Integrity tag is last 16 bytes
        if buf.remaining() < 16 {
            return Outcome::err(HandshakeError::InvalidPacket {
                reason: "missing retry integrity tag".to_string(),
            });
        }

        let retry_token_len = buf.remaining() - 16;
        let retry_token = Bytes::copy_from_slice(&buf[..retry_token_len]);
        buf.advance(retry_token_len);

        let mut integrity_tag = [0u8; 16];
        buf.copy_to_slice(&mut integrity_tag);

        let packet = Self {
            version,
            source_cid,
            dest_cid,
            retry_token,
            integrity_tag,
        };

        // Verify integrity tag
        let packet_without_tag = &data[..data.len() - 16];
        let pseudo_packet = packet.create_pseudo_retry_packet();
        let expected_tag =
            match Self::calculate_integrity_tag(packet_without_tag, &pseudo_packet, retry_key) {
                Outcome::Ok(tag) => tag,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };

        if integrity_tag != expected_tag {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        Outcome::ok(packet)
    }

    /// Create pseudo retry packet for integrity tag calculation
    fn create_pseudo_retry_packet(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.dest_cid.len() as u8);
        buf.put_slice(&self.dest_cid);
        buf.freeze()
    }

    /// Calculate retry packet integrity tag
    fn calculate_integrity_tag(
        retry_packet: &[u8],
        pseudo_packet: &[u8],
        key: &[u8; 32],
    ) -> Outcome<[u8; 16], HandshakeError> {
        let mut mac = match HmacSha256::new_from_slice(key) {
            Ok(mac) => mac,
            Err(_) => {
                return Outcome::err(HandshakeError::ProtectionError {
                    reason: "invalid retry key".to_string(),
                });
            }
        };

        mac.update(pseudo_packet);
        mac.update(retry_packet);

        let result = mac.finalize();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&result.into_bytes()[..16]);
        Outcome::ok(tag)
    }
}

/// Retry token generator and validator
pub struct RetryTokenHandler {
    /// Secret key for token generation
    secret_key: [u8; 32],
    /// Token lifetime in seconds
    token_lifetime: u64,
}

impl RetryTokenHandler {
    /// Create a new retry token handler
    pub fn new(secret_key: [u8; 32], token_lifetime: u64) -> Self {
        Self {
            secret_key,
            token_lifetime,
        }
    }

    /// Generate a retry token for client validation
    pub fn generate_token(
        &self,
        client_addr: std::net::SocketAddr,
        original_dest_cid: &[u8],
    ) -> Outcome<Bytes, HandshakeError> {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => {
                return Outcome::err(HandshakeError::ProtectionError {
                    reason: "system time error".to_string(),
                });
            }
        };

        let mut token = BytesMut::new();

        // Timestamp (8 bytes)
        token.put_u64(now);

        // Client address
        match client_addr {
            std::net::SocketAddr::V4(addr) => {
                token.put_u8(4); // IPv4 marker
                token.put_slice(&addr.ip().octets());
                token.put_u16(addr.port());
            }
            std::net::SocketAddr::V6(addr) => {
                token.put_u8(6); // IPv6 marker
                token.put_slice(&addr.ip().octets());
                token.put_u16(addr.port());
            }
        }

        // Original destination CID length and value
        token.put_u8(original_dest_cid.len() as u8);
        token.put_slice(original_dest_cid);

        // Calculate HMAC
        let mut mac = match HmacSha256::new_from_slice(&self.secret_key) {
            Ok(mac) => mac,
            Err(_) => {
                return Outcome::err(HandshakeError::ProtectionError {
                    reason: "invalid token key".to_string(),
                });
            }
        };
        mac.update(&token);
        let hmac_result = mac.finalize();

        // Append HMAC to token
        token.put_slice(&hmac_result.into_bytes());

        Outcome::ok(token.freeze())
    }

    /// Validate a retry token
    pub fn validate_token(
        &self,
        token: &[u8],
        client_addr: std::net::SocketAddr,
        original_dest_cid: &[u8],
    ) -> Outcome<(), HandshakeError> {
        if token.len() < 32 {
            // Minimum size: timestamp(8) + addr(6+) + cid_len(1) + hmac(32)
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        // Split token and HMAC
        let (token_data, hmac_bytes) = token.split_at(token.len() - 32);

        // Verify HMAC
        let mut mac = match HmacSha256::new_from_slice(&self.secret_key) {
            Ok(mac) => mac,
            Err(_) => {
                return Outcome::err(HandshakeError::ProtectionError {
                    reason: "invalid token key".to_string(),
                });
            }
        };
        mac.update(token_data);

        if mac.verify_slice(hmac_bytes).is_err() {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        let mut buf = token_data;

        // Check timestamp
        if buf.len() < 8 {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }
        let timestamp = (&mut buf).get_u64();
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => {
                return Outcome::err(HandshakeError::ProtectionError {
                    reason: "system time error".to_string(),
                });
            }
        };

        if now.saturating_sub(timestamp) > self.token_lifetime {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        // Validate client address
        if buf.is_empty() {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }
        let addr_type = buf.get_u8();

        let expected_addr_bytes = match (addr_type, client_addr) {
            (4, std::net::SocketAddr::V4(addr)) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
                bytes
            }
            (6, std::net::SocketAddr::V6(addr)) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&addr.ip().octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
                bytes
            }
            _ => return Outcome::err(HandshakeError::InvalidRetryToken),
        };

        if buf.len() < expected_addr_bytes.len() {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        let token_addr_bytes = &buf[..expected_addr_bytes.len()];
        if token_addr_bytes != expected_addr_bytes {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }
        buf.advance(expected_addr_bytes.len());

        // Validate original destination CID
        if buf.is_empty() {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }
        let cid_len = buf.get_u8() as usize;
        if buf.len() < cid_len {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }
        let token_cid = &buf[..cid_len];
        if token_cid != original_dest_cid {
            return Outcome::err(HandshakeError::InvalidRetryToken);
        }

        Outcome::ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_retry_packet_roundtrip() {
        let retry_key = [0u8; 32];
        let packet = RetryPacket::new(
            QuicVersion::V1 as u32,
            Bytes::from_static(b"server_cid"),
            Bytes::from_static(b"client_cid"),
            Bytes::from_static(b"retry_token_data"),
        );

        let encoded = packet.encode(&retry_key).unwrap();
        let decoded = RetryPacket::decode(&encoded, &retry_key).unwrap();

        assert_eq!(decoded.version, packet.version);
        assert_eq!(decoded.source_cid, packet.source_cid);
        assert_eq!(decoded.dest_cid, packet.dest_cid);
        assert_eq!(decoded.retry_token, packet.retry_token);
    }

    #[test]
    fn test_retry_token_roundtrip() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300); // 5 minute lifetime

        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let original_dest_cid = b"original_cid";

        let token = handler
            .generate_token(client_addr, original_dest_cid)
            .unwrap();
        let result = handler.validate_token(&token, client_addr, original_dest_cid);

        assert!(result.is_ok());
    }

    #[test]
    fn test_retry_token_invalid_address() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300);

        let client_addr1 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let client_addr2 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 12345);
        let original_dest_cid = b"original_cid";

        let token = handler
            .generate_token(client_addr1, original_dest_cid)
            .unwrap();
        let result = handler.validate_token(&token, client_addr2, original_dest_cid);

        assert!(result.is_err());
    }

    #[test]
    fn test_retry_token_invalid_cid() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300);

        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let original_dest_cid1 = b"original_cid1";
        let original_dest_cid2 = b"original_cid2";

        let token = handler
            .generate_token(client_addr, original_dest_cid1)
            .unwrap();
        let result = handler.validate_token(&token, client_addr, original_dest_cid2);

        assert!(result.is_err());
    }
}
