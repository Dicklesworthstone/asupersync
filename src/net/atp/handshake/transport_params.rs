//! QUIC Transport Parameters
//!
//! Implements QUIC transport parameter encoding, decoding, and validation
//! as specified in RFC 9000.

use crate::bytes::{Bytes, BytesMut};
use crate::net::atp::handshake::state_machine::HandshakeError;
use crate::net::atp::protocol::varint::VarInt;
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::time::Duration;

/// Standard QUIC transport parameter IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum TransportParamId {
    /// Original destination connection ID (0x00)
    OriginalDestinationConnectionId = 0x00,
    /// Maximum idle timeout (0x01)
    MaxIdleTimeout = 0x01,
    /// Stateless reset token (0x02)
    StatelessResetToken = 0x02,
    /// Maximum UDP payload size (0x03)
    MaxUdpPayloadSize = 0x03,
    /// Initial maximum data (0x04)
    InitialMaxData = 0x04,
    /// Initial maximum stream data (bidirectional, local) (0x05)
    InitialMaxStreamDataBidiLocal = 0x05,
    /// Initial maximum stream data (bidirectional, remote) (0x06)
    InitialMaxStreamDataBidiRemote = 0x06,
    /// Initial maximum stream data (unidirectional) (0x07)
    InitialMaxStreamDataUni = 0x07,
    /// Initial maximum streams (bidirectional) (0x08)
    InitialMaxStreamsBidi = 0x08,
    /// Initial maximum streams (unidirectional) (0x09)
    InitialMaxStreamsUni = 0x09,
    /// ACK delay exponent (0x0a)
    AckDelayExponent = 0x0a,
    /// Maximum ACK delay (0x0b)
    MaxAckDelay = 0x0b,
    /// Disable active migration (0x0c)
    DisableActiveMigration = 0x0c,
    /// Preferred address (0x0d)
    PreferredAddress = 0x0d,
    /// Active connection ID limit (0x0e)
    ActiveConnectionIdLimit = 0x0e,
    /// Initial source connection ID (0x0f)
    InitialSourceConnectionId = 0x0f,
    /// Retry source connection ID (0x10)
    RetrySourceConnectionId = 0x10,
    /// Maximum DATAGRAM frame size (0x20, RFC 9221)
    MaxDatagramFrameSize = 0x20,
}

impl TransportParamId {
    /// Convert to VarInt for wire encoding
    pub fn to_varint(self) -> VarInt {
        VarInt::from_u64_unchecked(self as u64)
    }

    /// Parse from VarInt
    pub fn from_varint(varint: VarInt) -> Option<Self> {
        match varint.value() {
            0x00 => Some(Self::OriginalDestinationConnectionId),
            0x01 => Some(Self::MaxIdleTimeout),
            0x02 => Some(Self::StatelessResetToken),
            0x03 => Some(Self::MaxUdpPayloadSize),
            0x04 => Some(Self::InitialMaxData),
            0x05 => Some(Self::InitialMaxStreamDataBidiLocal),
            0x06 => Some(Self::InitialMaxStreamDataBidiRemote),
            0x07 => Some(Self::InitialMaxStreamDataUni),
            0x08 => Some(Self::InitialMaxStreamsBidi),
            0x09 => Some(Self::InitialMaxStreamsUni),
            0x0a => Some(Self::AckDelayExponent),
            0x0b => Some(Self::MaxAckDelay),
            0x0c => Some(Self::DisableActiveMigration),
            0x0d => Some(Self::PreferredAddress),
            0x0e => Some(Self::ActiveConnectionIdLimit),
            0x0f => Some(Self::InitialSourceConnectionId),
            0x10 => Some(Self::RetrySourceConnectionId),
            0x20 => Some(Self::MaxDatagramFrameSize),
            _ => None,
        }
    }

    /// Check if parameter requires a value
    pub fn requires_value(self) -> bool {
        !matches!(self, Self::DisableActiveMigration)
    }
}

/// Transport parameter value
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportParamValue {
    /// Integer value
    Integer(u64),
    /// Byte array value
    Bytes(Bytes),
    /// No value (for flag parameters)
    Empty,
}

impl TransportParamValue {
    /// Encode value to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            Self::Integer(value) => {
                let mut buf = BytesMut::new();
                let varint = VarInt::from_u64_unchecked(*value);
                match varint.encode(&mut buf) {
                    Outcome::Ok(()) => {}
                    Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                        unreachable!("validated varint encoding must succeed")
                    }
                }
                buf.freeze()
            }
            Self::Bytes(bytes) => bytes.clone(),
            Self::Empty => Bytes::new(),
        }
    }

    /// Decode integer value
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Bytes(bytes) if !bytes.is_empty() => {
                let mut buf = BytesMut::from(&bytes[..]);
                match VarInt::decode(&mut buf) {
                    Outcome::Ok(Some(value)) => Some(value.value()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Decode bytes value
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}

/// Transport parameters collection
#[derive(Debug, Clone)]
pub struct TransportParameters {
    /// Parameter values indexed by ID
    params: HashMap<u64, TransportParamValue>,
}

impl TransportParameters {
    /// Create new empty transport parameters
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    /// Create default client transport parameters
    pub fn client_defaults() -> Self {
        let mut params = Self::new();

        // Set reasonable defaults
        params.set_integer(TransportParamId::MaxIdleTimeout, 30_000); // 30 seconds
        params.set_integer(TransportParamId::MaxUdpPayloadSize, 65527); // Maximum IPv6 UDP payload
        params.set_integer(TransportParamId::InitialMaxData, 1024 * 1024); // 1MB
        params.set_integer(TransportParamId::InitialMaxStreamDataBidiLocal, 256 * 1024); // 256KB
        params.set_integer(TransportParamId::InitialMaxStreamDataBidiRemote, 256 * 1024); // 256KB
        params.set_integer(TransportParamId::InitialMaxStreamDataUni, 256 * 1024); // 256KB
        params.set_integer(TransportParamId::InitialMaxStreamsBidi, 100);
        params.set_integer(TransportParamId::InitialMaxStreamsUni, 100);
        params.set_integer(TransportParamId::AckDelayExponent, 3);
        params.set_integer(TransportParamId::MaxAckDelay, 25); // 25ms
        params.set_integer(TransportParamId::ActiveConnectionIdLimit, 8);

        params
    }

    /// Create default server transport parameters
    pub fn server_defaults() -> Self {
        let mut params = Self::client_defaults();

        let mut stateless_reset_token = [0_u8; 16];
        getrandom::fill(&mut stateless_reset_token)
            .expect("OS entropy is required for QUIC stateless reset tokens");
        params.set_bytes(
            TransportParamId::StatelessResetToken,
            Bytes::copy_from_slice(&stateless_reset_token),
        );

        params
    }

    /// Set integer parameter
    pub fn set_integer(&mut self, id: TransportParamId, value: u64) {
        self.params
            .insert(id as u64, TransportParamValue::Integer(value));
    }

    /// Set bytes parameter
    pub fn set_bytes(&mut self, id: TransportParamId, value: Bytes) {
        self.params
            .insert(id as u64, TransportParamValue::Bytes(value));
    }

    /// Set flag parameter (empty value)
    pub fn set_flag(&mut self, id: TransportParamId) {
        self.params.insert(id as u64, TransportParamValue::Empty);
    }

    /// Get parameter value
    pub fn get(&self, id: TransportParamId) -> Option<&TransportParamValue> {
        self.params.get(&(id as u64))
    }

    /// Get integer parameter
    pub fn get_integer(&self, id: TransportParamId) -> Option<u64> {
        self.get(id)?.as_integer()
    }

    /// Get bytes parameter
    pub fn get_bytes(&self, id: TransportParamId) -> Option<&Bytes> {
        self.get(id)?.as_bytes()
    }

    /// Check if flag parameter is set
    pub fn has_flag(&self, id: TransportParamId) -> bool {
        matches!(self.get(id), Some(TransportParamValue::Empty))
    }

    /// Encode transport parameters for TLS extension
    pub fn encode(&self) -> Outcome<Bytes, HandshakeError> {
        let mut buf = BytesMut::new();

        for (&param_id, param_value) in &self.params {
            // Parameter ID
            let id_varint = match VarInt::new(param_id) {
                Outcome::Ok(varint) => varint,
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "parameter ID too large".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };
            match id_varint.encode(&mut buf) {
                Outcome::Ok(()) => {}
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "failed to encode parameter ID".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }

            // Parameter value
            let value_bytes = param_value.encode();
            let length_varint = match VarInt::new(value_bytes.len() as u64) {
                Outcome::Ok(varint) => varint,
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "parameter value too large".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };
            match length_varint.encode(&mut buf) {
                Outcome::Ok(()) => {}
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "failed to encode parameter length".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
            buf.put_slice(&value_bytes);
        }

        Outcome::ok(buf.freeze())
    }

    /// Decode transport parameters from TLS extension
    pub fn decode(data: &[u8]) -> Outcome<Self, HandshakeError> {
        let mut params = Self::new();
        let mut buf = BytesMut::from(data);

        while !buf.is_empty() {
            // Parse parameter ID
            let id_varint = match VarInt::decode(&mut buf) {
                Outcome::Ok(Some(varint)) => varint,
                Outcome::Ok(None) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id: 0,
                        reason: "truncated parameter ID".to_string(),
                    });
                }
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id: 0,
                        reason: "failed to decode parameter ID".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };

            let param_id = id_varint.value();

            // Check for duplicate parameter
            if params.params.contains_key(&param_id) {
                return Outcome::err(HandshakeError::DuplicateTransportParam { param_id });
            }

            // Parse parameter length
            let length_varint = match VarInt::decode(&mut buf) {
                Outcome::Ok(Some(varint)) => varint,
                Outcome::Ok(None) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "truncated parameter length".to_string(),
                    });
                }
                Outcome::Err(_) => {
                    return Outcome::err(HandshakeError::InvalidTransportParam {
                        param_id,
                        reason: "failed to decode parameter length".to_string(),
                    });
                }
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };

            let length = length_varint.value() as usize;
            if buf.len() < length {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id,
                    reason: "truncated parameter value".to_string(),
                });
            }

            // Parse parameter value
            let value_bytes = if length == 0 {
                TransportParamValue::Empty
            } else {
                let bytes = buf.split_to(length).freeze();

                // For known parameters that should be integers, decode as integer
                if let Some(param_type) = TransportParamId::from_varint(id_varint) {
                    if param_type.requires_value()
                        && param_type != TransportParamId::StatelessResetToken
                        && param_type != TransportParamId::OriginalDestinationConnectionId
                        && param_type != TransportParamId::InitialSourceConnectionId
                        && param_type != TransportParamId::RetrySourceConnectionId
                        && param_type != TransportParamId::PreferredAddress
                    {
                        // Decode as integer
                        let mut value_buf = BytesMut::from(&bytes[..]);
                        if let Outcome::Ok(Some(int_varint)) = VarInt::decode(&mut value_buf) {
                            TransportParamValue::Integer(int_varint.value())
                        } else {
                            TransportParamValue::Bytes(bytes)
                        }
                    } else {
                        TransportParamValue::Bytes(bytes)
                    }
                } else {
                    TransportParamValue::Bytes(bytes)
                }
            };

            params.params.insert(param_id, value_bytes);
        }

        Outcome::ok(params)
    }

    /// Validate transport parameters
    pub fn validate(&self) -> Outcome<(), HandshakeError> {
        // Validate ACK delay exponent
        if let Some(exp) = self.get_integer(TransportParamId::AckDelayExponent) {
            if exp > 20 {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id: TransportParamId::AckDelayExponent as u64,
                    reason: "ACK delay exponent too large".to_string(),
                });
            }
        }

        // Validate maximum ACK delay
        if let Some(delay) = self.get_integer(TransportParamId::MaxAckDelay) {
            if delay >= (1u64 << 14) {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id: TransportParamId::MaxAckDelay as u64,
                    reason: "maximum ACK delay too large".to_string(),
                });
            }
        }

        // Validate maximum UDP payload size
        if let Some(size) = self.get_integer(TransportParamId::MaxUdpPayloadSize) {
            if size < 1200 {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id: TransportParamId::MaxUdpPayloadSize as u64,
                    reason: "maximum UDP payload size too small".to_string(),
                });
            }
        }

        // Validate active connection ID limit
        if let Some(limit) = self.get_integer(TransportParamId::ActiveConnectionIdLimit) {
            if limit < 2 {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id: TransportParamId::ActiveConnectionIdLimit as u64,
                    reason: "active connection ID limit too small".to_string(),
                });
            }
        }

        // Validate stateless reset token length
        if let Some(token) = self.get_bytes(TransportParamId::StatelessResetToken) {
            if token.len() != 16 {
                return Outcome::err(HandshakeError::InvalidTransportParam {
                    param_id: TransportParamId::StatelessResetToken as u64,
                    reason: "stateless reset token must be 16 bytes".to_string(),
                });
            }
        }

        Outcome::ok(())
    }

    /// Get maximum idle timeout as duration
    pub fn max_idle_timeout(&self) -> Option<Duration> {
        self.get_integer(TransportParamId::MaxIdleTimeout)
            .map(Duration::from_millis)
    }
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::BufMut;

    #[test]
    fn test_transport_params_roundtrip() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxIdleTimeout, 30000);
        params.set_integer(TransportParamId::InitialMaxData, 1048576);
        params.set_flag(TransportParamId::DisableActiveMigration);
        params.set_bytes(
            TransportParamId::StatelessResetToken,
            Bytes::from_static(b"0123456789abcdef"),
        );

        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();

        assert_eq!(
            decoded.get_integer(TransportParamId::MaxIdleTimeout),
            Some(30000)
        );
        assert_eq!(
            decoded.get_integer(TransportParamId::InitialMaxData),
            Some(1048576)
        );
        assert!(decoded.has_flag(TransportParamId::DisableActiveMigration));
        assert_eq!(
            decoded.get_bytes(TransportParamId::StatelessResetToken),
            Some(&Bytes::from_static(b"0123456789abcdef"))
        );
    }

    #[test]
    fn test_client_defaults() {
        let params = TransportParameters::client_defaults();

        assert!(
            params
                .get_integer(TransportParamId::MaxIdleTimeout)
                .is_some()
        );
        assert!(
            params
                .get_integer(TransportParamId::InitialMaxData)
                .is_some()
        );
        assert!(!params.has_flag(TransportParamId::DisableActiveMigration));
    }

    #[test]
    fn test_validation() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::AckDelayExponent, 25); // Too large

        assert!(params.validate().is_err());

        params.set_integer(TransportParamId::AckDelayExponent, 3); // Valid
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_duplicate_parameter() {
        let mut buf = BytesMut::new();

        // Add same parameter twice
        VarInt::new(0x01).unwrap().encode(&mut buf).unwrap(); // MaxIdleTimeout
        VarInt::new(2).unwrap().encode(&mut buf).unwrap(); // Length
        buf.put_u16(30000);

        VarInt::new(0x01).unwrap().encode(&mut buf).unwrap(); // MaxIdleTimeout again
        VarInt::new(2).unwrap().encode(&mut buf).unwrap(); // Length
        buf.put_u16(60000);

        let result = TransportParameters::decode(&buf);
        assert!(matches!(
            result,
            Outcome::Err(HandshakeError::DuplicateTransportParam { .. })
        ));
    }

    #[test]
    fn test_max_idle_timeout_duration() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxIdleTimeout, 5000);

        assert_eq!(params.max_idle_timeout(), Some(Duration::from_millis(5000)));
    }

    #[test]
    fn test_max_datagram_frame_size_roundtrip() {
        let mut params = TransportParameters::new();
        params.set_integer(TransportParamId::MaxDatagramFrameSize, 1200);

        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();

        assert_eq!(
            decoded.get_integer(TransportParamId::MaxDatagramFrameSize),
            Some(1200)
        );
    }
}
