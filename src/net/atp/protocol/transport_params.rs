//! QUIC Transport Parameter Parsing and Validation
//!
//! Implements QUIC transport parameter encoding, decoding, and validation
//! as specified in RFC 9000. Handles parameter duplicates, invalid values,
//! missing required parameters, forbidden combinations, and unknown extension
//! preservation.

use crate::bytes::{BufMut, Bytes, BytesMut};
use crate::net::atp::protocol::varint::{VarInt, VarIntError};
use crate::types::outcome::Outcome;
use std::collections::HashMap;

/// QUIC Transport Parameter IDs from RFC 9000
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u64)]
pub enum TransportParameterId {
    /// original_destination_connection_id (0x00)
    OriginalDestinationConnectionId = 0x00,
    /// max_idle_timeout (0x01)
    MaxIdleTimeout = 0x01,
    /// stateless_reset_token (0x02)
    StatelessResetToken = 0x02,
    /// max_udp_payload_size (0x03)
    MaxUdpPayloadSize = 0x03,
    /// initial_max_data (0x04)
    InitialMaxData = 0x04,
    /// initial_max_stream_data_bidi_local (0x05)
    InitialMaxStreamDataBidiLocal = 0x05,
    /// initial_max_stream_data_bidi_remote (0x06)
    InitialMaxStreamDataBidiRemote = 0x06,
    /// initial_max_stream_data_uni (0x07)
    InitialMaxStreamDataUni = 0x07,
    /// initial_max_streams_bidi (0x08)
    InitialMaxStreamsBidi = 0x08,
    /// initial_max_streams_uni (0x09)
    InitialMaxStreamsUni = 0x09,
    /// ack_delay_exponent (0x0a)
    AckDelayExponent = 0x0a,
    /// max_ack_delay (0x0b)
    MaxAckDelay = 0x0b,
    /// disable_active_migration (0x0c)
    DisableActiveMigration = 0x0c,
    /// preferred_address (0x0d)
    PreferredAddress = 0x0d,
    /// active_connection_id_limit (0x0e)
    ActiveConnectionIdLimit = 0x0e,
    /// initial_source_connection_id (0x0f)
    InitialSourceConnectionId = 0x0f,
    /// retry_source_connection_id (0x10)
    RetrySourceConnectionId = 0x10,
}

impl TransportParameterId {
    /// Convert to VarInt for wire format
    pub fn to_varint(self) -> VarInt {
        match VarInt::new(self as u64) {
            Outcome::Ok(varint) => varint,
            _ => panic!("transport parameter ID fits in varint"),
        }
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
            _ => None,
        }
    }

    /// Check if parameter is required for clients
    pub fn is_required_for_client(self) -> bool {
        match self {
            Self::InitialMaxData
            | Self::InitialMaxStreamDataBidiLocal
            | Self::InitialMaxStreamDataBidiRemote
            | Self::InitialMaxStreamDataUni
            | Self::InitialMaxStreamsBidi
            | Self::InitialMaxStreamsUni => true,
            _ => false,
        }
    }

    /// Check if parameter is required for servers
    pub fn is_required_for_server(self) -> bool {
        match self {
            Self::InitialMaxData
            | Self::InitialMaxStreamDataBidiLocal
            | Self::InitialMaxStreamDataBidiRemote
            | Self::InitialMaxStreamDataUni
            | Self::InitialMaxStreamsBidi
            | Self::InitialMaxStreamsUni => true,
            _ => false,
        }
    }

    /// Check if parameter is forbidden for clients
    pub fn is_forbidden_for_client(self) -> bool {
        match self {
            Self::StatelessResetToken
            | Self::PreferredAddress
            | Self::OriginalDestinationConnectionId
            | Self::RetrySourceConnectionId => true,
            _ => false,
        }
    }

    /// Check if parameter is forbidden for servers
    pub fn is_forbidden_for_server(self) -> bool {
        match self {
            Self::OriginalDestinationConnectionId | Self::RetrySourceConnectionId => false,
            _ => false,
        }
    }
}

/// Transport parameter values
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportParameterValue {
    /// Variable-length integer value
    VarInt(VarInt),
    /// Raw byte value
    Bytes(Bytes),
    /// Zero-length parameter (flag)
    Empty,
}

impl TransportParameterValue {
    /// Get as VarInt if possible
    pub fn as_varint(&self) -> Option<VarInt> {
        match self {
            TransportParameterValue::VarInt(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as bytes if possible
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            TransportParameterValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        matches!(self, TransportParameterValue::Empty)
    }

    /// Encode to buffer
    pub fn encode<B: BufMut>(
        &self,
        parameter: TransportParameterId,
        buf: &mut B,
    ) -> Result<(), TransportParameterError> {
        match self {
            TransportParameterValue::VarInt(v) => {
                let mut temp = BytesMut::new();
                match v.encode(&mut temp) {
                    Outcome::Ok(()) => {}
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: 0,
                            reason: "VarInt encode failed".to_string(),
                        });
                    }
                }
                let len_varint = match VarInt::new(temp.len() as u64) {
                    Outcome::Ok(varint) => varint,
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: temp.len() as u64,
                            reason: "Invalid length".to_string(),
                        });
                    }
                };
                let mut len_buf = BytesMut::new();
                match len_varint.encode(&mut len_buf) {
                    Outcome::Ok(()) => buf.put_slice(&len_buf),
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: 0,
                            reason: "Length varint encode failed".to_string(),
                        });
                    }
                }
                buf.put_slice(&temp);
            }
            TransportParameterValue::Bytes(bytes) => {
                let len_varint = match VarInt::new(bytes.len() as u64) {
                    Outcome::Ok(varint) => varint,
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: bytes.len() as u64,
                            reason: "Bytes length too large".to_string(),
                        });
                    }
                };
                let mut len_buf = BytesMut::new();
                match len_varint.encode(&mut len_buf) {
                    Outcome::Ok(()) => buf.put_slice(&len_buf),
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: 0,
                            reason: "Length varint encode failed".to_string(),
                        });
                    }
                }
                buf.put_slice(bytes);
            }
            TransportParameterValue::Empty => {
                let zero_varint = match VarInt::new(0) {
                    Outcome::Ok(varint) => varint,
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: 0,
                            reason: "Zero varint creation failed".to_string(),
                        });
                    }
                };
                let mut zero_buf = BytesMut::new();
                match zero_varint.encode(&mut zero_buf) {
                    Outcome::Ok(()) => buf.put_slice(&zero_buf),
                    _ => {
                        return Err(TransportParameterError::InvalidParameterValue {
                            parameter,
                            value: 0,
                            reason: "Zero varint encode failed".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Decode from buffer
    pub fn decode(
        buf: &mut BytesMut,
        expected_type: TransportParameterValueType,
    ) -> Result<Self, TransportParameterError> {
        let length = match VarInt::decode(buf) {
            Outcome::Ok(Some(varint)) => varint,
            Outcome::Ok(None) => return Err(TransportParameterError::UnexpectedEof),
            _ => {
                return Err(TransportParameterError::VarInt(
                    VarIntError::InvalidEncoding,
                ));
            }
        };

        if buf.len() < length.value() as usize {
            return Err(TransportParameterError::UnexpectedEof);
        }

        match expected_type {
            TransportParameterValueType::VarInt => {
                if length.value() == 0 {
                    return Err(TransportParameterError::InvalidParameterLength {
                        parameter: "varint parameter".to_string(),
                        expected_min: 1,
                        actual: 0,
                    });
                }
                let mut param_buf = buf.split_to(length.value() as usize);
                let varint = match VarInt::decode(&mut param_buf) {
                    Outcome::Ok(Some(varint)) => varint,
                    Outcome::Ok(None) => return Err(TransportParameterError::UnexpectedEof),
                    _ => {
                        return Err(TransportParameterError::VarInt(
                            VarIntError::InvalidEncoding,
                        ));
                    }
                };
                Ok(TransportParameterValue::VarInt(varint))
            }
            TransportParameterValueType::Bytes => {
                let bytes = buf.split_to(length.value() as usize).freeze();
                Ok(TransportParameterValue::Bytes(bytes))
            }
            TransportParameterValueType::Empty => {
                if length.value() != 0 {
                    return Err(TransportParameterError::InvalidParameterLength {
                        parameter: "empty parameter".to_string(),
                        expected_min: 0,
                        actual: length.value() as usize,
                    });
                }
                Ok(TransportParameterValue::Empty)
            }
        }
    }
}

/// Expected type for transport parameter value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportParameterValueType {
    /// Variable-length integer parameter body.
    VarInt,
    /// Opaque byte parameter body.
    Bytes,
    /// Empty parameter body.
    Empty,
}

/// QUIC Transport Parameters
#[derive(Debug, Clone)]
pub struct TransportParameters {
    /// Known transport parameters
    known_parameters: HashMap<TransportParameterId, TransportParameterValue>,
    /// Unknown/extension parameters (preserved)
    unknown_parameters: HashMap<u64, Bytes>,
}

impl TransportParameters {
    /// Create new transport parameters
    pub fn new() -> Self {
        Self {
            known_parameters: HashMap::new(),
            unknown_parameters: HashMap::new(),
        }
    }

    /// Set a transport parameter
    pub fn set_parameter(&mut self, id: TransportParameterId, value: TransportParameterValue) {
        self.known_parameters.insert(id, value);
    }

    /// Set VarInt parameter
    pub fn set_varint(
        &mut self,
        id: TransportParameterId,
        value: u64,
    ) -> Result<(), TransportParameterError> {
        let varint = match VarInt::new(value) {
            Outcome::Ok(varint) => varint,
            _ => {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter: id,
                    value,
                    reason: "Invalid varint value".to_string(),
                });
            }
        };
        self.set_parameter(id, TransportParameterValue::VarInt(varint));
        Ok(())
    }

    /// Set bytes parameter
    pub fn set_bytes(&mut self, id: TransportParameterId, value: Bytes) {
        self.set_parameter(id, TransportParameterValue::Bytes(value));
    }

    /// Set empty parameter (flag)
    pub fn set_empty(&mut self, id: TransportParameterId) {
        self.set_parameter(id, TransportParameterValue::Empty);
    }

    /// Get parameter
    pub fn get_parameter(&self, id: TransportParameterId) -> Option<&TransportParameterValue> {
        self.known_parameters.get(&id)
    }

    /// Get VarInt parameter
    pub fn get_varint(&self, id: TransportParameterId) -> Option<u64> {
        self.get_parameter(id)?.as_varint().map(|v| v.value())
    }

    /// Get bytes parameter
    pub fn get_bytes(&self, id: TransportParameterId) -> Option<&Bytes> {
        self.get_parameter(id)?.as_bytes()
    }

    /// Check if empty parameter is set
    pub fn has_empty(&self, id: TransportParameterId) -> bool {
        self.get_parameter(id).is_some_and(|v| v.is_empty())
    }

    /// Set unknown parameter (for extensions)
    pub fn set_unknown_parameter(&mut self, id: u64, value: Bytes) {
        self.unknown_parameters.insert(id, value);
    }

    /// Get unknown parameter
    pub fn get_unknown_parameter(&self, id: u64) -> Option<&Bytes> {
        self.unknown_parameters.get(&id)
    }

    /// Get all unknown parameters
    pub fn unknown_parameters(&self) -> &HashMap<u64, Bytes> {
        &self.unknown_parameters
    }

    /// Validate transport parameters
    pub fn validate(&self, is_server: bool) -> Result<(), TransportParameterError> {
        // Check required parameters
        for &param in &[
            TransportParameterId::InitialMaxData,
            TransportParameterId::InitialMaxStreamDataBidiLocal,
            TransportParameterId::InitialMaxStreamDataBidiRemote,
            TransportParameterId::InitialMaxStreamDataUni,
            TransportParameterId::InitialMaxStreamsBidi,
            TransportParameterId::InitialMaxStreamsUni,
        ] {
            if !self.known_parameters.contains_key(&param) {
                return Err(TransportParameterError::MissingRequiredParameter(param));
            }
        }

        // Check forbidden parameters
        for &param in self.known_parameters.keys() {
            if is_server && param.is_forbidden_for_server() {
                return Err(TransportParameterError::ForbiddenParameter { param, is_server });
            }
            if !is_server && param.is_forbidden_for_client() {
                return Err(TransportParameterError::ForbiddenParameter { param, is_server });
            }
        }

        // Validate parameter values
        self.validate_parameter_values()?;

        // Check parameter combinations
        self.validate_parameter_combinations()?;

        Ok(())
    }

    /// Validate individual parameter values
    fn validate_parameter_values(&self) -> Result<(), TransportParameterError> {
        // max_udp_payload_size must be at least 1200
        if let Some(max_udp) = self.get_varint(TransportParameterId::MaxUdpPayloadSize) {
            if max_udp < 1200 {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter: TransportParameterId::MaxUdpPayloadSize,
                    value: max_udp,
                    reason: "must be at least 1200".to_string(),
                });
            }
        }

        // ack_delay_exponent must be <= 20
        if let Some(ack_exp) = self.get_varint(TransportParameterId::AckDelayExponent) {
            if ack_exp > 20 {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter: TransportParameterId::AckDelayExponent,
                    value: ack_exp,
                    reason: "must be <= 20".to_string(),
                });
            }
        }

        // max_ack_delay must be < 2^14
        if let Some(max_ack) = self.get_varint(TransportParameterId::MaxAckDelay) {
            if max_ack >= (1u64 << 14) {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter: TransportParameterId::MaxAckDelay,
                    value: max_ack,
                    reason: "must be < 2^14 milliseconds".to_string(),
                });
            }
        }

        // active_connection_id_limit must be at least 2
        if let Some(conn_limit) = self.get_varint(TransportParameterId::ActiveConnectionIdLimit) {
            if conn_limit < 2 {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter: TransportParameterId::ActiveConnectionIdLimit,
                    value: conn_limit,
                    reason: "must be at least 2".to_string(),
                });
            }
        }

        // stateless_reset_token must be exactly 16 bytes
        if let Some(reset_token) = self.get_bytes(TransportParameterId::StatelessResetToken) {
            if reset_token.len() != 16 {
                return Err(TransportParameterError::InvalidParameterLength {
                    parameter: "stateless_reset_token".to_string(),
                    expected_min: 16,
                    actual: reset_token.len(),
                });
            }
        }

        Ok(())
    }

    /// Validate parameter combinations and constraints
    fn validate_parameter_combinations(&self) -> Result<(), TransportParameterError> {
        // If disable_active_migration is set, preferred_address should not be set
        if self.has_empty(TransportParameterId::DisableActiveMigration)
            && self
                .known_parameters
                .contains_key(&TransportParameterId::PreferredAddress)
        {
            return Err(TransportParameterError::ConflictingParameters {
                param1: TransportParameterId::DisableActiveMigration,
                param2: TransportParameterId::PreferredAddress,
                reason: "disable_active_migration conflicts with preferred_address".to_string(),
            });
        }

        Ok(())
    }

    /// Encode transport parameters
    pub fn encode(&self) -> Result<Bytes, TransportParameterError> {
        let mut buf = BytesMut::new();

        // Encode known parameters in sorted order for deterministic output
        let mut sorted_known: Vec<_> = self.known_parameters.iter().collect();
        sorted_known.sort_by_key(|(id, _)| **id as u64);

        for (&id, value) in sorted_known {
            id.to_varint().encode_to_buf_for(id, &mut buf)?;
            value.encode(id, &mut buf)?;
        }

        // Encode unknown parameters in sorted order
        let mut sorted_unknown: Vec<_> = self.unknown_parameters.iter().collect();
        sorted_unknown.sort_by_key(|(id, _)| **id);

        for (&id, value) in sorted_unknown {
            let id_varint = match VarInt::new(id) {
                Outcome::Ok(varint) => varint,
                _ => {
                    return Err(TransportParameterError::InvalidUnknownParameterValue {
                        parameter_id: id,
                        value: id,
                        reason: "Invalid parameter ID".to_string(),
                    });
                }
            };
            id_varint.encode_to_buf_unknown(id, &mut buf)?;

            let len_varint = match VarInt::new(value.len() as u64) {
                Outcome::Ok(varint) => varint,
                _ => {
                    return Err(TransportParameterError::InvalidUnknownParameterValue {
                        parameter_id: id,
                        value: value.len() as u64,
                        reason: "Invalid parameter length".to_string(),
                    });
                }
            };
            len_varint.encode_to_buf_unknown(id, &mut buf)?;
            buf.put_slice(value);
        }

        Ok(buf.freeze())
    }

    /// Decode transport parameters
    pub fn decode(data: Bytes) -> Result<Self, TransportParameterError> {
        let mut params = Self::new();
        let mut seen_parameters = std::collections::HashSet::new();
        let mut data_buf = BytesMut::from(&data[..]);

        while !data_buf.is_empty() {
            let param_id_varint = match VarInt::decode(&mut data_buf) {
                Outcome::Ok(Some(varint)) => varint,
                Outcome::Ok(None) => return Err(TransportParameterError::UnexpectedEof),
                _ => {
                    return Err(TransportParameterError::VarInt(
                        VarIntError::InvalidEncoding,
                    ));
                }
            };
            let param_id = param_id_varint.value();

            // Check for duplicates
            if !seen_parameters.insert(param_id) {
                return Err(TransportParameterError::DuplicateParameter(param_id));
            }

            if let Some(known_id) = TransportParameterId::from_varint(param_id_varint) {
                // Known parameter
                let value_type = get_parameter_value_type(known_id);
                let value = TransportParameterValue::decode(&mut data_buf, value_type)?;
                params.set_parameter(known_id, value);
            } else {
                // Unknown parameter - preserve as extension
                let length = match VarInt::decode(&mut data_buf) {
                    Outcome::Ok(Some(varint)) => varint,
                    Outcome::Ok(None) => return Err(TransportParameterError::UnexpectedEof),
                    _ => {
                        return Err(TransportParameterError::VarInt(
                            VarIntError::InvalidEncoding,
                        ));
                    }
                };

                if data_buf.len() < length.value() as usize {
                    return Err(TransportParameterError::UnexpectedEof);
                }

                let value = data_buf.split_to(length.value() as usize).freeze();
                params.set_unknown_parameter(param_id, value);
            }
        }

        Ok(params)
    }
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the expected value type for a transport parameter
fn get_parameter_value_type(param: TransportParameterId) -> TransportParameterValueType {
    match param {
        TransportParameterId::OriginalDestinationConnectionId
        | TransportParameterId::StatelessResetToken
        | TransportParameterId::PreferredAddress
        | TransportParameterId::InitialSourceConnectionId
        | TransportParameterId::RetrySourceConnectionId => TransportParameterValueType::Bytes,

        TransportParameterId::DisableActiveMigration => TransportParameterValueType::Empty,

        _ => TransportParameterValueType::VarInt,
    }
}

/// Transport parameter errors
#[derive(Debug, thiserror::Error)]
pub enum TransportParameterError {
    /// VarInt encoding/decoding error
    #[error("varint error: {0}")]
    VarInt(#[from] VarIntError),

    /// Duplicate transport parameter
    #[error("duplicate transport parameter: {0}")]
    DuplicateParameter(u64),

    /// Missing required parameter
    #[error("missing required transport parameter: {0:?}")]
    MissingRequiredParameter(TransportParameterId),

    /// Forbidden parameter for endpoint type
    #[error("forbidden transport parameter {param:?} for {} endpoint", if *.is_server { "server" } else { "client" })]
    ForbiddenParameter {
        /// Rejected transport parameter id.
        param: TransportParameterId,
        /// Whether validation was for a server endpoint.
        is_server: bool,
    },

    /// Invalid parameter value
    #[error("invalid value {value} for transport parameter {parameter:?}: {reason}")]
    InvalidParameterValue {
        /// Rejected transport parameter id.
        parameter: TransportParameterId,
        /// Rejected numeric value.
        value: u64,
        /// Stable human-readable reason.
        reason: String,
    },

    /// Invalid value for an unknown extension parameter.
    #[error("invalid value {value} for unknown transport parameter {parameter_id}: {reason}")]
    InvalidUnknownParameterValue {
        /// Rejected extension parameter id.
        parameter_id: u64,
        /// Rejected numeric value.
        value: u64,
        /// Stable human-readable reason.
        reason: String,
    },

    /// Invalid parameter length
    #[error(
        "invalid length for transport parameter {parameter}: expected >= {expected_min}, got {actual}"
    )]
    InvalidParameterLength {
        /// Rejected transport parameter name.
        parameter: String,
        /// Minimum valid body length.
        expected_min: usize,
        /// Actual body length.
        actual: usize,
    },

    /// Conflicting parameters
    #[error("conflicting transport parameters {param1:?} and {param2:?}: {reason}")]
    ConflictingParameters {
        /// First conflicting parameter.
        param1: TransportParameterId,
        /// Second conflicting parameter.
        param2: TransportParameterId,
        /// Stable human-readable reason.
        reason: String,
    },

    /// Unexpected end of data
    #[error("unexpected end of transport parameter data")]
    UnexpectedEof,
}

/// Extensions for VarInt to work with transport parameters
trait VarIntTransportExt {
    fn encode_to_buf_for<B: BufMut>(
        &self,
        parameter: TransportParameterId,
        buf: &mut B,
    ) -> Result<(), TransportParameterError>;
    fn encode_to_buf_unknown<B: BufMut>(
        &self,
        parameter_id: u64,
        buf: &mut B,
    ) -> Result<(), TransportParameterError>;
}

impl VarIntTransportExt for VarInt {
    fn encode_to_buf_for<B: BufMut>(
        &self,
        parameter: TransportParameterId,
        buf: &mut B,
    ) -> Result<(), TransportParameterError> {
        let mut temp = BytesMut::new();
        match self.encode(&mut temp) {
            Outcome::Ok(()) => {}
            _ => {
                return Err(TransportParameterError::InvalidParameterValue {
                    parameter,
                    value: 0,
                    reason: "VarInt encode failed".to_string(),
                });
            }
        }
        buf.put_slice(&temp);
        Ok(())
    }

    fn encode_to_buf_unknown<B: BufMut>(
        &self,
        parameter_id: u64,
        buf: &mut B,
    ) -> Result<(), TransportParameterError> {
        let mut temp = BytesMut::new();
        match self.encode(&mut temp) {
            Outcome::Ok(()) => {}
            _ => {
                return Err(TransportParameterError::InvalidUnknownParameterValue {
                    parameter_id,
                    value: 0,
                    reason: "VarInt encode failed".to_string(),
                });
            }
        }
        buf.put_slice(&temp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_parameters_basic() {
        let mut params = TransportParameters::new();

        // Set some basic parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::MaxIdleTimeout, 30000)
            .unwrap();
        params.set_empty(TransportParameterId::DisableActiveMigration);

        assert_eq!(
            params.get_varint(TransportParameterId::InitialMaxData),
            Some(65536)
        );
        assert_eq!(
            params.get_varint(TransportParameterId::MaxIdleTimeout),
            Some(30000)
        );
        assert!(params.has_empty(TransportParameterId::DisableActiveMigration));
    }

    #[test]
    fn test_transport_parameters_encoding_roundtrip() {
        let mut params = TransportParameters::new();

        // Set required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add an unknown parameter
        params.set_unknown_parameter(0xFF00, Bytes::from_static(b"extension_data"));

        // Encode and decode
        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(encoded).unwrap();

        // Check that parameters match
        assert_eq!(
            decoded.get_varint(TransportParameterId::InitialMaxData),
            Some(65536)
        );
        assert_eq!(
            decoded.get_unknown_parameter(0xFF00),
            Some(&Bytes::from_static(b"extension_data"))
        );
    }

    #[test]
    fn test_transport_parameters_validation() {
        let mut params = TransportParameters::new();

        // Missing required parameters should fail validation
        assert!(params.validate(false).is_err());

        // Add all required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Should now validate successfully
        assert!(params.validate(false).is_ok());
    }

    #[test]
    fn test_invalid_parameter_values() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add invalid ACK delay exponent
        params
            .set_varint(TransportParameterId::AckDelayExponent, 25)
            .unwrap(); // > 20

        assert!(params.validate(false).is_err());
    }

    #[test]
    fn test_forbidden_parameters() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Add server-only parameter for client
        params.set_bytes(
            TransportParameterId::StatelessResetToken,
            Bytes::from(vec![0u8; 16]),
        );

        // Should fail validation for client
        assert!(params.validate(false).is_err());

        // Should succeed for server
        assert!(params.validate(true).is_ok());
    }

    #[test]
    fn test_duplicate_parameter_detection() {
        let mut buf = BytesMut::new();

        // Encode the same parameter twice
        let max_data_id = TransportParameterId::InitialMaxData.to_varint();
        let value = VarInt::new(65536).unwrap();

        // First instance
        max_data_id
            .encode_to_buf_for(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();
        TransportParameterValue::VarInt(value)
            .encode(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();

        // Duplicate instance
        max_data_id
            .encode_to_buf_for(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();
        TransportParameterValue::VarInt(value)
            .encode(TransportParameterId::InitialMaxData, &mut buf)
            .unwrap();

        // Decoding should fail
        let result = TransportParameters::decode(buf.freeze());
        assert!(matches!(
            result,
            Err(TransportParameterError::DuplicateParameter(_))
        ));
    }

    #[test]
    fn test_conflicting_parameters() {
        let mut params = TransportParameters::new();

        // Add required parameters
        params
            .set_varint(TransportParameterId::InitialMaxData, 65536)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiLocal, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataBidiRemote, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamDataUni, 32768)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsBidi, 100)
            .unwrap();
        params
            .set_varint(TransportParameterId::InitialMaxStreamsUni, 100)
            .unwrap();

        // Set conflicting parameters
        params.set_empty(TransportParameterId::DisableActiveMigration);
        params.set_bytes(
            TransportParameterId::PreferredAddress,
            Bytes::from_static(b"preferred_address_fixture"),
        );

        // Should fail validation
        assert!(params.validate(true).is_err());
    }
}
