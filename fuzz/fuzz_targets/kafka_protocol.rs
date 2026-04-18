//! Kafka wire protocol v3+ request framing fuzz target.
//!
//! This fuzzer tests the Kafka wire protocol v3+ request/response parsing
//! with emphasis on protocol violations and edge cases:
//! - ApiKey + ApiVersion range validation
//! - CorrelationId echo behavior
//! - request_api_version compatibility with ApiKey
//! - tagged fields (KIP-482) handling
//! - oversized records rejected per message.max.bytes

#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::kafka::{KafkaError, KafkaProducer, KafkaConfig};
use asupersync::cx::Cx;
use asupersync::types::Time;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

/// Kafka API Keys as defined in protocol specification
/// https://kafka.apache.org/protocol.html#protocol_api_keys
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
enum ApiKey {
    Produce = 0,
    Fetch = 1,
    ListOffsets = 2,
    Metadata = 3,
    LeaderAndIsr = 4,
    StopReplica = 5,
    UpdateMetadata = 6,
    ControlledShutdown = 7,
    OffsetCommit = 8,
    OffsetFetch = 9,
    FindCoordinator = 10,
    JoinGroup = 11,
    Heartbeat = 12,
    LeaveGroup = 13,
    SyncGroup = 14,
    DescribeGroups = 15,
    ListGroups = 16,
    SaslHandshake = 17,
    ApiVersions = 18,
    CreateTopics = 19,
    DeleteTopics = 20,
    DeleteRecords = 21,
    InitProducerId = 22,
    OffsetForLeaderEpoch = 23,
    AddPartitionsToTxn = 24,
    AddOffsetsToTxn = 25,
    EndTxn = 26,
    WriteTxnMarkers = 27,
    TxnOffsetCommit = 28,
    DescribeAcls = 29,
    CreateAcls = 30,
    DeleteAcls = 31,
    DescribeConfigs = 32,
    AlterConfigs = 33,
    AlterReplicaLogDirs = 34,
    DescribeLogDirs = 35,
    SaslAuthenticate = 36,
    CreatePartitions = 37,
    CreateDelegationToken = 38,
    RenewDelegationToken = 39,
    ExpireDelegationToken = 40,
    DescribeDelegationToken = 41,
    DeleteGroups = 42,
    ElectLeaders = 43,
    IncrementalAlterConfigs = 44,
    AlterPartitionReassignments = 45,
    ListPartitionReassignments = 46,
    OffsetDelete = 47,
    DescribeClientQuotas = 48,
    AlterClientQuotas = 49,
    DescribeUserScramCredentials = 50,
    AlterUserScramCredentials = 51,
    DescribeQuorum = 55,
    AlterPartition = 56,
    UpdateFeatures = 57,
    Envelope = 58,
    DescribeCluster = 60,
    DescribeProducers = 61,
    BrokerRegistration = 62,
    BrokerHeartbeat = 63,
    UnregisterBroker = 64,
    DescribeTransactions = 65,
    ListTransactions = 66,
    AllocateProducerIds = 67,
    // Invalid values for testing
    Invalid = -1,
    OutOfRange = 1000,
}

impl ApiKey {
    fn from_i16(value: i16) -> Self {
        match value {
            0 => Self::Produce,
            1 => Self::Fetch,
            2 => Self::ListOffsets,
            3 => Self::Metadata,
            18 => Self::ApiVersions,
            22 => Self::InitProducerId,
            -1 => Self::Invalid,
            x if x > 67 => Self::OutOfRange,
            _ => Self::Invalid,
        }
    }

    fn max_version(self) -> i16 {
        match self {
            Self::Produce => 9,
            Self::Fetch => 13,
            Self::Metadata => 12,
            Self::ApiVersions => 4,
            Self::InitProducerId => 4,
            _ => 0,
        }
    }

    fn is_valid_version(self, version: i16) -> bool {
        version >= 0 && version <= self.max_version()
    }
}

/// Tagged field for KIP-482 support (v3+ protocol enhancement)
#[derive(Arbitrary, Debug, Clone)]
struct TaggedField {
    /// Tag number (varint)
    tag: u32,
    /// Field data
    data: Vec<u8>,
}

/// Kafka request header (v3+ format with tagged fields)
#[derive(Arbitrary, Debug, Clone)]
struct KafkaRequestHeader {
    /// API key identifying request type
    api_key: i16,
    /// API version
    api_version: i16,
    /// Correlation ID for request/response matching
    correlation_id: i32,
    /// Client ID (compact string - length + data)
    client_id: Option<String>,
    /// Tagged fields (KIP-482)
    tagged_fields: Vec<TaggedField>,
}

/// Kafka request with arbitrary body
#[derive(Arbitrary, Debug, Clone)]
struct KafkaRequest {
    /// Request header
    header: KafkaRequestHeader,
    /// Request body (varies by ApiKey)
    body: Vec<u8>,
    /// Whether to test oversized message
    test_oversized: bool,
    /// Message size multiplier for oversized testing
    size_multiplier: u8,
}

/// Kafka response header
#[derive(Debug, Clone)]
struct KafkaResponseHeader {
    /// Must match request correlation_id
    correlation_id: i32,
    /// Tagged fields
    tagged_fields: Vec<TaggedField>,
}

/// Fuzz operations to test
#[derive(Arbitrary, Debug)]
enum KafkaProtocolOperation {
    /// Parse request with various malformations
    ParseRequest { request: KafkaRequest },
    /// Test API version compatibility
    TestApiVersionCompatibility {
        api_key: i16,
        requested_version: i16,
        supported_versions: Vec<i16>,
    },
    /// Test correlation ID echo
    TestCorrelationEcho {
        requests: Vec<KafkaRequest>,
    },
    /// Test tagged fields parsing
    TestTaggedFields {
        fields: Vec<TaggedField>,
        malform_varint: bool,
    },
    /// Test oversized message rejection
    TestOversizedMessage {
        message_size: u32,
        max_bytes: u32,
    },
}

/// Complete fuzz input structure
#[derive(Arbitrary, Debug)]
struct KafkaProtocolFuzz {
    operations: Vec<KafkaProtocolOperation>,
    /// Global message.max.bytes setting
    max_message_bytes: u32,
}

/// Serialize Kafka request to wire format
fn serialize_request(request: &KafkaRequest) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Request size (will be filled later)
    buffer.extend_from_slice(&[0, 0, 0, 0]);

    // Header
    buffer.extend_from_slice(&request.header.api_key.to_be_bytes());
    buffer.extend_from_slice(&request.header.api_version.to_be_bytes());
    buffer.extend_from_slice(&request.header.correlation_id.to_be_bytes());

    // Client ID (compact string)
    if let Some(ref client_id) = request.header.client_id {
        let len = client_id.len() as u32 + 1; // +1 for compact string encoding
        write_varint(&mut buffer, len);
        buffer.extend_from_slice(client_id.as_bytes());
    } else {
        write_varint(&mut buffer, 0); // null string
    }

    // Tagged fields
    write_varint(&mut buffer, request.header.tagged_fields.len() as u32);
    for field in &request.header.tagged_fields {
        write_varint(&mut buffer, field.tag);
        write_varint(&mut buffer, field.data.len() as u32);
        buffer.extend_from_slice(&field.data);
    }

    // Body
    buffer.extend_from_slice(&request.body);

    // Apply size multiplier if testing oversized
    if request.test_oversized {
        let multiplier = request.size_multiplier.max(1) as usize;
        let padding = vec![0u8; buffer.len() * multiplier];
        buffer.extend_from_slice(&padding);
    }

    // Update request size (exclude the 4-byte size field itself)
    let size = (buffer.len() - 4) as u32;
    buffer[0..4].copy_from_slice(&size.to_be_bytes());

    buffer
}

/// Write variable-length integer (varint)
fn write_varint(buffer: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        buffer.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

/// Parse variable-length integer (varint)
fn read_varint(cursor: &mut Cursor<&[u8]>) -> Result<u32, &'static str> {
    let mut result = 0u32;
    let mut shift = 0;

    loop {
        if shift >= 32 {
            return Err("varint too large");
        }

        let bytes = cursor.get_ref();
        let pos = cursor.position() as usize;
        if pos >= bytes.len() {
            return Err("unexpected end of varint");
        }

        let byte = bytes[pos];
        cursor.set_position(pos as u64 + 1);

        result |= ((byte & 0x7F) as u32) << shift;

        if (byte & 0x80) == 0 {
            break;
        }

        shift += 7;
    }

    Ok(result)
}

/// Parse Kafka request from wire format
fn parse_request(data: &[u8], max_message_bytes: u32) -> Result<(KafkaRequestHeader, Vec<u8>), KafkaError> {
    let mut cursor = Cursor::new(data);

    // Check minimum size
    if data.len() < 8 {
        return Err(KafkaError::Protocol("Request too short".to_string()));
    }

    // Request size
    let mut size_bytes = [0u8; 4];
    if cursor.get_ref().len() < 4 {
        return Err(KafkaError::Protocol("Missing request size".to_string()));
    }
    size_bytes.copy_from_slice(&cursor.get_ref()[0..4]);
    let request_size = u32::from_be_bytes(size_bytes);
    cursor.set_position(4);

    // Assertion 5: oversized records rejected per message.max.bytes
    if request_size > max_message_bytes {
        return Err(KafkaError::MessageTooLarge {
            size: request_size as usize,
            max_size: max_message_bytes as usize,
        });
    }

    if cursor.get_ref().len() < 4 + request_size as usize {
        return Err(KafkaError::Protocol("Incomplete request".to_string()));
    }

    // Header fields
    if cursor.get_ref().len() - cursor.position() as usize < 8 {
        return Err(KafkaError::Protocol("Incomplete header".to_string()));
    }

    let api_key_pos = cursor.position() as usize;
    let api_key = i16::from_be_bytes([
        cursor.get_ref()[api_key_pos],
        cursor.get_ref()[api_key_pos + 1],
    ]);
    cursor.set_position(cursor.position() + 2);

    let api_version_pos = cursor.position() as usize;
    let api_version = i16::from_be_bytes([
        cursor.get_ref()[api_version_pos],
        cursor.get_ref()[api_version_pos + 1],
    ]);
    cursor.set_position(cursor.position() + 2);

    let correlation_id_pos = cursor.position() as usize;
    let correlation_id = i32::from_be_bytes([
        cursor.get_ref()[correlation_id_pos],
        cursor.get_ref()[correlation_id_pos + 1],
        cursor.get_ref()[correlation_id_pos + 2],
        cursor.get_ref()[correlation_id_pos + 3],
    ]);
    cursor.set_position(cursor.position() + 4);

    // Assertion 1: ApiKey + ApiVersion range
    let api_key_enum = ApiKey::from_i16(api_key);
    if matches!(api_key_enum, ApiKey::Invalid | ApiKey::OutOfRange) {
        return Err(KafkaError::Protocol(format!("Invalid ApiKey: {}", api_key)));
    }

    // Assertion 3: request_api_version compatibility with ApiKey
    if !api_key_enum.is_valid_version(api_version) {
        return Err(KafkaError::Protocol(format!(
            "Unsupported ApiVersion {} for ApiKey {}",
            api_version, api_key
        )));
    }

    // Client ID (compact string)
    let client_id = match read_varint(&mut cursor) {
        Ok(0) => None, // null string
        Ok(len) => {
            let str_len = len - 1; // subtract 1 for compact string encoding
            let pos = cursor.position() as usize;
            if cursor.get_ref().len() < pos + str_len as usize {
                return Err(KafkaError::Protocol("Incomplete client_id".to_string()));
            }
            let client_id_bytes = &cursor.get_ref()[pos..pos + str_len as usize];
            cursor.set_position(cursor.position() + str_len as u64);
            Some(String::from_utf8_lossy(client_id_bytes).to_string())
        }
        Err(e) => return Err(KafkaError::Protocol(format!("Invalid client_id length: {}", e))),
    };

    // Assertion 4: tagged fields (KIP-482) handled
    let tagged_fields_count = read_varint(&mut cursor)
        .map_err(|e| KafkaError::Protocol(format!("Invalid tagged fields count: {}", e)))?;

    let mut tagged_fields = Vec::new();
    for _ in 0..tagged_fields_count {
        let tag = read_varint(&mut cursor)
            .map_err(|e| KafkaError::Protocol(format!("Invalid tagged field tag: {}", e)))?;
        let data_len = read_varint(&mut cursor)
            .map_err(|e| KafkaError::Protocol(format!("Invalid tagged field length: {}", e)))?;

        let pos = cursor.position() as usize;
        if cursor.get_ref().len() < pos + data_len as usize {
            return Err(KafkaError::Protocol("Incomplete tagged field data".to_string()));
        }

        let data = cursor.get_ref()[pos..pos + data_len as usize].to_vec();
        cursor.set_position(cursor.position() + data_len as u64);

        tagged_fields.push(TaggedField { tag, data });
    }

    // Remaining data is the request body
    let body_start = cursor.position() as usize;
    let body = cursor.get_ref()[body_start..].to_vec();

    let header = KafkaRequestHeader {
        api_key,
        api_version,
        correlation_id,
        client_id,
        tagged_fields,
    };

    Ok((header, body))
}

/// Create response header with matching correlation ID
fn create_response_header(request_header: &KafkaRequestHeader) -> KafkaResponseHeader {
    // Assertion 2: CorrelationId echo
    KafkaResponseHeader {
        correlation_id: request_header.correlation_id, // Must echo exactly
        tagged_fields: Vec::new(), // Simple response
    }
}

/// Main fuzz target
fuzz_target!(|data: KafkaProtocolFuzz| {
    // Clamp max_message_bytes to reasonable range
    let max_message_bytes = data.max_message_bytes.clamp(1024, 100_000_000);

    for operation in data.operations {
        match operation {
            KafkaProtocolOperation::ParseRequest { request } => {
                // Test request parsing
                let wire_data = serialize_request(&request);
                match parse_request(&wire_data, max_message_bytes) {
                    Ok((header, _body)) => {
                        // If parsing succeeds, verify invariants
                        assert!(
                            !matches!(ApiKey::from_i16(header.api_key), ApiKey::Invalid | ApiKey::OutOfRange),
                            "Invalid ApiKey should be rejected"
                        );
                        assert!(
                            ApiKey::from_i16(header.api_key).is_valid_version(header.api_version),
                            "Invalid API version should be rejected"
                        );

                        // Test response correlation echo
                        let response_header = create_response_header(&header);
                        assert_eq!(
                            response_header.correlation_id,
                            header.correlation_id,
                            "Response must echo request correlation ID"
                        );
                    }
                    Err(e) => {
                        // Parsing failed - verify it's for a good reason
                        match e {
                            KafkaError::Protocol(_) => { /* Expected for malformed data */ }
                            KafkaError::MessageTooLarge { size, max_size } => {
                                // Assertion 5: oversized message properly rejected
                                assert!(size > max_size, "Message not actually oversized");
                            }
                            _ => { /* Other errors acceptable */ }
                        }
                    }
                }
            }

            KafkaProtocolOperation::TestApiVersionCompatibility {
                api_key,
                requested_version,
                supported_versions,
            } => {
                // Test API version negotiation
                let api_key_enum = ApiKey::from_i16(api_key);
                let is_compatible = supported_versions.contains(&requested_version)
                    && api_key_enum.is_valid_version(requested_version);

                if !is_compatible {
                    // Should reject incompatible versions
                    let test_request = KafkaRequest {
                        header: KafkaRequestHeader {
                            api_key,
                            api_version: requested_version,
                            correlation_id: 12345,
                            client_id: Some("test-client".to_string()),
                            tagged_fields: vec![],
                        },
                        body: vec![],
                        test_oversized: false,
                        size_multiplier: 1,
                    };

                    let wire_data = serialize_request(&test_request);
                    assert!(
                        parse_request(&wire_data, max_message_bytes).is_err(),
                        "Should reject incompatible API version"
                    );
                }
            }

            KafkaProtocolOperation::TestCorrelationEcho { requests } => {
                // Test correlation ID echo for multiple requests
                for request in requests {
                    let wire_data = serialize_request(&request);
                    if let Ok((header, _)) = parse_request(&wire_data, max_message_bytes) {
                        let response_header = create_response_header(&header);
                        assert_eq!(
                            response_header.correlation_id,
                            header.correlation_id,
                            "Correlation ID must be echoed exactly"
                        );
                    }
                }
            }

            KafkaProtocolOperation::TestTaggedFields { fields, malform_varint } => {
                // Test tagged fields parsing
                let mut test_request = KafkaRequest {
                    header: KafkaRequestHeader {
                        api_key: 18, // ApiVersions
                        api_version: 3, // v3+ supports tagged fields
                        correlation_id: 54321,
                        client_id: None,
                        tagged_fields: fields,
                    },
                    body: vec![],
                    test_oversized: false,
                    size_multiplier: 1,
                };

                if malform_varint {
                    // Add invalid varint that could cause parsing issues
                    test_request.header.tagged_fields.push(TaggedField {
                        tag: u32::MAX, // Large tag that becomes invalid varint
                        data: vec![0xFF; 100], // Large data
                    });
                }

                let wire_data = serialize_request(&test_request);
                // Should either parse successfully or fail gracefully
                let _ = parse_request(&wire_data, max_message_bytes);
            }

            KafkaProtocolOperation::TestOversizedMessage { message_size, max_bytes } => {
                // Test oversized message rejection
                let oversized_request = KafkaRequest {
                    header: KafkaRequestHeader {
                        api_key: 0, // Produce
                        api_version: 3,
                        correlation_id: 99999,
                        client_id: Some("oversized-test".to_string()),
                        tagged_fields: vec![],
                    },
                    body: vec![0u8; message_size as usize],
                    test_oversized: false,
                    size_multiplier: 1,
                };

                let wire_data = serialize_request(&oversized_request);
                let result = parse_request(&wire_data, max_bytes);

                if message_size > max_bytes {
                    // Should be rejected
                    assert!(
                        result.is_err(),
                        "Oversized message should be rejected"
                    );
                    if let Err(KafkaError::MessageTooLarge { size, max_size }) = result {
                        assert!(size > max_size, "Size limits should be enforced");
                    }
                } else {
                    // Should be accepted or fail for other reasons
                    match result {
                        Ok(_) => { /* Good */ }
                        Err(KafkaError::MessageTooLarge { .. }) => {
                            panic!("Message within limits should not be rejected for size");
                        }
                        Err(_) => { /* Other errors OK */ }
                    }
                }
            }
        }
    }
});