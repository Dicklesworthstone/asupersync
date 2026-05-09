#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::net::quic_core::{
    QuicCoreError, TP_ACK_DELAY_EXPONENT, TP_DISABLE_ACTIVE_MIGRATION, TP_INITIAL_MAX_DATA,
    TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    TP_INITIAL_MAX_STREAM_DATA_UNI, TP_INITIAL_MAX_STREAMS_BIDI, TP_INITIAL_MAX_STREAMS_UNI,
    TP_MAX_ACK_DELAY, TP_MAX_IDLE_TIMEOUT, TP_MAX_UDP_PAYLOAD_SIZE, TransportParameters,
    UnknownTransportParameter, encode_varint,
};

/// Fuzz input for QUIC transport parameters TLV codec testing
#[derive(Arbitrary, Debug)]
struct TransportParamsFuzzInput {
    /// Operations to perform
    operations: Vec<TlvOperation>,
    /// Attack scenarios to test specific edge cases
    attack_scenario: AttackScenario,
}

/// Operations that can be performed on the transport parameters TLV codec
#[derive(Arbitrary, Debug, Clone)]
enum TlvOperation {
    /// Encode a structured transport parameters object
    Encode { params: FuzzTransportParams },
    /// Decode raw TLV bytes
    Decode { bytes: Vec<u8> },
    /// Round-trip: encode then decode
    RoundTrip { params: FuzzTransportParams },
}

/// Fuzzable version of transport parameters with constrained values
#[derive(Arbitrary, Debug, Clone)]
struct FuzzTransportParams {
    /// Maximum idle timeout (Option<u64>)
    max_idle_timeout: Option<u32>, // Use u32 to avoid extreme values
    /// Maximum UDP payload size (Option<u64>)
    max_udp_payload_size: Option<u16>, // Use u16, will test validation
    /// Initial max data (Option<u64>)
    initial_max_data: Option<u32>,
    /// Initial max stream data bidi local
    initial_max_stream_data_bidi_local: Option<u32>,
    /// Initial max stream data bidi remote
    initial_max_stream_data_bidi_remote: Option<u32>,
    /// Initial max stream data uni
    initial_max_stream_data_uni: Option<u32>,
    /// Initial max streams bidi
    initial_max_streams_bidi: Option<u16>,
    /// Initial max streams uni
    initial_max_streams_uni: Option<u16>,
    /// ACK delay exponent (0-20 valid, >20 invalid)
    ack_delay_exponent: Option<u8>,
    /// Max ack delay
    max_ack_delay: Option<u16>,
    /// Disable active migration flag
    disable_active_migration: bool,
    /// Unknown parameters to include
    unknown_params: Vec<FuzzUnknownParam>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzUnknownParam {
    /// Parameter ID (use u16 to keep reasonable)
    id: u16,
    /// Parameter value
    value: Vec<u8>,
}

impl From<FuzzTransportParams> for TransportParameters {
    fn from(fuzz: FuzzTransportParams) -> Self {
        TransportParameters {
            max_idle_timeout: fuzz.max_idle_timeout.map(|v| v as u64),
            max_udp_payload_size: fuzz.max_udp_payload_size.map(|v| v as u64),
            initial_max_data: fuzz.initial_max_data.map(|v| v as u64),
            initial_max_stream_data_bidi_local: fuzz
                .initial_max_stream_data_bidi_local
                .map(|v| v as u64),
            initial_max_stream_data_bidi_remote: fuzz
                .initial_max_stream_data_bidi_remote
                .map(|v| v as u64),
            initial_max_stream_data_uni: fuzz.initial_max_stream_data_uni.map(|v| v as u64),
            initial_max_streams_bidi: fuzz.initial_max_streams_bidi.map(|v| v as u64),
            initial_max_streams_uni: fuzz.initial_max_streams_uni.map(|v| v as u64),
            ack_delay_exponent: fuzz.ack_delay_exponent.map(|v| v as u64),
            max_ack_delay: fuzz.max_ack_delay.map(|v| v as u64),
            disable_active_migration: fuzz.disable_active_migration,
            unknown: fuzz
                .unknown_params
                .into_iter()
                .map(|p| UnknownTransportParameter {
                    id: p.id as u64,
                    value: p.value,
                })
                .collect(),
        }
    }
}

fn is_known_transport_parameter_id(id: u64) -> bool {
    matches!(
        id,
        TP_MAX_IDLE_TIMEOUT
            | TP_MAX_UDP_PAYLOAD_SIZE
            | TP_INITIAL_MAX_DATA
            | TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | TP_INITIAL_MAX_STREAM_DATA_UNI
            | TP_INITIAL_MAX_STREAMS_BIDI
            | TP_INITIAL_MAX_STREAMS_UNI
            | TP_ACK_DELAY_EXPONENT
            | TP_MAX_ACK_DELAY
            | TP_DISABLE_ACTIVE_MIGRATION
    )
}

fn can_assert_exact_round_trip(params: &TransportParameters) -> bool {
    let mut ids = Vec::with_capacity(11 + params.unknown.len());
    for id in known_ids_present(params) {
        ids.push(id);
    }
    for unknown in &params.unknown {
        if is_known_transport_parameter_id(unknown.id) || ids.contains(&unknown.id) {
            return false;
        }
        ids.push(unknown.id);
    }
    true
}

fn known_ids_present(params: &TransportParameters) -> Vec<u64> {
    let mut ids = Vec::with_capacity(11);
    push_present(&mut ids, params.max_idle_timeout, TP_MAX_IDLE_TIMEOUT);
    push_present(
        &mut ids,
        params.max_udp_payload_size,
        TP_MAX_UDP_PAYLOAD_SIZE,
    );
    push_present(&mut ids, params.initial_max_data, TP_INITIAL_MAX_DATA);
    push_present(
        &mut ids,
        params.initial_max_stream_data_bidi_local,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    );
    push_present(
        &mut ids,
        params.initial_max_stream_data_bidi_remote,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    );
    push_present(
        &mut ids,
        params.initial_max_stream_data_uni,
        TP_INITIAL_MAX_STREAM_DATA_UNI,
    );
    push_present(
        &mut ids,
        params.initial_max_streams_bidi,
        TP_INITIAL_MAX_STREAMS_BIDI,
    );
    push_present(
        &mut ids,
        params.initial_max_streams_uni,
        TP_INITIAL_MAX_STREAMS_UNI,
    );
    push_present(&mut ids, params.ack_delay_exponent, TP_ACK_DELAY_EXPONENT);
    push_present(&mut ids, params.max_ack_delay, TP_MAX_ACK_DELAY);
    if params.disable_active_migration {
        ids.push(TP_DISABLE_ACTIVE_MIGRATION);
    }
    ids
}

fn push_present(ids: &mut Vec<u64>, value: Option<u64>, id: u64) {
    if value.is_some() {
        ids.push(id);
    }
}

fn assert_valid_decoded_params(params: &TransportParameters) {
    if let Some(udp_size) = params.max_udp_payload_size {
        assert!(
            udp_size >= 1200,
            "UDP payload size should be >= 1200 if set"
        );
    }
    if let Some(ack_exp) = params.ack_delay_exponent {
        assert!(ack_exp <= 20, "ACK delay exponent should be <= 20");
    }
}

fn observe_transport_parameters_decode(bytes: &[u8]) -> Result<TransportParameters, QuicCoreError> {
    let result = TransportParameters::decode(bytes);

    match &result {
        Ok(params) => assert_valid_decoded_params(params),
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "transport parameter decode errors must remain observable"
            );
        }
    }

    result
}

fn encode_parameter(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    encode_varint(id, out).expect("fuzz transport parameter id should fit QUIC varint");
    encode_varint(value.len() as u64, out)
        .expect("fuzz transport parameter length should fit QUIC varint");
    out.extend_from_slice(value);
}

fn encode_u64_value(value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_varint(value, &mut encoded).expect("fuzz value should fit QUIC varint");
    encoded
}

fn valid_value_for_parameter(id: u64) -> Vec<u8> {
    match id {
        TP_MAX_UDP_PAYLOAD_SIZE => encode_u64_value(1200),
        TP_ACK_DELAY_EXPONENT => encode_u64_value(20),
        TP_DISABLE_ACTIVE_MIGRATION => Vec::new(),
        TP_MAX_IDLE_TIMEOUT
        | TP_INITIAL_MAX_DATA
        | TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
        | TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
        | TP_INITIAL_MAX_STREAM_DATA_UNI
        | TP_INITIAL_MAX_STREAMS_BIDI
        | TP_INITIAL_MAX_STREAMS_UNI
        | TP_MAX_ACK_DELAY => encode_u64_value(1),
        _ => vec![0xa5, 0x5a],
    }
}

/// Attack scenarios to test specific edge cases
#[derive(Arbitrary, Debug, Clone)]
enum AttackScenario {
    /// Normal operation (baseline)
    Normal,
    /// Malformed TLV structure
    MalformedTlv {
        /// Raw malformed bytes
        malformed_bytes: Vec<u8>,
    },
    /// Duplicate parameter IDs
    DuplicateParams {
        /// Parameter ID to duplicate
        param_id: u16,
        /// Number of duplicates (2-5)
        duplicate_count: u8,
    },
    /// Invalid parameter values
    InvalidValues {
        /// Test type for invalid values
        invalid_type: InvalidValueType,
    },
    /// Extremely large values
    LargeValues {
        /// Parameter to make large
        large_param: LargeParamType,
        /// Scale factor
        scale: u8,
    },
    /// Truncated TLV data
    TruncatedData {
        /// Number of bytes to truncate from end
        truncate_bytes: u8,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum InvalidValueType {
    /// UDP payload size < 1200 (invalid)
    SmallUdpPayload,
    /// ACK delay exponent > 20 (invalid)
    LargeAckDelayExponent,
    /// Non-empty disable active migration (invalid)
    NonEmptyDisableActiveMigration,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum LargeParamType {
    MaxIdleTimeout,
    InitialMaxData,
    UnknownParamValue,
}

fuzz_target!(|input: TransportParamsFuzzInput| {
    // Property 1: No panic on any input
    test_no_panic(&input);

    // Property 2: Valid parameters round-trip correctly
    test_round_trip_consistency(&input);

    // Property 3: Invalid inputs are rejected gracefully
    test_invalid_input_rejection(&input);

    // Property 4: Attack scenarios are handled robustly
    test_attack_scenarios(&input);

    // Property 5: Encoding is deterministic
    test_encoding_determinism(&input);
});

/// Property 1: No panic on any input
fn test_no_panic(input: &TransportParamsFuzzInput) {
    for operation in &input.operations {
        let result = std::panic::catch_unwind(|| {
            process_tlv_operation(operation);
        });
        assert!(result.is_ok(), "TLV operation panicked: {operation:?}");
    }

    let result = std::panic::catch_unwind(|| {
        process_attack_scenario(&input.attack_scenario);
    });
    assert!(
        result.is_ok(),
        "TLV attack scenario panicked: {:?}",
        input.attack_scenario
    );
}

/// Property 2: Valid parameters round-trip correctly
fn test_round_trip_consistency(input: &TransportParamsFuzzInput) {
    for operation in &input.operations {
        if let TlvOperation::RoundTrip { params } = operation {
            let tp: TransportParameters = params.clone().into();

            // Encode
            let mut encoded = Vec::new();
            match tp.encode(&mut encoded) {
                Ok(()) => {
                    // Decode back
                    match TransportParameters::decode(&encoded) {
                        Ok(decoded) => {
                            assert_valid_decoded_params(&decoded);
                            if can_assert_exact_round_trip(&tp) {
                                assert_eq!(decoded, tp, "valid transport parameters round-trip");
                            }
                        }
                        Err(err) => {
                            assert!(
                                matches!(
                                    err,
                                    QuicCoreError::DuplicateTransportParameter(_)
                                        | QuicCoreError::InvalidTransportParameter(_)
                                        | QuicCoreError::UnexpectedEof
                                ),
                                "unexpected round-trip decode error: {err:?}"
                            );
                        }
                    }
                }
                Err(err) => {
                    assert!(
                        matches!(err, QuicCoreError::VarIntOutOfRange(_)),
                        "unexpected round-trip encode error: {err:?}"
                    );
                }
            }
        }
    }
}

/// Property 3: Invalid inputs are rejected gracefully
fn test_invalid_input_rejection(input: &TransportParamsFuzzInput) {
    for operation in &input.operations {
        if let TlvOperation::Decode { bytes } = operation {
            match TransportParameters::decode(bytes) {
                Ok(params) => {
                    assert_valid_decoded_params(&params);
                }
                Err(QuicCoreError::DuplicateTransportParameter(_))
                | Err(QuicCoreError::InvalidTransportParameter(_))
                | Err(QuicCoreError::UnexpectedEof)
                | Err(QuicCoreError::VarIntOutOfRange(_)) => {}
                Err(err) => panic!("unexpected transport parameter decode error: {err:?}"),
            }
        }
    }
}

/// Property 4: Attack scenarios are handled robustly
fn test_attack_scenarios(input: &TransportParamsFuzzInput) {
    match &input.attack_scenario {
        AttackScenario::Normal => {
            let params = TransportParameters {
                max_idle_timeout: Some(30_000),
                max_udp_payload_size: Some(1500),
                initial_max_data: Some(1_000_000),
                disable_active_migration: true,
                ..TransportParameters::default()
            };
            let mut encoded = Vec::new();
            params
                .encode(&mut encoded)
                .expect("normal transport parameters should encode");
            let decoded = TransportParameters::decode(&encoded)
                .expect("normal transport parameters should decode");
            assert_eq!(decoded, params);
        }
        AttackScenario::MalformedTlv { malformed_bytes } => {
            // Should handle malformed TLV gracefully
            match TransportParameters::decode(malformed_bytes) {
                Ok(params) => assert_valid_decoded_params(&params),
                Err(
                    QuicCoreError::DuplicateTransportParameter(_)
                    | QuicCoreError::InvalidTransportParameter(_)
                    | QuicCoreError::UnexpectedEof
                    | QuicCoreError::VarIntOutOfRange(_),
                ) => {}
                Err(err) => panic!("unexpected malformed TLV error: {err:?}"),
            }
        }
        AttackScenario::DuplicateParams {
            param_id,
            duplicate_count,
        } => {
            let id = u64::from(*param_id);
            let value = valid_value_for_parameter(id);
            let duplicate_count = usize::from((*duplicate_count).clamp(2, 5));
            let mut encoded = Vec::new();
            for _ in 0..duplicate_count {
                encode_parameter(&mut encoded, id, &value);
            }
            let err = TransportParameters::decode(&encoded)
                .expect_err("duplicate transport parameter should fail");
            assert_eq!(err, QuicCoreError::DuplicateTransportParameter(id));
        }
        AttackScenario::InvalidValues { invalid_type } => {
            // Test specific invalid value scenarios
            let mut encoded = Vec::new();
            match invalid_type {
                InvalidValueType::SmallUdpPayload => {
                    let params = TransportParameters {
                        max_udp_payload_size: Some(1199), // Invalid: < 1200
                        ..TransportParameters::default()
                    };
                    params
                        .encode(&mut encoded)
                        .expect("small UDP payload should encode as TLV");
                    let err = TransportParameters::decode(&encoded)
                        .expect_err("small UDP payload should be rejected");
                    assert_eq!(
                        err,
                        QuicCoreError::InvalidTransportParameter(TP_MAX_UDP_PAYLOAD_SIZE)
                    );
                }
                InvalidValueType::LargeAckDelayExponent => {
                    let params = TransportParameters {
                        ack_delay_exponent: Some(25), // Invalid: > 20
                        ..TransportParameters::default()
                    };
                    params
                        .encode(&mut encoded)
                        .expect("large ACK delay exponent should encode as TLV");
                    let err = TransportParameters::decode(&encoded)
                        .expect_err("large ACK delay exponent should be rejected");
                    assert_eq!(
                        err,
                        QuicCoreError::InvalidTransportParameter(TP_ACK_DELAY_EXPONENT)
                    );
                }
                InvalidValueType::NonEmptyDisableActiveMigration => {
                    encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[0x01]);
                    let err = TransportParameters::decode(&encoded)
                        .expect_err("non-empty disable_active_migration should be rejected");
                    assert_eq!(
                        err,
                        QuicCoreError::InvalidTransportParameter(TP_DISABLE_ACTIVE_MIGRATION)
                    );
                }
            }
        }
        AttackScenario::LargeValues { large_param, scale } => {
            let out_of_range_value = u64::MAX - u64::from(*scale);
            let unknown_value_len = usize::from((*scale).max(1)).min(64);
            let params = match large_param {
                LargeParamType::MaxIdleTimeout => TransportParameters {
                    max_idle_timeout: Some(out_of_range_value),
                    ..TransportParameters::default()
                },
                LargeParamType::InitialMaxData => TransportParameters {
                    initial_max_data: Some(out_of_range_value),
                    ..TransportParameters::default()
                },
                LargeParamType::UnknownParamValue => TransportParameters {
                    unknown: vec![UnknownTransportParameter {
                        id: 0x1f,
                        value: vec![0xff; unknown_value_len],
                    }],
                    ..TransportParameters::default()
                },
            };
            let mut encoded = Vec::new();
            match large_param {
                LargeParamType::MaxIdleTimeout | LargeParamType::InitialMaxData => {
                    let err = params
                        .encode(&mut encoded)
                        .expect_err("u64::MAX exceeds QUIC varint range");
                    assert_eq!(err, QuicCoreError::VarIntOutOfRange(out_of_range_value));
                }
                LargeParamType::UnknownParamValue => {
                    params
                        .encode(&mut encoded)
                        .expect("bounded unknown parameter should encode");
                    let decoded = TransportParameters::decode(&encoded)
                        .expect("bounded unknown parameter should decode");
                    assert_eq!(decoded, params);
                }
            }
        }
        AttackScenario::TruncatedData { truncate_bytes } => {
            let value = encode_u64_value(5000);
            let mut encoded = Vec::new();
            encode_parameter(&mut encoded, TP_MAX_IDLE_TIMEOUT, &value);
            let truncate_amount = usize::from(*truncate_bytes).clamp(1, encoded.len() - 1);
            encoded.truncate(encoded.len() - truncate_amount);
            let err = TransportParameters::decode(&encoded).expect_err("truncated TLV should fail");
            assert_eq!(err, QuicCoreError::UnexpectedEof);
        }
    }
}

/// Property 5: Encoding is deterministic
fn test_encoding_determinism(input: &TransportParamsFuzzInput) {
    for operation in &input.operations {
        if let TlvOperation::Encode { params } = operation {
            let tp: TransportParameters = params.clone().into();

            let mut encoded1 = Vec::new();
            let mut encoded2 = Vec::new();

            if tp.encode(&mut encoded1).is_ok() && tp.encode(&mut encoded2).is_ok() {
                assert_eq!(encoded1, encoded2, "Encoding should be deterministic");
            }
        }
    }
}

/// Helper function to process a TLV operation
fn process_tlv_operation(operation: &TlvOperation) {
    match operation {
        TlvOperation::Encode { params } => {
            let tp: TransportParameters = params.clone().into();
            let mut encoded = Vec::new();
            let _ = tp.encode(&mut encoded);
        }
        TlvOperation::Decode { bytes } => {
            let _ = observe_transport_parameters_decode(bytes);
        }
        TlvOperation::RoundTrip { params } => {
            let tp: TransportParameters = params.clone().into();
            let mut encoded = Vec::new();
            if tp.encode(&mut encoded).is_ok() {
                let _ = observe_transport_parameters_decode(&encoded);
            }
        }
    }
}

/// Helper function to process an attack scenario
fn process_attack_scenario(scenario: &AttackScenario) {
    match scenario {
        AttackScenario::Normal => {
            // Test some basic valid parameters
            let params = TransportParameters {
                max_idle_timeout: Some(30_000),
                max_udp_payload_size: Some(1500),
                initial_max_data: Some(1_000_000),
                disable_active_migration: true,
                ..TransportParameters::default()
            };
            let mut encoded = Vec::new();
            if params.encode(&mut encoded).is_ok() {
                let _ = observe_transport_parameters_decode(&encoded);
            }
        }
        AttackScenario::TruncatedData { truncate_bytes } => {
            // Create valid TLV then truncate it
            let params = TransportParameters {
                max_idle_timeout: Some(5_000),
                initial_max_data: Some(100_000),
                ..TransportParameters::default()
            };
            let mut encoded = Vec::new();
            if params.encode(&mut encoded).is_ok() {
                let truncate_amount = (*truncate_bytes as usize).min(encoded.len());
                encoded.truncate(encoded.len().saturating_sub(truncate_amount));
                let _ = observe_transport_parameters_decode(&encoded);
            }
        }
        _ => {
            // Other scenarios handled in their respective test functions
        }
    }
}
