#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::database::mysql::{
    FuzzHandshakeProtocol41, MySqlError, fuzz_parse_handshake_protocol_41,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_CASES: usize = 16;
const MAX_RAW_HANDSHAKE_LEN: usize = 512;
const MAX_FIELD_LEN: usize = 64;

const CLIENT_CONNECT_WITH_DB: u32 = 8;
const CLIENT_LOCAL_FILES: u32 = 128;
const CLIENT_PROTOCOL_41: u32 = 512;
const CLIENT_SSL: u32 = 2048;
const CLIENT_TRANSACTIONS: u32 = 8192;
const CLIENT_SECURE_CONNECTION: u32 = 32768;
const CLIENT_MULTI_RESULTS: u32 = 1 << 17;
const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;

const BASE_CLIENT_CAPS: u32 = CLIENT_PROTOCOL_41
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_TRANSACTIONS
    | CLIENT_MULTI_RESULTS;

static FIXED_DISAGREEMENT_CASES: OnceLock<()> = OnceLock::new();

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    client_has_database: bool,
    raw_handshake: Vec<u8>,
    structured: Vec<StructuredHandshake>,
}

#[derive(Debug, Arbitrary)]
struct StructuredHandshake {
    protocol_version: u8,
    server_version: Vec<u8>,
    connection_id: u32,
    auth_data_1: [u8; 8],
    filler: u8,
    server_capabilities: u32,
    charset: u8,
    status_flags: u16,
    auth_data_len: u8,
    reserved: [u8; 10],
    auth_data_2: Vec<u8>,
    plugin_name: AuthPluginName,
    include_plugin_terminator: bool,
    truncate_to: Option<u16>,
}

#[derive(Debug, Arbitrary)]
enum AuthPluginName {
    CachingSha2,
    MysqlNative,
    Empty,
    Raw(Vec<u8>),
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut input) = FuzzInput::arbitrary(&mut Unstructured::new(data)) else {
        return;
    };

    input.raw_handshake.truncate(MAX_RAW_HANDSHAKE_LEN);
    run_handshake_case(&input.raw_handshake, input.client_has_database);

    input.structured.truncate(MAX_CASES);
    for case in input.structured {
        let payload = build_structured_handshake(case);
        run_handshake_case(&payload, input.client_has_database);
    }

    FIXED_DISAGREEMENT_CASES.get_or_init(run_fixed_disagreement_cases);
});

fn run_fixed_disagreement_cases() {
    let required = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
    let cases = [
        required | CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF | CLIENT_SSL | CLIENT_LOCAL_FILES,
        required | CLIENT_DEPRECATE_EOF | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
        required | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB,
        CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF,
        CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF,
    ];

    for client_has_database in [false, true] {
        for server_capabilities in cases {
            let payload = build_minimal_handshake(server_capabilities);
            run_handshake_case(&payload, client_has_database);
        }
    }
}

fn run_handshake_case(payload: &[u8], client_has_database: bool) {
    match fuzz_parse_handshake_protocol_41(payload, client_has_database) {
        Ok(parsed) => assert_capability_oracle(parsed, client_has_database),
        Err(MySqlError::InvalidPacket(_) | MySqlError::Protocol(_)) => {}
        Err(other) => panic!("unexpected Protocol 41 handshake parser error: {other:?}"),
    }
}

fn assert_capability_oracle(parsed: FuzzHandshakeProtocol41, client_has_database: bool) {
    let expected_client_caps = if client_has_database {
        BASE_CLIENT_CAPS | CLIENT_CONNECT_WITH_DB
    } else {
        BASE_CLIENT_CAPS
    };

    assert_eq!(parsed.client_capabilities, expected_client_caps);
    assert_eq!(
        parsed.negotiated_capabilities,
        parsed.server_capabilities & parsed.client_capabilities
    );

    assert_eq!(parsed.client_capabilities & CLIENT_DEPRECATE_EOF, 0);
    assert_eq!(parsed.negotiated_capabilities & CLIENT_DEPRECATE_EOF, 0);
    assert_eq!(parsed.client_capabilities & CLIENT_SSL, 0);
    assert_eq!(parsed.negotiated_capabilities & CLIENT_SSL, 0);
    assert_eq!(parsed.client_capabilities & CLIENT_LOCAL_FILES, 0);
    assert_eq!(parsed.negotiated_capabilities & CLIENT_LOCAL_FILES, 0);

    assert_ne!(parsed.negotiated_capabilities & CLIENT_PROTOCOL_41, 0);
    assert_ne!(parsed.negotiated_capabilities & CLIENT_SECURE_CONNECTION, 0);
    assert_eq!(
        parsed.negotiated_capabilities & CLIENT_PLUGIN_AUTH,
        parsed.server_capabilities & CLIENT_PLUGIN_AUTH
    );

    if parsed.server_capabilities & CLIENT_PLUGIN_AUTH == 0 {
        assert_eq!(parsed.auth_plugin_name, "mysql_native_password");
    }
    assert!(parsed.auth_plugin_data_len >= 8);
}

fn build_structured_handshake(mut case: StructuredHandshake) -> Vec<u8> {
    case.server_version.truncate(MAX_FIELD_LEN);
    case.auth_data_2.truncate(MAX_FIELD_LEN);

    let mut payload = Vec::new();
    payload.push(case.protocol_version);
    push_null_terminated_field(&mut payload, &case.server_version);
    payload.extend_from_slice(&case.connection_id.to_le_bytes());
    payload.extend_from_slice(&case.auth_data_1);
    payload.push(case.filler);
    payload.extend_from_slice(&(case.server_capabilities as u16).to_le_bytes());
    payload.push(case.charset);
    payload.extend_from_slice(&case.status_flags.to_le_bytes());
    payload.extend_from_slice(&((case.server_capabilities >> 16) as u16).to_le_bytes());
    payload.push(case.auth_data_len);
    payload.extend_from_slice(&case.reserved);

    if case.server_capabilities & CLIENT_SECURE_CONNECTION != 0 {
        payload.extend_from_slice(&case.auth_data_2);
    }

    if case.server_capabilities & CLIENT_PLUGIN_AUTH != 0 {
        let plugin = plugin_name_bytes(case.plugin_name);
        payload.extend_from_slice(&plugin);
        if case.include_plugin_terminator {
            payload.push(0);
        }
    }

    if let Some(truncate_to) = case.truncate_to {
        payload.truncate(usize::from(truncate_to).min(payload.len()));
    }

    payload
}

fn build_minimal_handshake(server_capabilities: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(10);
    payload.extend_from_slice(b"8.0.0-fuzz\0");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&(server_capabilities as u16).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&((server_capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0u8; 10]);

    if server_capabilities & CLIENT_SECURE_CONNECTION != 0 {
        payload.extend_from_slice(b"abcdefgh1234");
        payload.push(0);
    }
    if server_capabilities & CLIENT_PLUGIN_AUTH != 0 {
        payload.extend_from_slice(b"caching_sha2_password\0");
    }

    payload
}

fn push_null_terminated_field(payload: &mut Vec<u8>, bytes: &[u8]) {
    for &byte in bytes.iter().take(MAX_FIELD_LEN) {
        payload.push(if byte == 0 { b'_' } else { byte });
    }
    payload.push(0);
}

fn plugin_name_bytes(mut plugin_name: AuthPluginName) -> Vec<u8> {
    match &mut plugin_name {
        AuthPluginName::CachingSha2 => b"caching_sha2_password".to_vec(),
        AuthPluginName::MysqlNative => b"mysql_native_password".to_vec(),
        AuthPluginName::Empty => Vec::new(),
        AuthPluginName::Raw(bytes) => {
            bytes.truncate(MAX_FIELD_LEN);
            bytes.iter_mut().for_each(|byte| {
                if *byte == 0 {
                    *byte = b'_';
                }
            });
            bytes.clone()
        }
    }
}
