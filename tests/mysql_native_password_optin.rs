#![cfg(feature = "mysql")]
//! Opt-in `mysql_native_password` authentication, proven over a real
//! loopback TCP socket against a scripted MySQL server.
//!
//! What this proves:
//! - With `MySqlConnectOptions::insecure_legacy_mysql_native_password = true`
//!   the client answers a `mysql_native_password` challenge (HandshakeV10 or
//!   AuthSwitchRequest) with exactly
//!   `SHA1(password) XOR SHA1(nonce || SHA1(SHA1(password)))`, where `nonce`
//!   is the 20-byte challenge with the trailing NUL excluded, then completes
//!   authentication on the OK packet and performs a COM_PING round trip.
//! - With the flag `false` (the default) the client fails closed with
//!   `MySqlError::UnsupportedAuthPlugin` and the server observes ZERO bytes of
//!   authentication response.
//!
//! What this does NOT prove: interoperability with a real MySQL/MariaDB
//! server, `caching_sha2_password` fallback ordering, or TLS behaviour.
//!
//! Test-vector provenance (derived outside this crate with coreutils
//! `sha1sum`; password = "password"):
//!
//! ```text
//! SHA1("abc")                        = a9993e364706816aba3e25717850c26c9cd0d89d (RFC 3174)
//! SHA1("password")                   = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
//! SHA1(SHA1("password"))             = 2470c0c06dee42fd1618bb99005adca2ec9d1e19
//!     (= MySQL `SELECT PASSWORD('password')` -> *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19)
//! nonce A                            = "nativeauthnonce12345"
//! SHA1(A || SHA1(SHA1("password")))  = 01aeea635fa8907bbb219f283938dbd3869ff746
//! scramble(A)                        = 5a048b879611af44bda3ba2355c0e8c8f879789e
//! nonce B                            = "switchnonce-98765432"
//! SHA1(B || SHA1(SHA1("password")))  = 7c13b4eb235de8aff78e6d7267bcec88e4cd7a5c
//! scramble(B)                        = 27b9d50feae4d790f10c48790b44df939a2bf584
//! ```

use asupersync::cx::Cx;
use asupersync::database::{MySqlConnectOptions, MySqlConnection, MySqlError};
use asupersync::types::Outcome;
use sha1::{Digest as _, Sha1};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

const PASSWORD: &str = "password";
const HANDSHAKE_NONCE: &[u8; 20] = b"nativeauthnonce12345";
const HANDSHAKE_SCRAMBLE_HEX: &str = "5a048b879611af44bda3ba2355c0e8c8f879789e";
const SWITCH_NONCE: &[u8; 20] = b"switchnonce-98765432";
const SWITCH_SCRAMBLE_HEX: &str = "27b9d50feae4d790f10c48790b44df939a2bf584";
const CACHING_SHA2_NONCE: &[u8; 20] = b"caching-sha2-nonce00";
const DOUBLE_SHA1_PASSWORD_HEX: &str = "2470c0c06dee42fd1618bb99005adca2ec9d1e19";
const RFC3174_ABC_HEX: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const COM_PING: u8 = 0x0E;

/// Exact fail-closed messages the driver emits today; pinned verbatim so a
/// wording change is a deliberate act.
const PERMANENTLY_DISABLED_MESSAGE: &str = "mysql_native_password is permanently disabled due to \
    SHA1 cryptographic weaknesses that enable offline password cracking from captured network \
    exchanges. Use MySQL 5.7+ with caching_sha2_password (default in MySQL 8.0+) or configure \
    your MySQL server to require secure authentication plugins.";
const PERMANENTLY_BLOCKED_MESSAGE: &str = "mysql_native_password permanently blocked due to SHA1 \
    cryptographic weakness. SHA1 enables offline password cracking from captured network \
    exchanges. Use caching_sha2_password instead.";

// ---------------------------------------------------------------------------
// Reference computation (independent of asupersync::database)
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex digit pair"))
        .collect()
}

/// Reference `mysql_native_password` scramble written directly from the
/// formula against the `sha1` crate. It deliberately calls nothing in
/// `asupersync::database`.
fn reference_native_scramble(password: &str, nonce: &[u8]) -> Vec<u8> {
    let stage1 = Sha1::digest(password.as_bytes());
    let stage2 = Sha1::digest(stage1);
    let mut nonce_and_stage2 = Vec::with_capacity(nonce.len() + stage2.len());
    nonce_and_stage2.extend_from_slice(nonce);
    nonce_and_stage2.extend_from_slice(&stage2);
    let mask = Sha1::digest(&nonce_and_stage2);
    stage1.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
}

// ---------------------------------------------------------------------------
// Scripted-server wire helpers
// ---------------------------------------------------------------------------

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00FF_FFFF, "single-packet payload only");
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

/// HandshakeV10 with the 20-byte nonce split the way MySQL 5.7/8.0 send it:
/// auth-plugin-data-part-1 (8 bytes), then part-2 (12 bytes) followed by a
/// trailing NUL, with `auth_plugin_data_len = 21` counting that NUL.
fn handshake_v10_packet(plugin_name: &str, auth_data: &[u8; 20]) -> Vec<u8> {
    let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
    let caps_lower = u16::try_from(capabilities & 0xFFFF).expect("lower caps fit u16");
    let caps_upper = u16::try_from(capabilities >> 16).expect("upper caps fit u16");
    let auth_data_len = u8::try_from(auth_data.len() + 1).expect("auth data len fits u8");

    let mut payload = Vec::new();
    payload.push(10); // protocol version
    payload.extend_from_slice(b"8.0.0-asupersync-scripted\0");
    payload.extend_from_slice(&42_u32.to_le_bytes()); // connection id
    payload.extend_from_slice(&auth_data[..8]); // auth-plugin-data-part-1
    payload.push(0); // filler
    payload.extend_from_slice(&caps_lower.to_le_bytes());
    payload.push(33); // character set (utf8mb3_general_ci)
    payload.extend_from_slice(&0_u16.to_le_bytes()); // status flags
    payload.extend_from_slice(&caps_upper.to_le_bytes());
    payload.push(auth_data_len);
    payload.extend_from_slice(&[0; 10]); // reserved
    payload.extend_from_slice(&auth_data[8..]); // auth-plugin-data-part-2
    payload.push(0); // trailing NUL: must NOT enter the scramble
    payload.extend_from_slice(plugin_name.as_bytes());
    payload.push(0);
    mysql_packet(0, &payload)
}

fn auth_switch_request_packet(sequence: u8, plugin_name: &str, auth_data: &[u8]) -> Vec<u8> {
    let mut payload = vec![0xFE];
    payload.extend_from_slice(plugin_name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(auth_data);
    payload.push(0); // trailing NUL: must NOT enter the scramble
    mysql_packet(sequence, &payload)
}

fn ok_packet(sequence: u8) -> Vec<u8> {
    // OK header, affected rows, last insert id, status flags, warnings.
    mysql_packet(sequence, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
}

/// Read one packet; returns `(sequence_id, payload)`.
fn read_packet(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0; 4];
    stream.read_exact(&mut header).expect("read packet header");
    let len =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let mut payload = vec![0; len];
    stream
        .read_exact(&mut payload)
        .expect("read packet payload");
    (header[3], payload)
}

#[derive(Debug)]
struct HandshakeResponse {
    username: String,
    auth_response: Vec<u8>,
    plugin_name: String,
}

fn parse_handshake_response(payload: &[u8]) -> HandshakeResponse {
    let capabilities = u32::from_le_bytes(payload[..4].try_into().expect("capabilities"));
    let mut cursor = 4 + 4 + 1 + 23;

    let username = read_null_terminated(payload, &mut cursor);
    let auth_len = usize::try_from(read_lenenc_int(payload, &mut cursor)).expect("auth len");
    let auth_response = payload[cursor..cursor + auth_len].to_vec();
    cursor += auth_len;

    if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        let _ = read_null_terminated(payload, &mut cursor);
    }

    let plugin_name = read_null_terminated(payload, &mut cursor);
    HandshakeResponse {
        username,
        auth_response,
        plugin_name,
    }
}

fn read_null_terminated(payload: &[u8], cursor: &mut usize) -> String {
    let start = *cursor;
    let end = payload[start..]
        .iter()
        .position(|&byte| byte == 0)
        .map(|offset| start + offset)
        .expect("null-terminated field");
    *cursor = end + 1;
    String::from_utf8(payload[start..end].to_vec()).expect("utf8 field")
}

fn read_lenenc_int(payload: &[u8], cursor: &mut usize) -> u64 {
    let first = payload[*cursor];
    *cursor += 1;
    match first {
        0x00..=0xFA => u64::from(first),
        0xFC => {
            let bytes = &payload[*cursor..*cursor + 2];
            *cursor += 2;
            u64::from(u16::from_le_bytes(bytes.try_into().expect("u16 lenenc")))
        }
        0xFD => {
            let bytes = &payload[*cursor..*cursor + 3];
            *cursor += 3;
            u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16)
        }
        0xFE => {
            let bytes = &payload[*cursor..*cursor + 8];
            *cursor += 8;
            u64::from_le_bytes(bytes.try_into().expect("u64 lenenc"))
        }
        0xFB | 0xFF => panic!("unexpected length-encoded integer prefix: {first:#x}"),
    }
}

/// Number of bytes the client sends after the server's last write. `0` means
/// the client closed the socket (EOF) or stayed silent until the 2 s read
/// timeout; any other error is a test failure.
fn count_client_bytes(stream: &mut TcpStream) -> usize {
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(n) => n,
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset
                    | ErrorKind::TimedOut
                    | ErrorKind::WouldBlock
            ) =>
        {
            0
        }
        Err(err) => panic!("unexpected server-side read error: {err}"),
    }
}

/// Script the post-authentication COM_PING exchange and return the command
/// byte(s) the client sent, so the test proves a real command round trip
/// after the OK packet.
fn serve_ping(stream: &mut TcpStream) -> Vec<u8> {
    let (sequence, payload) = read_packet(stream);
    stream
        .write_all(&ok_packet(sequence.wrapping_add(1)))
        .expect("write ping ok");
    stream.flush().expect("flush ping ok");
    payload
}

fn connect_options(addr: SocketAddr) -> MySqlConnectOptions {
    let mut options = MySqlConnectOptions::parse(&format!(
        "mysql://user:{PASSWORD}@{}:{}/db",
        addr.ip(),
        addr.port()
    ))
    .expect("parse mysql options");
    options.connect_timeout = Some(Duration::from_secs(2));
    options
}

fn spawn_scripted_server<T, F>(script: F) -> (SocketAddr, JoinHandle<T>)
where
    T: Send + 'static,
    F: FnOnce(TcpStream) -> T + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        script(stream)
    });
    (addr, handle)
}

fn connect_and_ping(options: MySqlConnectOptions) -> Outcome<(), MySqlError> {
    futures_lite::future::block_on(async {
        let cx = Cx::for_testing();
        let mut conn = match MySqlConnection::connect_with_options(&cx, options).await {
            Outcome::Ok(conn) => conn,
            other => panic!("expected opt-in native-password connect to succeed, got {other:?}"),
        };
        conn.ping(&cx).await
    })
}

fn connect_only(options: MySqlConnectOptions) -> Outcome<MySqlConnection, MySqlError> {
    futures_lite::future::block_on(async {
        MySqlConnection::connect_with_options(&Cx::for_testing(), options).await
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The in-test reference formula reproduces the externally derived vectors
/// (RFC 3174 `abc`, MySQL's documented `PASSWORD('password')`, and the two
/// `sha1sum`-derived scrambles). This anchors every later byte comparison.
#[test]
fn reference_scramble_matches_externally_derived_vectors() {
    assert_eq!(
        Sha1::digest(b"abc").as_slice(),
        hex_to_bytes(RFC3174_ABC_HEX).as_slice()
    );
    assert_eq!(
        Sha1::digest(Sha1::digest(PASSWORD.as_bytes())).as_slice(),
        hex_to_bytes(DOUBLE_SHA1_PASSWORD_HEX).as_slice()
    );
    assert_eq!(
        reference_native_scramble(PASSWORD, HANDSHAKE_NONCE),
        hex_to_bytes(HANDSHAKE_SCRAMBLE_HEX)
    );
    assert_eq!(
        reference_native_scramble(PASSWORD, SWITCH_NONCE),
        hex_to_bytes(SWITCH_SCRAMBLE_HEX)
    );
}

#[derive(Debug)]
struct HandshakeObservation {
    response: HandshakeResponse,
    ping_payload: Vec<u8>,
}

/// Positive, initial-handshake path: server demands `mysql_native_password`
/// in HandshakeV10 with nonce A; client (flag = true) must send exactly
/// scramble(A), then authenticate on OK and complete a COM_PING.
#[test]
fn handshake_native_password_opt_in_sends_documented_scramble_and_connects() {
    let (addr, server) = spawn_scripted_server(|mut stream| {
        stream
            .write_all(&handshake_v10_packet(
                "mysql_native_password",
                HANDSHAKE_NONCE,
            ))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let (sequence, payload) = read_packet(&mut stream);
        let response = parse_handshake_response(&payload);
        // Scripted server: accept unconditionally; the test asserts the bytes.
        stream
            .write_all(&ok_packet(sequence.wrapping_add(1)))
            .expect("write ok");
        stream.flush().expect("flush ok");

        let ping_payload = serve_ping(&mut stream);
        HandshakeObservation {
            response,
            ping_payload,
        }
    });

    let mut options = connect_options(addr);
    options.insecure_legacy_mysql_native_password = true;
    let ping_outcome = connect_and_ping(options);
    assert!(
        matches!(ping_outcome, Outcome::Ok(())),
        "post-auth COM_PING must succeed, got {ping_outcome:?}"
    );

    let observed = server.join().expect("join server");
    assert_eq!(observed.response.username, "user");
    assert_eq!(observed.response.plugin_name, "mysql_native_password");
    assert_eq!(
        observed.response.auth_response,
        hex_to_bytes(HANDSHAKE_SCRAMBLE_HEX),
        "auth response must be the sha1sum-derived scramble for nonce A"
    );
    assert_eq!(
        observed.response.auth_response,
        reference_native_scramble(PASSWORD, HANDSHAKE_NONCE),
        "auth response must match the in-test reference formula"
    );
    assert_eq!(observed.ping_payload, [COM_PING]);
}

/// Planted negative, initial-handshake path: flag = false (default) must fail
/// closed with the existing error and message, and the server must observe
/// that no bytes at all were sent in response to the native challenge.
#[test]
fn handshake_native_password_without_opt_in_fails_closed_and_sends_no_bytes() {
    let (addr, server) = spawn_scripted_server(|mut stream| {
        stream
            .write_all(&handshake_v10_packet(
                "mysql_native_password",
                HANDSHAKE_NONCE,
            ))
            .expect("write handshake");
        stream.flush().expect("flush handshake");
        count_client_bytes(&mut stream)
    });

    let mut options = connect_options(addr);
    // Even the downgrade opt-in must not enable the plugin by itself.
    options.insecure_allow_auth_switch_downgrade = true;
    assert!(!options.insecure_legacy_mysql_native_password);
    let outcome = connect_only(options);

    match outcome {
        Outcome::Err(MySqlError::UnsupportedAuthPlugin(message)) => {
            assert_eq!(message, PERMANENTLY_DISABLED_MESSAGE);
        }
        other => panic!("expected fail-closed UnsupportedAuthPlugin, got {other:?}"),
    }

    let client_bytes = server.join().expect("join server");
    assert_eq!(
        client_bytes, 0,
        "client must not send any handshake response when native auth is not opted in"
    );
}

#[derive(Debug)]
struct SwitchObservation {
    initial: HandshakeResponse,
    switch_response: Vec<u8>,
    ping_payload: Vec<u8>,
}

/// Positive, AuthSwitchRequest path: server starts with `caching_sha2_password`
/// then switches to `mysql_native_password` with nonce B (NUL-terminated).
/// Client (both opt-ins) must answer with exactly scramble(B) -- proving it
/// used the switch nonce, not the handshake nonce, and excluded the NUL.
#[test]
fn auth_switch_native_password_opt_in_sends_documented_scramble_and_connects() {
    let (addr, server) = spawn_scripted_server(|mut stream| {
        stream
            .write_all(&handshake_v10_packet(
                "caching_sha2_password",
                CACHING_SHA2_NONCE,
            ))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let (sequence, payload) = read_packet(&mut stream);
        let initial = parse_handshake_response(&payload);

        stream
            .write_all(&auth_switch_request_packet(
                sequence.wrapping_add(1),
                "mysql_native_password",
                SWITCH_NONCE,
            ))
            .expect("write auth switch");
        stream.flush().expect("flush auth switch");

        let (switch_sequence, switch_response) = read_packet(&mut stream);
        stream
            .write_all(&ok_packet(switch_sequence.wrapping_add(1)))
            .expect("write ok");
        stream.flush().expect("flush ok");

        let ping_payload = serve_ping(&mut stream);
        SwitchObservation {
            initial,
            switch_response,
            ping_payload,
        }
    });

    let mut options = connect_options(addr);
    options.insecure_legacy_mysql_native_password = true;
    options.insecure_allow_auth_switch_downgrade = true;
    let ping_outcome = connect_and_ping(options);
    assert!(
        matches!(ping_outcome, Outcome::Ok(())),
        "post-auth COM_PING must succeed, got {ping_outcome:?}"
    );

    let observed = server.join().expect("join server");
    assert_eq!(observed.initial.plugin_name, "caching_sha2_password");
    assert_eq!(
        observed.initial.auth_response.len(),
        32,
        "initial caching_sha2 response should be SHA-256 sized"
    );
    assert_eq!(
        observed.switch_response,
        hex_to_bytes(SWITCH_SCRAMBLE_HEX),
        "auth-switch response must be the sha1sum-derived scramble for nonce B"
    );
    assert_eq!(
        observed.switch_response,
        reference_native_scramble(PASSWORD, SWITCH_NONCE),
        "auth-switch response must match the in-test reference formula"
    );
    assert_ne!(
        observed.switch_response,
        reference_native_scramble(PASSWORD, HANDSHAKE_NONCE),
        "switch response must not be computed from the handshake nonce"
    );
    assert_eq!(observed.ping_payload, [COM_PING]);
}

/// Planted negative, AuthSwitchRequest path: the downgrade policy is opted in
/// but the legacy plugin is not. The client must fail closed with the existing
/// error and message, and the server must observe NO auth-switch response.
#[test]
fn auth_switch_native_password_without_legacy_opt_in_fails_closed_and_sends_no_response() {
    let (addr, server) = spawn_scripted_server(|mut stream| {
        stream
            .write_all(&handshake_v10_packet(
                "caching_sha2_password",
                CACHING_SHA2_NONCE,
            ))
            .expect("write handshake");
        stream.flush().expect("flush handshake");

        let (sequence, payload) = read_packet(&mut stream);
        let initial = parse_handshake_response(&payload);
        assert_eq!(initial.plugin_name, "caching_sha2_password");

        stream
            .write_all(&auth_switch_request_packet(
                sequence.wrapping_add(1),
                "mysql_native_password",
                SWITCH_NONCE,
            ))
            .expect("write auth switch");
        stream.flush().expect("flush auth switch");

        count_client_bytes(&mut stream)
    });

    let mut options = connect_options(addr);
    options.insecure_allow_auth_switch_downgrade = true;
    assert!(!options.insecure_legacy_mysql_native_password);
    let outcome = connect_only(options);

    match outcome {
        Outcome::Err(MySqlError::UnsupportedAuthPlugin(message)) => {
            assert_eq!(message, PERMANENTLY_BLOCKED_MESSAGE);
        }
        other => panic!("expected fail-closed UnsupportedAuthPlugin, got {other:?}"),
    }

    let client_bytes = server.join().expect("join server");
    assert_eq!(
        client_bytes, 0,
        "client must not send an auth-switch response when native auth is not opted in"
    );
}
