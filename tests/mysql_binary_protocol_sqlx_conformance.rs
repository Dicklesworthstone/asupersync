#![cfg(all(feature = "mysql", feature = "test-internals"))]
//! Differential conformance harness for MySQL COM_STMT_EXECUTE bytes vs sqlx.

use asupersync::database::mysql::{ToSql, fuzz_build_stmt_execute_packet};
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};
use sqlx::{Connection, MySqlConnection};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const COM_QUERY: u8 = 0x03;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_CLOSE: u8 = 0x19;
const MYSQL_TYPE_VAR_STRING: u8 = 0xFD;

const CLIENT_PROTOCOL_41: u32 = 512;
const CLIENT_TRANSACTIONS: u32 = 8192;
const CLIENT_SECURE_CONNECTION: u32 = 32768;
const CLIENT_MULTI_RESULTS: u32 = 1 << 17;
const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;

const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
const STATEMENT_ID: u32 = 7;
const SQL: &str = "DO ?, ?, ?";

#[derive(Debug)]
struct CapturedPacket {
    full: Vec<u8>,
    payload: Vec<u8>,
}

fn lenenc_int(value: usize) -> Vec<u8> {
    match value {
        0..=250 => vec![value as u8],
        251..=0xFFFF => {
            let mut out = vec![0xFC];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xFF_FFFF => {
            let value = value as u32;
            vec![
                0xFD,
                (value & 0xFF) as u8,
                ((value >> 8) & 0xFF) as u8,
                ((value >> 16) & 0xFF) as u8,
            ]
        }
        _ => {
            let mut out = vec![0xFE];
            out.extend_from_slice(&(value as u64).to_le_bytes());
            out
        }
    }
}

fn packetize(payload: &[u8], sequence: u8) -> Vec<u8> {
    assert!(
        payload.len() < (1 << 24),
        "payload must fit in one MySQL packet"
    );
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push((len & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(sequence);
    out.extend_from_slice(payload);
    out
}

fn read_packet(stream: &mut TcpStream) -> io::Result<CapturedPacket> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let payload_len =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;

    let mut full = header.to_vec();
    full.extend_from_slice(&payload);
    Ok(CapturedPacket { full, payload })
}

fn write_packet(stream: &mut TcpStream, payload: &[u8], sequence: u8) -> io::Result<()> {
    stream.write_all(&packetize(payload, sequence))?;
    stream.flush()
}

fn ok_packet_payload() -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00];
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

fn eof_packet_payload() -> Vec<u8> {
    let mut payload = vec![0xFE];
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload
}

fn column_definition_payload(name: &str, column_type_code: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&lenenc_int(3));
    payload.extend_from_slice(b"def");
    payload.extend_from_slice(&lenenc_int(0));
    payload.extend_from_slice(&lenenc_int(0));
    payload.extend_from_slice(&lenenc_int(0));
    payload.extend_from_slice(&lenenc_int(name.len()));
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&lenenc_int(name.len()));
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&lenenc_int(0x0C));
    payload.extend_from_slice(&33u16.to_le_bytes());
    payload.extend_from_slice(&255u32.to_le_bytes());
    payload.push(column_type_code);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0, 0]);
    payload
}

fn stmt_prepare_ok_payload(statement_id: u32, param_count: u16) -> Vec<u8> {
    let mut payload = vec![0x00];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&param_count.to_le_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

fn handshake_payload() -> Vec<u8> {
    let capabilities = CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    let auth_plugin_data = b"12345678abcdefgh1234";

    let mut payload = Vec::new();
    payload.push(0x0A);
    payload.extend_from_slice(b"8.0.36-asupersync-test\0");
    payload.extend_from_slice(&41u32.to_le_bytes());
    payload.extend_from_slice(&auth_plugin_data[..8]);
    payload.push(0x00);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(33);
    payload.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0u8; 10]);
    payload.extend_from_slice(&auth_plugin_data[8..]);
    payload.push(0x00);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn capture_sqlx_execute_packet() -> (Vec<u8>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake mysql server");
    let addr = listener.local_addr().expect("fake mysql address");

    let server = thread::spawn(move || -> (Vec<u8>, Vec<u8>) {
        let (mut stream, _) = listener.accept().expect("accept sqlx client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set fake mysql read timeout");

        write_packet(&mut stream, &handshake_payload(), 0).expect("write handshake");

        let _login = read_packet(&mut stream).expect("read login packet");
        write_packet(&mut stream, &ok_packet_payload(), 2).expect("write login ok");

        let prepare = loop {
            let packet = read_packet(&mut stream).expect("read post-login client packet");
            match packet.payload.first().copied() {
                Some(COM_QUERY) => {
                    write_packet(&mut stream, &ok_packet_payload(), 1).expect("write init ok");
                }
                Some(COM_STMT_PREPARE) => break packet.payload,
                other => panic!("unexpected packet before prepare: {other:?}"),
            }
        };

        write_packet(&mut stream, &stmt_prepare_ok_payload(STATEMENT_ID, 3), 1)
            .expect("write prepare ok");
        for (sequence, name) in (2u8..=4).zip(["p0", "p1", "p2"]) {
            write_packet(
                &mut stream,
                &column_definition_payload(name, MYSQL_TYPE_VAR_STRING),
                sequence,
            )
            .expect("write parameter definition");
        }
        write_packet(&mut stream, &eof_packet_payload(), 5).expect("write parameter eof");

        let execute = loop {
            let packet = read_packet(&mut stream).expect("read packet after prepare");
            match packet.payload.first().copied() {
                Some(COM_STMT_EXECUTE) => break packet.full,
                Some(COM_QUERY) => {
                    write_packet(&mut stream, &ok_packet_payload(), 1).expect("write init ok");
                }
                other => panic!("unexpected packet before execute: {other:?}"),
            }
        };

        write_packet(&mut stream, &ok_packet_payload(), 1).expect("write execute ok");

        loop {
            match read_packet(&mut stream) {
                Ok(packet) if packet.payload.first().copied() == Some(COM_STMT_CLOSE) => {}
                Ok(packet) if packet.payload.first().copied() == Some(COM_QUERY) => {
                    write_packet(&mut stream, &ok_packet_payload(), 1)
                        .expect("write trailing query ok");
                }
                Ok(_) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("unexpected fake mysql read error: {err}"),
            }
        }

        (prepare, execute)
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    runtime.block_on(async move {
        let options = MySqlConnectOptions::new()
            .host("127.0.0.1")
            .port(addr.port())
            .username("user")
            .ssl_mode(MySqlSslMode::Disabled);

        let mut conn = MySqlConnection::connect_with(&options)
            .await
            .expect("connect sqlx client");

        let param_int = -42_i32;
        let param_text = "bind-vs-sqlx";
        let param_null: Option<i32> = None;

        sqlx::query(SQL)
            .bind(param_int)
            .bind(param_text)
            .bind(param_null)
            .execute(&mut conn)
            .await
            .expect("execute sqlx prepared statement");
    });

    server.join().expect("join fake mysql server")
}

#[test]
fn stmt_execute_packet_matches_sqlx_for_same_params() {
    let (sqlx_prepare_payload, sqlx_execute_packet) = capture_sqlx_execute_packet();

    assert_eq!(
        sqlx_prepare_payload[0], COM_STMT_PREPARE,
        "sqlx must prepare before sending COM_STMT_EXECUTE for bound parameters"
    );
    assert_eq!(
        &sqlx_prepare_payload[1..],
        SQL.as_bytes(),
        "sqlx prepared SQL must match the harness fixture"
    );

    let param_int = -42_i32;
    let param_text = String::from("bind-vs-sqlx");
    let param_null: Option<i32> = None;
    let asupersync_params: [&dyn ToSql; 3] = [&param_int, &param_text, &param_null];
    let asupersync_execute_packet =
        fuzz_build_stmt_execute_packet(STATEMENT_ID, &asupersync_params)
            .expect("build asupersync COM_STMT_EXECUTE packet");

    assert_eq!(
        sqlx_execute_packet,
        asupersync_execute_packet,
        "same prepared SQL + same params must produce byte-identical COM_STMT_EXECUTE wire bytes\n\
         sqlx:       {}\n\
         asupersync: {}",
        hex(&sqlx_execute_packet),
        hex(&asupersync_execute_packet),
    );
}
