//! Golden snapshots of canonical database wire-protocol frames produced or
//! consumed by `src/database/`. Each snapshot freezes the byte-exact
//! frame layout against the relevant protocol spec so any drift between
//! asupersync's encoder/decoder and the over-the-wire format is caught
//! at unit-test time without needing a real backend.
//!
//! Bead: br-asupersync-x3313u
//!
//! Run with:
//!     cargo test --features "postgres mysql" --test database_wire_frame_goldens
//!
//! Update goldens on intentional change:
//!     cargo insta review
//!
//! Frame coverage:
//!   PostgreSQL (frontend Extended Query Protocol, RFC §53.2):
//!     * Bind anonymous, no params, all-text result format
//!     * Bind anonymous, single i32 param (binary), all-text result
//!     * Bind named portal + named statement, no params
//!     * Execute anonymous portal, max_rows = 0 (all rows)
//!     * Execute named portal, max_rows = 100
//!     * Sync (zero-body terminator of an extended query batch)
//!
//!   MySQL (server-side packets the connection MUST decode, MySQL Internals
//!   manual §14):
//!     * OK packet, minimal body (affected_rows = 0, last_insert_id = 0,
//!       status_flags = SERVER_STATUS_AUTOCOMMIT, warnings = 0)
//!     * ERR packet, ER_DUP_ENTRY (1062), SQLSTATE 23000
//!
//! Goldens use a hexdump renderer so any byte change produces a one-line
//! diff that humans can review against the spec.

#![cfg(all(test, feature = "postgres", feature = "mysql"))]

use asupersync::database::mysql::{fuzz_parse_error_packet, fuzz_parse_ok_packet_fields};
use asupersync::database::postgres::{
    Format, ToSql, build_bind_msg, build_execute_msg, build_sync_msg,
};

/// Render a byte slice as `xxd`-style hexdump:
///
///     0000  01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10  |................|
///
/// Goldens are easier to review than raw `[u8]` Debug because every
/// 16-byte row aligns the offset, hex bytes, and ASCII view.
fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let offset = row * 16;
        out.push_str(&format!("{offset:04x}  "));
        for (i, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x} "));
            if i == 7 {
                out.push(' ');
            }
        }
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in chunk {
            let c = if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push_str("|\n");
    }
    out.push_str(&format!("({} bytes)\n", bytes.len()));
    out
}

// ---------------------------------------------------------------------------
// PostgreSQL Extended Query Protocol — frontend frames
// ---------------------------------------------------------------------------

/// Bind ('B') with empty portal name, empty prepared-statement name, zero
/// parameters, all-text result format. Per PG protocol §53.2.4 the wire
/// layout is:
///
///   byte1   = 'B'                            ; FrontendMessage::Bind
///   int32   = total length including length  ; minimum 12 with empty cstrings
///   cstr    = portal name                    ; "\0"
///   cstr    = statement name                 ; "\0"
///   int16   = N param format codes           ; 0 (all-text default)
///   int16   = N param values                 ; 0
///   int16   = M result format codes          ; 1 (single uniform code)
///   int16   = format[0]                      ; 0 = Text
///
/// Total = 1 + 4 + 1 + 1 + 2 + 2 + 2 + 2 = 15 bytes.
#[test]
fn pg_bind_msg_anonymous_no_params_text_result() {
    let msg = build_bind_msg("", "", &[], Format::Text).expect("build_bind_msg");
    insta::assert_snapshot!("pg_bind_anonymous_no_params_text", hexdump(&msg));
}

/// Bind with a single i32 (binary-encoded) parameter. Layout adds:
///   int16 = 1 (uniform format code) + int16 = 1 (Binary)
///   int16 = 1 (one value) + int32 = 4 (length) + 4 bytes (i32 BE = 42)
///   int16 = 1 (one result format) + int16 = 0 (Text)
#[test]
fn pg_bind_msg_one_i32_binary_param() {
    let v: i32 = 42;
    let params: &[&dyn ToSql] = &[&v];
    let msg = build_bind_msg("", "", params, Format::Text).expect("build_bind_msg");
    insta::assert_snapshot!("pg_bind_one_i32_binary_param", hexdump(&msg));
}

/// Bind with named portal and named prepared statement. Same shape as the
/// anonymous case but with non-empty cstrings.
#[test]
fn pg_bind_msg_named_portal_named_stmt() {
    let msg = build_bind_msg("p1", "stmt_1", &[], Format::Binary).expect("build_bind_msg");
    insta::assert_snapshot!(
        "pg_bind_named_portal_named_stmt_binary_result",
        hexdump(&msg)
    );
}

/// Execute ('E') with empty portal, max_rows = 0 (deliver all rows).
/// Layout:
///   byte1 = 'E'
///   int32 = length
///   cstr  = portal
///   int32 = max_rows
#[test]
fn pg_execute_msg_anonymous_all_rows() {
    let msg = build_execute_msg("", 0).expect("build_execute_msg");
    insta::assert_snapshot!("pg_execute_anonymous_all_rows", hexdump(&msg));
}

/// Execute with named portal and a row cap of 100.
#[test]
fn pg_execute_msg_named_portal_max_100() {
    let msg = build_execute_msg("p1", 100).expect("build_execute_msg");
    insta::assert_snapshot!("pg_execute_named_portal_max_100", hexdump(&msg));
}

/// Sync ('S') is the zero-body terminator of an extended-query batch.
/// Layout: byte1 = 'S', int32 = 4 (length only). Total = 5 bytes.
#[test]
fn pg_sync_msg_canonical_5_bytes() {
    let msg = build_sync_msg().expect("build_sync_msg");
    insta::assert_snapshot!("pg_sync_canonical_5_bytes", hexdump(&msg));
}

// ---------------------------------------------------------------------------
// MySQL — server packets the client must decode
// ---------------------------------------------------------------------------

/// OK packet body (header byte 0x00 already stripped by the packet framing
/// layer). Per MySQL Internals §14.1.3.1:
///
///   header           = 0x00
///   lenenc int       = affected_rows                 ; 0 → 0x00
///   lenenc int       = last_insert_id                ; 0 → 0x00
///   int<2>           = status_flags                  ; SERVER_STATUS_AUTOCOMMIT = 0x0002
///   int<2>           = warnings                      ; 0
///
/// Fixed-byte hex: `00 00 00 02 00 00 00`. The fuzz helper returns
/// `(affected_rows, status_flags)`.
#[test]
fn mysql_ok_packet_minimal_autocommit_no_warnings() {
    // SERVER_STATUS_AUTOCOMMIT (bit 1) — the canonical idle-session state.
    let body: &[u8] = &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    let (affected_rows, status_flags) = fuzz_parse_ok_packet_fields(body).expect("parse OK");
    insta::assert_debug_snapshot!(
        "mysql_ok_minimal_autocommit_no_warnings",
        (
            "input_hex",
            body.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            "affected_rows",
            affected_rows,
            "status_flags_hex",
            format!("0x{status_flags:04x}"),
        )
    );
}

/// ERR packet body (also pre-stripped of the packet framing). Per
/// MySQL Internals §14.1.3.2:
///
///   header     = 0xff
///   int<2>     = error code (le)         ; 1062 = ER_DUP_ENTRY
///   string<1>  = sql_state_marker        ; '#'
///   string<5>  = sql_state               ; "23000"
///   string<EOF> = error message
///
/// Picks the canonical UNIQUE-violation case so the SQLSTATE classifier
/// path (`MySqlError::is_unique_violation`) has a wire-level golden it
/// can never silently regress.
#[test]
fn mysql_err_packet_dup_entry_23000() {
    // 0xff | 1062 LE | '#' | b"23000" | b"Duplicate entry 'x' for key 'PRIMARY'"
    let mut body: Vec<u8> = Vec::new();
    body.push(0xff);
    body.extend_from_slice(&1062u16.to_le_bytes());
    body.push(b'#');
    body.extend_from_slice(b"23000");
    body.extend_from_slice(b"Duplicate entry 'x' for key 'PRIMARY'");
    let err = fuzz_parse_error_packet(&body);
    insta::assert_debug_snapshot!("mysql_err_dup_entry_23000", err);
}
