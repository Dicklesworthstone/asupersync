//! TLS 1.3 0-RTT and anti-replay conformance (RFC 8446 §4.1.2, §4.2.8 to
//! §4.2.11, §4.5, §4.6.1, §8 and Appendix E.5), run against `asupersync::tls`.
//!
//! Each requirement is either decided by production code or reported as
//! `TestVerdict::Skipped` with the source line that shows why production
//! cannot be observed. No verdict comes from a model in this file:
//!
//! * Builder gates: `TlsAcceptorBuilder::build` and `TlsConnectorBuilder::build`
//!   run with each 0-RTT configuration, and the exact `TlsError` they return
//!   is compared (src/tls/acceptor.rs:1007-1062, src/tls/connector.rs:1058-1068).
//! * Replay policies: `EarlyDataReplayProtection::validate_request_for_early_data`
//!   (src/tls/acceptor.rs:186-221) is asked about methods, idempotency keys and
//!   nonces, and its exact refusal text is compared.
//! * Handshakes: a `TlsConnector` and a `TlsAcceptor`, both made by the
//!   production builders, run TLS 1.3 handshakes over an in-memory
//!   `VirtualTcpStream` pair (the pattern of tests/tls_conformance.rs). The
//!   bytes each side writes are recorded as they leave production, and their
//!   plaintext parts (record framing, ClientHello, ServerHello,
//!   HelloRetryRequest, alerts) are read with the RFC 8446 layout in `wire`
//!   below. Tickets live in a recording `ClientSessionStore`, passed in with
//!   `TlsConnectorBuilder::session_resumption`, that hands every call to
//!   rustls's `ClientSessionMemoryCache` and notes each ticket's
//!   `max_early_data_size`.
//! * Replays and tampering: a ClientHello that production sent is presented
//!   again to the same `TlsAcceptor::accept`, unchanged or with one change, and
//!   what the server writes back decides the verdict.
//!
//! The TLS state machine under `asupersync::tls` is rustls (Cargo.lock pins
//! 0.23.45). The handshake rows test that stack as asupersync configures it,
//! and each row names the asupersync setting that makes the behaviour
//! reachable.
//!
//! `ExpectedFailure` marks a requirement whose conforming outcome is a
//! refusal, where production refused with exactly the asserted error or wire
//! response. Any other outcome is `Fail`. Every refusal is paired with a
//! control that production accepts.
//!
//! Without `--features tls` every production row reports Skipped ("needs
//! --features tls").

use serde::{Deserialize, Serialize};
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

/// Test category for 0-RTT replay protection conformance tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum TestCategory {
    PreSharedKeyExtension,
    TicketAgeObfuscation,
    ServerReplayRejection,
    AntiReplayCache,
    EarlyDataLimits,
    FreshnessWindow,
    HelloRetryRequest,
}

/// Requirement level from RFC 8446.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test verdict for conformance tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// Result of one TLS 0-RTT conformance requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Tls0RttConformanceResult {
    pub test_id: String,
    /// The RFC 8446 sections the requirement comes from.
    pub rfc_section: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    /// What production did, for a Pass or ExpectedFailure verdict.
    pub evidence: Option<String>,
    /// Why the requirement failed or was skipped.
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Start of every Skipped note for a requirement production cannot show.
const NO_OBSERVABLE: &str = "production exposes no observable for this";

/// Start of every Skipped note in a build without the tls feature.
#[allow(dead_code)]
const NEEDS_TLS: &str = "needs --features tls";

/// How a requirement was decided.
#[derive(Debug)]
enum Decision {
    /// Production ran. `Ok` carries what it did, `Err` the violation.
    Decided(Result<String, String>),
    /// Production could not be reached; the note says why.
    Skipped(String),
}

/// Whether the conforming outcome is an acceptance or a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polarity {
    Conforms,
    Refuses,
}

/// What decides a requirement.
#[derive(Clone, Copy)]
enum Check {
    /// Production code, run against the collected handshakes.
    Production(fn(&production::Lab) -> Result<String, String>),
    /// No production observable; always Skipped with this note.
    Unobservable(fn() -> String),
}

struct Requirement {
    id: &'static str,
    rfc_section: &'static str,
    description: &'static str,
    category: TestCategory,
    level: RequirementLevel,
    polarity: Polarity,
    check: Check,
}

// ============================================================================
// Spec side: the RFC 8446 wire layout of the plaintext parts of a flight
// ============================================================================

/// RFC 8446 §4 and §5.1 layouts, used to read the bytes production wrote.
#[allow(dead_code)]
mod wire {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;

    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;

    pub const EXT_SUPPORTED_GROUPS: u16 = 10;
    pub const EXT_PRE_SHARED_KEY: u16 = 41;
    pub const EXT_EARLY_DATA: u16 = 42;
    pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
    pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const EXT_KEY_SHARE: u16 = 51;

    /// PskKeyExchangeMode psk_dhe_ke (RFC 8446 §4.2.9).
    pub const PSK_DHE_KE: u8 = 1;

    pub const GROUP_SECP384R1: u16 = 0x0018;
    pub const GROUP_X25519: u16 = 0x001d;

    pub const ALERT_FATAL: u8 = 2;
    pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;
    pub const ALERT_DECRYPT_ERROR: u8 = 51;

    const RECORD_HEADER: usize = 5;

    /// Offset of ClientHello.random in a record: the 5-byte record header,
    /// the 4-byte handshake header and the 2-byte legacy_version.
    pub const RANDOM_OFFSET: usize = 11;

    /// ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3).
    pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];

    /// One TLSPlaintext/TLSCiphertext record of a flight.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Record {
        pub content_type: u8,
        /// Offset of the record header in the flight.
        pub start: usize,
        /// Offset one past the last fragment byte.
        pub end: usize,
    }

    impl Record {
        /// The whole record, header included.
        pub fn bytes<'a>(&self, flight: &'a [u8]) -> &'a [u8] {
            &flight[self.start..self.end]
        }

        /// The record fragment.
        pub fn fragment<'a>(&self, flight: &'a [u8]) -> &'a [u8] {
            &flight[self.start + RECORD_HEADER..self.end]
        }
    }

    /// One extension of a hello; offsets are within the record bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Extension {
        pub kind: u16,
        pub data: Vec<u8>,
        pub start: usize,
        pub end: usize,
    }

    /// A ClientHello, ServerHello or HelloRetryRequest.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Hello {
        pub msg_type: u8,
        pub random: [u8; 32],
        pub extensions: Vec<Extension>,
    }

    impl Hello {
        pub fn extension(&self, kind: u16) -> Option<&Extension> {
            self.extensions
                .iter()
                .find(|extension| extension.kind == kind)
        }

        pub fn has(&self, kind: u16) -> bool {
            self.extension(kind).is_some()
        }

        pub fn kinds(&self) -> Vec<u16> {
            self.extensions
                .iter()
                .map(|extension| extension.kind)
                .collect()
        }

        pub fn is_hello_retry_request(&self) -> bool {
            self.msg_type == SERVER_HELLO && self.random == HELLO_RETRY_REQUEST_RANDOM
        }
    }

    /// The identities and binders of an OfferedPsks (RFC 8446 §4.2.11).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OfferedPsks {
        /// (identity, obfuscated_ticket_age) per PskIdentity.
        pub identities: Vec<(Vec<u8>, u32)>,
        pub binder_lengths: Vec<usize>,
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(bytes: &'a [u8], pos: usize) -> Self {
            Self { bytes, pos }
        }

        fn take(&mut self, count: usize, what: &str) -> Result<&'a [u8], String> {
            let bytes: &'a [u8] = self.bytes;
            let end = self
                .pos
                .checked_add(count)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| {
                    format!(
                        "{what}: needs {count} bytes at offset {}, {} remain",
                        self.pos,
                        bytes.len().saturating_sub(self.pos)
                    )
                })?;
            let taken = &bytes[self.pos..end];
            self.pos = end;
            Ok(taken)
        }

        fn read_u8(&mut self, what: &str) -> Result<u8, String> {
            Ok(self.take(1, what)?[0])
        }

        fn read_u16(&mut self, what: &str) -> Result<u16, String> {
            let bytes = self.take(2, what)?;
            Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
        }

        fn read_u24(&mut self, what: &str) -> Result<usize, String> {
            let bytes = self.take(3, what)?;
            Ok(
                (usize::from(bytes[0]) << 16)
                    | (usize::from(bytes[1]) << 8)
                    | usize::from(bytes[2]),
            )
        }

        fn read_u32(&mut self, what: &str) -> Result<u32, String> {
            let bytes = self.take(4, what)?;
            Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

        fn read_vec8(&mut self, what: &str) -> Result<&'a [u8], String> {
            let length = usize::from(self.read_u8(what)?);
            self.take(length, what)
        }

        fn read_vec16(&mut self, what: &str) -> Result<&'a [u8], String> {
            let length = usize::from(self.read_u16(what)?);
            self.take(length, what)
        }

        fn is_done(&self) -> bool {
            self.pos == self.bytes.len()
        }
    }

    /// Splits a flight into records (RFC 8446 §5.1).
    pub fn records(flight: &[u8]) -> Result<Vec<Record>, String> {
        let mut found = Vec::new();
        let mut start = 0;
        while start < flight.len() {
            let Some(header) = flight.get(start..start + RECORD_HEADER) else {
                return Err(format!(
                    "record at byte {start}: truncated header, {} bytes left",
                    flight.len() - start
                ));
            };
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let end = start + RECORD_HEADER + length;
            if end > flight.len() {
                return Err(format!(
                    "record at byte {start}: declares {length} fragment bytes, {} follow",
                    flight.len() - start - RECORD_HEADER
                ));
            }
            found.push(Record {
                content_type: header[0],
                start,
                end,
            });
            start = end;
        }
        Ok(found)
    }

    /// Reads the hello in a handshake record (RFC 8446 §4.1.2, §4.1.3).
    pub fn parse_hello(record: &[u8]) -> Result<Hello, String> {
        let mut header = Reader::new(record, 0);
        let content_type = header.read_u8("record content type")?;
        if content_type != HANDSHAKE {
            return Err(format!(
                "record content type {content_type} is not handshake ({HANDSHAKE})"
            ));
        }
        header.take(2, "record legacy_record_version")?;
        let fragment_length = usize::from(header.read_u16("record length")?);
        if RECORD_HEADER + fragment_length != record.len() {
            return Err(format!(
                "record declares {fragment_length} fragment bytes, {} are present",
                record.len().saturating_sub(RECORD_HEADER)
            ));
        }
        let msg_type = header.read_u8("handshake msg_type")?;
        let body_length = header.read_u24("handshake length")?;
        let body_end = header.pos + body_length;
        if body_end > record.len() {
            return Err(format!(
                "handshake message declares {body_length} bytes, {} are present",
                record.len() - header.pos
            ));
        }
        let mut body = Reader::new(&record[..body_end], header.pos);
        body.take(2, "legacy_version")?;
        let random: [u8; 32] = body
            .take(32, "random")?
            .try_into()
            .map_err(|_| "random is not 32 bytes".to_string())?;
        body.read_vec8("legacy_session_id")?;
        match msg_type {
            CLIENT_HELLO => {
                body.read_vec16("cipher_suites")?;
                body.read_vec8("legacy_compression_methods")?;
            }
            SERVER_HELLO => {
                body.take(2, "cipher_suite")?;
                body.take(1, "legacy_compression_method")?;
            }
            other => {
                return Err(format!(
                    "handshake msg_type {other} is neither ClientHello ({CLIENT_HELLO}) nor ServerHello ({SERVER_HELLO})"
                ));
            }
        }
        let extensions_length = usize::from(body.read_u16("extensions length")?);
        let extensions_end = body.pos + extensions_length;
        if extensions_end != body_end {
            return Err(format!(
                "extensions end at byte {extensions_end}, the hello at byte {body_end}"
            ));
        }
        let mut extensions = Vec::new();
        while !body.is_done() {
            let start = body.pos;
            let kind = body.read_u16("extension type")?;
            let data = body.read_vec16("extension_data")?.to_vec();
            extensions.push(Extension {
                kind,
                data,
                start,
                end: body.pos,
            });
        }
        Ok(Hello {
            msg_type,
            random,
            extensions,
        })
    }

    /// The record with its last two extensions in swapped order. No length
    /// changes, so the record stays well formed.
    pub fn with_last_two_extensions_swapped(record: &[u8]) -> Result<Vec<u8>, String> {
        let hello = parse_hello(record)?;
        let [.., earlier, last] = hello.extensions.as_slice() else {
            return Err(format!(
                "the hello has {} extensions, two are needed",
                hello.extensions.len()
            ));
        };
        let mut swapped = record[..earlier.start].to_vec();
        swapped.extend_from_slice(&record[last.start..last.end]);
        swapped.extend_from_slice(&record[earlier.start..earlier.end]);
        swapped.extend_from_slice(&record[last.end..]);
        Ok(swapped)
    }

    /// The record with the lowest bit of the first ClientHello.random byte
    /// inverted.
    pub fn with_random_bit_flipped(record: &[u8]) -> Result<Vec<u8>, String> {
        let hello = parse_hello(record)?;
        if hello.msg_type != CLIENT_HELLO {
            return Err(format!(
                "handshake msg_type {} is not a ClientHello",
                hello.msg_type
            ));
        }
        let mut altered = record.to_vec();
        altered[RANDOM_OFFSET] ^= 0x01;
        Ok(altered)
    }

    /// PskKeyExchangeModes (RFC 8446 §4.2.9).
    pub fn psk_modes(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut reader = Reader::new(data, 0);
        let modes = reader.read_vec8("ke_modes")?.to_vec();
        if !reader.is_done() {
            return Err("psk_key_exchange_modes has bytes after ke_modes".to_string());
        }
        Ok(modes)
    }

    /// NamedGroupList of supported_groups (RFC 8446 §4.2.7).
    pub fn named_groups(data: &[u8]) -> Result<Vec<u16>, String> {
        let mut outer = Reader::new(data, 0);
        let list = outer.read_vec16("named_group_list")?;
        if !outer.is_done() {
            return Err("supported_groups has bytes after named_group_list".to_string());
        }
        let mut reader = Reader::new(list, 0);
        let mut groups = Vec::new();
        while !reader.is_done() {
            groups.push(reader.read_u16("named group")?);
        }
        Ok(groups)
    }

    /// The groups of a ClientHello key_share (RFC 8446 §4.2.8).
    pub fn client_key_share_groups(data: &[u8]) -> Result<Vec<u16>, String> {
        let mut outer = Reader::new(data, 0);
        let list = outer.read_vec16("client_shares")?;
        if !outer.is_done() {
            return Err("key_share has bytes after client_shares".to_string());
        }
        let mut reader = Reader::new(list, 0);
        let mut groups = Vec::new();
        while !reader.is_done() {
            groups.push(reader.read_u16("KeyShareEntry.group")?);
            reader.read_vec16("KeyShareEntry.key_exchange")?;
        }
        Ok(groups)
    }

    /// A 2-byte extension body: ServerHello pre_shared_key.selected_identity
    /// or HelloRetryRequest key_share.selected_group.
    pub fn u16_value(data: &[u8], what: &str) -> Result<u16, String> {
        let [high, low] = data else {
            return Err(format!("{what}: {} bytes, expected 2", data.len()));
        };
        Ok(u16::from_be_bytes([*high, *low]))
    }

    /// OfferedPsks of a ClientHello pre_shared_key (RFC 8446 §4.2.11).
    pub fn offered_psks(data: &[u8]) -> Result<OfferedPsks, String> {
        let mut outer = Reader::new(data, 0);
        let identities_block = outer.read_vec16("identities")?;
        let binders_block = outer.read_vec16("binders")?;
        if !outer.is_done() {
            return Err("pre_shared_key has bytes after binders".to_string());
        }
        let mut identities = Vec::new();
        let mut reader = Reader::new(identities_block, 0);
        while !reader.is_done() {
            let identity = reader.read_vec16("PskIdentity.identity")?.to_vec();
            let age = reader.read_u32("PskIdentity.obfuscated_ticket_age")?;
            identities.push((identity, age));
        }
        let mut binder_lengths = Vec::new();
        let mut reader = Reader::new(binders_block, 0);
        while !reader.is_done() {
            binder_lengths.push(reader.read_vec8("PskBinderEntry")?.len());
        }
        Ok(OfferedPsks {
            identities,
            binder_lengths,
        })
    }

    /// (level, description) of an alert fragment (RFC 8446 §6).
    pub fn alert(fragment: &[u8]) -> Result<(u8, u8), String> {
        let [level, description] = fragment else {
            return Err(format!(
                "alert fragment of {} bytes, expected 2",
                fragment.len()
            ));
        };
        Ok((*level, *description))
    }
}

// ============================================================================
// Requirements production exposes no observable for
// ============================================================================

fn ticket_lifetime_unobservable() -> String {
    format!(
        "{NO_OBSERVABLE}: NewSessionTicket.ticket_lifetime travels encrypted under the \
         application traffic key, rustls keeps the received lifetime private \
         (Tls13ClientSessionValue exposes max_early_data_size() and suite() only), and \
         TlsAcceptorBuilder::build neither sets nor reports a lifetime: it builds the \
         ServerConfig with with_single_cert (src/tls/acceptor.rs:1205) and keeps rustls's \
         stateful session cache, whose lifetime no asupersync API returns"
    )
}

fn psk_parameters_unobservable() -> String {
    format!(
        "{NO_OBSERVABLE}: no public API resumes a ticket under a different ALPN protocol, \
         cipher suite or version. TlsConnector::connect (src/tls/connector.rs:135) takes no \
         per-connection ALPN or suite, rustls reuses a ticket only under the ClientConfig that \
         received it, and every TlsAcceptorBuilder::build (src/tls/acceptor.rs:1205) gets its \
         own session cache, so two acceptors with different ALPN never share a ticket"
    )
}

fn early_data_delivery_unobservable() -> String {
    format!(
        "{NO_OBSERVABLE}: TlsStream keeps the rustls connection in a private enum \
         (src/tls/stream.rs:86) and its public accessors (src/tls/stream.rs:213-257) include no \
         early-data reader or received-early-data flag; poll_read reads only the 1-RTT plaintext \
         (src/tls/stream.rs:514). EarlyDataReplayProtection::validate_request_for_early_data \
         (src/tls/acceptor.rs:186) has no caller outside src/tls/acceptor.rs, so no server \
         pipeline screens requests that arrived as 0-RTT; build() refuses the strategies that \
         would need it (src/tls/acceptor.rs:1029-1060)"
    )
}

fn client_early_data_cap_unobservable() -> String {
    format!(
        "{NO_OBSERVABLE}: an asupersync client cannot send 0-RTT application data. \
         TlsConnector::connect drives the handshake to completion before it returns the stream \
         (src/tls/connector.rs:135-156), and TlsStream has no early-data writer \
         (src/tls/stream.rs:86, 213-257), so enable_early_data(true) only adds the early_data \
         extension and its EndOfEarlyData"
    )
}

fn server_early_data_cap_unobservable() -> String {
    format!(
        "{NO_OBSERVABLE}: the cap reaches rustls (src/tls/acceptor.rs:1224), but exceeding it \
         needs a client that writes 0-RTT data, and TlsConnector::connect completes the \
         handshake before the caller can write (src/tls/connector.rs:135-156; no early-data \
         writer on TlsStream, src/tls/stream.rs:86, 213-257)"
    )
}

// ============================================================================
// Requirements decided by production code
// ============================================================================

#[cfg(feature = "tls")]
mod production {
    use super::Decision;
    use super::wire::{self, Hello};
    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use asupersync::net::tcp::VirtualTcpStream;
    use asupersync::tls::{
        Certificate, CertificateChain, EarlyDataReplayProtection, PrivateKey, TlsAcceptor,
        TlsAcceptorBuilder, TlsConnector, TlsConnectorBuilder, TlsError, TlsStream,
    };
    use futures_lite::future::{block_on, zip};
    use rustls::client::{
        ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
        Tls13ClientSessionValue,
    };
    use rustls::pki_types::ServerName;
    use rustls::server::{ProducesTickets, StoresServerSessions};
    use rustls::{NamedGroup, ProtocolVersion};
    use std::io;
    use std::net::SocketAddr;
    use std::panic::AssertUnwindSafe;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::task::{Context, Poll};

    // Test CA, and a localhost server certificate it signed, valid until
    // 2036-05-26; the same material as tests/tls_conformance.rs.
    const CA_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUNmLaJqmpTgkGxR6LEoTx80ZsAGswDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSYXN1cGVyc3luYyB0ZXN0IGNhMB4XDTI2MDUyOTAxMjMz
N1oXDTM2MDUyNjAxMjMzN1owHTEbMBkGA1UEAwwSYXN1cGVyc3luYyB0ZXN0IGNh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAX0S7sppjw4BZ4DlbQ9
GsU7aUCiZSG2Zp1pTtgbM9nQy82ULr5kS+CnZI/TXhc/lWDYcrniduGiGvzRcLYI
VW4Ha1LNuu8LrAUHiorL1Pbq3OpRNxATe0qt+GP0YiLGyKdb8boYL2wkXxDjJDxh
IOTSZD7w0uwOlMJ5OjxcVvaDCwpQOD7++gNYXFxZ+WBjcud2Oamaf5KEaY2mhOqB
HOGRWBRcYDY/qDqEk9kL2R+VZoozE5gZFPxZNAHK/R3luF7cgQLj4A/RO4XSVr5h
m4+XIYAqvnmjNl0KH8FBXPQvBkz9pbQ/w9jFWiz+rRoR6mfsJmnCikZDJKs5WZsX
vQIDAQABo2MwYTAdBgNVHQ4EFgQUYPNklSSK2fNAh/FLiJVTyxwmMPMwHwYDVR0j
BBgwFoAUYPNklSSK2fNAh/FLiJVTyxwmMPMwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAJsyp44YP64rxhh51r3/wOc4
4V9jL9m6JjHWe1RlkbeUh/ZfEwTx63rFC2SvwXAGyDJyjZ1g/GgTdoQwJg6aTzEb
SKsI+O7O3H/R5jk0Vi0bj2nZLpBru6HWiieckV5z0MuRS5rqyvLUFNOx6egYIo9I
kRrbrN1pg2FOupAuYZ1Dv1V/mfODkOBw0F7SQ1c1k3Rqi0mMxVmD6nvIGfXfKgFf
MJ6L4DdiQnAjvSOTPx1zLQjsUOShk5lQCeySSbHJP990AJluQPUpX+0HxQFakEW+
+g/QuWMScJXA9oaJ+dvDifEjlN9XxN7TpskEaFfrzQShbqjnGFNamQspMXPCmhA=
-----END CERTIFICATE-----";

    const SERVER_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIUFAAU1gIA1vscc6XrGt6Wo523lzUwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSYXN1cGVyc3luYyB0ZXN0IGNhMB4XDTI2MDUyOTAxMjMz
OFoXDTM2MDUyNjAxMjMzOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7dxYfOkdhecBOd96ETuRR/11btBsqzgD
hMmkwGOUz5DEgQtwrM0j82dS5kPy2K4EVRcOZkisJKm9EeTSGYEjNFWk5NqZbLo9
vB0buNlVLaiNdFjNKVXaekD2lykTKvuouOWyHtvCxd8zeNoi/7OcJ22LKxJoF88S
Ci2DyVkU+4sCYElkqmGNa3aZ6O/pgGQ4qkC3lHPteU1Uuo4+6w7YuJ1JLeme8JcQ
2DHPsrh6Z81Li15UPf6fzLFRfaMnPnP/AzNQ2RgZ1TmIIPEg/e55oYRO8FYZaeBB
T8cCJf1VZ6JfRBtw3NjTuZRuhbydIVS6CIvX1AxyjlNfna1xk4TbiQIDAQABo4GM
MIGJMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUNXPJnylplS7j
9sdymmWV4ezuQI8wHwYDVR0jBBgwFoAUYPNklSSK2fNAh/FLiJVTyxwmMPMwDQYJ
KoZIhvcNAQELBQADggEBADsD9TS21k8crkfA0yhcOus+IYvKHUzkwc0tkDryVY0Z
o8wBjzjnpXRNRkZz4b97f5MRfaFNckv6GD8++sDCByEaDtMmyo09PQbGNCQEZ2Rb
52Yh91ysthP9bcbeD4hpkZJAjIyK0CPCuWogFKYnlDv7+gqXhZFTwYa4qsB981S4
PqZMasYfgFYD6cK07dSbn+K1ndOrAu0I+ukEAy84b5/Oo/0pHqelp5dXWz3sx+2w
MspqgKD0oZ/ducTzXygcXDwGvboes8qlWM41S7YZkowngJcfmk2d+yTyepZtE1+J
XgfWNNot+IyLR8iGf343mzDSZBKRhnCq86yKuJijKmM=
-----END CERTIFICATE-----";

    const SERVER_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDt3Fh86R2F5wE5
33oRO5FH/XVu0GyrOAOEyaTAY5TPkMSBC3CszSPzZ1LmQ/LYrgRVFw5mSKwkqb0R
5NIZgSM0VaTk2plsuj28HRu42VUtqI10WM0pVdp6QPaXKRMq+6i45bIe28LF3zN4
2iL/s5wnbYsrEmgXzxIKLYPJWRT7iwJgSWSqYY1rdpno7+mAZDiqQLeUc+15TVS6
jj7rDti4nUkt6Z7wlxDYMc+yuHpnzUuLXlQ9/p/MsVF9oyc+c/8DM1DZGBnVOYgg
8SD97nmhhE7wVhlp4EFPxwIl/VVnol9EG3Dc2NO5lG6FvJ0hVLoIi9fUDHKOU1+d
rXGThNuJAgMBAAECgf9J3aOdJseETbiTwFKoB1eWg590SkV05nAxTG1dUY9k5hAg
Au16vDnt3Khh2bgQkfnGcuKF4QuUVyHf7K9SPEgyeGY8q6X5ndyODnwNa3CIPU+w
UeNkcsTmMkZhqt/I+V3sDWjDLHvP9wCFBzjXL2/OzrXpKk4pFqUDhB7o6EEb2/Yb
I6qYCH3iKzJ1toBgtGNGNILg6kbzYOCX0I1yASGaPhrycGvgk33jtlUWtQ4uwBiL
D/aUkUMmd2GfUQyg5FA0FvGawbbQAPy5680LJ6EtELhyPOYOs5ta63tqZxB8aC4M
f5+GWDmVuXhN0z8orLZQFLIosUv7XSitP3QfojcCgYEA+X0C6zzuoegQpglyhMKy
/jMMdTKT8MWV0ioR9+2YU6j1qXn0BeoBolRuc8fLAEIfYFCouvcUmcXAtrmo7uyh
9wWUPCNo4YAZFXzeG52jkHWxle3fysSVb6z7givgdiDivbuu6m5uCtVzVaG/o+eC
/KRcWdppaVnfRlybg4nhn9cCgYEA9BGkl0SOA+7Bd3v0qa6Ju1a0JSG1n8AYquhr
tT9KzStumkMcqbey1atbmb234Yu9H2qAci0N852Mrc0AG4Pr+s2h066ZQ2FOLKrP
T42EUMKKmmGXAgWSviHnZSK8VSt4QRJQma1QODZnw3cp5Fip50sXUB8HAJfCidPi
0Xhzc58CgYEApsritq3nw6pH5xkNzJ/11mf+fiOwMBmIThb+KEhZvCSLCCCV+ZY2
PXZA2XrKxoNuQo/qHgStaxh//CknPYRJy8GZFpN9vLRNEMaIHuJGxX9JmDiNkxvV
4/E7vAzlZVQbAkmFaQkm3GtTTf5zBnryYUDo1NFmA56n3HxxI4F8q8UCgYBzuzn0
kIlWzAvpAFoPa7fboU1ing1lZs1LnVIVa6GokAOuGkypHXYrY0nYKOHcjUpsby/g
9AQ9lGN0tlRqt69aCc/GdHAwRx+uhoAvFMe9E8JtWgEk8EeY6LK0fjgXmrk3Adw+
QrRbM1EYmpS+tlw6VJ0FXPEREuUoPdS7xwXXuQKBgAldofCPhEMC8sGfuLDNQWWE
eSG2Km+7Hed6SK+Ycw8E82Q3aikeN/tg0V7Wp+5qqbb6Gv0EwDWYMNEE4YxayShr
0Gcdact/vDsgkdtEZ29QZucxqPmM2z/yZy0McPyNMA4wFGDoSCiGLlqcksSczbLI
Xg9lOuhkQdFEb9ak2cOw
-----END PRIVATE KEY-----";

    const SERVER_NAME: &str = "localhost";
    /// The 0-RTT cap given to `enable_early_data_with_protection`.
    const EARLY_DATA_CAP: u32 = 16_384;
    /// How far the stale-ticket study moves each ticket's receipt time back,
    /// far outside rustls's 60 s freshness tolerance.
    const STALE_BY_SECS: u32 = 3_600;
    /// Application data the server writes after a handshake; reading it makes
    /// the client process the NewSessionTickets sent before it.
    const TICKET_CARRIER: &[u8] = b"ticket carrier";

    /// `TlsError::Handshake` text when the peer closes mid-handshake
    /// (src/tls/stream.rs:345).
    const PEER_CLOSED: &str = "connection closed during handshake";
    /// rustls's `Error` text for a ClientHello whose pre_shared_key is not last.
    const NON_FINAL_PSK: &str = "received corrupt message of type PreSharedKeyIsNotFinalExtension";
    /// rustls's `Error` text for a PSK binder that does not verify.
    const BAD_BINDER: &str = "peer misbehaved: IncorrectBinder";

    // validate_request_for_early_data refusals (src/tls/acceptor.rs:193-219).
    const SAFE_METHODS_REFUSAL: &str =
        "only safe HTTP methods (GET/HEAD/OPTIONS) allowed for 0-RTT";
    const IDEMPOTENCY_REFUSAL: &str = "idempotency key required for 0-RTT requests";
    const NONCE_REFUSAL: &str = "valid nonce required for 0-RTT requests";
    const NO_POLICY_REFUSAL: &str =
        "0-RTT enabled without replay protection - all requests vulnerable";

    /// TlsConnectorBuilder::build refusal text (src/tls/connector.rs:1059-1066).
    const UNACKNOWLEDGED_EARLY_DATA: &str = "enable_early_data(true) requires \
         acknowledge_zero_rtt_replay_risk() \u{2014} TLS 1.3 0-RTT is replay-vulnerable \
         by spec (RFC 8446 \u{a7}8) and rustls's in-memory session store provides \
         no anti-replay window. Wire up application-level idempotency for every \
         request that could carry early data, then call \
         acknowledge_zero_rtt_replay_risk() to confirm";

    /// TlsAcceptorBuilder::build refusal text for 0-RTT without a strategy
    /// (src/tls/acceptor.rs:1010-1016).
    fn missing_strategy_message(cap: u32) -> String {
        format!(
            "TLS 1.3 0-RTT enabled (max_bytes={cap}) but no replay protection configured. \
             0-RTT is vulnerable to replay attacks where captured requests can be \
             replayed within ticket validity. You MUST specify replay protection via \
             with_early_data_replay_protection() before enabling 0-RTT. \
             See EarlyDataReplayProtection variants for options (asupersync-ycuuwy)"
        )
    }

    /// TlsAcceptorBuilder::build refusal text for 0-RTT with a strategy whose
    /// screening is not wired (src/tls/acceptor.rs:1047-1058).
    fn unenforced_strategy_message(cap: u32, strategy: &str) -> String {
        format!(
            "TLS 1.3 0-RTT enabled (max_bytes={cap}) with replay strategy \
             {strategy}, but per-request replay enforcement is NOT wired into \
             the server request pipeline: validate_request_for_early_data() \
             has no production caller and TlsStream exposes no early-data \
             signal, so early data would be accepted on the wire and \
             processed WITHOUT any replay screening \u{2014} a false sense of \
             protection. Until per-request enforcement is wired, either do \
             not enable 0-RTT, or, for tests that explicitly accept NO replay \
             protection, select EarlyDataReplayProtection::UnprotectedForTesting \
             (asupersync-snv902)."
        )
    }

    pub(super) fn decide(lab: &Lab, check: fn(&Lab) -> Result<String, String>) -> Decision {
        Decision::Decided(check(lab))
    }

    // ------------------------------------------------------------------------
    // Transport and ticket store
    // ------------------------------------------------------------------------

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn snapshot(log: &Mutex<Vec<u8>>) -> Vec<u8> {
        lock(log).clone()
    }

    fn virtual_pair() -> (VirtualTcpStream, VirtualTcpStream) {
        VirtualTcpStream::pair(
            SocketAddr::from(([127, 0, 0, 1], 47_001)),
            SocketAddr::from(([127, 0, 0, 1], 47_002)),
        )
    }

    /// One end of a `VirtualTcpStream` pair that records every byte written
    /// through it.
    #[derive(Debug)]
    struct WireTap {
        inner: VirtualTcpStream,
        log: Arc<Mutex<Vec<u8>>>,
    }

    impl WireTap {
        fn new(inner: VirtualTcpStream) -> Self {
            Self {
                inner,
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn log(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.log)
        }
    }

    impl AsyncRead for WireTap {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for WireTap {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let written = Pin::new(&mut this.inner).poll_write(cx, data);
            if let Poll::Ready(Ok(count)) = &written {
                lock(&this.log).extend_from_slice(&data[..*count]);
            }
            written
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Client ticket store: rustls's `ClientSessionMemoryCache`, plus a note
    /// of each ticket's max_early_data_size. The stale-ticket study moves each
    /// ticket's receipt time back with rustls's public `rewind_epoch`; the
    /// HelloRetryRequest study answers `kx_hint` with secp384r1, so the client
    /// sends its only key share for a group the server does not pick first.
    #[derive(Debug)]
    struct TicketLedger {
        tickets: ClientSessionMemoryCache,
        issued: Mutex<Vec<u32>>,
        stale_by_secs: u32,
        forced_key_share: Mutex<Option<NamedGroup>>,
    }

    impl TicketLedger {
        fn new(stale_by_secs: u32) -> Self {
            Self {
                tickets: ClientSessionMemoryCache::new(32),
                issued: Mutex::new(Vec::new()),
                stale_by_secs,
                forced_key_share: Mutex::new(None),
            }
        }

        fn issued(&self) -> Vec<u32> {
            lock(&self.issued).clone()
        }

        fn force_key_share(&self, group: NamedGroup) {
            *lock(&self.forced_key_share) = Some(group);
        }
    }

    impl ClientSessionStore for TicketLedger {
        fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
            self.tickets.set_kx_hint(server_name, group);
        }

        fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
            let forced = *lock(&self.forced_key_share);
            forced.or_else(|| self.tickets.kx_hint(server_name))
        }

        fn set_tls12_session(
            &self,
            server_name: ServerName<'static>,
            value: Tls12ClientSessionValue,
        ) {
            self.tickets.set_tls12_session(server_name, value);
        }

        fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
            self.tickets.tls12_session(server_name)
        }

        fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
            self.tickets.remove_tls12_session(server_name);
        }

        fn insert_tls13_ticket(
            &self,
            server_name: ServerName<'static>,
            mut value: Tls13ClientSessionValue,
        ) {
            lock(&self.issued).push(value.max_early_data_size());
            if self.stale_by_secs > 0 {
                value.rewind_epoch(self.stale_by_secs);
            }
            self.tickets.insert_tls13_ticket(server_name, value);
        }

        fn take_tls13_ticket(
            &self,
            server_name: &ServerName<'static>,
        ) -> Option<Tls13ClientSessionValue> {
            self.tickets.take_tls13_ticket(server_name)
        }
    }

    // ------------------------------------------------------------------------
    // Production endpoints
    // ------------------------------------------------------------------------

    fn ca_certificate() -> Result<Certificate, String> {
        Certificate::from_pem(CA_CERT_PEM)
            .map_err(|e| format!("CA certificate fixture did not parse: {e:?}"))?
            .into_iter()
            .next()
            .ok_or_else(|| "CA certificate fixture holds no certificate".to_string())
    }

    fn server_builder() -> Result<TlsAcceptorBuilder, String> {
        let chain = CertificateChain::from_pem(SERVER_CERT_PEM)
            .map_err(|e| format!("server certificate fixture did not parse: {e:?}"))?;
        let key = PrivateKey::from_pem(SERVER_KEY_PEM)
            .map_err(|e| format!("server key fixture did not parse: {e:?}"))?;
        Ok(TlsAcceptorBuilder::new(chain, key))
    }

    /// The only acceptor configuration that puts 0-RTT on the wire.
    fn zero_rtt_acceptor() -> Result<TlsAcceptor, String> {
        server_builder()?
            .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
            .enable_early_data_with_protection(EARLY_DATA_CAP)
            .build()
            .map_err(|e| {
                format!(
                    "TlsAcceptorBuilder with UnprotectedForTesting and cap {EARLY_DATA_CAP} did not build: {e:?}"
                )
            })
    }

    fn default_acceptor() -> Result<TlsAcceptor, String> {
        server_builder()?
            .build()
            .map_err(|e| format!("default TlsAcceptorBuilder did not build: {e:?}"))
    }

    fn recording_connector(
        ledger: &Arc<TicketLedger>,
        early_data: bool,
    ) -> Result<TlsConnector, String> {
        let store: Arc<dyn ClientSessionStore> = Arc::<TicketLedger>::clone(ledger);
        let builder = TlsConnectorBuilder::new()
            .add_root_certificate(&ca_certificate()?)
            .session_resumption(Resumption::store(store));
        let builder = if early_data {
            builder
                .enable_early_data(true)
                .acknowledge_zero_rtt_replay_risk()
        } else {
            builder
        };
        builder.build().map_err(|e| {
            format!("TlsConnectorBuilder (early data {early_data}) did not build: {e:?}")
        })
    }

    // ------------------------------------------------------------------------
    // Observations
    // ------------------------------------------------------------------------

    /// One connect/accept pair, with the bytes each side wrote during the
    /// handshake.
    #[derive(Debug)]
    struct Exchange {
        client_wire: Vec<u8>,
        server_wire: Vec<u8>,
        client: Result<Option<ProtocolVersion>, String>,
        server: Result<Option<ProtocolVersion>, String>,
        /// Whether application data flowed after the handshake.
        tickets: Result<(), String>,
    }

    impl Exchange {
        fn require_tls13(&self, what: &str) -> Result<(), String> {
            let tls13 = Ok(Some(ProtocolVersion::TLSv1_3));
            if self.client == tls13 && self.server == tls13 {
                Ok(())
            } else {
                Err(format!(
                    "{what}: both sides must complete a TLS 1.3 handshake; client {:?}, server {:?}",
                    self.client, self.server
                ))
            }
        }

        fn client_hellos(&self, what: &str) -> Result<Vec<Hello>, String> {
            hellos(&self.client_wire, wire::CLIENT_HELLO, what)
        }

        fn first_client_hello(&self, what: &str) -> Result<Hello, String> {
            self.client_hellos(what)?
                .into_iter()
                .next()
                .ok_or_else(|| format!("{what}: the client flight holds no ClientHello"))
        }

        fn server_hello(&self, what: &str) -> Result<Hello, String> {
            final_server_hello(&self.server_wire, what)
        }

        /// Encrypted records the client wrote during the handshake: Finished,
        /// plus EndOfEarlyData when the server accepted 0-RTT. The two are
        /// protected under different keys, so they never share a record
        /// (RFC 8446 §5.1, §4.5).
        fn client_encrypted_records(&self, what: &str) -> Result<usize, String> {
            Ok(wire::records(&self.client_wire)
                .map_err(|e| format!("{what}: {e}"))?
                .iter()
                .filter(|record| record.content_type == wire::APPLICATION_DATA)
                .count())
        }
    }

    /// Bytes presented to `TlsAcceptor::accept` by a peer that hangs up after
    /// them, and what the server answered.
    #[derive(Debug)]
    struct Probe {
        sent: Vec<u8>,
        server_wire: Vec<u8>,
        refusal: Option<TlsError>,
    }

    /// Two handshakes between one acceptor and one connector: the first
    /// obtains tickets, the second resumes one of them.
    #[derive(Debug)]
    struct Study {
        server_cap: u32,
        client_offers_early_data: bool,
        stateless_tickets: bool,
        session_cache: bool,
        first_tickets: Vec<u32>,
        first: Exchange,
        second: Exchange,
    }

    /// The 0-RTT study, plus ClientHellos presented again to its acceptor.
    #[derive(Debug)]
    struct ZeroRttStudy {
        base: Study,
        /// The resumption ClientHello of `base.second`, byte for byte.
        replay: Probe,
        /// A captured ClientHello with its last two extensions swapped.
        reordered: Probe,
        /// The same captured ClientHello, unchanged.
        untouched: Probe,
        /// A second captured ClientHello with one bit of its random flipped.
        altered_binder: Probe,
    }

    #[derive(Debug, Clone, Copy)]
    struct StudySpec {
        server_zero_rtt: bool,
        client_zero_rtt: bool,
        stale_by_secs: u32,
        retry_group: Option<NamedGroup>,
    }

    impl StudySpec {
        const ZERO_RTT: Self = Self {
            server_zero_rtt: true,
            client_zero_rtt: true,
            stale_by_secs: 0,
            retry_group: None,
        };
        const STALE: Self = Self {
            stale_by_secs: STALE_BY_SECS,
            ..Self::ZERO_RTT
        };
        const SERVER_DISABLED: Self = Self {
            server_zero_rtt: false,
            ..Self::ZERO_RTT
        };
        const CLIENT_DEFAULT: Self = Self {
            client_zero_rtt: false,
            ..Self::ZERO_RTT
        };
        const RETRY: Self = Self {
            retry_group: Some(NamedGroup::secp384r1),
            ..Self::ZERO_RTT
        };
    }

    struct Rig {
        acceptor: TlsAcceptor,
        connector: TlsConnector,
        ledger: Arc<TicketLedger>,
    }

    impl Rig {
        fn build(spec: StudySpec) -> Result<Self, String> {
            let acceptor = if spec.server_zero_rtt {
                zero_rtt_acceptor()?
            } else {
                default_acceptor()?
            };
            let ledger = Arc::new(TicketLedger::new(spec.stale_by_secs));
            let connector = recording_connector(&ledger, spec.client_zero_rtt)?;
            Ok(Self {
                acceptor,
                connector,
                ledger,
            })
        }

        fn study(spec: StudySpec) -> Result<Study, String> {
            Self::build(spec)?.observe(spec)
        }

        fn observe(&self, spec: StudySpec) -> Result<Study, String> {
            let first = self.exchange();
            if let Err(why) = &first.tickets {
                return Err(format!(
                    "the first handshake left no ticket ({why}); client {:?}, server {:?}",
                    first.client, first.server
                ));
            }
            let first_tickets = self.ledger.issued();
            if let Some(group) = spec.retry_group {
                self.ledger.force_key_share(group);
            }
            let second = self.exchange();
            let server_config = self.acceptor.config();
            Ok(Study {
                server_cap: server_config.max_early_data_size,
                client_offers_early_data: self.connector.config().enable_early_data,
                stateless_tickets: ProducesTickets::enabled(&*server_config.ticketer),
                session_cache: StoresServerSessions::can_cache(&*server_config.session_storage),
                first_tickets,
                first,
                second,
            })
        }

        fn exchange(&self) -> Exchange {
            let (client_end, server_end) = virtual_pair();
            let client_tap = WireTap::new(client_end);
            let server_tap = WireTap::new(server_end);
            let client_log = client_tap.log();
            let server_log = server_tap.log();
            let (mut client, mut server) = block_on(zip(
                self.connector.connect(SERVER_NAME, client_tap),
                self.acceptor.accept(server_tap),
            ));
            let client_wire = snapshot(&client_log);
            let server_wire = snapshot(&server_log);
            let tickets = if let (Ok(client_stream), Ok(server_stream)) =
                (client.as_mut(), server.as_mut())
            {
                deliver_tickets(client_stream, server_stream)
            } else {
                Err("the handshake did not complete".to_string())
            };
            Exchange {
                client_wire,
                server_wire,
                client: client
                    .map(|stream| stream.protocol_version())
                    .map_err(|e| format!("{e:?}")),
                server: server
                    .map(|stream| stream.protocol_version())
                    .map_err(|e| format!("{e:?}")),
                tickets,
            }
        }

        /// Connects to a peer that hangs up as soon as the ClientHello
        /// arrives, and returns that ClientHello record. Its ticket is taken
        /// from the client store but never reaches the server.
        fn capture_client_hello(&self) -> Result<Vec<u8>, String> {
            let (client_end, peer_end) = virtual_pair();
            let tap = WireTap::new(client_end);
            let log = tap.log();
            let mut peer = Some(peer_end);
            let mut polls = 0_u32;
            let hang_up = std::future::poll_fn(|cx| {
                polls += 1;
                if lock(&log).is_empty() && polls < 10_000 {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    drop(peer.take());
                    Poll::Ready(())
                }
            });
            let (outcome, ()) = block_on(zip(self.connector.connect(SERVER_NAME, tap), hang_up));
            if outcome.is_ok() {
                return Err(
                    "connect() completed against a peer that hung up after the ClientHello"
                        .to_string(),
                );
            }
            first_record(&snapshot(&log), "ClientHello sent to a peer that hung up")
        }

        /// Presents `offer` to `TlsAcceptor::accept` from a peer that closes
        /// its side after it.
        fn present(&self, offer: &[u8]) -> Result<Probe, String> {
            let (mut peer, server_end) = virtual_pair();
            let tap = WireTap::new(server_end);
            let log = tap.log();
            block_on(async {
                peer.write_all(offer).await?;
                std::future::poll_fn(|cx| Pin::new(&mut peer).poll_shutdown(cx)).await
            })
            .map_err(|e| format!("could not stage {} bytes for the server: {e}", offer.len()))?;
            let refusal = block_on(self.acceptor.accept(tap)).err();
            let server_wire = snapshot(&log);
            drop(peer);
            Ok(Probe {
                sent: offer.to_vec(),
                server_wire,
                refusal,
            })
        }
    }

    fn deliver_tickets(
        client: &mut TlsStream<WireTap>,
        server: &mut TlsStream<WireTap>,
    ) -> Result<(), String> {
        let mut echo = vec![0_u8; TICKET_CARRIER.len()];
        block_on(async {
            server.write_all(TICKET_CARRIER).await?;
            server.flush().await?;
            client.read_exact(&mut echo).await
        })
        .map_err(|e| format!("application data after the handshake did not flow: {e}"))?;
        if echo == TICKET_CARRIER {
            Ok(())
        } else {
            Err(format!(
                "the client read {echo:02x?} after the handshake, the server wrote {TICKET_CARRIER:02x?}"
            ))
        }
    }

    fn zero_rtt_study() -> Result<ZeroRttStudy, String> {
        let spec = StudySpec::ZERO_RTT;
        let rig = Rig::build(spec)?;
        let base = rig.observe(spec)?;
        let resumption_hello = first_record(&base.second.client_wire, "resumption client flight")?;
        let replay = rig.present(&resumption_hello)?;
        let offer = rig.capture_client_hello()?;
        let second_offer = rig.capture_client_hello()?;
        // The reordered copy fails to parse before its ticket is looked up,
        // so the unchanged copy presented next still finds the ticket.
        let reordered = rig.present(&wire::with_last_two_extensions_swapped(&offer)?)?;
        let untouched = rig.present(&offer)?;
        let altered_binder = rig.present(&wire::with_random_bit_flipped(&second_offer)?)?;
        Ok(ZeroRttStudy {
            base,
            replay,
            reordered,
            untouched,
            altered_binder,
        })
    }

    /// Every handshake the requirements read, run once per harness run.
    pub(super) struct Lab {
        zero_rtt: Result<ZeroRttStudy, String>,
        stale: Result<Study, String>,
        disabled_server: Result<Study, String>,
        default_client: Result<Study, String>,
        retry: Result<Study, String>,
    }

    impl Lab {
        pub(super) fn collect() -> Self {
            Self {
                zero_rtt: guarded("the 0-RTT study", zero_rtt_study),
                stale: guarded("the stale-ticket study", || Rig::study(StudySpec::STALE)),
                disabled_server: guarded("the 0-RTT-disabled server study", || {
                    Rig::study(StudySpec::SERVER_DISABLED)
                }),
                default_client: guarded("the default client study", || {
                    Rig::study(StudySpec::CLIENT_DEFAULT)
                }),
                retry: guarded("the HelloRetryRequest study", || {
                    Rig::study(StudySpec::RETRY)
                }),
            }
        }
    }

    fn guarded<T>(what: &str, run: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        std::panic::catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|payload| {
            Err(format!("{what} panicked: {}", super::panic_text(&*payload)))
        })
    }

    fn zero_rtt(lab: &Lab) -> Result<&ZeroRttStudy, String> {
        lab.zero_rtt
            .as_ref()
            .map_err(|why| format!("the 0-RTT study did not run: {why}"))
    }

    fn stale(lab: &Lab) -> Result<&Study, String> {
        lab.stale
            .as_ref()
            .map_err(|why| format!("the stale-ticket study did not run: {why}"))
    }

    fn disabled_server(lab: &Lab) -> Result<&Study, String> {
        lab.disabled_server
            .as_ref()
            .map_err(|why| format!("the 0-RTT-disabled server study did not run: {why}"))
    }

    fn default_client(lab: &Lab) -> Result<&Study, String> {
        lab.default_client
            .as_ref()
            .map_err(|why| format!("the default client study did not run: {why}"))
    }

    fn retry(lab: &Lab) -> Result<&Study, String> {
        lab.retry
            .as_ref()
            .map_err(|why| format!("the HelloRetryRequest study did not run: {why}"))
    }

    // ------------------------------------------------------------------------
    // Reading the recorded flights
    // ------------------------------------------------------------------------

    fn first_record(flight: &[u8], what: &str) -> Result<Vec<u8>, String> {
        let records = wire::records(flight).map_err(|e| format!("{what}: {e}"))?;
        let first = records
            .first()
            .ok_or_else(|| format!("{what}: nothing was written"))?;
        Ok(first.bytes(flight).to_vec())
    }

    fn hellos(flight: &[u8], msg_type: u8, what: &str) -> Result<Vec<Hello>, String> {
        let mut found = Vec::new();
        for record in wire::records(flight).map_err(|e| format!("{what}: {e}"))? {
            if record.content_type == wire::HANDSHAKE {
                let hello =
                    wire::parse_hello(record.bytes(flight)).map_err(|e| format!("{what}: {e}"))?;
                if hello.msg_type == msg_type {
                    found.push(hello);
                }
            }
        }
        Ok(found)
    }

    fn final_server_hello(flight: &[u8], what: &str) -> Result<Hello, String> {
        hellos(flight, wire::SERVER_HELLO, what)?
            .into_iter()
            .find(|hello| !hello.is_hello_retry_request())
            .ok_or_else(|| format!("{what}: the server wrote no ServerHello"))
    }

    fn selected_identity(hello: &Hello) -> Result<Option<u16>, String> {
        hello
            .extension(wire::EXT_PRE_SHARED_KEY)
            .map(|psk| wire::u16_value(&psk.data, "ServerHello pre_shared_key"))
            .transpose()
    }

    fn offered_ticket_age(exchange: &Exchange, what: &str) -> Result<u32, String> {
        let hello = exchange.first_client_hello(what)?;
        let psk = hello
            .extension(wire::EXT_PRE_SHARED_KEY)
            .ok_or_else(|| format!("{what}: the ClientHello offers no pre_shared_key"))?;
        let offered = wire::offered_psks(&psk.data).map_err(|e| format!("{what}: {e}"))?;
        offered
            .identities
            .first()
            .map(|(_, age)| *age)
            .ok_or_else(|| format!("{what}: pre_shared_key lists no identity"))
    }

    /// Every ClientHello the client side of every study produced.
    fn all_client_hellos(lab: &Lab) -> Result<Vec<(String, Hello)>, String> {
        let zero = zero_rtt(lab)?;
        let mut flights: Vec<(String, &[u8])> = Vec::new();
        for (name, study) in [
            ("0-RTT", &zero.base),
            ("stale-ticket", stale(lab)?),
            ("0-RTT-disabled server", disabled_server(lab)?),
            ("default client", default_client(lab)?),
            ("HelloRetryRequest", retry(lab)?),
        ] {
            flights.push((
                format!("{name} study, first handshake"),
                study.first.client_wire.as_slice(),
            ));
            flights.push((
                format!("{name} study, resumption handshake"),
                study.second.client_wire.as_slice(),
            ));
        }
        flights.push((
            "captured ClientHello".to_string(),
            zero.untouched.sent.as_slice(),
        ));
        let mut found = Vec::new();
        for (name, flight) in flights {
            for hello in hellos(flight, wire::CLIENT_HELLO, &name)? {
                found.push((name.clone(), hello));
            }
        }
        Ok(found)
    }

    /// The server aborted `probe` with `TlsError::Handshake(message)` and sent
    /// only a fatal `alert`, before any ServerHello.
    fn expect_abort(probe: &Probe, what: &str, message: &str, alert: u8) -> Result<String, String> {
        let Some(TlsError::Handshake(got)) = probe.refusal.as_ref() else {
            return Err(format!(
                "{what}: TlsAcceptor::accept returned {:?}, expected TlsError::Handshake({message:?})",
                probe.refusal
            ));
        };
        if got.as_str() != message {
            return Err(format!(
                "{what}: refused with TlsError::Handshake({got:?}), expected TlsError::Handshake({message:?})"
            ));
        }
        let records =
            wire::records(&probe.server_wire).map_err(|e| format!("{what}: server flight: {e}"))?;
        let [record] = records.as_slice() else {
            return Err(format!(
                "{what}: the server wrote records of content types {:?}, expected only its fatal alert",
                records
                    .iter()
                    .map(|record| record.content_type)
                    .collect::<Vec<_>>()
            ));
        };
        if record.content_type != wire::ALERT {
            return Err(format!(
                "{what}: the server wrote a record of content type {}, expected an alert",
                record.content_type
            ));
        }
        let (level, description) =
            wire::alert(record.fragment(&probe.server_wire)).map_err(|e| format!("{what}: {e}"))?;
        if (level, description) != (wire::ALERT_FATAL, alert) {
            return Err(format!(
                "{what}: alert level {level} description {description}, expected fatal ({}) {alert}",
                wire::ALERT_FATAL
            ));
        }
        Ok(format!(
            "{what}: TlsError::Handshake({got:?}) and a fatal alert {description}, no ServerHello"
        ))
    }

    /// The server accepted the PSK of `probe` with selected_identity 0, then
    /// failed only because the presenting peer had closed.
    fn expect_resumed_probe(probe: &Probe, what: &str) -> Result<String, String> {
        let hello = final_server_hello(&probe.server_wire, what)?;
        let Some(identity) = selected_identity(&hello).map_err(|e| format!("{what}: {e}"))? else {
            return Err(format!(
                "{what}: the ServerHello has no pre_shared_key, so the server did not accept the PSK; extensions {:?}",
                hello.kinds()
            ));
        };
        if identity != 0 {
            return Err(format!("{what}: selected_identity {identity}, expected 0"));
        }
        let closed = matches!(
            probe.refusal.as_ref(),
            Some(TlsError::Handshake(got)) if got.as_str() == PEER_CLOSED
        );
        if !closed {
            return Err(format!(
                "{what}: after its reply the server should stop only because the peer closed \
                 (TlsError::Handshake({PEER_CLOSED:?})), got {:?}",
                probe.refusal
            ));
        }
        Ok(format!(
            "{what}: ServerHello with pre_shared_key selected_identity 0"
        ))
    }

    fn expect_configuration_error<T>(
        outcome: Result<T, TlsError>,
        expected: &str,
        what: &str,
    ) -> Result<(), String> {
        match outcome {
            Err(TlsError::Configuration(message)) if message == expected => Ok(()),
            Err(other) => Err(format!(
                "{what}: build() refused with {other:?}, expected TlsError::Configuration({expected:?})"
            )),
            Ok(_) => Err(format!(
                "{what}: build() succeeded, expected TlsError::Configuration({expected:?})"
            )),
        }
    }

    fn expect_admitted(
        policy: &EarlyDataReplayProtection,
        method: &str,
        idempotency_key: bool,
        nonce: bool,
    ) -> Result<(), String> {
        policy
            .validate_request_for_early_data(method, idempotency_key, nonce)
            .map_err(|refusal| {
                format!(
                    "{policy:?} refused {method} (idempotency key {idempotency_key}, nonce {nonce}) with {refusal:?}; it should admit it"
                )
            })
    }

    fn expect_refused(
        policy: &EarlyDataReplayProtection,
        method: &str,
        idempotency_key: bool,
        nonce: bool,
        reason: &str,
    ) -> Result<(), String> {
        match policy.validate_request_for_early_data(method, idempotency_key, nonce) {
            Err(got) if got == reason => Ok(()),
            other => Err(format!(
                "{policy:?} answered {method} (idempotency key {idempotency_key}, nonce {nonce}) with {other:?}, expected Err({reason:?})"
            )),
        }
    }

    // ------------------------------------------------------------------------
    // PreSharedKeyExtension
    // ------------------------------------------------------------------------

    /// TLS0RTT-PSK-01.
    pub(super) fn early_data_needs_pre_shared_key(lab: &Lab) -> Result<String, String> {
        let hellos = all_client_hellos(lab)?;
        let mut offers = 0_usize;
        for (flight, hello) in &hellos {
            if hello.has(wire::EXT_EARLY_DATA) {
                offers += 1;
                if !hello.has(wire::EXT_PRE_SHARED_KEY) {
                    return Err(format!(
                        "{flight}: the ClientHello offers early_data without pre_shared_key; extensions {:?}",
                        hello.kinds()
                    ));
                }
            }
        }
        let ticketless = zero_rtt(lab)?
            .base
            .first
            .first_client_hello("0-RTT study, first handshake")?;
        if ticketless.has(wire::EXT_EARLY_DATA) || ticketless.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the ticketless ClientHello of a 0-RTT-enabled TlsConnector carries early_data or pre_shared_key; extensions {:?}",
                ticketless.kinds()
            ));
        }
        if offers == 0 {
            return Err(
                "no ClientHello offered early_data, so the rule was never exercised; the 0-RTT \
                 study's resumption ClientHello should have"
                    .to_string(),
            );
        }
        Ok(format!(
            "{} ClientHellos read; the {offers} that offered early_data all offered pre_shared_key, \
             and the ticketless ClientHello of the 0-RTT-enabled TlsConnector offered neither",
            hellos.len()
        ))
    }

    /// TLS0RTT-PSK-02.
    pub(super) fn pre_shared_key_sends_modes(lab: &Lab) -> Result<String, String> {
        let hellos = all_client_hellos(lab)?;
        let mut offers = 0_usize;
        for (flight, hello) in &hellos {
            if !hello.has(wire::EXT_PRE_SHARED_KEY) {
                continue;
            }
            offers += 1;
            let modes_extension = hello
                .extension(wire::EXT_PSK_KEY_EXCHANGE_MODES)
                .ok_or_else(|| {
                    format!(
                        "{flight}: the ClientHello offers pre_shared_key without psk_key_exchange_modes; extensions {:?}",
                        hello.kinds()
                    )
                })?;
            let modes =
                wire::psk_modes(&modes_extension.data).map_err(|e| format!("{flight}: {e}"))?;
            if !modes.contains(&wire::PSK_DHE_KE) {
                return Err(format!(
                    "{flight}: psk_key_exchange_modes {modes:?} lacks psk_dhe_ke ({})",
                    wire::PSK_DHE_KE
                ));
            }
        }
        if offers == 0 {
            return Err(
                "no ClientHello offered pre_shared_key, so the rule was never exercised"
                    .to_string(),
            );
        }
        Ok(format!(
            "{offers} ClientHellos offered pre_shared_key; each also sent psk_key_exchange_modes listing psk_dhe_ke"
        ))
    }

    /// TLS0RTT-PSK-03.
    pub(super) fn pre_shared_key_is_last(lab: &Lab) -> Result<String, String> {
        let hellos = all_client_hellos(lab)?;
        let mut offers = 0_usize;
        for (flight, hello) in &hellos {
            let Some(psk) = hello.extension(wire::EXT_PRE_SHARED_KEY) else {
                continue;
            };
            offers += 1;
            if hello.kinds().last() != Some(&wire::EXT_PRE_SHARED_KEY) {
                return Err(format!(
                    "{flight}: pre_shared_key is not the last ClientHello extension: {:?}",
                    hello.kinds()
                ));
            }
            let offered = wire::offered_psks(&psk.data).map_err(|e| format!("{flight}: {e}"))?;
            if offered.identities.is_empty()
                || offered.identities.len() != offered.binder_lengths.len()
            {
                return Err(format!(
                    "{flight}: pre_shared_key lists {} identities and {} binders",
                    offered.identities.len(),
                    offered.binder_lengths.len()
                ));
            }
            if let Some(length) = offered
                .binder_lengths
                .iter()
                .find(|length| !(32..=255).contains(*length))
            {
                return Err(format!(
                    "{flight}: a binder of {length} bytes is outside PskBinderEntry<32..255>"
                ));
            }
        }
        if offers == 0 {
            return Err(
                "no ClientHello offered pre_shared_key, so the rule was never exercised"
                    .to_string(),
            );
        }
        Ok(format!(
            "{offers} ClientHellos offered pre_shared_key; in each it was the last extension, with one 32..255-byte binder per identity"
        ))
    }

    /// TLS0RTT-PSK-04.
    pub(super) fn server_refuses_non_final_pre_shared_key(lab: &Lab) -> Result<String, String> {
        let zero = zero_rtt(lab)?;
        let reordered = wire::parse_hello(&zero.reordered.sent)
            .map_err(|e| format!("reordered ClientHello: {e}"))?;
        let original = wire::parse_hello(&zero.untouched.sent)
            .map_err(|e| format!("captured ClientHello: {e}"))?;
        let mut reordered_kinds = reordered.kinds();
        let mut original_kinds = original.kinds();
        if !reordered.has(wire::EXT_PRE_SHARED_KEY)
            || reordered_kinds.last() == Some(&wire::EXT_PRE_SHARED_KEY)
        {
            return Err(format!(
                "the altered ClientHello should carry pre_shared_key before its last extension; extensions {reordered_kinds:?}"
            ));
        }
        reordered_kinds.sort_unstable();
        original_kinds.sort_unstable();
        if reordered_kinds != original_kinds
            || zero.reordered.sent.len() != zero.untouched.sent.len()
        {
            return Err(
                "the altered ClientHello should differ from the captured one only in extension order"
                    .to_string(),
            );
        }
        let refusal = expect_abort(
            &zero.reordered,
            "ClientHello with pre_shared_key moved before its last extension",
            NON_FINAL_PSK,
            wire::ALERT_ILLEGAL_PARAMETER,
        )?;
        let control = expect_resumed_probe(
            &zero.untouched,
            "the same ClientHello as the client sent it",
        )?;
        Ok(format!("{refusal}; control: {control}"))
    }

    /// TLS0RTT-PSK-05.
    pub(super) fn server_validates_binder(lab: &Lab) -> Result<String, String> {
        let zero = zero_rtt(lab)?;
        let altered = wire::parse_hello(&zero.altered_binder.sent)
            .map_err(|e| format!("altered ClientHello: {e}"))?;
        if !altered.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(
                "the altered ClientHello offers no pre_shared_key, so it tests no binder"
                    .to_string(),
            );
        }
        let refusal = expect_abort(
            &zero.altered_binder,
            "ClientHello with one bit of its random flipped after the binder was computed",
            BAD_BINDER,
            wire::ALERT_DECRYPT_ERROR,
        )?;
        let control = expect_resumed_probe(
            &zero.untouched,
            "an unaltered ClientHello captured from the same TlsConnector",
        )?;
        Ok(format!("{refusal}; control: {control}"))
    }

    /// TLS0RTT-PSK-06.
    pub(super) fn server_selects_offered_identity(lab: &Lab) -> Result<String, String> {
        let second = &zero_rtt(lab)?.base.second;
        second.require_tls13("0-RTT study, resumption handshake")?;
        let offer = second.first_client_hello("resumption client flight")?;
        let psk = offer
            .extension(wire::EXT_PRE_SHARED_KEY)
            .ok_or_else(|| "the resumption ClientHello offers no pre_shared_key".to_string())?;
        let identities = wire::offered_psks(&psk.data)?.identities.len();
        let answer = second.server_hello("resumption server flight")?;
        let selected = selected_identity(&answer)?.ok_or_else(|| {
            format!(
                "the server did not accept the PSK: its ServerHello has no pre_shared_key; extensions {:?}",
                answer.kinds()
            )
        })?;
        if selected != 0 || usize::from(selected) >= identities {
            return Err(format!(
                "selected_identity {selected} for {identities} offered identities; 0-RTT needs the first (0)"
            ));
        }
        Ok(format!(
            "ServerHello pre_shared_key selected_identity {selected} of {identities} offered identities"
        ))
    }

    /// TLS0RTT-PSK-07.
    pub(super) fn client_respects_ticket_without_early_data(lab: &Lab) -> Result<String, String> {
        let study = disabled_server(lab)?;
        if !study.client_offers_early_data {
            return Err(
                "control: this study's TlsConnector should have early data enabled".to_string(),
            );
        }
        if study.first_tickets.is_empty() || study.first_tickets.iter().any(|size| *size != 0) {
            return Err(format!(
                "a TlsAcceptor with 0-RTT disabled issued tickets with max_early_data_size {:?}, expected only 0",
                study.first_tickets
            ));
        }
        let hello = study
            .second
            .first_client_hello("resumption client flight")?;
        if !hello.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the client did not resume (no pre_shared_key), so the rule was not exercised; extensions {:?}",
                hello.kinds()
            ));
        }
        if hello.has(wire::EXT_EARLY_DATA) {
            return Err(format!(
                "resuming a ticket with no early_data indication, the client still offered early_data; extensions {:?}",
                hello.kinds()
            ));
        }
        Ok(format!(
            "{} tickets without early_data; the 0-RTT-enabled client resumed one with pre_shared_key and no early_data",
            study.first_tickets.len()
        ))
    }

    /// TLS0RTT-PSK-08.
    pub(super) fn default_connector_never_offers_early_data(lab: &Lab) -> Result<String, String> {
        let study = default_client(lab)?;
        if study.client_offers_early_data {
            return Err(
                "TlsConnectorBuilder without enable_early_data built a ClientConfig with enable_early_data = true"
                    .to_string(),
            );
        }
        if study.first_tickets.is_empty()
            || study
                .first_tickets
                .iter()
                .any(|size| *size != EARLY_DATA_CAP)
        {
            return Err(format!(
                "control: the 0-RTT TlsAcceptor should issue tickets that permit {EARLY_DATA_CAP} bytes of 0-RTT, got {:?}",
                study.first_tickets
            ));
        }
        for (what, exchange) in [
            ("first handshake", &study.first),
            ("resumption handshake", &study.second),
        ] {
            for hello in exchange.client_hellos(what)? {
                if hello.has(wire::EXT_EARLY_DATA) {
                    return Err(format!(
                        "{what}: the default TlsConnector offered early_data; extensions {:?}",
                        hello.kinds()
                    ));
                }
            }
        }
        let resumed = study
            .second
            .first_client_hello("resumption client flight")?;
        if !resumed.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(
                "the default TlsConnector did not resume, so the rule was not exercised"
                    .to_string(),
            );
        }
        Ok(format!(
            "ClientConfig::enable_early_data is false; resuming a ticket that permits {EARLY_DATA_CAP} bytes of 0-RTT, the client sent pre_shared_key and no early_data"
        ))
    }

    /// TLS0RTT-PSK-09.
    pub(super) fn connector_requires_replay_acknowledgement(_lab: &Lab) -> Result<String, String> {
        let ca = ca_certificate()?;
        let refused = TlsConnectorBuilder::new()
            .add_root_certificate(&ca)
            .enable_early_data(true)
            .build();
        expect_configuration_error(
            refused,
            UNACKNOWLEDGED_EARLY_DATA,
            "TlsConnectorBuilder with enable_early_data(true) and no acknowledgement",
        )?;
        let acknowledged = TlsConnectorBuilder::new()
            .add_root_certificate(&ca)
            .enable_early_data(true)
            .acknowledge_zero_rtt_replay_risk()
            .build()
            .map_err(|e| {
                format!("control: the acknowledged TlsConnectorBuilder did not build: {e:?}")
            })?;
        if !acknowledged.config().enable_early_data {
            return Err(
                "control: with acknowledge_zero_rtt_replay_risk() the ClientConfig should have enable_early_data = true"
                    .to_string(),
            );
        }
        Ok(
            "build() refused enable_early_data(true) without acknowledge_zero_rtt_replay_risk() with \
             the exact TlsError::Configuration text; control: acknowledged, it built a ClientConfig \
             with enable_early_data = true"
                .to_string(),
        )
    }

    // ------------------------------------------------------------------------
    // TicketAgeObfuscation and FreshnessWindow
    // ------------------------------------------------------------------------

    /// TLS0RTT-AGE-01.
    pub(super) fn ticket_age_reaches_server(lab: &Lab) -> Result<String, String> {
        let fresh = &zero_rtt(lab)?.base.second;
        let shifted = &stale(lab)?.second;
        let fresh_age = offered_ticket_age(fresh, "fresh ticket")?;
        let shifted_age = offered_ticket_age(shifted, "ticket recorded 3600 s early")?;
        for (what, exchange) in [
            ("fresh ticket", fresh),
            ("ticket recorded 3600 s early", shifted),
        ] {
            exchange.require_tls13(what)?;
            if !exchange.first_client_hello(what)?.has(wire::EXT_EARLY_DATA) {
                return Err(format!(
                    "{what}: the client did not offer early_data, so the server had no ticket age to judge"
                ));
            }
            if selected_identity(&exchange.server_hello(what)?)?.is_none() {
                return Err(format!("{what}: the server did not resume the PSK"));
            }
        }
        let fresh_records = fresh.client_encrypted_records("fresh ticket")?;
        let shifted_records = shifted.client_encrypted_records("ticket recorded 3600 s early")?;
        if fresh_records != 2 {
            return Err(format!(
                "fresh ticket: the client sent {fresh_records} encrypted handshake records, expected EndOfEarlyData and Finished (2); the server did not find the age inside its window"
            ));
        }
        if shifted_records != 1 {
            return Err(format!(
                "ticket recorded 3600 s early: the client sent {shifted_records} encrypted handshake records, expected Finished only (1); the server accepted an age 3600 s off"
            ));
        }
        Ok(format!(
            "obfuscated_ticket_age {fresh_age:#010x} (fresh ticket): 0-RTT accepted; \
             obfuscated_ticket_age {shifted_age:#010x} (receipt time 3600 s earlier): 0-RTT refused, PSK resumed"
        ))
    }

    /// TLS0RTT-AGE-02.
    pub(super) fn server_checks_ticket_age(lab: &Lab) -> Result<String, String> {
        let shifted = &stale(lab)?.second;
        shifted.require_tls13("stale-ticket study, resumption handshake")?;
        let hello = shifted.first_client_hello("stale-ticket resumption client flight")?;
        if !hello.has(wire::EXT_EARLY_DATA) || !hello.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the stale-ticket ClientHello should offer 0-RTT (early_data and pre_shared_key); extensions {:?}",
                hello.kinds()
            ));
        }
        let answer = shifted.server_hello("stale-ticket resumption server flight")?;
        if selected_identity(&answer)? != Some(0) {
            return Err(format!(
                "the server did not accept the PSK, so a 0-RTT refusal is not attributable to the ticket age; ServerHello extensions {:?}",
                answer.kinds()
            ));
        }
        let records = shifted.client_encrypted_records("stale-ticket resumption client flight")?;
        if records != 1 {
            return Err(format!(
                "the server accepted 0-RTT for a ticket age 3600 s outside its window: the client sent {records} encrypted handshake records (EndOfEarlyData present)"
            ));
        }
        let control = zero_rtt(lab)?
            .base
            .second
            .client_encrypted_records("0-RTT resumption client flight")?;
        if control != 2 {
            return Err(format!(
                "control: a fresh ticket's 0-RTT should be accepted (2 encrypted records), got {control}"
            ));
        }
        Ok(
            "0-RTT refused for a ticket age 3600 s outside the window: the server resumed the PSK \
             (selected_identity 0) without early_data in EncryptedExtensions, and the client sent \
             Finished without EndOfEarlyData; control: a fresh ticket's 0-RTT was accepted"
                .to_string(),
        )
    }

    /// TLS0RTT-FRESH-01.
    pub(super) fn stale_ticket_completes_handshake(lab: &Lab) -> Result<String, String> {
        let second = &stale(lab)?.second;
        second.require_tls13("stale-ticket study, resumption handshake")?;
        if let Err(why) = &second.tickets {
            return Err(format!("the handshake completed but {why}"));
        }
        let resumed =
            selected_identity(&second.server_hello("stale-ticket resumption server flight")?)?
                .is_some();
        Ok(format!(
            "with an out-of-window ticket age both sides completed a TLS 1.3 handshake ({}) and application data flowed",
            if resumed {
                "resumed with the PSK"
            } else {
                "full handshake"
            }
        ))
    }

    // ------------------------------------------------------------------------
    // AntiReplayCache
    // ------------------------------------------------------------------------

    /// TLS0RTT-REPLAY-01.
    pub(super) fn replayed_client_hello_not_resumed(lab: &Lab) -> Result<String, String> {
        let zero = zero_rtt(lab)?;
        let original = first_record(&zero.base.second.client_wire, "resumption client flight")?;
        if original != zero.replay.sent {
            return Err(
                "the replayed bytes differ from the ClientHello production sent".to_string(),
            );
        }
        let hello =
            wire::parse_hello(&original).map_err(|e| format!("resumption ClientHello: {e}"))?;
        if !hello.has(wire::EXT_EARLY_DATA) || !hello.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the resumption ClientHello offered no 0-RTT, so replaying it tests nothing; extensions {:?}",
                hello.kinds()
            ));
        }
        let first_use = zero.base.second.server_hello("first use")?;
        if selected_identity(&first_use)? != Some(0) {
            return Err(
                "first use: the server did not accept the PSK, so the replay is not a second use"
                    .to_string(),
            );
        }
        let replayed = final_server_hello(&zero.replay.server_wire, "replayed ClientHello")?;
        if replayed.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the server accepted the PSK of a ClientHello it had already resumed, so the replayed 0-RTT data could be accepted twice; ServerHello extensions {:?}",
                replayed.kinds()
            ));
        }
        let closed = matches!(
            zero.replay.refusal.as_ref(),
            Some(TlsError::Handshake(got)) if got.as_str() == PEER_CLOSED
        );
        if !closed {
            return Err(format!(
                "after its full-handshake reply the server should stop only because the peer closed, got {:?}",
                zero.replay.refusal
            ));
        }
        Ok(
            "a byte-identical replay of a resumed 0-RTT ClientHello got a full-handshake ServerHello \
             (no pre_shared_key), so its early data cannot be accepted again; first use: \
             selected_identity 0"
                .to_string(),
        )
    }

    /// TLS0RTT-REPLAY-02.
    pub(super) fn zero_rtt_tickets_are_stateful(lab: &Lab) -> Result<String, String> {
        let study = &zero_rtt(lab)?.base;
        if study.server_cap != EARLY_DATA_CAP {
            return Err(format!(
                "ServerConfig::max_early_data_size is {}, expected {EARLY_DATA_CAP}",
                study.server_cap
            ));
        }
        if study.stateless_tickets {
            return Err(
                "the 0-RTT TlsAcceptor uses a stateless ticketer, whose tickets cannot be single-use"
                    .to_string(),
            );
        }
        if !study.session_cache {
            return Err("the 0-RTT TlsAcceptor's session cache stores nothing".to_string());
        }
        Ok(format!(
            "0-RTT TlsAcceptor (cap {EARLY_DATA_CAP}): ServerConfig::ticketer is disabled and \
             session_storage caches, so each ticket is a cache key removed on first use"
        ))
    }

    /// TLS0RTT-REPLAY-03.
    pub(super) fn safe_methods_policy(_lab: &Lab) -> Result<String, String> {
        let policy = EarlyDataReplayProtection::SafeMethodsOnly;
        for method in ["POST", "PUT", "DELETE", "PATCH", "post"] {
            expect_refused(&policy, method, true, true, SAFE_METHODS_REFUSAL)?;
        }
        for method in ["GET", "HEAD", "OPTIONS", "get", "Options"] {
            expect_admitted(&policy, method, false, false)?;
        }
        Ok(format!(
            "SafeMethodsOnly refused POST, PUT, DELETE, PATCH and post with {SAFE_METHODS_REFUSAL:?}, \
             even with an idempotency key and a nonce; control: GET, HEAD and OPTIONS admitted in any case"
        ))
    }

    /// TLS0RTT-REPLAY-04.
    pub(super) fn idempotency_key_policy(_lab: &Lab) -> Result<String, String> {
        let policy = EarlyDataReplayProtection::IdempotencyKeys;
        for (method, nonce) in [("POST", false), ("PUT", true), ("DELETE", false)] {
            expect_refused(&policy, method, false, nonce, IDEMPOTENCY_REFUSAL)?;
        }
        for method in ["POST", "PUT"] {
            expect_admitted(&policy, method, true, false)?;
        }
        Ok(format!(
            "IdempotencyKeys refused POST, PUT and DELETE without an idempotency key with \
             {IDEMPOTENCY_REFUSAL:?}, a nonce notwithstanding; control: POST and PUT with a key admitted"
        ))
    }

    /// TLS0RTT-REPLAY-05.
    pub(super) fn nonce_policy(_lab: &Lab) -> Result<String, String> {
        let policy = EarlyDataReplayProtection::NonceValidation;
        for (method, idempotency_key) in [("POST", true), ("GET", false)] {
            expect_refused(&policy, method, idempotency_key, false, NONCE_REFUSAL)?;
        }
        for method in ["POST", "GET"] {
            expect_admitted(&policy, method, false, true)?;
        }
        Ok(format!(
            "NonceValidation refused POST and GET without a valid nonce with {NONCE_REFUSAL:?}, an \
             idempotency key notwithstanding; control: both admitted with a nonce"
        ))
    }

    /// TLS0RTT-REPLAY-06.
    pub(super) fn missing_policy_refuses_all(_lab: &Lab) -> Result<String, String> {
        let policy = EarlyDataReplayProtection::None;
        for (method, idempotency_key, nonce) in [
            ("GET", false, false),
            ("GET", true, true),
            ("POST", true, true),
        ] {
            expect_refused(&policy, method, idempotency_key, nonce, NO_POLICY_REFUSAL)?;
        }
        expect_admitted(
            &EarlyDataReplayProtection::UnprotectedForTesting,
            "POST",
            false,
            false,
        )?;
        Ok(format!(
            "EarlyDataReplayProtection::None refused GET and POST, with or without key and nonce, with \
             {NO_POLICY_REFUSAL:?}; control: UnprotectedForTesting, the explicit opt-out, admitted POST"
        ))
    }

    // ------------------------------------------------------------------------
    // ServerReplayRejection
    // ------------------------------------------------------------------------

    /// TLS0RTT-SRV-01.
    pub(super) fn acceptor_requires_replay_strategy(_lab: &Lab) -> Result<String, String> {
        let expected = missing_strategy_message(EARLY_DATA_CAP);
        let explicit_none = server_builder()?
            .with_early_data_replay_protection(EarlyDataReplayProtection::None)
            .enable_early_data_with_protection(EARLY_DATA_CAP)
            .build();
        expect_configuration_error(
            explicit_none,
            &expected,
            "0-RTT with EarlyDataReplayProtection::None",
        )?;
        let unset = server_builder()?
            .enable_early_data_with_protection(EARLY_DATA_CAP)
            .build();
        expect_configuration_error(
            unset,
            &expected,
            "0-RTT with the strategy left at its default",
        )?;
        let control = zero_rtt_acceptor().map_err(|e| format!("control: {e}"))?;
        Ok(format!(
            "build() refused 0-RTT (cap {EARLY_DATA_CAP}) with no strategy, set to None or left \
             unset, with the exact TlsError::Configuration text (asupersync-ycuuwy); control: \
             UnprotectedForTesting built with max_early_data_size {}",
            control.config().max_early_data_size
        ))
    }

    /// TLS0RTT-SRV-02.
    pub(super) fn acceptor_refuses_unenforced_strategies(_lab: &Lab) -> Result<String, String> {
        for (policy, cap, name) in [
            (
                EarlyDataReplayProtection::SafeMethodsOnly,
                16_384,
                "SafeMethodsOnly",
            ),
            (
                EarlyDataReplayProtection::IdempotencyKeys,
                8_192,
                "IdempotencyKeys",
            ),
            (
                EarlyDataReplayProtection::NonceValidation,
                32_768,
                "NonceValidation",
            ),
        ] {
            let refused = server_builder()?
                .with_early_data_replay_protection(policy)
                .enable_early_data_with_protection(cap)
                .build();
            expect_configuration_error(
                refused,
                &unenforced_strategy_message(cap, name),
                &format!("0-RTT (cap {cap}) with {name}"),
            )?;
        }
        let control = zero_rtt_acceptor().map_err(|e| format!("control: {e}"))?;
        Ok(format!(
            "build() refused 0-RTT with SafeMethodsOnly (cap 16384), IdempotencyKeys (cap 8192) and \
             NonceValidation (cap 32768) with the exact TlsError::Configuration text \
             (asupersync-snv902); control: UnprotectedForTesting built with max_early_data_size {}",
            control.config().max_early_data_size
        ))
    }

    /// TLS0RTT-SRV-03.
    pub(super) fn fresh_ticket_zero_rtt_accepted(lab: &Lab) -> Result<String, String> {
        let second = &zero_rtt(lab)?.base.second;
        second.require_tls13("0-RTT study, resumption handshake")?;
        let hello = second.first_client_hello("resumption client flight")?;
        if !hello.has(wire::EXT_EARLY_DATA) || !hello.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "the resumption ClientHello should offer 0-RTT (early_data and pre_shared_key); extensions {:?}",
                hello.kinds()
            ));
        }
        let answer = second.server_hello("resumption server flight")?;
        if selected_identity(&answer)? != Some(0) {
            return Err(format!(
                "the server did not resume with selected_identity 0; ServerHello extensions {:?}",
                answer.kinds()
            ));
        }
        let records = second.client_encrypted_records("resumption client flight")?;
        if records != 2 {
            return Err(format!(
                "the server did not accept 0-RTT on a fresh single-use ticket: the client sent {records} encrypted handshake records, expected EndOfEarlyData and Finished (2)"
            ));
        }
        let control = stale(lab)?
            .second
            .client_encrypted_records("stale-ticket resumption client flight")?;
        if control != 1 {
            return Err(format!(
                "control: with a stale ticket the client should send Finished only (1 encrypted record), got {control}"
            ));
        }
        Ok(
            "fresh ticket: resumed with selected_identity 0, early_data accepted (the client sent \
             EndOfEarlyData then Finished, 2 encrypted records); control: stale ticket, Finished only"
                .to_string(),
        )
    }

    // ------------------------------------------------------------------------
    // EarlyDataLimits
    // ------------------------------------------------------------------------

    /// TLS0RTT-EDL-01.
    pub(super) fn ticket_advertises_configured_cap(lab: &Lab) -> Result<String, String> {
        let study = &zero_rtt(lab)?.base;
        if study.server_cap != EARLY_DATA_CAP {
            return Err(format!(
                "TlsAcceptor::config().max_early_data_size is {}, expected {EARLY_DATA_CAP}",
                study.server_cap
            ));
        }
        if study.first_tickets.is_empty()
            || study
                .first_tickets
                .iter()
                .any(|size| *size != EARLY_DATA_CAP)
        {
            return Err(format!(
                "NewSessionTickets carried max_early_data_size {:?}, expected each to be {EARLY_DATA_CAP}",
                study.first_tickets
            ));
        }
        Ok(format!(
            "{} NewSessionTickets carried early_data.max_early_data_size {EARLY_DATA_CAP}, the cap \
             given to enable_early_data_with_protection",
            study.first_tickets.len()
        ))
    }

    /// TLS0RTT-EDL-02.
    pub(super) fn disabled_acceptor_issues_no_early_data(lab: &Lab) -> Result<String, String> {
        let study = disabled_server(lab)?;
        if study.server_cap != 0 {
            return Err(format!(
                "the default TlsAcceptor has max_early_data_size {}, expected 0",
                study.server_cap
            ));
        }
        if study.first_tickets.is_empty() || study.first_tickets.iter().any(|size| *size != 0) {
            return Err(format!(
                "the default TlsAcceptor issued tickets with max_early_data_size {:?}, expected no early_data indication (0)",
                study.first_tickets
            ));
        }
        Ok(format!(
            "the default TlsAcceptor issued {} NewSessionTickets, none with an early_data indication",
            study.first_tickets.len()
        ))
    }

    /// TLS0RTT-EDL-03.
    pub(super) fn builder_cap_wiring(_lab: &Lab) -> Result<String, String> {
        let opted_in = zero_rtt_acceptor()?;
        if opted_in.config().max_early_data_size != EARLY_DATA_CAP {
            return Err(format!(
                "UnprotectedForTesting with cap {EARLY_DATA_CAP}: ServerConfig::max_early_data_size is {}",
                opted_in.config().max_early_data_size
            ));
        }
        if !matches!(
            opted_in.early_data_replay_protection(),
            EarlyDataReplayProtection::UnprotectedForTesting
        ) {
            return Err(format!(
                "the 0-RTT TlsAcceptor reports strategy {:?}, expected UnprotectedForTesting",
                opted_in.early_data_replay_protection()
            ));
        }
        let withdrawn = server_builder()?
            .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
            .enable_early_data_with_protection(EARLY_DATA_CAP)
            .disable_early_data()
            .build()
            .map_err(|e| format!("disable_early_data() after a cap did not build: {e:?}"))?;
        if withdrawn.config().max_early_data_size != 0 {
            return Err(format!(
                "disable_early_data() left max_early_data_size {}",
                withdrawn.config().max_early_data_size
            ));
        }
        let zero_cap = server_builder()?
            .enable_early_data_with_protection(0)
            .build()
            .map_err(|e| format!("a zero cap with no strategy did not build: {e:?}"))?;
        if zero_cap.config().max_early_data_size != 0 {
            return Err(format!(
                "a zero cap left max_early_data_size {}",
                zero_cap.config().max_early_data_size
            ));
        }
        let plain = default_acceptor()?;
        if plain.config().max_early_data_size != 0
            || !matches!(
                plain.early_data_replay_protection(),
                EarlyDataReplayProtection::None
            )
        {
            return Err(format!(
                "the default TlsAcceptor has max_early_data_size {} and strategy {:?}, expected 0 and None",
                plain.config().max_early_data_size,
                plain.early_data_replay_protection()
            ));
        }
        Ok(format!(
            "cap {EARLY_DATA_CAP} reached ServerConfig::max_early_data_size; disable_early_data(), a \
             zero cap and the default all gave 0 and built without a replay strategy"
        ))
    }

    // ------------------------------------------------------------------------
    // HelloRetryRequest
    // ------------------------------------------------------------------------

    /// TLS0RTT-HRR-01.
    pub(super) fn retry_drops_early_data(lab: &Lab) -> Result<String, String> {
        let second = &retry(lab)?.second;
        let hellos = second.client_hellos("HelloRetryRequest study, resumption client flight")?;
        let [initial, retried] = hellos.as_slice() else {
            return Err(format!(
                "expected two ClientHellos around a HelloRetryRequest, the client sent {}",
                hellos.len()
            ));
        };
        if !initial.has(wire::EXT_EARLY_DATA) || !initial.has(wire::EXT_PRE_SHARED_KEY) {
            return Err(format!(
                "ClientHello1 should offer 0-RTT (early_data and pre_shared_key); extensions {:?}",
                initial.kinds()
            ));
        }
        let initial_shares = key_share_groups(initial, "ClientHello1")?;
        if initial_shares != [wire::GROUP_SECP384R1] {
            return Err(format!(
                "ClientHello1 key shares {initial_shares:#06x?}, expected only secp384r1 (the ClientSessionStore kx_hint)"
            ));
        }
        if retried.has(wire::EXT_EARLY_DATA) {
            return Err(format!(
                "ClientHello2, sent after HelloRetryRequest, still carries early_data; extensions {:?}",
                retried.kinds()
            ));
        }
        let retried_shares = key_share_groups(retried, "ClientHello2")?;
        if retried_shares != [wire::GROUP_X25519] {
            return Err(format!(
                "ClientHello2 key shares {retried_shares:#06x?}, expected one share for the requested group x25519"
            ));
        }
        Ok(format!(
            "ClientHello1 offered early_data with one secp384r1 share; ClientHello2 dropped \
             early_data, sent one x25519 share{}",
            if retried.has(wire::EXT_PRE_SHARED_KEY) {
                " and kept pre_shared_key"
            } else {
                " and dropped pre_shared_key"
            }
        ))
    }

    fn key_share_groups(hello: &Hello, what: &str) -> Result<Vec<u16>, String> {
        let shares = hello
            .extension(wire::EXT_KEY_SHARE)
            .ok_or_else(|| format!("{what}: no key_share extension"))?;
        wire::client_key_share_groups(&shares.data).map_err(|e| format!("{what}: {e}"))
    }

    /// TLS0RTT-HRR-02.
    pub(super) fn retry_refuses_zero_rtt(lab: &Lab) -> Result<String, String> {
        let second = &retry(lab)?.second;
        second.require_tls13("HelloRetryRequest study, resumption handshake")?;
        let answers = hellos(
            &second.server_wire,
            wire::SERVER_HELLO,
            "HelloRetryRequest study, server flight",
        )?;
        let Some(request) = answers.first() else {
            return Err("the server wrote no ServerHello or HelloRetryRequest".to_string());
        };
        if !request.is_hello_retry_request() {
            return Err(format!(
                "the server's first reply is not a HelloRetryRequest (random {:02x?})",
                request.random
            ));
        }
        let selected = wire::u16_value(
            &request
                .extension(wire::EXT_KEY_SHARE)
                .ok_or_else(|| "HelloRetryRequest has no key_share".to_string())?
                .data,
            "HelloRetryRequest key_share",
        )?;
        let initial = second.first_client_hello("HelloRetryRequest study, ClientHello1")?;
        if !initial.has(wire::EXT_EARLY_DATA) {
            return Err(
                "ClientHello1 offered no early_data, so the rule was not exercised".to_string(),
            );
        }
        let listed = wire::named_groups(
            &initial
                .extension(wire::EXT_SUPPORTED_GROUPS)
                .ok_or_else(|| "ClientHello1 has no supported_groups".to_string())?
                .data,
        )?;
        let initial_shares = key_share_groups(&initial, "ClientHello1")?;
        if !listed.contains(&selected) || initial_shares.contains(&selected) {
            return Err(format!(
                "HelloRetryRequest selected group {selected:#06x}; it must be in supported_groups {listed:#06x?} and not among the key shares {initial_shares:#06x?}"
            ));
        }
        let records = second.client_encrypted_records("HelloRetryRequest study, client flight")?;
        if records != 1 {
            return Err(format!(
                "after HelloRetryRequest the client sent {records} encrypted handshake records; an EndOfEarlyData means the server accepted 0-RTT"
            ));
        }
        let resumed =
            selected_identity(&second.server_hello("HelloRetryRequest study, ServerHello")?)?
                .is_some();
        Ok(format!(
            "the server answered the 0-RTT ClientHello with HelloRetryRequest selecting {selected:#06x}, \
             then completed a {} TLS 1.3 handshake in which the client sent no EndOfEarlyData",
            if resumed { "PSK-resumed" } else { "full" }
        ))
    }
}

#[cfg(not(feature = "tls"))]
mod production {
    use super::Decision;

    /// Without the tls feature there is nothing to collect.
    pub(super) struct Lab;

    impl Lab {
        pub(super) fn collect() -> Self {
            Self
        }
    }

    pub(super) fn decide(_lab: &Lab, _check: fn(&Lab) -> Result<String, String>) -> Decision {
        Decision::Skipped(format!(
            "{}: TlsAcceptorBuilder::build and TlsConnectorBuilder::build only build with the tls \
             feature (src/tls/acceptor.rs:984-985, src/tls/connector.rs:1032-1033); without it \
             they return an error (src/tls/acceptor.rs:1244-1245, src/tls/connector.rs:1215-1216)",
            super::NEEDS_TLS
        ))
    }

    macro_rules! needs_tls {
        ($($name:ident),* $(,)?) => {
            $(
                pub(super) fn $name(_lab: &Lab) -> Result<String, String> {
                    Err(super::NEEDS_TLS.to_string())
                }
            )*
        };
    }

    needs_tls!(
        early_data_needs_pre_shared_key,
        pre_shared_key_sends_modes,
        pre_shared_key_is_last,
        server_refuses_non_final_pre_shared_key,
        server_validates_binder,
        server_selects_offered_identity,
        client_respects_ticket_without_early_data,
        default_connector_never_offers_early_data,
        connector_requires_replay_acknowledgement,
        ticket_age_reaches_server,
        server_checks_ticket_age,
        stale_ticket_completes_handshake,
        replayed_client_hello_not_resumed,
        zero_rtt_tickets_are_stateful,
        safe_methods_policy,
        idempotency_key_policy,
        nonce_policy,
        missing_policy_refuses_all,
        acceptor_requires_replay_strategy,
        acceptor_refuses_unenforced_strategies,
        fresh_ticket_zero_rtt_accepted,
        ticket_advertises_configured_cap,
        disabled_acceptor_issues_no_early_data,
        builder_cap_wiring,
        retry_drops_early_data,
        retry_refuses_zero_rtt,
    );
}

// ============================================================================
// Requirement table and harness
// ============================================================================

#[allow(clippy::too_many_lines)]
fn requirements() -> Vec<Requirement> {
    use Check::{Production, Unobservable};
    use Polarity::{Conforms, Refuses};
    use RequirementLevel::{Must, Should};
    use TestCategory::{
        AntiReplayCache, EarlyDataLimits, FreshnessWindow, HelloRetryRequest,
        PreSharedKeyExtension, ServerReplayRejection, TicketAgeObfuscation,
    };
    vec![
        Requirement {
            id: "TLS0RTT-PSK-01",
            rfc_section: "RFC 8446 §4.2.10",
            description: "A client offers early_data only together with pre_shared_key; the ticketless ClientHello of a 0-RTT-enabled TlsConnector offers neither",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::early_data_needs_pre_shared_key),
        },
        Requirement {
            id: "TLS0RTT-PSK-02",
            rfc_section: "RFC 8446 §4.2.9",
            description: "A ClientHello that offers pre_shared_key also sends psk_key_exchange_modes, listing psk_dhe_ke",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::pre_shared_key_sends_modes),
        },
        Requirement {
            id: "TLS0RTT-PSK-03",
            rfc_section: "RFC 8446 §4.2.11",
            description: "pre_shared_key is the last ClientHello extension and carries one 32..255-byte binder per identity",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::pre_shared_key_is_last),
        },
        Requirement {
            id: "TLS0RTT-PSK-04",
            rfc_section: "RFC 8446 §4.2.11",
            description: "TlsAcceptor aborts a ClientHello whose pre_shared_key is not the last extension, with a fatal illegal_parameter alert",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Refuses,
            check: Production(production::server_refuses_non_final_pre_shared_key),
        },
        Requirement {
            id: "TLS0RTT-PSK-05",
            rfc_section: "RFC 8446 §4.2.11, §4.2.11.2",
            description: "TlsAcceptor validates the PSK binder: a ClientHello altered after its binder was computed is aborted with a fatal decrypt_error alert",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Refuses,
            check: Production(production::server_validates_binder),
        },
        Requirement {
            id: "TLS0RTT-PSK-06",
            rfc_section: "RFC 8446 §4.2.11",
            description: "A TlsAcceptor that accepts the PSK answers with pre_shared_key selected_identity 0, inside the client's identity list",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::server_selects_offered_identity),
        },
        Requirement {
            id: "TLS0RTT-PSK-07",
            rfc_section: "RFC 8446 §4.2.10, §4.6.1",
            description: "A client does not offer early_data when the ticket it resumes carries no early_data indication (TlsAcceptor with 0-RTT disabled)",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::client_respects_ticket_without_early_data),
        },
        Requirement {
            id: "TLS0RTT-PSK-08",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "0-RTT stays off unless the application opts in: a TlsConnector built without enable_early_data(true) never offers early_data, even resuming a ticket that permits it",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Conforms,
            check: Production(production::default_connector_never_offers_early_data),
        },
        Requirement {
            id: "TLS0RTT-PSK-09",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "TlsConnectorBuilder::build refuses enable_early_data(true) until acknowledge_zero_rtt_replay_risk() is called",
            category: PreSharedKeyExtension,
            level: Must,
            polarity: Refuses,
            check: Production(production::connector_requires_replay_acknowledgement),
        },
        Requirement {
            id: "TLS0RTT-AGE-01",
            rfc_section: "RFC 8446 §4.2.11.1",
            description: "obfuscated_ticket_age carries the real ticket age: the server finds a fresh ticket inside its window and one received 3600 s earlier outside it",
            category: TicketAgeObfuscation,
            level: Must,
            polarity: Conforms,
            check: Production(production::ticket_age_reaches_server),
        },
        Requirement {
            id: "TLS0RTT-AGE-02",
            rfc_section: "RFC 8446 §4.2.10",
            description: "The server validates the ticket age and refuses 0-RTT for an age outside its tolerance, while still accepting the PSK",
            category: TicketAgeObfuscation,
            level: Must,
            polarity: Refuses,
            check: Production(production::server_checks_ticket_age),
        },
        Requirement {
            id: "TLS0RTT-FRESH-01",
            rfc_section: "RFC 8446 §4.2.10, §8.3",
            description: "A ClientHello with an out-of-window ticket age still completes as a 1-RTT handshake instead of being aborted",
            category: FreshnessWindow,
            level: Should,
            polarity: Conforms,
            check: Production(production::stale_ticket_completes_handshake),
        },
        Requirement {
            id: "TLS0RTT-FRESH-02",
            rfc_section: "RFC 8446 §4.6.1",
            description: "NewSessionTicket.ticket_lifetime is at most 604800 seconds",
            category: FreshnessWindow,
            level: Must,
            polarity: Conforms,
            check: Unobservable(ticket_lifetime_unobservable),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-01",
            rfc_section: "RFC 8446 §8, §8.1",
            description: "A byte-identical replay of a resumed 0-RTT ClientHello is not resumed again (single-use ticket), so its early data cannot be accepted twice",
            category: AntiReplayCache,
            level: Must,
            polarity: Refuses,
            check: Production(production::replayed_client_hello_not_resumed),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-02",
            rfc_section: "RFC 8446 §8.1",
            description: "A 0-RTT TlsAcceptor issues stateful, single-use tickets: no stateless ticketer, session cache enabled",
            category: AntiReplayCache,
            level: Must,
            polarity: Conforms,
            check: Production(production::zero_rtt_tickets_are_stateful),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-03",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "EarlyDataReplayProtection::SafeMethodsOnly refuses POST, PUT, DELETE and PATCH in early data and admits GET, HEAD and OPTIONS",
            category: AntiReplayCache,
            level: Must,
            polarity: Refuses,
            check: Production(production::safe_methods_policy),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-04",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "EarlyDataReplayProtection::IdempotencyKeys refuses an early-data request without an idempotency key and admits one with it",
            category: AntiReplayCache,
            level: Must,
            polarity: Refuses,
            check: Production(production::idempotency_key_policy),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-05",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "EarlyDataReplayProtection::NonceValidation refuses an early-data request without a valid nonce and admits one with it",
            category: AntiReplayCache,
            level: Must,
            polarity: Refuses,
            check: Production(production::nonce_policy),
        },
        Requirement {
            id: "TLS0RTT-REPLAY-06",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "EarlyDataReplayProtection::None refuses every early-data request; only UnprotectedForTesting, the explicit opt-out, admits them",
            category: AntiReplayCache,
            level: Must,
            polarity: Refuses,
            check: Production(production::missing_policy_refuses_all),
        },
        Requirement {
            id: "TLS0RTT-SRV-01",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "TlsAcceptorBuilder::build refuses 0-RTT when no replay strategy is configured",
            category: ServerReplayRejection,
            level: Must,
            polarity: Refuses,
            check: Production(production::acceptor_requires_replay_strategy),
        },
        Requirement {
            id: "TLS0RTT-SRV-02",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "TlsAcceptorBuilder::build refuses 0-RTT for SafeMethodsOnly, IdempotencyKeys and NonceValidation, whose per-request screening is not wired",
            category: ServerReplayRejection,
            level: Must,
            polarity: Refuses,
            check: Production(production::acceptor_refuses_unenforced_strategies),
        },
        Requirement {
            id: "TLS0RTT-SRV-03",
            rfc_section: "RFC 8446 §4.2.10, §4.5",
            description: "On a fresh single-use ticket a 0-RTT TlsAcceptor accepts early data: it resumes with selected_identity 0 and the client closes the early data with EndOfEarlyData",
            category: ServerReplayRejection,
            level: Must,
            polarity: Conforms,
            check: Production(production::fresh_ticket_zero_rtt_accepted),
        },
        Requirement {
            id: "TLS0RTT-SRV-04",
            rfc_section: "RFC 8446 §4.2.10",
            description: "0-RTT is accepted only when the TLS version, cipher suite and ALPN protocol match those of the PSK",
            category: ServerReplayRejection,
            level: Must,
            polarity: Conforms,
            check: Unobservable(psk_parameters_unobservable),
        },
        Requirement {
            id: "TLS0RTT-SRV-05",
            rfc_section: "RFC 8446 §8, Appendix E.5",
            description: "The server application receives accepted early data marked as early and screens it with the configured replay strategy",
            category: ServerReplayRejection,
            level: Must,
            polarity: Conforms,
            check: Unobservable(early_data_delivery_unobservable),
        },
        Requirement {
            id: "TLS0RTT-EDL-01",
            rfc_section: "RFC 8446 §4.6.1",
            description: "NewSessionTicket early_data.max_early_data_size equals the cap given to enable_early_data_with_protection",
            category: EarlyDataLimits,
            level: Must,
            polarity: Conforms,
            check: Production(production::ticket_advertises_configured_cap),
        },
        Requirement {
            id: "TLS0RTT-EDL-02",
            rfc_section: "RFC 8446 §4.2.10, §4.6.1",
            description: "A TlsAcceptor with 0-RTT disabled issues tickets without an early_data indication",
            category: EarlyDataLimits,
            level: Must,
            polarity: Conforms,
            check: Production(production::disabled_acceptor_issues_no_early_data),
        },
        Requirement {
            id: "TLS0RTT-EDL-03",
            rfc_section: "RFC 8446 §4.6.1",
            description: "The configured cap reaches ServerConfig::max_early_data_size; disable_early_data() and a zero cap turn 0-RTT off without a replay strategy",
            category: EarlyDataLimits,
            level: Must,
            polarity: Conforms,
            check: Production(production::builder_cap_wiring),
        },
        Requirement {
            id: "TLS0RTT-EDL-04",
            rfc_section: "RFC 8446 §4.6.1",
            description: "A client sends no more than max_early_data_size bytes of early data",
            category: EarlyDataLimits,
            level: Must,
            polarity: Conforms,
            check: Unobservable(client_early_data_cap_unobservable),
        },
        Requirement {
            id: "TLS0RTT-EDL-05",
            rfc_section: "RFC 8446 §4.6.1",
            description: "A server receiving more than max_early_data_size bytes of early data terminates the connection with unexpected_message",
            category: EarlyDataLimits,
            level: Should,
            polarity: Conforms,
            check: Unobservable(server_early_data_cap_unobservable),
        },
        Requirement {
            id: "TLS0RTT-HRR-01",
            rfc_section: "RFC 8446 §4.1.2",
            description: "After HelloRetryRequest the client removes early_data and sends one key share, for the requested group",
            category: HelloRetryRequest,
            level: Must,
            polarity: Conforms,
            check: Production(production::retry_drops_early_data),
        },
        Requirement {
            id: "TLS0RTT-HRR-02",
            rfc_section: "RFC 8446 §4.1.4, §4.2.8, §4.2.10",
            description: "A server that answers a 0-RTT ClientHello with HelloRetryRequest selects a group the client listed but sent no share for, and accepts no early data afterwards",
            category: HelloRetryRequest,
            level: Must,
            polarity: Conforms,
            check: Production(production::retry_refuses_zero_rtt),
        },
    ]
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn elapsed_millis_for_report(elapsed: Duration) -> u64 {
    let rounded = elapsed.as_nanos().saturating_add(999_999) / 1_000_000;
    u64::try_from(rounded.max(1)).unwrap_or(u64::MAX)
}

fn run_requirement(requirement: &Requirement, lab: &production::Lab) -> Tls0RttConformanceResult {
    let start = Instant::now();
    let decision = match requirement.check {
        Check::Unobservable(note) => Decision::Skipped(note()),
        // A panic in production code fails that requirement, not the harness.
        Check::Production(check) => {
            std::panic::catch_unwind(AssertUnwindSafe(|| production::decide(lab, check)))
                .unwrap_or_else(|payload| {
                    Decision::Decided(Err(format!(
                        "production code panicked: {}",
                        panic_text(&*payload)
                    )))
                })
        }
    };
    let (verdict, evidence, error_message) = match decision {
        Decision::Decided(Ok(observed)) => match requirement.polarity {
            Polarity::Conforms => (TestVerdict::Pass, Some(observed), None),
            Polarity::Refuses => (TestVerdict::ExpectedFailure, Some(observed), None),
        },
        Decision::Decided(Err(violation)) => (TestVerdict::Fail, None, Some(violation)),
        Decision::Skipped(note) => (TestVerdict::Skipped, None, Some(note)),
    };
    Tls0RttConformanceResult {
        test_id: requirement.id.to_string(),
        rfc_section: requirement.rfc_section.to_string(),
        description: format!("[{}] {}", requirement.rfc_section, requirement.description),
        category: requirement.category,
        requirement_level: requirement.level,
        verdict,
        evidence,
        error_message,
        execution_time_ms: elapsed_millis_for_report(start.elapsed()),
    }
}

/// Conformance harness for TLS 1.3 0-RTT replay protection.
#[allow(dead_code)]
pub struct Tls0RttConformanceHarness {
    requirements: Vec<Requirement>,
}

#[allow(dead_code)]
impl Tls0RttConformanceHarness {
    /// Create a new TLS 0-RTT conformance harness.
    pub fn new() -> Self {
        Self {
            requirements: requirements(),
        }
    }

    /// Run every requirement. The handshakes are collected once per call.
    pub fn run_all_tests(&self) -> Vec<Tls0RttConformanceResult> {
        let lab = production::Lab::collect();
        self.requirements
            .iter()
            .map(|requirement| run_requirement(requirement, &lab))
            .collect()
    }
}

impl Default for Tls0RttConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    const REQUIREMENT_COUNT: usize = 31;

    /// The requirements no production observable can decide. Moving one out
    /// of this set needs a production observable for it.
    const UNOBSERVABLE: [&str; 5] = [
        "TLS0RTT-FRESH-02",
        "TLS0RTT-SRV-04",
        "TLS0RTT-SRV-05",
        "TLS0RTT-EDL-04",
        "TLS0RTT-EDL-05",
    ];

    /// The requirements whose conforming outcome is a refusal.
    const REFUSALS: [&str; 11] = [
        "TLS0RTT-PSK-04",
        "TLS0RTT-PSK-05",
        "TLS0RTT-PSK-09",
        "TLS0RTT-AGE-02",
        "TLS0RTT-REPLAY-01",
        "TLS0RTT-REPLAY-03",
        "TLS0RTT-REPLAY-04",
        "TLS0RTT-REPLAY-05",
        "TLS0RTT-REPLAY-06",
        "TLS0RTT-SRV-01",
        "TLS0RTT-SRV-02",
    ];

    fn expected_verdict(requirement: &Requirement) -> TestVerdict {
        match (requirement.check, requirement.polarity) {
            (Check::Unobservable(_), _) => TestVerdict::Skipped,
            (Check::Production(_), _) if !cfg!(feature = "tls") => TestVerdict::Skipped,
            (Check::Production(_), Polarity::Conforms) => TestVerdict::Pass,
            (Check::Production(_), Polarity::Refuses) => TestVerdict::ExpectedFailure,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn tls_0rtt_conformance_suite_completeness() {
        let table = requirements();
        let results = Tls0RttConformanceHarness::new().run_all_tests();

        for result in &results {
            println!(
                "tls_0rtt_conformance id={} section={:?} level={:?} verdict={:?} elapsed_ms={} evidence={:?} message={:?}",
                result.test_id,
                result.rfc_section,
                result.requirement_level,
                result.verdict,
                result.execution_time_ms,
                result.evidence,
                result.error_message
            );
        }

        // Any RFC 8446 violation, or a study that could not run, fails the
        // suite whatever its requirement level.
        let failures: Vec<&Tls0RttConformanceResult> = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Fail)
            .collect();
        assert!(failures.is_empty(), "failed requirements: {failures:#?}");

        assert_eq!(results.len(), REQUIREMENT_COUNT, "requirement count");
        let ids: BTreeSet<&str> = results
            .iter()
            .map(|result| result.test_id.as_str())
            .collect();
        assert_eq!(ids.len(), results.len(), "requirement ids must be unique");

        let categories: HashSet<TestCategory> =
            results.iter().map(|result| result.category).collect();
        for category in [
            TestCategory::PreSharedKeyExtension,
            TestCategory::TicketAgeObfuscation,
            TestCategory::ServerReplayRejection,
            TestCategory::AntiReplayCache,
            TestCategory::EarlyDataLimits,
            TestCategory::FreshnessWindow,
            TestCategory::HelloRetryRequest,
        ] {
            assert!(
                categories.contains(&category),
                "category {category:?} has no requirement"
            );
        }

        let unobservable: BTreeSet<&str> = table
            .iter()
            .filter(|requirement| matches!(requirement.check, Check::Unobservable(_)))
            .map(|requirement| requirement.id)
            .collect();
        assert_eq!(
            unobservable,
            UNOBSERVABLE.into_iter().collect::<BTreeSet<_>>()
        );

        let refusals: BTreeSet<&str> = table
            .iter()
            .filter(|requirement| requirement.polarity == Polarity::Refuses)
            .map(|requirement| requirement.id)
            .collect();
        assert_eq!(refusals, REFUSALS.into_iter().collect::<BTreeSet<_>>());

        // The Skipped set is pinned exactly: the unobservable requirements
        // with --features tls, every requirement without it.
        let skipped: BTreeSet<&str> = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Skipped)
            .map(|result| result.test_id.as_str())
            .collect();
        let expected_skipped: BTreeSet<&str> = if cfg!(feature = "tls") {
            UNOBSERVABLE.into_iter().collect()
        } else {
            ids.clone()
        };
        assert_eq!(skipped, expected_skipped, "Skipped requirement ids");

        for (requirement, result) in table.iter().zip(&results) {
            assert_eq!(result.test_id, requirement.id);
            assert_eq!(
                result.verdict,
                expected_verdict(requirement),
                "{}: evidence {:?}, message {:?}",
                result.test_id,
                result.evidence,
                result.error_message
            );
            match result.verdict {
                TestVerdict::Skipped => {
                    let note = result.error_message.as_deref().unwrap_or("");
                    let prefix = if matches!(requirement.check, Check::Unobservable(_)) {
                        NO_OBSERVABLE
                    } else {
                        NEEDS_TLS
                    };
                    assert!(
                        note.starts_with(prefix),
                        "{}: skip note {note:?} must start with {prefix:?}",
                        result.test_id
                    );
                }
                TestVerdict::Pass | TestVerdict::ExpectedFailure => {
                    assert!(
                        result
                            .evidence
                            .as_deref()
                            .is_some_and(|text| !text.is_empty()),
                        "{}: a decided requirement must record what production did",
                        result.test_id
                    );
                    assert!(result.error_message.is_none(), "{}", result.test_id);
                }
                TestVerdict::Fail => {}
            }
            assert!(
                result
                    .description
                    .starts_with(&format!("[{}] ", requirement.rfc_section)),
                "{}: description must name its RFC 8446 section",
                result.test_id
            );
        }

        assert!(
            results.iter().all(|result| result.execution_time_ms > 0),
            "every result must record a non-zero elapsed time"
        );

        let count = |verdict: TestVerdict| {
            results
                .iter()
                .filter(|result| result.verdict == verdict)
                .count()
        };
        println!(
            "tls_0rtt_conformance summary: {} requirements, {} passed, {} refused as required, {} skipped, 0 failed",
            results.len(),
            count(TestVerdict::Pass),
            count(TestVerdict::ExpectedFailure),
            count(TestVerdict::Skipped)
        );
    }

    /// A ClientHello record encoded by hand from RFC 8446 §4.1.2, §4.2.9,
    /// §4.2.10 and §4.2.11.
    fn hand_encoded_client_hello() -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x6d]; // handshake record, 109 bytes
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x69]); // ClientHello, 105 bytes
        record.extend_from_slice(&[0x03, 0x03]); // legacy_version
        record.extend_from_slice(&[0x11; 32]); // random
        record.push(0x00); // legacy_session_id
        record.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        record.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods
        record.extend_from_slice(&[0x00, 0x3e]); // extensions, 62 bytes
        record.extend_from_slice(&[0x00, 0x2a, 0x00, 0x00]); // early_data
        record.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]); // psk_key_exchange_modes
        record.extend_from_slice(&[0x00, 0x29, 0x00, 0x30]); // pre_shared_key, 48 bytes
        record.extend_from_slice(&[0x00, 0x0b, 0x00, 0x05]); // identities (11), identity (5)
        record.extend_from_slice(b"abcde");
        record.extend_from_slice(&[0x00, 0x00, 0x00, 0x07]); // obfuscated_ticket_age 7
        record.extend_from_slice(&[0x00, 0x21, 0x20]); // binders (33), binder (32)
        record.extend_from_slice(&[0x22; 32]);
        record
    }

    /// A ServerHello record encoded by hand (RFC 8446 §4.1.3): supported_versions,
    /// then `last_extension`.
    fn hand_encoded_server_hello(random: &[u8; 32], last_extension: [u8; 6]) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x38]; // handshake record, 56 bytes
        record.extend_from_slice(&[0x02, 0x00, 0x00, 0x34, 0x03, 0x03]); // ServerHello, 52 bytes
        record.extend_from_slice(random);
        record.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]); // session id, suite, compression
        record.extend_from_slice(&[0x00, 0x0c]); // extensions, 12 bytes
        record.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
        record.extend_from_slice(&last_extension);
        record
    }

    /// Pins the wire reader to bytes encoded by hand from RFC 8446, so the
    /// reader cannot drift along with production.
    #[test]
    fn wire_oracle_reads_hand_encoded_records() {
        let client_hello = hand_encoded_client_hello();
        assert_eq!(client_hello.len(), 114);
        let hello = wire::parse_hello(&client_hello).expect("hand-encoded ClientHello");
        assert_eq!(hello.msg_type, wire::CLIENT_HELLO);
        assert_eq!(hello.random, [0x11; 32]);
        assert_eq!(
            hello.kinds(),
            vec![
                wire::EXT_EARLY_DATA,
                wire::EXT_PSK_KEY_EXCHANGE_MODES,
                wire::EXT_PRE_SHARED_KEY
            ]
        );
        let modes = hello
            .extension(wire::EXT_PSK_KEY_EXCHANGE_MODES)
            .expect("modes");
        assert_eq!(wire::psk_modes(&modes.data), Ok(vec![wire::PSK_DHE_KE]));
        let psk = hello
            .extension(wire::EXT_PRE_SHARED_KEY)
            .expect("pre_shared_key");
        assert_eq!(
            wire::offered_psks(&psk.data),
            Ok(wire::OfferedPsks {
                identities: vec![(b"abcde".to_vec(), 7)],
                binder_lengths: vec![32],
            })
        );
        assert!(!hello.is_hello_retry_request());

        let swapped = wire::with_last_two_extensions_swapped(&client_hello).expect("swap");
        assert_eq!(swapped.len(), client_hello.len());
        assert_eq!(
            wire::parse_hello(&swapped)
                .expect("swapped ClientHello")
                .kinds(),
            vec![
                wire::EXT_EARLY_DATA,
                wire::EXT_PRE_SHARED_KEY,
                wire::EXT_PSK_KEY_EXCHANGE_MODES
            ]
        );
        let flipped = wire::with_random_bit_flipped(&client_hello).expect("flip");
        let differing: Vec<usize> = (0..client_hello.len())
            .filter(|index| client_hello[*index] != flipped[*index])
            .collect();
        assert_eq!(differing, vec![wire::RANDOM_OFFSET]);
        assert_eq!(flipped[wire::RANDOM_OFFSET], 0x10);
        assert!(wire::parse_hello(&client_hello[..client_hello.len() - 1]).is_err());

        let server_hello =
            hand_encoded_server_hello(&[0x33; 32], [0x00, 0x29, 0x00, 0x02, 0x00, 0x00]);
        assert_eq!(server_hello.len(), 61);
        let answer = wire::parse_hello(&server_hello).expect("hand-encoded ServerHello");
        assert_eq!(answer.msg_type, wire::SERVER_HELLO);
        assert_eq!(
            answer.kinds(),
            vec![wire::EXT_SUPPORTED_VERSIONS, wire::EXT_PRE_SHARED_KEY]
        );
        assert!(!answer.is_hello_retry_request());
        let selected = answer
            .extension(wire::EXT_PRE_SHARED_KEY)
            .expect("selected_identity");
        assert_eq!(wire::u16_value(&selected.data, "selected_identity"), Ok(0));

        let retry_request = hand_encoded_server_hello(
            &wire::HELLO_RETRY_REQUEST_RANDOM,
            [0x00, 0x33, 0x00, 0x02, 0x00, 0x1d],
        );
        let request = wire::parse_hello(&retry_request).expect("hand-encoded HelloRetryRequest");
        assert!(request.is_hello_retry_request());
        let group = request
            .extension(wire::EXT_KEY_SHARE)
            .expect("selected_group");
        assert_eq!(
            wire::u16_value(&group.data, "selected_group"),
            Ok(wire::GROUP_X25519)
        );

        assert_eq!(
            wire::client_key_share_groups(&[0x00, 0x06, 0x00, 0x1d, 0x00, 0x02, 0xaa, 0xbb]),
            Ok(vec![wire::GROUP_X25519])
        );
        assert_eq!(
            wire::named_groups(&[0x00, 0x04, 0x00, 0x1d, 0x00, 0x18]),
            Ok(vec![wire::GROUP_X25519, wire::GROUP_SECP384R1])
        );

        let mut flight = server_hello.clone();
        flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]); // change_cipher_spec
        flight.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc]); // application_data
        flight.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x33]); // fatal decrypt_error
        let records = wire::records(&flight).expect("flight");
        assert_eq!(
            records
                .iter()
                .map(|record| record.content_type)
                .collect::<Vec<_>>(),
            vec![
                wire::HANDSHAKE,
                wire::CHANGE_CIPHER_SPEC,
                wire::APPLICATION_DATA,
                wire::ALERT
            ]
        );
        assert_eq!(records[0].bytes(&flight), server_hello.as_slice());
        assert_eq!(
            wire::alert(records[3].fragment(&flight)),
            Ok((wire::ALERT_FATAL, wire::ALERT_DECRYPT_ERROR))
        );
        assert!(wire::records(&flight[..flight.len() - 1]).is_err());
    }
}
