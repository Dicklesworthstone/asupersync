//! Structure-aware fuzzer for ATP-over-RaptorQ UDP symbol datagrams.
//!
//! This drives the `transport_rq` symbol datagram parser with raw and generated
//! datagrams covering the `ATRQ` magic, transfer tag, entry, SBN, ESI, symbol
//! kind, payload length, optional auth tag, and payload bytes. Authenticated
//! inputs are verified through `SecurityContext` so forged tags fail closed.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::Arbitrary;
use asupersync::net::atp::transport_rq::{
    RqSymbolDatagramFuzzError, parse_symbol_datagram_for_fuzz,
};
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use libfuzzer_sys::fuzz_target;

const SYMBOL_MAGIC: u32 = 0x4154_5251;
const DGRAM_HEADER: usize = 4 + 8 + 4 + 1 + 4 + 1 + 2;
const TAG_SIZE: usize = 32;
const AUTH_DGRAM_HEADER: usize = DGRAM_HEADER + TAG_SIZE;
const MAX_RAW_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 2048;
const MAX_TRAILING_BYTES: usize = 256;
const DEFAULT_OBJECT_HI: u64 = 0xA511_FEC0_DA7A_0000;
const DEFAULT_OBJECT_LO: u64 = 0x5251_0000_0000_0001;

#[derive(Debug, Arbitrary)]
struct RqDatagramFuzzInput {
    mode: RqDatagramMode,
}

#[derive(Debug, Arbitrary)]
enum RqDatagramMode {
    Raw {
        bytes: Vec<u8>,
        expect_tag: u64,
        auth_required: bool,
        max_payload_hint: u16,
    },
    Structured {
        transfer_tag: u64,
        expect_tag_delta: i8,
        entry: u32,
        sbn: u8,
        esi: u32,
        is_repair: bool,
        payload: Vec<u8>,
        auth: AuthShape,
        declared_len_delta: i8,
        truncate_tail: u8,
        trailing: Vec<u8>,
        bad_magic: bool,
        auth_required: bool,
        max_payload_delta: i16,
    },
}

#[derive(Debug, Arbitrary)]
enum AuthShape {
    None,
    Valid { key_seed: u64 },
    Forged { key_seed: u64, flip_byte: u8 },
    Literal { tag: [u8; TAG_SIZE] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthExpectation {
    NotAuthenticated,
    MustVerify { key_seed: u64 },
    MustReject { key_seed: u64 },
}

fuzz_target!(|input: RqDatagramFuzzInput| {
    let result = catch_unwind(AssertUnwindSafe(|| exercise_input(input)));
    assert!(
        result.is_ok(),
        "transport_rq symbol datagram parsing panicked"
    );
});

fn exercise_input(input: RqDatagramFuzzInput) {
    match input.mode {
        RqDatagramMode::Raw {
            bytes,
            expect_tag,
            auth_required,
            max_payload_hint,
        } => {
            if bytes.len() > MAX_RAW_BYTES {
                return;
            }
            let max_payload = usize::from(max_payload_hint).clamp(1, MAX_PAYLOAD_BYTES);
            match parse_symbol_datagram_for_fuzz(&bytes, expect_tag, auth_required, max_payload) {
                Ok(parsed) => assert_raw_acceptance(&bytes, parsed_payload_bounds(&parsed)),
                Err(error) => assert_typed_parser_error(error),
            }
        }
        RqDatagramMode::Structured {
            transfer_tag,
            expect_tag_delta,
            entry,
            sbn,
            esi,
            is_repair,
            payload,
            auth,
            declared_len_delta,
            truncate_tail,
            trailing,
            bad_magic,
            auth_required,
            max_payload_delta,
        } => {
            let payload = limit_vec(payload, MAX_PAYLOAD_BYTES);
            let trailing = limit_vec(trailing, MAX_TRAILING_BYTES);
            let declared_len = biased_len(payload.len(), declared_len_delta);
            let emitted_len = payload
                .len()
                .saturating_sub(usize::from(truncate_tail).min(payload.len()));
            let expect_tag = offset_tag(transfer_tag, expect_tag_delta);
            let max_payload = biased_max_payload(declared_len, max_payload_delta);

            let (datagram, auth_expectation) = build_structured_datagram(
                transfer_tag,
                entry,
                sbn,
                esi,
                is_repair,
                &payload[..emitted_len],
                &trailing,
                declared_len,
                auth,
                bad_magic,
            );

            match parse_symbol_datagram_for_fuzz(&datagram, expect_tag, auth_required, max_payload)
            {
                Ok(parsed) => {
                    assert_structured_acceptance(
                        &datagram,
                        &parsed,
                        declared_len,
                        auth_required,
                        auth_expectation,
                    );
                }
                Err(error) => assert_structured_error(
                    error,
                    &datagram,
                    expect_tag,
                    transfer_tag,
                    bad_magic,
                    declared_len,
                    max_payload,
                    auth_required,
                ),
            }
        }
    }
}

fn build_structured_datagram(
    transfer_tag: u64,
    entry: u32,
    sbn: u8,
    esi: u32,
    is_repair: bool,
    payload: &[u8],
    trailing: &[u8],
    declared_len: usize,
    auth: AuthShape,
    bad_magic: bool,
) -> (Vec<u8>, AuthExpectation) {
    let kind = if is_repair {
        SymbolKind::Repair
    } else {
        SymbolKind::Source
    };
    let symbol = Symbol::new(
        SymbolId::new(
            ObjectId::new(DEFAULT_OBJECT_HI, DEFAULT_OBJECT_LO),
            sbn,
            esi,
        ),
        payload.to_vec(),
        kind,
    );

    let (tag, expectation) = match auth {
        AuthShape::None => (None, AuthExpectation::NotAuthenticated),
        AuthShape::Valid { key_seed } => {
            let ctx = SecurityContext::for_testing(key_seed);
            let expectation = if declared_len == payload.len() {
                AuthExpectation::MustVerify { key_seed }
            } else {
                AuthExpectation::MustReject { key_seed }
            };
            (
                Some(*ctx.sign_symbol(&symbol).tag().as_bytes()),
                expectation,
            )
        }
        AuthShape::Forged {
            key_seed,
            flip_byte,
        } => {
            let ctx = SecurityContext::for_testing(key_seed);
            let mut tag = *ctx.sign_symbol(&symbol).tag().as_bytes();
            tag[usize::from(flip_byte) % TAG_SIZE] ^= 0xA5;
            (Some(tag), AuthExpectation::MustReject { key_seed })
        }
        AuthShape::Literal { tag } => (Some(tag), AuthExpectation::MustReject { key_seed: 0 }),
    };

    let mut out = Vec::with_capacity(AUTH_DGRAM_HEADER + payload.len() + trailing.len());
    let magic = if bad_magic {
        SYMBOL_MAGIC ^ 0xFFFF_0000
    } else {
        SYMBOL_MAGIC
    };
    out.extend_from_slice(&magic.to_be_bytes());
    out.extend_from_slice(&transfer_tag.to_be_bytes());
    out.extend_from_slice(&entry.to_be_bytes());
    out.push(sbn);
    out.extend_from_slice(&esi.to_be_bytes());
    out.push(u8::from(is_repair));
    out.extend_from_slice(&(u16_len(declared_len) as u16).to_be_bytes());
    if let Some(tag) = tag {
        out.extend_from_slice(&tag);
    }
    out.extend_from_slice(payload);
    out.extend_from_slice(trailing);
    (out, expectation)
}

fn assert_structured_acceptance(
    datagram: &[u8],
    parsed: &asupersync::net::atp::transport_rq::RqSymbolDatagramFuzzParse,
    declared_len: usize,
    auth_required: bool,
    auth_expectation: AuthExpectation,
) {
    assert_eq!(parsed.payload_len, u16_len(declared_len));
    let (start, end) = parsed_payload_bounds(parsed);
    assert!(end <= datagram.len());
    assert_eq!(end - start, parsed.payload_len);

    if auth_required {
        assert!(
            parsed.auth_tag.is_some(),
            "auth-required parser accepted a datagram without an auth tag"
        );
        assert_auth_posture(datagram, parsed, auth_expectation);
    } else {
        assert_eq!(
            parsed.auth_tag, None,
            "unauthenticated parser mode must not surface auth-tag bytes"
        );
    }
}

fn assert_auth_posture(
    datagram: &[u8],
    parsed: &asupersync::net::atp::transport_rq::RqSymbolDatagramFuzzParse,
    expectation: AuthExpectation,
) {
    let Some(tag) = parsed.auth_tag else {
        assert_eq!(expectation, AuthExpectation::NotAuthenticated);
        return;
    };
    let (start, end) = parsed_payload_bounds(parsed);
    let kind = if parsed.is_repair {
        SymbolKind::Repair
    } else {
        SymbolKind::Source
    };
    let symbol = Symbol::new(
        SymbolId::new(
            ObjectId::new(DEFAULT_OBJECT_HI, DEFAULT_OBJECT_LO),
            parsed.sbn,
            parsed.esi,
        ),
        datagram[start..end].to_vec(),
        kind,
    );
    let mut authenticated =
        AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::from_bytes(tag));

    match expectation {
        AuthExpectation::MustVerify { key_seed } => {
            SecurityContext::for_testing(key_seed)
                .verify_authenticated_symbol(&mut authenticated)
                .expect("valid structured symbol tag must verify");
        }
        AuthExpectation::MustReject { key_seed } => {
            assert!(
                SecurityContext::for_testing(key_seed)
                    .verify_authenticated_symbol(&mut authenticated)
                    .is_err(),
                "forged symbol tag unexpectedly verified"
            );
        }
        AuthExpectation::NotAuthenticated => {
            assert!(
                SecurityContext::for_testing(0)
                    .verify_authenticated_symbol(&mut authenticated)
                    .is_err(),
                "unauthenticated symbol bytes unexpectedly verified as a real tag"
            );
        }
    }
}

fn assert_raw_acceptance(datagram: &[u8], (start, end): (usize, usize)) {
    assert!(start <= end);
    assert!(end <= datagram.len());
}

fn assert_structured_error(
    error: RqSymbolDatagramFuzzError,
    datagram: &[u8],
    expect_tag: u64,
    transfer_tag: u64,
    bad_magic: bool,
    declared_len: usize,
    max_payload: usize,
    auth_required: bool,
) {
    assert_typed_parser_error(error);
    match error {
        RqSymbolDatagramFuzzError::BadMagic { .. } => assert!(bad_magic),
        RqSymbolDatagramFuzzError::WrongTransferTag { found, expected } => {
            assert_ne!(expect_tag, transfer_tag);
            assert_eq!(found, transfer_tag);
            assert_eq!(expected, expect_tag);
        }
        RqSymbolDatagramFuzzError::PayloadTooLarge { declared, max } => {
            assert_eq!(declared, u16_len(declared_len));
            assert_eq!(max, max_payload);
            assert!(declared > max);
        }
        RqSymbolDatagramFuzzError::TruncatedHeader { len, min } => {
            assert_eq!(len, datagram.len());
            let required = if auth_required {
                AUTH_DGRAM_HEADER
            } else {
                DGRAM_HEADER
            };
            assert_eq!(min, required);
            assert!(len < min);
        }
        RqSymbolDatagramFuzzError::TruncatedPayload { len, min } => {
            assert_eq!(len, datagram.len());
            assert!(len < min);
        }
    }
}

fn assert_typed_parser_error(error: RqSymbolDatagramFuzzError) {
    match error {
        RqSymbolDatagramFuzzError::TruncatedHeader { len, min }
        | RqSymbolDatagramFuzzError::TruncatedPayload { len, min } => assert!(len < min),
        RqSymbolDatagramFuzzError::BadMagic { found } => assert_ne!(found, SYMBOL_MAGIC),
        RqSymbolDatagramFuzzError::WrongTransferTag { found, expected } => {
            assert_ne!(found, expected);
        }
        RqSymbolDatagramFuzzError::PayloadTooLarge { declared, max } => {
            assert!(declared > max);
        }
    }
}

fn parsed_payload_bounds(
    parsed: &asupersync::net::atp::transport_rq::RqSymbolDatagramFuzzParse,
) -> (usize, usize) {
    (
        parsed.payload_offset,
        parsed.payload_offset + parsed.payload_len,
    )
}

fn offset_tag(tag: u64, delta: i8) -> u64 {
    if delta.is_negative() {
        tag.wrapping_sub(u64::from(delta.unsigned_abs()))
    } else {
        tag.wrapping_add(delta as u64)
    }
}

fn biased_len(base: usize, delta: i8) -> usize {
    let magnitude = usize::from(delta.unsigned_abs()).min(64);
    let biased = if delta.is_negative() {
        base.saturating_sub(magnitude)
    } else {
        base.saturating_add(magnitude)
    };
    biased.min(u16::MAX as usize)
}

fn biased_max_payload(declared_len: usize, delta: i16) -> usize {
    let base = declared_len.clamp(1, MAX_PAYLOAD_BYTES);
    let magnitude = usize::from(delta.unsigned_abs()).min(512);
    if delta.is_negative() {
        base.saturating_sub(magnitude).max(1)
    } else {
        base.saturating_add(magnitude).min(MAX_PAYLOAD_BYTES)
    }
}

fn u16_len(len: usize) -> usize {
    len.min(u16::MAX as usize)
}

fn limit_vec(mut bytes: Vec<u8>, limit: usize) -> Vec<u8> {
    bytes.truncate(limit);
    bytes
}
