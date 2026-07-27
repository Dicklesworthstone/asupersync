//! Strict, bounded DER residue reader for the staged X.509 replacement.
//!
//! This module implements only the four fact-only profiles approved by
//! `artifacts/x509_der_residue_spec_v1.json`. It deliberately has no clock,
//! trust store, chain, server name, signature verifier, or policy callback.
//! A6 owns migration of incumbent call sites; until then these crate-private
//! entry points are intentionally unused outside their inline A4 tests.

#![allow(dead_code)]

use core::fmt;

const MAX_CERTIFICATE_DER_BYTES: usize = 1_048_576;
const MAX_CERTIFICATE_DER_BYTES_U64: u64 = 1_048_576;
const MAX_TLV_DEPTH: usize = 16;
const MAX_TLV_NODES: usize = 4_096;
const MAX_OID_CONTENT_BYTES: usize = 64;
const MAX_INTEGER_CONTENT_BYTES: usize = 262_144;
const MAX_BIT_STRING_CONTENT_BYTES: usize = 262_144;
const MAX_SPKI_DER_BYTES: usize = 262_144;
const MAX_EXTENSION_COUNT: usize = 64;
const MAX_EXTENSION_VALUE_BYTES: usize = 262_144;
const MAX_SUBJECT_RDNS: usize = 128;
const MAX_SUBJECT_ATTRIBUTES: usize = 256;
const MAX_DIRECTORY_STRING_BYTES: usize = 4_096;
const MAX_EKU_PURPOSE_COUNT: usize = 64;
const MAX_SAN_ENTRY_COUNT: usize = 128;
const MAX_DNS_SAN_BYTES: usize = 253;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_TELETEX_STRING: u8 = 0x14;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_UNIVERSAL_STRING: u8 = 0x1c;
const TAG_BMP_STRING: u8 = 0x1e;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_VERSION_EXPLICIT: u8 = 0xa0;
const TAG_ISSUER_UNIQUE_ID: u8 = 0x81;
const TAG_SUBJECT_UNIQUE_ID: u8 = 0x82;
const TAG_EXTENSIONS_EXPLICIT: u8 = 0xa3;

const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const OID_ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// Stable, closed error classes approved by the A3 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerErrorClass {
    EmptyOrTrailing,
    CertificateLimit,
    UnexpectedEof,
    IndefiniteLength,
    NonminimalLength,
    LengthOverflow,
    Bounds,
    Tag,
    ConstructedBit,
    DepthLimit,
    NodeLimit,
    CountLimit,
    ValueLimit,
    Boolean,
    Integer,
    BitString,
    Null,
    Oid,
    SetOrder,
    ExplicitDefault,
    Schema,
    ExtensionShape,
    DuplicateExtension,
    DuplicateEku,
    UnknownCritical,
    SelectedExtension,
    Time,
    ValidityOrder,
    String,
    MissingSelectedField,
}

impl DerErrorClass {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyOrTrailing => "X509-DER-EMPTY-OR-TRAILING",
            Self::CertificateLimit => "X509-DER-CERTIFICATE-LIMIT",
            Self::UnexpectedEof => "X509-DER-UNEXPECTED-EOF",
            Self::IndefiniteLength => "X509-DER-INDEFINITE-LENGTH",
            Self::NonminimalLength => "X509-DER-NONMINIMAL-LENGTH",
            Self::LengthOverflow => "X509-DER-LENGTH-OVERFLOW",
            Self::Bounds => "X509-DER-BOUNDS",
            Self::Tag => "X509-DER-TAG",
            Self::ConstructedBit => "X509-DER-CONSTRUCTED-BIT",
            Self::DepthLimit => "X509-DER-DEPTH-LIMIT",
            Self::NodeLimit => "X509-DER-NODE-LIMIT",
            Self::CountLimit => "X509-DER-COUNT-LIMIT",
            Self::ValueLimit => "X509-DER-VALUE-LIMIT",
            Self::Boolean => "X509-DER-BOOLEAN",
            Self::Integer => "X509-DER-INTEGER",
            Self::BitString => "X509-DER-BIT-STRING",
            Self::Null => "X509-DER-NULL",
            Self::Oid => "X509-DER-OID",
            Self::SetOrder => "X509-DER-SET-ORDER",
            Self::ExplicitDefault => "X509-DER-EXPLICIT-DEFAULT",
            Self::Schema => "X509-DER-SCHEMA",
            Self::ExtensionShape => "X509-DER-EXTENSION-SHAPE",
            Self::DuplicateExtension => "X509-DER-DUPLICATE-EXTENSION",
            Self::DuplicateEku => "X509-DER-DUPLICATE-EKU",
            Self::UnknownCritical => "X509-DER-UNKNOWN-CRITICAL",
            Self::SelectedExtension => "X509-DER-SELECTED-EXTENSION",
            Self::Time => "X509-DER-TIME",
            Self::ValidityOrder => "X509-DER-VALIDITY-ORDER",
            Self::String => "X509-DER-STRING",
            Self::MissingSelectedField => "X509-DER-MISSING-SELECTED-FIELD",
        }
    }
}

/// Optional numeric detail whose values are always bounded by the input cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerLimitDetail {
    pub observed: u64,
    pub limit: u64,
}

/// Deterministic failure value with no peer-controlled text or bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerError {
    pub class: DerErrorClass,
    pub offset: usize,
    pub detail: Option<DerLimitDetail>,
}

impl fmt::Display for DerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at byte {}", self.class.code(), self.offset)
    }
}

impl std::error::Error for DerError {}

/// Checked Unix-second validity facts. No current-time comparison occurs here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityWindowUnixSeconds {
    pub not_before: i64,
    pub not_after: i64,
}

/// Extension presence is separate from every caller-owned admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionFact<T> {
    Absent,
    Present(T),
}

/// BasicConstraints presence and `cA` value, without CA admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BasicConstraintsFact {
    Absent,
    Present { ca: bool },
}

/// Bounded SAN facts borrowed directly from the input certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAltNameFacts<'a> {
    pub dns_names: Vec<&'a [u8]>,
    pub ip_addresses: Vec<&'a [u8]>,
}

/// Facts needed by the configured-server-chain preflight caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerChainMetadata {
    pub validity: ValidityWindowUnixSeconds,
    pub subject_identity_present: bool,
}

/// Facts needed by the exact-leaf fallback caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedLeafFacts<'a> {
    pub validity: ValidityWindowUnixSeconds,
    pub extended_key_usage: ExtensionFact<bool>,
    pub key_usage: ExtensionFact<bool>,
    pub subject_alt_name: ExtensionFact<SubjectAltNameFacts<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Spki,
    RootCa,
    AcceptorPreflight,
    PinnedLeaf,
}

#[derive(Clone, Copy, Debug)]
struct Cursor {
    position: usize,
    end: usize,
    depth: usize,
}

impl Cursor {
    const fn new(position: usize, end: usize, depth: usize) -> Self {
        Self {
            position,
            end,
            depth,
        }
    }

    const fn is_empty(self) -> bool {
        self.position == self.end
    }
}

#[derive(Clone, Copy, Debug)]
struct Tlv {
    tag: u8,
    start: usize,
    content_start: usize,
    end: usize,
    depth: usize,
}

impl Tlv {
    const fn content_range(self) -> core::ops::Range<usize> {
        self.content_start..self.end
    }

    const fn full_range(self) -> core::ops::Range<usize> {
        self.start..self.end
    }

    const fn content_len(self) -> usize {
        self.end - self.content_start
    }

    const fn child_cursor(self) -> Cursor {
        Cursor::new(self.content_start, self.end, self.depth + 1)
    }
}

struct Parser<'a> {
    input: &'a [u8],
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Result<Self, DerError> {
        if input.is_empty() {
            return Err(DerError {
                class: DerErrorClass::EmptyOrTrailing,
                offset: 0,
                detail: None,
            });
        }
        if input.len() > MAX_CERTIFICATE_DER_BYTES {
            return Err(DerError {
                class: DerErrorClass::CertificateLimit,
                offset: MAX_CERTIFICATE_DER_BYTES,
                detail: None,
            });
        }
        Ok(Self { input, nodes: 0 })
    }

    fn error(&self, class: DerErrorClass, offset: usize) -> DerError {
        DerError {
            class,
            offset: offset.min(self.input.len()),
            detail: None,
        }
    }

    fn limit_error(
        &self,
        class: DerErrorClass,
        offset: usize,
        observed: usize,
        limit: usize,
    ) -> DerError {
        let detail = u64::try_from(observed)
            .ok()
            .zip(u64::try_from(limit).ok())
            .filter(|(observed, limit)| {
                *observed <= MAX_CERTIFICATE_DER_BYTES_U64
                    && *limit <= MAX_CERTIFICATE_DER_BYTES_U64
            })
            .map(|(observed, limit)| DerLimitDetail { observed, limit });
        DerError {
            class,
            offset: offset.min(self.input.len()),
            detail,
        }
    }

    fn peek_tag(&self, cursor: Cursor) -> Option<u8> {
        (cursor.position < cursor.end).then(|| self.input[cursor.position])
    }

    fn read_tlv(&mut self, cursor: &mut Cursor) -> Result<Tlv, DerError> {
        if cursor.position >= cursor.end {
            return Err(self.error(DerErrorClass::UnexpectedEof, cursor.end));
        }
        if cursor.depth > MAX_TLV_DEPTH {
            return Err(self.limit_error(
                DerErrorClass::DepthLimit,
                cursor.position,
                cursor.depth,
                MAX_TLV_DEPTH,
            ));
        }

        let start = cursor.position;
        let tag = self.input[start];
        if tag & 0x1f == 0x1f {
            return Err(self.error(DerErrorClass::Tag, start));
        }
        let length_offset = start
            .checked_add(1)
            .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, start))?;
        if length_offset >= cursor.end {
            return Err(self.error(DerErrorClass::UnexpectedEof, cursor.end));
        }

        let first_length = self.input[length_offset];
        let (content_start, content_len) = if first_length & 0x80 == 0 {
            (
                length_offset
                    .checked_add(1)
                    .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, length_offset))?,
                usize::from(first_length),
            )
        } else {
            let octets = usize::from(first_length & 0x7f);
            if octets == 0 {
                return Err(self.error(DerErrorClass::IndefiniteLength, length_offset));
            }
            if octets > core::mem::size_of::<u64>() {
                return Err(self.error(DerErrorClass::LengthOverflow, length_offset));
            }
            let first_content_octet = length_offset
                .checked_add(1)
                .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, length_offset))?;
            let after_length = first_content_octet
                .checked_add(octets)
                .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, length_offset))?;
            if after_length > cursor.end {
                return Err(self.error(DerErrorClass::UnexpectedEof, cursor.end));
            }
            if self.input[first_content_octet] == 0 {
                return Err(self.error(DerErrorClass::NonminimalLength, first_content_octet));
            }
            let mut value = 0_u64;
            for byte in &self.input[first_content_octet..after_length] {
                value = value
                    .checked_mul(256)
                    .and_then(|current| current.checked_add(u64::from(*byte)))
                    .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, length_offset))?;
            }
            if value <= 127 {
                return Err(self.error(DerErrorClass::NonminimalLength, length_offset));
            }
            let required_octets = usize::try_from((64 - value.leading_zeros() + 7) / 8)
                .map_err(|_| self.error(DerErrorClass::LengthOverflow, length_offset))?;
            if required_octets != octets {
                return Err(self.error(DerErrorClass::NonminimalLength, length_offset));
            }
            let value = usize::try_from(value)
                .map_err(|_| self.error(DerErrorClass::LengthOverflow, length_offset))?;
            (after_length, value)
        };

        let end = content_start
            .checked_add(content_len)
            .ok_or_else(|| self.error(DerErrorClass::LengthOverflow, length_offset))?;
        if end > cursor.end {
            let class = if cursor.end == self.input.len() {
                DerErrorClass::UnexpectedEof
            } else {
                DerErrorClass::Bounds
            };
            return Err(self.error(class, cursor.end));
        }
        let observed_nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| self.error(DerErrorClass::NodeLimit, start))?;
        if observed_nodes > MAX_TLV_NODES {
            return Err(self.limit_error(
                DerErrorClass::NodeLimit,
                start,
                observed_nodes,
                MAX_TLV_NODES,
            ));
        }
        self.nodes = observed_nodes;
        cursor.position = end;

        Ok(Tlv {
            tag,
            start,
            content_start,
            end,
            depth: cursor.depth,
        })
    }

    fn expect(&mut self, cursor: &mut Cursor, expected: u8) -> Result<Tlv, DerError> {
        let tlv = self.read_tlv(cursor)?;
        if tlv.tag != expected {
            let class = if (tlv.tag ^ expected) == 0x20 {
                DerErrorClass::ConstructedBit
            } else {
                DerErrorClass::Tag
            };
            return Err(self.error(class, tlv.start));
        }
        Ok(tlv)
    }

    fn ensure_consumed(&self, cursor: Cursor, class: DerErrorClass) -> Result<(), DerError> {
        if cursor.is_empty() {
            Ok(())
        } else {
            Err(self.error(class, cursor.position))
        }
    }

    fn slice(&self, range: core::ops::Range<usize>) -> &'a [u8] {
        &self.input[range]
    }
}

fn checked_count(
    parser: &Parser<'_>,
    observed: usize,
    limit: usize,
    offset: usize,
) -> Result<(), DerError> {
    if observed > limit {
        Err(parser.limit_error(DerErrorClass::CountLimit, offset, observed, limit))
    } else {
        Ok(())
    }
}

fn checked_value_len(
    parser: &Parser<'_>,
    observed: usize,
    limit: usize,
    offset: usize,
) -> Result<(), DerError> {
    if observed > limit {
        Err(parser.limit_error(DerErrorClass::ValueLimit, offset, observed, limit))
    } else {
        Ok(())
    }
}

fn validate_integer<'input>(parser: &Parser<'input>, tlv: Tlv) -> Result<&'input [u8], DerError> {
    let content = parser.slice(tlv.content_range());
    checked_value_len(
        parser,
        content.len(),
        MAX_INTEGER_CONTENT_BYTES,
        tlv.content_start,
    )?;
    if content.is_empty() {
        return Err(parser.error(DerErrorClass::Integer, tlv.content_start));
    }
    if content.len() > 1
        && ((content[0] == 0 && content[1] & 0x80 == 0)
            || (content[0] == 0xff && content[1] & 0x80 != 0))
    {
        return Err(parser.error(DerErrorClass::Integer, tlv.content_start));
    }
    Ok(content)
}

fn validate_bit_string_content<'input>(
    parser: &Parser<'input>,
    tlv: Tlv,
) -> Result<&'input [u8], DerError> {
    let content = parser.slice(tlv.content_range());
    checked_value_len(
        parser,
        content.len(),
        MAX_BIT_STRING_CONTENT_BYTES,
        tlv.content_start,
    )?;
    let Some((&unused_bits, data)) = content.split_first() else {
        return Err(parser.error(DerErrorClass::BitString, tlv.content_start));
    };
    if unused_bits > 7 || (data.is_empty() && unused_bits != 0) {
        return Err(parser.error(DerErrorClass::BitString, tlv.content_start));
    }
    if let Some(last) = data.last()
        && unused_bits != 0
        && last & ((1_u8 << unused_bits) - 1) != 0
    {
        return Err(parser.error(DerErrorClass::BitString, tlv.end - 1));
    }
    Ok(content)
}

fn validate_oid<'input>(parser: &Parser<'input>, tlv: Tlv) -> Result<&'input [u8], DerError> {
    let content = parser.slice(tlv.content_range());
    checked_value_len(
        parser,
        content.len(),
        MAX_OID_CONTENT_BYTES,
        tlv.content_start,
    )?;
    if content.is_empty() {
        return Err(parser.error(DerErrorClass::Oid, tlv.content_start));
    }

    let mut at_subidentifier_start = true;
    let mut value = 0_u64;
    for (index, byte) in content.iter().copied().enumerate() {
        if at_subidentifier_start && byte == 0x80 {
            return Err(parser.error(DerErrorClass::Oid, tlv.content_start + index));
        }
        value = value
            .checked_mul(128)
            .and_then(|current| current.checked_add(u64::from(byte & 0x7f)))
            .ok_or_else(|| parser.error(DerErrorClass::Oid, tlv.content_start + index))?;
        at_subidentifier_start = byte & 0x80 == 0;
        if at_subidentifier_start {
            value = 0;
        }
    }
    if !at_subidentifier_start {
        return Err(parser.error(DerErrorClass::Oid, tlv.end));
    }
    Ok(content)
}

fn parse_boolean(parser: &Parser<'_>, tlv: Tlv) -> Result<bool, DerError> {
    let content = parser.slice(tlv.content_range());
    if content.len() != 1 {
        return Err(parser.error(DerErrorClass::Boolean, tlv.content_start));
    }
    match content[0] {
        0x00 => Ok(false),
        0xff => Ok(true),
        _ => Err(parser.error(DerErrorClass::Boolean, tlv.content_start)),
    }
}

fn parse_algorithm_identifier(
    parser: &mut Parser<'_>,
    cursor: &mut Cursor,
) -> Result<(), DerError> {
    let algorithm = parser.expect(cursor, TAG_SEQUENCE)?;
    let mut fields = algorithm.child_cursor();
    let oid = parser.expect(&mut fields, TAG_OID)?;
    validate_oid(parser, oid)?;
    if !fields.is_empty() {
        let parameter = parser.read_tlv(&mut fields)?;
        if parameter.tag == TAG_NULL && parameter.content_len() != 0 {
            return Err(parser.error(DerErrorClass::Null, parameter.content_start));
        }
    }
    parser.ensure_consumed(fields, DerErrorClass::Schema)
}

fn parse_version(parser: &mut Parser<'_>, cursor: &mut Cursor) -> Result<Option<u8>, DerError> {
    if parser.peek_tag(*cursor) != Some(TAG_VERSION_EXPLICIT) {
        return Ok(None);
    }
    let explicit = parser.expect(cursor, TAG_VERSION_EXPLICIT)?;
    let mut inner = explicit.child_cursor();
    let integer = parser.expect(&mut inner, TAG_INTEGER)?;
    let value = validate_integer(parser, integer)?;
    parser.ensure_consumed(inner, DerErrorClass::Schema)?;
    if value == [0] {
        return Err(parser.error(DerErrorClass::ExplicitDefault, integer.content_start));
    }
    match value {
        [1] => Ok(Some(1)),
        [2] => Ok(Some(2)),
        _ => Err(parser.error(DerErrorClass::Schema, integer.content_start)),
    }
}

fn decimal(bytes: &[u8], start: usize, width: usize) -> Option<u32> {
    let end = start.checked_add(width)?;
    let mut value = 0_u32;
    for byte in bytes.get(start..end)? {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    Some(value)
}

const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: i64, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn unix_seconds(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if year == 0
        || day == 0
        || day > days_in_month(year, month)?
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era
        .checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)?;
    days.checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))
}

fn parse_time(parser: &Parser<'_>, tlv: Tlv) -> Result<i64, DerError> {
    let bytes = parser.slice(tlv.content_range());
    let (year, offset) = match tlv.tag {
        TAG_UTC_TIME if bytes.len() == 13 => {
            let year = decimal(bytes, 0, 2)
                .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start))?;
            let year = if year >= 50 {
                1_900 + i64::from(year)
            } else {
                2_000 + i64::from(year)
            };
            (year, 2)
        }
        TAG_GENERALIZED_TIME if bytes.len() == 15 => {
            let year = decimal(bytes, 0, 4)
                .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start))?;
            (i64::from(year), 4)
        }
        TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            return Err(parser.error(DerErrorClass::Time, tlv.content_start));
        }
        _ => return Err(parser.error(DerErrorClass::Tag, tlv.start)),
    };
    if bytes.last() != Some(&b'Z') {
        return Err(parser.error(DerErrorClass::Time, tlv.end.saturating_sub(1)));
    }
    let month = decimal(bytes, offset, 2)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start + offset))?;
    let day = decimal(bytes, offset + 2, 2)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start + offset + 2))?;
    let hour = decimal(bytes, offset + 4, 2)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start + offset + 4))?;
    let minute = decimal(bytes, offset + 6, 2)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start + offset + 6))?;
    let second = decimal(bytes, offset + 8, 2)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start + offset + 8))?;
    unix_seconds(year, month, day, hour, minute, second)
        .ok_or_else(|| parser.error(DerErrorClass::Time, tlv.content_start))
}

fn parse_validity(
    parser: &mut Parser<'_>,
    cursor: &mut Cursor,
) -> Result<ValidityWindowUnixSeconds, DerError> {
    if cursor.is_empty() {
        return Err(parser.error(DerErrorClass::MissingSelectedField, cursor.end));
    }
    let validity = parser.expect(cursor, TAG_SEQUENCE)?;
    let mut times = validity.child_cursor();
    if times.is_empty() {
        return Err(parser.error(DerErrorClass::MissingSelectedField, times.end));
    }
    let not_before_tlv = parser.read_tlv(&mut times)?;
    let not_before = parse_time(parser, not_before_tlv)?;
    if times.is_empty() {
        return Err(parser.error(DerErrorClass::MissingSelectedField, times.end));
    }
    let not_after_tlv = parser.read_tlv(&mut times)?;
    let not_after = parse_time(parser, not_after_tlv)?;
    parser.ensure_consumed(times, DerErrorClass::Schema)?;
    if not_before > not_after {
        return Err(parser.error(DerErrorClass::ValidityOrder, validity.content_start));
    }
    Ok(ValidityWindowUnixSeconds {
        not_before,
        not_after,
    })
}

fn validate_directory_string(parser: &Parser<'_>, tlv: Tlv) -> Result<bool, DerError> {
    let bytes = parser.slice(tlv.content_range());
    checked_value_len(
        parser,
        bytes.len(),
        MAX_DIRECTORY_STRING_BYTES,
        tlv.content_start,
    )?;
    match tlv.tag {
        TAG_UTF8_STRING => {
            if bytes.is_empty() || core::str::from_utf8(bytes).is_err() {
                return Err(parser.error(DerErrorClass::String, tlv.content_start));
            }
            Ok(true)
        }
        TAG_PRINTABLE_STRING => {
            let valid = !bytes.is_empty()
                && bytes.iter().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            *byte,
                            b' ' | b'\''
                                | b'('
                                | b')'
                                | b'+'
                                | b','
                                | b'-'
                                | b'.'
                                | b'/'
                                | b':'
                                | b'='
                                | b'?'
                        )
                });
            if !valid {
                return Err(parser.error(DerErrorClass::String, tlv.content_start));
            }
            Ok(true)
        }
        TAG_BMP_STRING => {
            if bytes.is_empty() || bytes.len() % 2 != 0 {
                return Err(parser.error(DerErrorClass::String, tlv.content_start));
            }
            for chunk in bytes.chunks_exact(2) {
                let unit = u16::from_be_bytes([chunk[0], chunk[1]]);
                if (0xd800..=0xdfff).contains(&unit) {
                    return Err(parser.error(DerErrorClass::String, tlv.content_start));
                }
            }
            Ok(true)
        }
        TAG_UNIVERSAL_STRING => {
            if bytes.is_empty() || bytes.len() % 4 != 0 {
                return Err(parser.error(DerErrorClass::String, tlv.content_start));
            }
            for chunk in bytes.chunks_exact(4) {
                let scalar = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if char::from_u32(scalar).is_none() {
                    return Err(parser.error(DerErrorClass::String, tlv.content_start));
                }
            }
            Ok(true)
        }
        TAG_TELETEX_STRING => Ok(false),
        _ => Err(parser.error(DerErrorClass::String, tlv.start)),
    }
}

fn parse_name(
    parser: &mut Parser<'_>,
    cursor: &mut Cursor,
    inspect_subject_identity: bool,
) -> Result<bool, DerError> {
    let name = parser.expect(cursor, TAG_SEQUENCE)?;
    let mut rdns = name.child_cursor();
    let mut rdn_count = 0_usize;
    let mut attribute_count = 0_usize;
    let mut identity_present = false;

    while !rdns.is_empty() {
        rdn_count = rdn_count
            .checked_add(1)
            .ok_or_else(|| parser.error(DerErrorClass::CountLimit, rdns.position))?;
        if inspect_subject_identity {
            checked_count(parser, rdn_count, MAX_SUBJECT_RDNS, rdns.position)?;
        }
        let rdn = parser.expect(&mut rdns, TAG_SET)?;
        let mut attributes = rdn.child_cursor();
        if attributes.is_empty() {
            return Err(parser.error(DerErrorClass::Schema, rdn.content_start));
        }
        let mut previous: Option<&[u8]> = None;
        while !attributes.is_empty() {
            attribute_count = attribute_count
                .checked_add(1)
                .ok_or_else(|| parser.error(DerErrorClass::CountLimit, attributes.position))?;
            if inspect_subject_identity {
                checked_count(
                    parser,
                    attribute_count,
                    MAX_SUBJECT_ATTRIBUTES,
                    attributes.position,
                )?;
            }
            let attribute = parser.expect(&mut attributes, TAG_SEQUENCE)?;
            let encoded = parser.slice(attribute.full_range());
            if previous.is_some_and(|previous| previous > encoded) {
                return Err(parser.error(DerErrorClass::SetOrder, attribute.start));
            }
            previous = Some(encoded);

            let mut fields = attribute.child_cursor();
            let oid_tlv = parser.expect(&mut fields, TAG_OID)?;
            let oid = validate_oid(parser, oid_tlv)?;
            if fields.is_empty() {
                return Err(parser.error(DerErrorClass::Schema, fields.end));
            }
            let value = parser.read_tlv(&mut fields)?;
            parser.ensure_consumed(fields, DerErrorClass::Schema)?;
            if inspect_subject_identity
                && matches!(
                    oid,
                    OID_COMMON_NAME | OID_ORGANIZATION | OID_ORGANIZATIONAL_UNIT
                )
            {
                identity_present |= validate_directory_string(parser, value)?;
            }
        }
    }
    Ok(identity_present)
}

fn parse_subject_public_key_info<'a>(
    parser: &mut Parser<'a>,
    cursor: &mut Cursor,
) -> Result<&'a [u8], DerError> {
    if cursor.is_empty() {
        return Err(parser.error(DerErrorClass::MissingSelectedField, cursor.end));
    }
    let spki = parser.expect(cursor, TAG_SEQUENCE)?;
    checked_value_len(
        parser,
        spki.end - spki.start,
        MAX_SPKI_DER_BYTES,
        spki.start,
    )?;
    let mut fields = spki.child_cursor();
    parse_algorithm_identifier(parser, &mut fields)?;
    let key = parser.expect(&mut fields, TAG_BIT_STRING)?;
    validate_bit_string_content(parser, key)?;
    parser.ensure_consumed(fields, DerErrorClass::Schema)?;
    Ok(parser.slice(spki.full_range()))
}

fn parse_basic_constraints(parser: &mut Parser<'_>, extn_value: Tlv) -> Result<bool, DerError> {
    let mut inner = Cursor::new(
        extn_value.content_start,
        extn_value.end,
        extn_value.depth + 1,
    );
    let sequence = parser.expect(&mut inner, TAG_SEQUENCE)?;
    parser.ensure_consumed(inner, DerErrorClass::SelectedExtension)?;
    let mut fields = sequence.child_cursor();
    let mut ca = false;
    if parser.peek_tag(fields) == Some(TAG_BOOLEAN) {
        let boolean = parser.expect(&mut fields, TAG_BOOLEAN)?;
        ca = parse_boolean(parser, boolean)?;
        if !ca {
            return Err(parser.error(DerErrorClass::ExplicitDefault, boolean.content_start));
        }
    }
    if parser.peek_tag(fields) == Some(TAG_INTEGER) {
        let path_len = parser.expect(&mut fields, TAG_INTEGER)?;
        let value = validate_integer(parser, path_len)?;
        if !ca || value[0] & 0x80 != 0 {
            return Err(parser.error(DerErrorClass::SelectedExtension, path_len.content_start));
        }
    }
    parser.ensure_consumed(fields, DerErrorClass::SelectedExtension)?;
    Ok(ca)
}

fn parse_key_usage(parser: &mut Parser<'_>, extn_value: Tlv) -> Result<bool, DerError> {
    let mut inner = Cursor::new(
        extn_value.content_start,
        extn_value.end,
        extn_value.depth + 1,
    );
    let bit_string = parser.expect(&mut inner, TAG_BIT_STRING)?;
    parser.ensure_consumed(inner, DerErrorClass::SelectedExtension)?;
    let content = validate_bit_string_content(parser, bit_string)?;
    let (&unused_bits, data) = content
        .split_first()
        .ok_or_else(|| parser.error(DerErrorClass::BitString, bit_string.content_start))?;
    if data.is_empty()
        || data.len() > 2
        || data.last() == Some(&0)
        || data
            .last()
            .is_some_and(|last| u32::from(unused_bits) != last.trailing_zeros())
        || (data.len() == 2 && data[1] & 0x7f != 0)
    {
        return Err(parser.error(DerErrorClass::BitString, bit_string.content_start));
    }
    Ok(data[0] & 0x80 != 0)
}

fn parse_extended_key_usage(parser: &mut Parser<'_>, extn_value: Tlv) -> Result<bool, DerError> {
    let mut inner = Cursor::new(
        extn_value.content_start,
        extn_value.end,
        extn_value.depth + 1,
    );
    let sequence = parser.expect(&mut inner, TAG_SEQUENCE)?;
    parser.ensure_consumed(inner, DerErrorClass::SelectedExtension)?;
    let mut purposes = sequence.child_cursor();
    if purposes.is_empty() {
        return Err(parser.error(DerErrorClass::SelectedExtension, sequence.content_start));
    }
    let mut seen = Vec::<&[u8]>::new();
    seen.try_reserve(MAX_EKU_PURPOSE_COUNT)
        .map_err(|_| parser.error(DerErrorClass::ValueLimit, sequence.content_start))?;
    let mut server_auth = false;
    while !purposes.is_empty() {
        let oid_tlv = parser.expect(&mut purposes, TAG_OID)?;
        let oid = validate_oid(parser, oid_tlv)?;
        let observed = seen
            .len()
            .checked_add(1)
            .ok_or_else(|| parser.error(DerErrorClass::CountLimit, oid_tlv.start))?;
        checked_count(parser, observed, MAX_EKU_PURPOSE_COUNT, oid_tlv.start)?;
        if seen.contains(&oid) {
            return Err(parser.error(DerErrorClass::DuplicateEku, oid_tlv.start));
        }
        server_auth |= oid.cmp(OID_SERVER_AUTH).is_eq();
        seen.push(oid);
    }
    Ok(server_auth)
}

const fn expected_general_name_tag(tag: u8) -> bool {
    matches!(
        tag,
        0xa0 | 0x81 | 0x82 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x87 | 0x88
    )
}

fn parse_subject_alt_name<'a>(
    parser: &mut Parser<'a>,
    extn_value: Tlv,
    critical: bool,
) -> Result<SubjectAltNameFacts<'a>, DerError> {
    let mut inner = Cursor::new(
        extn_value.content_start,
        extn_value.end,
        extn_value.depth + 1,
    );
    let sequence = parser.expect(&mut inner, TAG_SEQUENCE)?;
    parser.ensure_consumed(inner, DerErrorClass::SelectedExtension)?;
    let mut names = sequence.child_cursor();
    if names.is_empty() {
        return Err(parser.error(DerErrorClass::SelectedExtension, sequence.content_start));
    }

    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    dns_names
        .try_reserve(MAX_SAN_ENTRY_COUNT)
        .map_err(|_| parser.error(DerErrorClass::ValueLimit, sequence.content_start))?;
    ip_addresses
        .try_reserve(MAX_SAN_ENTRY_COUNT)
        .map_err(|_| parser.error(DerErrorClass::ValueLimit, sequence.content_start))?;

    let mut count = 0_usize;
    while !names.is_empty() {
        let name = parser.read_tlv(&mut names)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| parser.error(DerErrorClass::CountLimit, name.start))?;
        checked_count(parser, count, MAX_SAN_ENTRY_COUNT, name.start)?;
        if !expected_general_name_tag(name.tag) {
            return Err(parser.error(DerErrorClass::SelectedExtension, name.start));
        }
        match name.tag {
            0x82 => {
                let bytes = parser.slice(name.content_range());
                checked_value_len(parser, bytes.len(), MAX_DNS_SAN_BYTES, name.content_start)?;
                if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii()) {
                    return Err(parser.error(DerErrorClass::SelectedExtension, name.content_start));
                }
                dns_names.push(bytes);
            }
            0x87 => {
                let bytes = parser.slice(name.content_range());
                if !matches!(bytes.len(), 4 | 16) {
                    return Err(parser.error(DerErrorClass::SelectedExtension, name.content_start));
                }
                ip_addresses.push(bytes);
            }
            _ if critical => {
                return Err(parser.error(DerErrorClass::UnknownCritical, name.start));
            }
            _ => {}
        }
    }
    Ok(SubjectAltNameFacts {
        dns_names,
        ip_addresses,
    })
}

struct ParsedCertificate<'a> {
    spki: &'a [u8],
    validity: ValidityWindowUnixSeconds,
    subject_identity_present: bool,
    basic_constraints: BasicConstraintsFact,
    extended_key_usage: ExtensionFact<bool>,
    key_usage: ExtensionFact<bool>,
    subject_alt_name: ExtensionFact<SubjectAltNameFacts<'a>>,
}

fn parse_extensions<'a>(
    parser: &mut Parser<'a>,
    wrapper: Tlv,
    profile: Profile,
    parsed: &mut ParsedCertificate<'a>,
) -> Result<(), DerError> {
    let mut wrapper_fields = wrapper.child_cursor();
    let extensions = parser.expect(&mut wrapper_fields, TAG_SEQUENCE)?;
    parser.ensure_consumed(wrapper_fields, DerErrorClass::ExtensionShape)?;
    let mut rows = extensions.child_cursor();
    if rows.is_empty() {
        return Err(parser.error(DerErrorClass::ExtensionShape, extensions.content_start));
    }
    let mut seen = Vec::<&[u8]>::new();
    seen.try_reserve(MAX_EXTENSION_COUNT)
        .map_err(|_| parser.error(DerErrorClass::ValueLimit, extensions.content_start))?;

    while !rows.is_empty() {
        let extension = parser.expect(&mut rows, TAG_SEQUENCE)?;
        let observed = seen
            .len()
            .checked_add(1)
            .ok_or_else(|| parser.error(DerErrorClass::CountLimit, extension.start))?;
        checked_count(parser, observed, MAX_EXTENSION_COUNT, extension.start)?;

        let mut fields = extension.child_cursor();
        let oid_tlv = parser.expect(&mut fields, TAG_OID)?;
        let oid = validate_oid(parser, oid_tlv)?;
        if seen.contains(&oid) {
            return Err(parser.error(DerErrorClass::DuplicateExtension, oid_tlv.start));
        }
        seen.push(oid);

        let mut critical = false;
        if parser.peek_tag(fields) == Some(TAG_BOOLEAN) {
            let boolean = parser.expect(&mut fields, TAG_BOOLEAN)?;
            critical = parse_boolean(parser, boolean)?;
            if !critical {
                return Err(parser.error(DerErrorClass::ExplicitDefault, boolean.content_start));
            }
        }
        let extn_value = parser.expect(&mut fields, TAG_OCTET_STRING)?;
        checked_value_len(
            parser,
            extn_value.content_len(),
            MAX_EXTENSION_VALUE_BYTES,
            extn_value.content_start,
        )?;
        parser.ensure_consumed(fields, DerErrorClass::ExtensionShape)?;

        match profile {
            Profile::RootCa if oid == OID_BASIC_CONSTRAINTS => {
                let ca = parse_basic_constraints(parser, extn_value)?;
                parsed.basic_constraints = BasicConstraintsFact::Present { ca };
            }
            Profile::PinnedLeaf if oid == OID_KEY_USAGE => {
                parsed.key_usage = ExtensionFact::Present(parse_key_usage(parser, extn_value)?);
            }
            Profile::PinnedLeaf if oid == OID_EXTENDED_KEY_USAGE => {
                parsed.extended_key_usage =
                    ExtensionFact::Present(parse_extended_key_usage(parser, extn_value)?);
            }
            Profile::PinnedLeaf if oid == OID_SUBJECT_ALT_NAME => {
                parsed.subject_alt_name =
                    ExtensionFact::Present(parse_subject_alt_name(parser, extn_value, critical)?);
            }
            Profile::PinnedLeaf if critical => {
                return Err(parser.error(DerErrorClass::UnknownCritical, oid_tlv.start));
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_certificate(input: &[u8], profile: Profile) -> Result<ParsedCertificate<'_>, DerError> {
    let mut parser = Parser::new(input)?;
    let mut root = Cursor::new(0, input.len(), 1);
    let certificate = parser.expect(&mut root, TAG_SEQUENCE)?;
    if !root.is_empty() {
        return Err(parser.error(DerErrorClass::EmptyOrTrailing, root.position));
    }
    let mut certificate_fields = certificate.child_cursor();
    let tbs = parser.expect(&mut certificate_fields, TAG_SEQUENCE)?;

    let mut tbs_fields = tbs.child_cursor();
    let _version = parse_version(&mut parser, &mut tbs_fields)?;
    if tbs_fields.is_empty() {
        return Err(parser.error(DerErrorClass::Schema, tbs_fields.end));
    }
    let serial = parser.expect(&mut tbs_fields, TAG_INTEGER)?;
    validate_integer(&parser, serial)?;
    parse_algorithm_identifier(&mut parser, &mut tbs_fields)?;
    parse_name(&mut parser, &mut tbs_fields, false)?;
    let validity = parse_validity(&mut parser, &mut tbs_fields)?;
    let subject_identity_present = parse_name(
        &mut parser,
        &mut tbs_fields,
        profile == Profile::AcceptorPreflight,
    )?;
    let spki = parse_subject_public_key_info(&mut parser, &mut tbs_fields)?;

    let mut parsed = ParsedCertificate {
        spki,
        validity,
        subject_identity_present,
        basic_constraints: BasicConstraintsFact::Absent,
        extended_key_usage: ExtensionFact::Absent,
        key_usage: ExtensionFact::Absent,
        subject_alt_name: ExtensionFact::Absent,
    };

    let mut optional_stage = 0_u8;
    while !tbs_fields.is_empty() {
        match parser.peek_tag(tbs_fields) {
            Some(TAG_ISSUER_UNIQUE_ID) if optional_stage < 1 => {
                optional_stage = 1;
                let unique_id = parser.expect(&mut tbs_fields, TAG_ISSUER_UNIQUE_ID)?;
                validate_bit_string_content(&parser, unique_id)?;
            }
            Some(TAG_SUBJECT_UNIQUE_ID) if optional_stage < 2 => {
                optional_stage = 2;
                let unique_id = parser.expect(&mut tbs_fields, TAG_SUBJECT_UNIQUE_ID)?;
                validate_bit_string_content(&parser, unique_id)?;
            }
            Some(TAG_EXTENSIONS_EXPLICIT) if optional_stage < 3 => {
                optional_stage = 3;
                let wrapper = parser.expect(&mut tbs_fields, TAG_EXTENSIONS_EXPLICIT)?;
                parse_extensions(&mut parser, wrapper, profile, &mut parsed)?;
            }
            _ => return Err(parser.error(DerErrorClass::Schema, tbs_fields.position)),
        }
    }

    parse_algorithm_identifier(&mut parser, &mut certificate_fields)?;
    let signature = parser.expect(&mut certificate_fields, TAG_BIT_STRING)?;
    validate_bit_string_content(&parser, signature)?;
    parser.ensure_consumed(certificate_fields, DerErrorClass::Schema)?;
    Ok(parsed)
}

/// Locate and borrow the complete encoded `SubjectPublicKeyInfo` TLV.
pub fn extract_spki_der(certificate_der: &[u8]) -> Result<&[u8], DerError> {
    parse_certificate(certificate_der, Profile::Spki).map(|parsed| parsed.spki)
}

/// Return BasicConstraints presence and `cA`, without making a CA decision.
pub fn inspect_basic_constraints_ca(
    certificate_der: &[u8],
) -> Result<BasicConstraintsFact, DerError> {
    parse_certificate(certificate_der, Profile::RootCa).map(|parsed| parsed.basic_constraints)
}

/// Return configured-chain validity and supported subject-identity presence.
pub fn inspect_server_chain_metadata(
    certificate_der: &[u8],
) -> Result<ServerChainMetadata, DerError> {
    parse_certificate(certificate_der, Profile::AcceptorPreflight).map(|parsed| {
        ServerChainMetadata {
            validity: parsed.validity,
            subject_identity_present: parsed.subject_identity_present,
        }
    })
}

/// Return exact-leaf residue facts without applying time, purpose, or name policy.
pub fn inspect_pinned_leaf_shape(certificate_der: &[u8]) -> Result<PinnedLeafFacts<'_>, DerError> {
    parse_certificate(certificate_der, Profile::PinnedLeaf).map(|parsed| PinnedLeafFacts {
        validity: parsed.validity,
        extended_key_usage: parsed.extended_key_usage,
        key_usage: parsed.key_usage,
        subject_alt_name: parsed.subject_alt_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    fn encoded_length(length: usize) -> Vec<u8> {
        if length <= 127 {
            return vec![length.to_be_bytes()[core::mem::size_of::<usize>() - 1]];
        }
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("nonzero long-form length");
        let significant = &bytes[first..];
        let mut encoded = Vec::with_capacity(significant.len() + 1);
        let octet_count = significant.len().to_be_bytes()[core::mem::size_of::<usize>() - 1];
        encoded.push(0x80 | octet_count);
        encoded.extend_from_slice(significant);
        encoded
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let length = encoded_length(content.len());
        let mut encoded = Vec::with_capacity(1 + length.len() + content.len());
        encoded.push(tag);
        encoded.extend_from_slice(&length);
        encoded.extend_from_slice(content);
        encoded
    }

    fn concatenate(parts: Vec<Vec<u8>>) -> Vec<u8> {
        parts.into_iter().flatten().collect()
    }

    fn sequence(parts: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &concatenate(parts))
    }

    fn oid(content: &[u8]) -> Vec<u8> {
        tlv(TAG_OID, content)
    }

    fn integer(content: &[u8]) -> Vec<u8> {
        tlv(TAG_INTEGER, content)
    }

    fn algorithm_identifier() -> Vec<u8> {
        sequence(vec![oid(OID_RSA_ENCRYPTION), tlv(TAG_NULL, &[])])
    }

    fn attribute(oid_content: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        sequence(vec![oid(oid_content), tlv(value_tag, value)])
    }

    fn rdn(mut attributes: Vec<Vec<u8>>) -> Vec<u8> {
        attributes.sort();
        tlv(TAG_SET, &concatenate(attributes))
    }

    fn name(rdns: Vec<Vec<u8>>) -> Vec<u8> {
        sequence(rdns)
    }

    fn common_name(value_tag: u8, value: &[u8]) -> Vec<u8> {
        name(vec![rdn(vec![attribute(
            OID_COMMON_NAME,
            value_tag,
            value,
        )])])
    }

    fn validity(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        sequence(vec![
            tlv(TAG_UTC_TIME, not_before),
            tlv(TAG_UTC_TIME, not_after),
        ])
    }

    fn default_validity() -> Vec<u8> {
        validity(b"250101000000Z", b"260101000000Z")
    }

    fn subject_public_key_info(key_bytes: &[u8]) -> Vec<u8> {
        let mut bit_string = Vec::with_capacity(key_bytes.len() + 1);
        bit_string.push(0);
        bit_string.extend_from_slice(key_bytes);
        sequence(vec![
            algorithm_identifier(),
            tlv(TAG_BIT_STRING, &bit_string),
        ])
    }

    fn extension(oid_content: &[u8], critical: Option<bool>, inner_der: &[u8]) -> Vec<u8> {
        let mut fields = vec![oid(oid_content)];
        if let Some(critical) = critical {
            fields.push(tlv(TAG_BOOLEAN, &[if critical { 0xff } else { 0 }]));
        }
        fields.push(tlv(TAG_OCTET_STRING, inner_der));
        sequence(fields)
    }

    fn certificate(
        serial_content: &[u8],
        certificate_validity: Vec<u8>,
        subject: Vec<u8>,
        spki: Vec<u8>,
        extensions: Option<Vec<Vec<u8>>>,
        signature_content: &[u8],
    ) -> Vec<u8> {
        let mut tbs_fields = vec![
            tlv(TAG_VERSION_EXPLICIT, &integer(&[2])),
            integer(serial_content),
            algorithm_identifier(),
            common_name(TAG_UTF8_STRING, b"Issuer"),
            certificate_validity,
            subject,
            spki,
        ];
        if let Some(rows) = extensions {
            tbs_fields.push(tlv(TAG_EXTENSIONS_EXPLICIT, &sequence(rows)));
        }
        sequence(vec![
            sequence(tbs_fields),
            algorithm_identifier(),
            tlv(TAG_BIT_STRING, signature_content),
        ])
    }

    fn default_certificate(extensions: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1, 2, 3]),
            extensions,
            &[0, 1],
        )
    }

    fn expect_error<T>(result: Result<T, DerError>, class: DerErrorClass) -> DerError {
        let error = result.err().expect("expected deterministic DER error");
        assert_eq!(error.class, class);
        error
    }

    #[test]
    fn four_profiles_return_only_approved_borrowed_facts() {
        let basic_constraints = extension(
            OID_BASIC_CONSTRAINTS,
            None,
            &sequence(vec![tlv(TAG_BOOLEAN, &[0xff]), integer(&[0])]),
        );
        let key_usage = extension(OID_KEY_USAGE, Some(true), &tlv(TAG_BIT_STRING, &[7, 0x80]));
        let extended_key_usage = extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(vec![oid(OID_SERVER_AUTH)]),
        );
        let san_inner = sequence(vec![tlv(0x82, b"example.com"), tlv(0x87, &[192, 0, 2, 1])]);
        let subject_alt_name = extension(OID_SUBJECT_ALT_NAME, None, &san_inner);
        let spki = subject_public_key_info(&[1, 2, 3]);
        let certificate = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"example.com"),
            spki.clone(),
            Some(vec![
                basic_constraints,
                key_usage,
                extended_key_usage,
                subject_alt_name,
            ]),
            &[0, 1],
        );

        assert_eq!(
            extract_spki_der(&certificate).expect("SPKI profile"),
            spki.as_slice()
        );
        assert_eq!(
            inspect_basic_constraints_ca(&certificate).expect("root profile"),
            BasicConstraintsFact::Present { ca: true }
        );
        let metadata =
            inspect_server_chain_metadata(&certificate).expect("acceptor preflight profile");
        assert!(metadata.subject_identity_present);
        assert!(metadata.validity.not_before < metadata.validity.not_after);

        let pin = inspect_pinned_leaf_shape(&certificate).expect("pinned leaf profile");
        assert_eq!(pin.extended_key_usage, ExtensionFact::Present(true));
        assert_eq!(pin.key_usage, ExtensionFact::Present(true));
        assert_eq!(
            pin.subject_alt_name,
            ExtensionFact::Present(SubjectAltNameFacts {
                dns_names: vec![b"example.com".as_slice()],
                ip_addresses: vec![[192, 0, 2, 1].as_slice()],
            })
        );

        let absent = default_certificate(None);
        assert_eq!(
            inspect_basic_constraints_ca(&absent).expect("absent root facts"),
            BasicConstraintsFact::Absent
        );
        let absent_pin = inspect_pinned_leaf_shape(&absent).expect("absent pin facts");
        assert_eq!(absent_pin.extended_key_usage, ExtensionFact::Absent);
        assert_eq!(absent_pin.key_usage, ExtensionFact::Absent);
        assert_eq!(absent_pin.subject_alt_name, ExtensionFact::Absent);
    }

    #[test]
    fn full_consumption_and_every_truncation_offset_fail_closed() {
        let certificate = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"example.com")]),
        )]));
        for end in 0..certificate.len() {
            assert!(extract_spki_der(&certificate[..end]).is_err(), "end={end}");
            assert!(
                inspect_basic_constraints_ca(&certificate[..end]).is_err(),
                "end={end}"
            );
            assert!(
                inspect_server_chain_metadata(&certificate[..end]).is_err(),
                "end={end}"
            );
            assert!(
                inspect_pinned_leaf_shape(&certificate[..end]).is_err(),
                "end={end}"
            );
        }
        assert!(extract_spki_der(&certificate).is_ok());

        let mut trailing = certificate;
        trailing.push(0);
        expect_error(extract_spki_der(&trailing), DerErrorClass::EmptyOrTrailing);
    }

    #[test]
    fn tag_and_length_boundaries_are_canonical_and_deterministic() {
        for length in [0, 1, 127, 128, 255, 256] {
            let encoded = tlv(TAG_OCTET_STRING, &vec![0; length]);
            let mut parser = Parser::new(&encoded).expect("bounded parser");
            let mut cursor = Cursor::new(0, encoded.len(), 1);
            let value = parser
                .expect(&mut cursor, TAG_OCTET_STRING)
                .expect("canonical TLV");
            assert_eq!(value.content_len(), length);
            assert!(cursor.is_empty());
        }

        for (input, class) in [
            (
                vec![TAG_OCTET_STRING, 0x80],
                DerErrorClass::IndefiniteLength,
            ),
            (
                vec![TAG_OCTET_STRING, 0x81, 0x01, 0],
                DerErrorClass::NonminimalLength,
            ),
            (
                vec![TAG_OCTET_STRING, 0x82, 0, 0x80],
                DerErrorClass::NonminimalLength,
            ),
            (vec![0x1f, 0], DerErrorClass::Tag),
            (vec![TAG_OCTET_STRING, 0x89], DerErrorClass::LengthOverflow),
        ] {
            let mut parser = Parser::new(&input).expect("nonempty parser");
            let mut cursor = Cursor::new(0, input.len(), 1);
            expect_error(parser.read_tlv(&mut cursor), class);
        }

        let input = [0x10, 0];
        let mut parser = Parser::new(&input).expect("nonempty parser");
        let mut cursor = Cursor::new(0, input.len(), 1);
        expect_error(
            parser.expect(&mut cursor, TAG_SEQUENCE),
            DerErrorClass::ConstructedBit,
        );

        let nested_bounds = [TAG_SEQUENCE, 2, TAG_OCTET_STRING, 1, TAG_NULL, 0];
        let mut parser = Parser::new(&nested_bounds).expect("nonempty parser");
        let mut root = Cursor::new(0, nested_bounds.len(), 1);
        let sequence = parser
            .expect(&mut root, TAG_SEQUENCE)
            .expect("outer sequence");
        let mut inner = sequence.child_cursor();
        expect_error(parser.read_tlv(&mut inner), DerErrorClass::Bounds);
    }

    #[test]
    fn extension_duplicates_and_criticality_are_fail_closed() {
        let san = extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"example.com")]),
        );
        let duplicate_extension = default_certificate(Some(vec![san.clone(), san]));
        expect_error(
            inspect_pinned_leaf_shape(&duplicate_extension),
            DerErrorClass::DuplicateExtension,
        );

        let duplicate_eku = default_certificate(Some(vec![extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(vec![oid(OID_SERVER_AUTH), oid(OID_SERVER_AUTH)]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&duplicate_eku),
            DerErrorClass::DuplicateEku,
        );

        let unknown_oid = [0x2a, 0x03, 0x04];
        let unknown_critical =
            default_certificate(Some(vec![extension(&unknown_oid, Some(true), &[])]));
        expect_error(
            inspect_pinned_leaf_shape(&unknown_critical),
            DerErrorClass::UnknownCritical,
        );
        let unknown_noncritical =
            default_certificate(Some(vec![extension(&unknown_oid, None, &[])]));
        assert!(inspect_pinned_leaf_shape(&unknown_noncritical).is_ok());

        let unsupported_general_name = sequence(vec![tlv(0x81, b"mail@example.com")]);
        let critical_san = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            Some(true),
            &unsupported_general_name,
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&critical_san),
            DerErrorClass::UnknownCritical,
        );
        let noncritical_san = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &unsupported_general_name,
        )]));
        let pin = inspect_pinned_leaf_shape(&noncritical_san).expect("skipped noncritical name");
        assert_eq!(
            pin.subject_alt_name,
            ExtensionFact::Present(SubjectAltNameFacts {
                dns_names: Vec::new(),
                ip_addresses: Vec::new(),
            })
        );

        let explicit_false =
            default_certificate(Some(vec![extension(&unknown_oid, Some(false), &[])]));
        expect_error(
            inspect_pinned_leaf_shape(&explicit_false),
            DerErrorClass::ExplicitDefault,
        );
    }

    #[test]
    fn selected_extension_semantics_preserve_presence_and_defaults() {
        let empty_basic_constraints = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(Vec::new()),
        )]));
        assert_eq!(
            inspect_basic_constraints_ca(&empty_basic_constraints).expect("empty defaults"),
            BasicConstraintsFact::Present { ca: false }
        );

        let explicit_false = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(vec![tlv(TAG_BOOLEAN, &[0])]),
        )]));
        expect_error(
            inspect_basic_constraints_ca(&explicit_false),
            DerErrorClass::ExplicitDefault,
        );

        let path_without_ca = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(vec![integer(&[0])]),
        )]));
        expect_error(
            inspect_basic_constraints_ca(&path_without_ca),
            DerErrorClass::SelectedExtension,
        );

        let digital_signature = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[7, 0x80]),
        )]));
        assert_eq!(
            inspect_pinned_leaf_shape(&digital_signature)
                .expect("digitalSignature")
                .key_usage,
            ExtensionFact::Present(true)
        );
        let key_encipherment = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[5, 0x20]),
        )]));
        assert_eq!(
            inspect_pinned_leaf_shape(&key_encipherment)
                .expect("keyEncipherment")
                .key_usage,
            ExtensionFact::Present(false)
        );
        let nonminimal_named_bits = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[0, 0x80, 0]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&nonminimal_named_bits),
            DerErrorClass::BitString,
        );
    }

    #[test]
    fn validity_and_directory_strings_are_strict_without_policy() {
        let invalid_date = certificate(
            &[1],
            validity(b"250229000000Z", b"260101000000Z"),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&invalid_date),
            DerErrorClass::Time,
        );

        let reversed = certificate(
            &[1],
            validity(b"260101000000Z", b"250101000000Z"),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&reversed),
            DerErrorClass::ValidityOrder,
        );

        for subject in [
            common_name(TAG_UTF8_STRING, &[0xff]),
            common_name(TAG_PRINTABLE_STRING, b"bad@value"),
            common_name(TAG_BMP_STRING, &[0]),
            common_name(TAG_UNIVERSAL_STRING, &[0, 0, 0]),
        ] {
            let malformed = certificate(
                &[1],
                default_validity(),
                subject,
                subject_public_key_info(&[1]),
                None,
                &[0, 1],
            );
            expect_error(
                inspect_server_chain_metadata(&malformed),
                DerErrorClass::String,
            );
        }

        let teletex = certificate(
            &[1],
            default_validity(),
            common_name(TAG_TELETEX_STRING, b"Legacy"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        assert!(
            !inspect_server_chain_metadata(&teletex)
                .expect("Teletex is recognized but not a supported identity")
                .subject_identity_present
        );
    }

    #[test]
    fn every_configured_resource_budget_fails_before_unbounded_work() {
        let oversized_certificate = vec![0; MAX_CERTIFICATE_DER_BYTES + 1];
        let certificate_error = expect_error(
            extract_spki_der(&oversized_certificate),
            DerErrorClass::CertificateLimit,
        );
        assert_eq!(certificate_error.offset, MAX_CERTIFICATE_DER_BYTES);

        let mut extension_rows = Vec::new();
        for suffix in 0..=MAX_EXTENSION_COUNT {
            let suffix_octet = suffix.to_be_bytes()[core::mem::size_of::<usize>() - 1];
            extension_rows.push(extension(&[0x2a, 0x03, suffix_octet], None, &[]));
        }
        let too_many_extensions = default_certificate(Some(extension_rows));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_extensions),
            DerErrorClass::CountLimit,
        );

        let oversized_extension = default_certificate(Some(vec![extension(
            &[0x2a, 0x03, 1],
            None,
            &vec![0; MAX_EXTENSION_VALUE_BYTES + 1],
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&oversized_extension),
            DerErrorClass::ValueLimit,
        );

        let encoded_attribute = attribute(OID_COMMON_NAME, TAG_UTF8_STRING, b"x");
        let too_many_rdns = name(
            (0..=MAX_SUBJECT_RDNS)
                .map(|_| rdn(vec![encoded_attribute.clone()]))
                .collect(),
        );
        let rdn_limited_certificate = certificate(
            &[1],
            default_validity(),
            too_many_rdns,
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&rdn_limited_certificate),
            DerErrorClass::CountLimit,
        );

        let too_many_attributes = name(vec![rdn(vec![
            encoded_attribute.clone();
            MAX_SUBJECT_ATTRIBUTES + 1
        ])]);
        let attribute_limited_certificate = certificate(
            &[1],
            default_validity(),
            too_many_attributes,
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&attribute_limited_certificate),
            DerErrorClass::CountLimit,
        );

        let oversized_string = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, &vec![b'x'; MAX_DIRECTORY_STRING_BYTES + 1]),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&oversized_string),
            DerErrorClass::ValueLimit,
        );

        let eku_purposes = (0..=MAX_EKU_PURPOSE_COUNT)
            .map(|suffix| {
                let suffix_octet = suffix.to_be_bytes()[core::mem::size_of::<usize>() - 1];
                oid(&[0x2a, 0x03, suffix_octet])
            })
            .collect();
        let too_many_eku = default_certificate(Some(vec![extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(eku_purposes),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_eku),
            DerErrorClass::CountLimit,
        );

        let too_many_sans = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"x"); MAX_SAN_ENTRY_COUNT + 1]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_sans),
            DerErrorClass::CountLimit,
        );

        let oversized_dns = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, &vec![b'x'; MAX_DNS_SAN_BYTES + 1])]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&oversized_dns),
            DerErrorClass::ValueLimit,
        );

        let oversized_spki = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&vec![1; MAX_SPKI_DER_BYTES - 24]),
            None,
            &[0, 1],
        );
        expect_error(extract_spki_der(&oversized_spki), DerErrorClass::ValueLimit);

        let oversized_integer = certificate(
            &vec![1; MAX_INTEGER_CONTENT_BYTES + 1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            extract_spki_der(&oversized_integer),
            DerErrorClass::ValueLimit,
        );

        let oversized_signature = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&[1]),
            None,
            &vec![0; MAX_BIT_STRING_CONTENT_BYTES + 1],
        );
        expect_error(
            extract_spki_der(&oversized_signature),
            DerErrorClass::ValueLimit,
        );

        let oversized_oid = certificate(
            &[1],
            default_validity(),
            name(vec![rdn(vec![attribute(
                &vec![0x2a; MAX_OID_CONTENT_BYTES + 1],
                TAG_UTF8_STRING,
                b"x",
            )])]),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(extract_spki_der(&oversized_oid), DerErrorClass::ValueLimit);

        let input = [TAG_NULL, 0];
        let mut parser = Parser::new(&input).expect("nonempty parser");
        let mut too_deep = Cursor::new(0, input.len(), MAX_TLV_DEPTH + 1);
        expect_error(parser.read_tlv(&mut too_deep), DerErrorClass::DepthLimit);

        let mut nodes = Vec::with_capacity((MAX_TLV_NODES + 1) * 2);
        for _ in 0..=MAX_TLV_NODES {
            nodes.extend_from_slice(&[TAG_NULL, 0]);
        }
        let mut parser = Parser::new(&nodes).expect("bounded node corpus");
        let mut cursor = Cursor::new(0, nodes.len(), 1);
        for _ in 0..MAX_TLV_NODES {
            parser.read_tlv(&mut cursor).expect("within node budget");
        }
        expect_error(parser.read_tlv(&mut cursor), DerErrorClass::NodeLimit);
    }

    #[test]
    fn deterministic_mutations_repeat_the_same_bounded_result() {
        let certificate = default_certificate(Some(vec![
            extension(
                OID_EXTENDED_KEY_USAGE,
                None,
                &sequence(vec![oid(OID_SERVER_AUTH)]),
            ),
            extension(OID_KEY_USAGE, None, &tlv(TAG_BIT_STRING, &[7, 0x80])),
            extension(
                OID_SUBJECT_ALT_NAME,
                None,
                &sequence(vec![tlv(0x82, b"example.com")]),
            ),
        ]));

        for index in 0..certificate.len() {
            let mut mutated = certificate.clone();
            mutated[index] ^= 1;
            assert_eq!(
                extract_spki_der(&mutated),
                extract_spki_der(&mutated),
                "SPKI mutation index {index}"
            );
            assert_eq!(
                inspect_basic_constraints_ca(&mutated),
                inspect_basic_constraints_ca(&mutated),
                "root mutation index {index}"
            );
            assert_eq!(
                inspect_server_chain_metadata(&mutated),
                inspect_server_chain_metadata(&mutated),
                "preflight mutation index {index}"
            );
            assert_eq!(
                inspect_pinned_leaf_shape(&mutated),
                inspect_pinned_leaf_shape(&mutated),
                "pin mutation index {index}"
            );
        }
    }
}
