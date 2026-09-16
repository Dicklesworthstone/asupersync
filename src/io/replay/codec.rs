//! Explicit persistence for sensitive completed-I/O transcripts.

use super::{Event, IoCaptureLimits, IoFailure, IoTape};
use sha2::{Digest, Sha256};
use std::{fmt, io};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPIO\0\0";
const VERSION: u32 = 1;
const FIXED_HEADER: usize = 46;
const CHECKSUM: usize = 32;
const DOMAIN: &[u8] = b"asupersync.io-tape.v1";

// Stable explicit wire IDs, independent of Rust enum discriminants. Unknown
// future/nightly-only kinds fail export instead of silently becoming Other.
const KINDS: &[io::ErrorKind] = &[
    io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied,
    io::ErrorKind::ConnectionRefused, io::ErrorKind::ConnectionReset,
    io::ErrorKind::ConnectionAborted, io::ErrorKind::NotConnected,
    io::ErrorKind::AddrInUse, io::ErrorKind::AddrNotAvailable,
    io::ErrorKind::BrokenPipe, io::ErrorKind::AlreadyExists,
    io::ErrorKind::WouldBlock, io::ErrorKind::InvalidInput,
    io::ErrorKind::InvalidData, io::ErrorKind::TimedOut,
    io::ErrorKind::WriteZero, io::ErrorKind::Interrupted,
    io::ErrorKind::Unsupported, io::ErrorKind::UnexpectedEof,
    io::ErrorKind::OutOfMemory, io::ErrorKind::Other,
    io::ErrorKind::HostUnreachable, io::ErrorKind::NetworkUnreachable,
    io::ErrorKind::NetworkDown, io::ErrorKind::NotADirectory,
    io::ErrorKind::IsADirectory, io::ErrorKind::DirectoryNotEmpty,
    io::ErrorKind::ReadOnlyFilesystem, io::ErrorKind::StaleNetworkFileHandle,
    io::ErrorKind::StorageFull, io::ErrorKind::NotSeekable,
    io::ErrorKind::QuotaExceeded, io::ErrorKind::FileTooLarge,
    io::ErrorKind::ResourceBusy, io::ErrorKind::ExecutableFileBusy,
    io::ErrorKind::Deadlock, io::ErrorKind::CrossesDevices,
    io::ErrorKind::TooManyLinks, io::ErrorKind::ArgumentListTooLong,
];

/// Bounds checked before allocating decoded event/payload storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoTapeDecodeLimits {
    /// Entire admitted encoding, including checksum.
    pub max_encoded_bytes: usize,
    /// Maximum admitted event, read, write, and per-vector counts.
    pub capture: IoCaptureLimits,
    /// Logical event storage plus payload and slice-length storage; allocator
    /// overhead and the caller's encoded input buffer are separate.
    pub max_decoded_bytes: usize,
}

impl IoTapeDecodeLimits {
    /// Set all admission limits explicitly.
    #[must_use]
    pub const fn new(encoded: usize, capture: IoCaptureLimits, decoded: usize) -> Self {
        Self { max_encoded_bytes: encoded, capture, max_decoded_bytes: decoded }
    }
}

/// Redacted tape validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IoTapeError {
    /// Missing bytes or inconsistent framing.
    #[error("I/O tape is truncated")]
    Truncated,
    /// Unknown magic/version/flags or unsupported OS-name encoding.
    #[error("unsupported I/O tape format")]
    Format,
    /// The checksum did not match the complete body.
    #[error("I/O tape checksum mismatch")]
    Checksum,
    /// A caller-selected resource ceiling was exceeded.
    #[error("I/O tape exceeds its {0} limit")]
    Limit(&'static str),
    /// Counts, tags or progress were inconsistent.
    #[error("invalid I/O tape structure: {0}")]
    Invalid(&'static str),
    /// The source OS or current native error mapping differs.
    #[error("native I/O error cannot be replayed on this platform")]
    PlatformMismatch,
    /// This kind has no V1 wire ID; the in-memory tape is still usable.
    #[error("I/O error kind is not supported by tape version 1")]
    UnsupportedErrorKind,
    /// A size overflowed this target's address space.
    #[error("I/O tape size overflow")]
    Overflow,
    /// Bounded allocation failed.
    #[error("I/O tape allocation failed")]
    Allocation,
}

/// Owned sensitive plaintext encoding.
///
/// Drop zeroizes this buffer, not copies or files made by a caller. Protect
/// exports with caller-owned encryption and access controls; a checksum is
/// neither encryption nor authentication.
pub struct IoTapeBytes(Vec<u8>);

impl fmt::Debug for IoTapeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoTapeBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for IoTapeBytes { fn as_ref(&self) -> &[u8] { &self.0 } }
impl Drop for IoTapeBytes { fn drop(&mut self) { self.0.zeroize(); } }

fn add(a: usize, b: usize) -> Result<usize, IoTapeError> { a.checked_add(b).ok_or(IoTapeError::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize, IoTapeError> { a.checked_mul(b).ok_or(IoTapeError::Overflow) }
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), IoTapeError> {
    out.extend_from_slice(&u64::try_from(value).map_err(|_| IoTapeError::Overflow)?.to_le_bytes());
    Ok(())
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); hash.finalize().into()
}
fn error_len(error: Option<IoFailure>) -> usize {
    match error { None => 1, Some(IoFailure { raw: None, .. }) => 2, Some(_) => 6 }
}
fn put_error(out: &mut Vec<u8>, error: Option<IoFailure>) -> Result<(), IoTapeError> {
    let Some(error) = error else { out.push(0); return Ok(()); };
    let kind = KINDS.iter().position(|kind| *kind == error.kind).ok_or(IoTapeError::UnsupportedErrorKind)?;
    out.push(if error.raw.is_some() { 2 } else { 1 });
    out.push(u8::try_from(kind).map_err(|_| IoTapeError::Overflow)?);
    if let Some(raw) = error.raw { out.extend_from_slice(&raw.to_le_bytes()); }
    Ok(())
}

impl IoTape {
    /// Export under an explicit encoded-byte limit, without consuming the tape.
    ///
    /// V1 uses little-endian fixed integers, a source OS tag, exact operation and
    /// vector shapes, normalized error kinds/native codes, and a domain-separated
    /// checksum. Unsupported error kinds refuse export rather than lose meaning.
    /// Nothing is written to disk automatically; these bytes can contain secrets.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<IoTapeBytes, IoTapeError> {
        let os = std::env::consts::OS.as_bytes();
        if os.is_empty() || os.len() > 64 { return Err(IoTapeError::Format); }
        let mut size = add(add(FIXED_HEADER, os.len())?, CHECKSUM)?;
        let mut slices_total = 0;
        for event in &self.events {
            size = add(size, 1)?;
            size = add(size, match event {
                Event::Read { bytes, error, .. } => add(add(16, bytes.len())?, error_len(*error))?,
                Event::Write { slices, error, .. } => {
                    let n = slices.as_ref().map_or(0, Vec::len);
                    slices_total = add(slices_total, n)?;
                    add(add(48, if slices.is_some() { add(8, mul(n, 8)?)? } else { 0 })?, error_len(*error))?
                }
                Event::Flush(error) | Event::Shutdown(error) => error_len(*error),
            })?;
        }
        if size > max_encoded_bytes { return Err(IoTapeError::Limit("encoded bytes")); }
        let mut out = IoTapeBytes(Vec::new());
        out.0.try_reserve_exact(size).map_err(|_| IoTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC); out.0.extend_from_slice(&VERSION.to_le_bytes());
        out.0.push(u8::from(self.vectored));
        put(&mut out.0, self.events.len())?; put(&mut out.0, self.read_bytes)?;
        put(&mut out.0, self.write_bytes)?; put(&mut out.0, slices_total)?;
        out.0.push(u8::try_from(os.len()).map_err(|_| IoTapeError::Overflow)?);
        out.0.extend_from_slice(os);
        for event in &self.events {
            match event {
                Event::Read { capacity, bytes, error } => {
                    out.0.push(0); put(&mut out.0, *capacity)?; put(&mut out.0, bytes.len())?;
                    out.0.extend_from_slice(bytes); put_error(&mut out.0, *error)?;
                }
                Event::Write { length, slices, digest, accepted, error } => {
                    out.0.push(if slices.is_some() { 2 } else { 1 });
                    put(&mut out.0, *length)?; put(&mut out.0, *accepted)?;
                    out.0.extend_from_slice(digest);
                    if let Some(slices) = slices {
                        put(&mut out.0, slices.len())?;
                        for length in slices { put(&mut out.0, *length)?; }
                    }
                    put_error(&mut out.0, *error)?;
                }
                Event::Flush(error) => { out.0.push(3); put_error(&mut out.0, *error)?; }
                Event::Shutdown(error) => { out.0.push(4); put_error(&mut out.0, *error)?; }
            }
        }
        let digest = checksum(&out.0); out.0.extend_from_slice(&digest);
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }

    /// Validate a complete encoding before exposing a replayable transcript.
    ///
    /// Resource limits and checksum precede allocations. Read progress, accepted
    /// write lengths, exact vector sums, aggregate counts, errors, flags and EOF
    /// are checked. V1 is deliberately OS-bound; native codes additionally
    /// require the same error-kind mapping. No platform translation or
    /// unknown-kind substitution is performed.
    pub fn from_canonical_bytes(bytes: &[u8], limits: IoTapeDecodeLimits) -> Result<Self, IoTapeError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(IoTapeError::Limit("encoded bytes")); }
        if bytes.len() < FIXED_HEADER + CHECKSUM { return Err(IoTapeError::Truncated); }
        let body_len = bytes.len() - CHECKSUM;
        let mut input = Input { bytes: &bytes[..body_len], offset: 0 };
        if input.take(8)? != MAGIC || input.u32()? != VERSION { return Err(IoTapeError::Format); }
        let vectored = match input.byte()? { 0 => false, 1 => true, _ => return Err(IoTapeError::Format) };
        let operations = input.size()?; let read_bytes = input.size()?;
        let write_bytes = input.size()?; let slices_total = input.size()?;
        let os_len = usize::from(input.byte()?);
        if os_len == 0 || os_len > 64 { return Err(IoTapeError::Format); }
        let os = input.take(os_len)?;
        if !os.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_') { return Err(IoTapeError::Format); }
        let same_os = os == std::env::consts::OS.as_bytes();
        if !same_os { return Err(IoTapeError::PlatformMismatch); }
        if operations > limits.capture.max_operations { return Err(IoTapeError::Limit("operations")); }
        if read_bytes > limits.capture.max_read_bytes { return Err(IoTapeError::Limit("read bytes")); }
        if write_bytes > limits.capture.max_write_bytes { return Err(IoTapeError::Limit("write bytes")); }
        let minimum = add(input.offset, add(mul(operations, 2)?, add(read_bytes, mul(slices_total, 8)?)?)?)?;
        if minimum > body_len { return Err(IoTapeError::Truncated); }
        let decoded = add(mul(operations, std::mem::size_of::<Event>())?,
            add(read_bytes, mul(slices_total, std::mem::size_of::<usize>())?)?)?;
        if decoded > limits.max_decoded_bytes { return Err(IoTapeError::Limit("decoded bytes")); }
        if checksum(&bytes[..body_len])[..] != bytes[body_len..] { return Err(IoTapeError::Checksum); }
        let mut events = Vec::new();
        events.try_reserve_exact(operations).map_err(|_| IoTapeError::Allocation)?;
        let (mut seen_read, mut seen_write, mut seen_slices) = (0, 0, 0);
        for _ in 0..operations {
            let event = match input.byte()? {
                0 => {
                    let capacity = input.size()?; let count = input.size()?;
                    if count > capacity || count > read_bytes - seen_read { return Err(IoTapeError::Invalid("read count")); }
                    let data = input.take(count)?;
                    let error = input.error(same_os)?;
                    let mut retained = Vec::new();
                    retained.try_reserve_exact(count).map_err(|_| IoTapeError::Allocation)?;
                    retained.extend_from_slice(data); seen_read += count;
                    Event::Read { capacity, bytes: retained, error }
                }
                tag @ (1 | 2) => {
                    let length = input.size()?; let accepted = input.size()?;
                    if accepted > length || length > write_bytes - seen_write { return Err(IoTapeError::Invalid("write count")); }
                    let digest = input.take(32)?.try_into().map_err(|_| IoTapeError::Truncated)?;
                    let slices = if tag == 2 {
                        let count = input.size()?;
                        if count > limits.capture.max_vectored_slices { return Err(IoTapeError::Limit("vectored slices")); }
                        if count > slices_total - seen_slices { return Err(IoTapeError::Invalid("slice count")); }
                        let mut lengths = Vec::new();
                        lengths.try_reserve_exact(count).map_err(|_| IoTapeError::Allocation)?;
                        let mut total = 0;
                        for _ in 0..count {
                            let length = input.size()?; total = add(total, length)?; lengths.push(length);
                        }
                        if total != length { return Err(IoTapeError::Invalid("vector sum")); }
                        seen_slices += count; Some(lengths)
                    } else { None };
                    let error = input.error(same_os)?;
                    if error.is_some() && accepted != 0 { return Err(IoTapeError::Invalid("error with accepted write")); }
                    seen_write += length;
                    Event::Write { length, slices, digest, accepted, error }
                }
                3 => Event::Flush(input.error(same_os)?),
                4 => Event::Shutdown(input.error(same_os)?),
                _ => return Err(IoTapeError::Invalid("event tag")),
            };
            events.push(event);
        }
        if (seen_read, seen_write, seen_slices) != (read_bytes, write_bytes, slices_total) {
            return Err(IoTapeError::Invalid("aggregate counts"));
        }
        if input.offset != body_len { return Err(IoTapeError::Invalid("trailing bytes")); }
        Ok(Self { events, read_bytes, write_bytes, vectored })
    }
}

struct Input<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], IoTapeError> {
        let end = add(self.offset, count)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(IoTapeError::Truncated)?;
        self.offset = end; Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, IoTapeError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, IoTapeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| IoTapeError::Truncated)?))
    }
    fn size(&mut self) -> Result<usize, IoTapeError> {
        let n = u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| IoTapeError::Truncated)?);
        usize::try_from(n).map_err(|_| IoTapeError::Overflow)
    }
    fn error(&mut self, same_os: bool) -> Result<Option<IoFailure>, IoTapeError> {
        let tag = self.byte()?;
        if tag == 0 { return Ok(None); }
        if tag > 2 { return Err(IoTapeError::Invalid("error tag")); }
        let kind = *KINDS.get(usize::from(self.byte()?)).ok_or(IoTapeError::UnsupportedErrorKind)?;
        let raw = if tag == 2 {
            let raw = i32::from_le_bytes(self.take(4)?.try_into().map_err(|_| IoTapeError::Truncated)?);
            if !same_os || io::Error::from_raw_os_error(raw).kind() != kind { return Err(IoTapeError::PlatformMismatch); }
            Some(raw)
        } else { None };
        Ok(Some(IoFailure { kind, raw }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tape() -> IoTape {
        IoTape { events: vec![Event::Read { capacity: 5, bytes: b"secret"[..4].to_vec(), error: None },
            Event::Write { length: 3, slices: Some(vec![1, 0, 2]), digest: [42; 32], accepted: 2, error: None },
            Event::Flush(Some(IoFailure { kind: io::ErrorKind::InvalidInput, raw: None })),
            Event::Shutdown(None)], read_bytes: 4, write_bytes: 3, vectored: true }
    }
    fn limits() -> IoTapeDecodeLimits { IoTapeDecodeLimits::new(4096, IoCaptureLimits::new(32, 1024, 1024, 16), 8192) }
    fn seal(bytes: &mut [u8]) {
        let body = bytes.len() - CHECKSUM; let hash = checksum(&bytes[..body]); bytes[body..].copy_from_slice(&hash);
    }

    #[test]
    fn canonical_io_tape_roundtrips_every_event_and_redacts_debug() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let decoded = IoTape::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
        assert_eq!((decoded.operations(), decoded.read_bytes(), decoded.write_bytes()), (4, 4, 3));
        assert_eq!(decoded.to_canonical_bytes(4096).unwrap().as_ref(), encoded.as_ref());
        assert!(!format!("{decoded:?} {encoded:?}").contains("secr"));
        assert!(matches!(tape().to_canonical_bytes(1), Err(IoTapeError::Limit("encoded bytes"))));
    }

    #[test]
    fn every_truncation_and_single_byte_mutation_is_rejected() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        for end in 0..encoded.as_ref().len() {
            assert!(IoTape::from_canonical_bytes(&encoded.as_ref()[..end], limits()).is_err());
        }
        for index in 0..encoded.as_ref().len() {
            let mut changed = encoded.as_ref().to_vec(); changed[index] ^= 1;
            assert!(IoTape::from_canonical_bytes(&changed, limits()).is_err(), "offset={index}");
        }
    }

    #[test]
    fn recomputed_checksum_does_not_admit_invalid_progress_or_extra_data() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let start = FIXED_HEADER + std::env::consts::OS.len();
        let mut changed = encoded.as_ref().to_vec();
        changed[start + 1..start + 9].copy_from_slice(&1u64.to_le_bytes()); // capacity < returned bytes
        seal(&mut changed);
        assert!(matches!(IoTape::from_canonical_bytes(&changed, limits()), Err(IoTapeError::Invalid("read count"))));
        let mut extra = encoded.as_ref()[..encoded.as_ref().len() - CHECKSUM].to_vec();
        extra.push(0); extra.extend_from_slice(&[0; CHECKSUM]); seal(&mut extra);
        assert!(matches!(IoTape::from_canonical_bytes(&extra, limits()), Err(IoTapeError::Invalid("trailing bytes"))));
    }

    #[test]
    fn logical_storage_and_declared_event_limits_are_enforced() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let mut bounded = limits(); bounded.capture.max_operations = 3;
        assert!(matches!(IoTape::from_canonical_bytes(encoded.as_ref(), bounded), Err(IoTapeError::Limit("operations"))));
        let mut bounded = limits(); bounded.max_decoded_bytes = 1;
        assert!(matches!(IoTape::from_canonical_bytes(encoded.as_ref(), bounded), Err(IoTapeError::Limit("decoded bytes"))));
        let mut bounded = limits(); bounded.capture.max_vectored_slices = 2;
        assert!(matches!(IoTape::from_canonical_bytes(encoded.as_ref(), bounded), Err(IoTapeError::Limit("vectored slices"))));
    }

    #[test]
    fn native_errors_cannot_be_reinterpreted_under_a_different_os_tag() {
        // File-not-found on both POSIX and Windows. EINVAL's POSIX value (22)
        // is not a portable Windows error and may map to an unexportable kind.
        let error = io::Error::from_raw_os_error(2);
        let tape = IoTape { events: vec![Event::Flush(Some(IoFailure::capture(&error)))], read_bytes: 0, write_bytes: 0, vectored: false };
        let encoded = tape.to_canonical_bytes(4096).unwrap();
        let decoded = IoTape::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
        assert_eq!(decoded.to_canonical_bytes(4096).unwrap().as_ref(), encoded.as_ref());
        let mut changed = encoded.as_ref().to_vec(); changed[FIXED_HEADER] = if changed[FIXED_HEADER] == b'x' { b'y' } else { b'x' }; seal(&mut changed);
        assert!(matches!(IoTape::from_canonical_bytes(&changed, limits()), Err(IoTapeError::PlatformMismatch)));
    }
}
