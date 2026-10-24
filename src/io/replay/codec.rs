//! Explicit persistence for sensitive completed- and pending-I/O transcripts.

use super::{Event, IoCaptureLimits, IoFailure, IoTape, PendingRequest};
use sha2::{Digest, Sha256};
use std::{fmt, io};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPIO\0\0";
const VERSION: u32 = 1;
const PENDING_VERSION: u32 = 2;
const FIXED_HEADER: usize = 46;
const CHECKSUM: usize = 32;
const DOMAIN: &[u8] = b"asupersync.io-tape.v1";
const PENDING_DOMAIN: &[u8] = b"asupersync.io-tape.v2";

// Stable explicit wire IDs, independent of Rust enum discriminants. Unknown
// future/nightly-only kinds fail export instead of silently becoming Other.
const KINDS: &[io::ErrorKind] = &[
    io::ErrorKind::NotFound,
    io::ErrorKind::PermissionDenied,
    io::ErrorKind::ConnectionRefused,
    io::ErrorKind::ConnectionReset,
    io::ErrorKind::ConnectionAborted,
    io::ErrorKind::NotConnected,
    io::ErrorKind::AddrInUse,
    io::ErrorKind::AddrNotAvailable,
    io::ErrorKind::BrokenPipe,
    io::ErrorKind::AlreadyExists,
    io::ErrorKind::WouldBlock,
    io::ErrorKind::InvalidInput,
    io::ErrorKind::InvalidData,
    io::ErrorKind::TimedOut,
    io::ErrorKind::WriteZero,
    io::ErrorKind::Interrupted,
    io::ErrorKind::Unsupported,
    io::ErrorKind::UnexpectedEof,
    io::ErrorKind::OutOfMemory,
    io::ErrorKind::Other,
    io::ErrorKind::HostUnreachable,
    io::ErrorKind::NetworkUnreachable,
    io::ErrorKind::NetworkDown,
    io::ErrorKind::NotADirectory,
    io::ErrorKind::IsADirectory,
    io::ErrorKind::DirectoryNotEmpty,
    io::ErrorKind::ReadOnlyFilesystem,
    io::ErrorKind::StaleNetworkFileHandle,
    io::ErrorKind::StorageFull,
    io::ErrorKind::NotSeekable,
    io::ErrorKind::QuotaExceeded,
    io::ErrorKind::FileTooLarge,
    io::ErrorKind::ResourceBusy,
    io::ErrorKind::ExecutableFileBusy,
    io::ErrorKind::Deadlock,
    io::ErrorKind::CrossesDevices,
    io::ErrorKind::TooManyLinks,
    io::ErrorKind::ArgumentListTooLong,
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
        Self {
            max_encoded_bytes: encoded,
            capture,
            max_decoded_bytes: decoded,
        }
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
        f.debug_struct("IoTapeBytes")
            .field("encoded_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for IoTapeBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for IoTapeBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn add(a: usize, b: usize) -> Result<usize, IoTapeError> {
    a.checked_add(b).ok_or(IoTapeError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, IoTapeError> {
    a.checked_mul(b).ok_or(IoTapeError::Overflow)
}
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), IoTapeError> {
    out.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| IoTapeError::Overflow)?
            .to_le_bytes(),
    );
    Ok(())
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
fn version_checksum(version: u32, bytes: &[u8]) -> [u8; 32] {
    if version == VERSION {
        return checksum(bytes);
    }
    let mut hash = Sha256::new();
    hash.update(PENDING_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
fn error_len(error: Option<IoFailure>) -> usize {
    match error {
        None => 1,
        Some(IoFailure { raw: None, .. }) => 2,
        Some(_) => 6,
    }
}
fn put_error(out: &mut Vec<u8>, error: Option<IoFailure>) -> Result<(), IoTapeError> {
    let Some(error) = error else {
        out.push(0);
        return Ok(());
    };
    let kind = KINDS
        .iter()
        .position(|kind| *kind == error.kind)
        .ok_or(IoTapeError::UnsupportedErrorKind)?;
    out.push(if error.raw.is_some() { 2 } else { 1 });
    out.push(u8::try_from(kind).map_err(|_| IoTapeError::Overflow)?);
    if let Some(raw) = error.raw {
        out.extend_from_slice(&raw.to_le_bytes());
    }
    Ok(())
}

impl IoTape {
    /// Export under an explicit encoded-byte limit, without consuming the tape.
    ///
    /// V1 uses little-endian fixed integers, a source OS tag, exact operation and
    /// vector shapes, normalized error kinds/native codes, and a domain-separated
    /// checksum. Unsupported error kinds refuse export rather than lose meaning.
    /// Pending-aware captures select V2, which adds exact pending request tags
    /// and a separate checksum domain. Completed-only captures retain V1 bytes.
    /// Nothing is written to disk automatically; these bytes can contain secrets.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<IoTapeBytes, IoTapeError> {
        let os = std::env::consts::OS.as_bytes();
        if os.is_empty() || os.len() > 64 {
            return Err(IoTapeError::Format);
        }
        let mut size = add(add(FIXED_HEADER, os.len())?, CHECKSUM)?;
        let mut slices_total = 0;
        for event in &self.events {
            size = add(size, 1)?;
            size = add(
                size,
                match event {
                    Event::Read { bytes, error, .. } => {
                        add(add(16, bytes.len())?, error_len(*error))?
                    }
                    Event::Write { slices, error, .. } => {
                        let n = slices.as_ref().map_or(0, Vec::len);
                        slices_total = add(slices_total, n)?;
                        add(
                            add(
                                48,
                                if slices.is_some() {
                                    add(8, mul(n, 8)?)?
                                } else {
                                    0
                                },
                            )?,
                            error_len(*error),
                        )?
                    }
                    Event::Flush(error) | Event::Shutdown(error) => error_len(*error),
                    Event::Pending(request) => match request {
                        PendingRequest::Read { .. } => 8,
                        PendingRequest::Write { slices, .. } => {
                            let n = slices.as_ref().map_or(0, Vec::len);
                            slices_total = add(slices_total, n)?;
                            add(40, if slices.is_some() { add(8, mul(n, 8)?)? } else { 0 })?
                        }
                        PendingRequest::Flush | PendingRequest::Shutdown => 0,
                    },
                },
            )?;
        }
        if size > max_encoded_bytes {
            return Err(IoTapeError::Limit("encoded bytes"));
        }
        let mut out = IoTapeBytes(Vec::new());
        out.0
            .try_reserve_exact(size)
            .map_err(|_| IoTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC);
        let version = if self.pending_polls { PENDING_VERSION } else { VERSION };
        out.0.extend_from_slice(&version.to_le_bytes());
        out.0.push(u8::from(self.vectored));
        put(&mut out.0, self.events.len())?;
        put(&mut out.0, self.read_bytes)?;
        put(&mut out.0, self.write_bytes)?;
        put(&mut out.0, slices_total)?;
        out.0
            .push(u8::try_from(os.len()).map_err(|_| IoTapeError::Overflow)?);
        out.0.extend_from_slice(os);
        for event in &self.events {
            match event {
                Event::Read {
                    capacity,
                    bytes,
                    error,
                } => {
                    out.0.push(0);
                    put(&mut out.0, *capacity)?;
                    put(&mut out.0, bytes.len())?;
                    out.0.extend_from_slice(bytes);
                    put_error(&mut out.0, *error)?;
                }
                Event::Write {
                    length,
                    slices,
                    digest,
                    accepted,
                    error,
                } => {
                    out.0.push(if slices.is_some() { 2 } else { 1 });
                    put(&mut out.0, *length)?;
                    put(&mut out.0, *accepted)?;
                    out.0.extend_from_slice(&digest[..]);
                    if let Some(slices) = slices {
                        put(&mut out.0, slices.len())?;
                        for length in slices {
                            put(&mut out.0, *length)?;
                        }
                    }
                    put_error(&mut out.0, *error)?;
                }
                Event::Flush(error) => {
                    out.0.push(3);
                    put_error(&mut out.0, *error)?;
                }
                Event::Shutdown(error) => {
                    out.0.push(4);
                    put_error(&mut out.0, *error)?;
                }
                Event::Pending(PendingRequest::Read { capacity }) => {
                    out.0.push(5);
                    put(&mut out.0, *capacity)?;
                }
                Event::Pending(PendingRequest::Write { length, slices, digest }) => {
                    out.0.push(if slices.is_some() { 7 } else { 6 });
                    put(&mut out.0, *length)?;
                    out.0.extend_from_slice(&digest[..]);
                    if let Some(slices) = slices {
                        put(&mut out.0, slices.len())?;
                        for length in slices {
                            put(&mut out.0, *length)?;
                        }
                    }
                }
                Event::Pending(PendingRequest::Flush) => out.0.push(8),
                Event::Pending(PendingRequest::Shutdown) => out.0.push(9),
            }
        }
        let digest = version_checksum(version, &out.0);
        out.0.extend_from_slice(&digest);
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }

    /// Validate a complete encoding before exposing a replayable transcript.
    ///
    /// Resource limits and checksum precede allocations. Read progress, accepted
    /// write lengths, exact vector sums, aggregate counts, errors, flags and EOF
    /// are checked. V1 and V2 are deliberately OS-bound; native codes additionally
    /// require the same error-kind mapping. No platform translation or
    /// unknown-kind substitution is performed.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: IoTapeDecodeLimits,
    ) -> Result<Self, IoTapeError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(IoTapeError::Limit("encoded bytes"));
        }
        if bytes.len() < FIXED_HEADER + CHECKSUM {
            return Err(IoTapeError::Truncated);
        }
        let body_len = bytes.len() - CHECKSUM;
        let mut input = Input {
            bytes: &bytes[..body_len],
            offset: 0,
        };
        if input.take(8)? != MAGIC {
            return Err(IoTapeError::Format);
        }
        let version = input.u32()?;
        let pending_polls = match version {
            VERSION => false,
            PENDING_VERSION => true,
            _ => return Err(IoTapeError::Format),
        };
        let vectored = match input.byte()? {
            0 => false,
            1 => true,
            _ => return Err(IoTapeError::Format),
        };
        let operations = input.size()?;
        let read_bytes = input.size()?;
        let write_bytes = input.size()?;
        let slices_total = input.size()?;
        let os_len = usize::from(input.byte()?);
        if os_len == 0 || os_len > 64 {
            return Err(IoTapeError::Format);
        }
        let os = input.take(os_len)?;
        if !os
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(IoTapeError::Format);
        }
        let same_os = os == std::env::consts::OS.as_bytes();
        if !same_os {
            return Err(IoTapeError::PlatformMismatch);
        }
        if operations > limits.capture.max_operations {
            return Err(IoTapeError::Limit("operations"));
        }
        if read_bytes > limits.capture.max_read_bytes {
            return Err(IoTapeError::Limit("read bytes"));
        }
        if write_bytes > limits.capture.max_write_bytes {
            return Err(IoTapeError::Limit("write bytes"));
        }
        let minimum = add(
            input.offset,
            add(
                mul(operations, if pending_polls { 1 } else { 2 })?,
                add(read_bytes, mul(slices_total, 8)?)?,
            )?,
        )?;
        if minimum > body_len {
            return Err(IoTapeError::Truncated);
        }
        let decoded = add(
            mul(operations, std::mem::size_of::<Event>())?,
            add(read_bytes, mul(slices_total, std::mem::size_of::<usize>())?)?,
        )?;
        if decoded > limits.max_decoded_bytes {
            return Err(IoTapeError::Limit("decoded bytes"));
        }
        if version_checksum(version, &bytes[..body_len])[..] != bytes[body_len..] {
            return Err(IoTapeError::Checksum);
        }
        let mut events = Vec::new();
        events
            .try_reserve_exact(operations)
            .map_err(|_| IoTapeError::Allocation)?;
        let (mut seen_read, mut seen_write, mut seen_slices) = (0, 0, 0);
        for _ in 0..operations {
            let event = match input.byte()? {
                0 => {
                    let capacity = input.size()?;
                    let count = input.size()?;
                    if count > capacity || count > read_bytes - seen_read {
                        return Err(IoTapeError::Invalid("read count"));
                    }
                    let data = input.take(count)?;
                    let error = input.error(same_os)?;
                    let mut retained = Vec::new();
                    retained
                        .try_reserve_exact(count)
                        .map_err(|_| IoTapeError::Allocation)?;
                    retained.extend_from_slice(data);
                    seen_read += count;
                    Event::Read {
                        capacity,
                        bytes: retained,
                        error,
                    }
                }
                tag @ (1 | 2 | 6 | 7) if tag <= 2 || pending_polls => {
                    let pending = tag >= 6;
                    let length = input.size()?;
                    let accepted = if pending { 0 } else { input.size()? };
                    if accepted > length || length > write_bytes - seen_write {
                        return Err(IoTapeError::Invalid("write count"));
                    }
                    let raw_digest: [u8; 32] = input
                        .take(32)?
                        .try_into()
                        .map_err(|_| IoTapeError::Truncated)?;
                    let digest = zeroize::Zeroizing::new(raw_digest);
                    let slices = if tag == 2 || tag == 7 {
                        let count = input.size()?;
                        if count > limits.capture.max_vectored_slices {
                            return Err(IoTapeError::Limit("vectored slices"));
                        }
                        if count > slices_total - seen_slices {
                            return Err(IoTapeError::Invalid("slice count"));
                        }
                        let mut lengths = Vec::new();
                        lengths
                            .try_reserve_exact(count)
                            .map_err(|_| IoTapeError::Allocation)?;
                        let mut total = 0;
                        for _ in 0..count {
                            let length = input.size()?;
                            total = add(total, length)?;
                            lengths.push(length);
                        }
                        if total != length {
                            return Err(IoTapeError::Invalid("vector sum"));
                        }
                        seen_slices += count;
                        Some(lengths)
                    } else {
                        None
                    };
                    let error = if pending { None } else { input.error(same_os)? };
                    if error.is_some() && accepted != 0 {
                        return Err(IoTapeError::Invalid("error with accepted write"));
                    }
                    seen_write += length;
                    if pending {
                        Event::Pending(PendingRequest::Write { length, slices, digest })
                    } else {
                        Event::Write {
                            length,
                            slices,
                            digest,
                            accepted,
                            error,
                        }
                    }
                }
                3 => Event::Flush(input.error(same_os)?),
                4 => Event::Shutdown(input.error(same_os)?),
                5 if pending_polls => Event::Pending(PendingRequest::Read {
                    capacity: input.size()?,
                }),
                8 if pending_polls => Event::Pending(PendingRequest::Flush),
                9 if pending_polls => Event::Pending(PendingRequest::Shutdown),
                _ => return Err(IoTapeError::Invalid("event tag")),
            };
            events.push(event);
        }
        if (seen_read, seen_write, seen_slices) != (read_bytes, write_bytes, slices_total) {
            return Err(IoTapeError::Invalid("aggregate counts"));
        }
        if input.offset != body_len {
            return Err(IoTapeError::Invalid("trailing bytes"));
        }
        Ok(Self {
            events,
            read_bytes,
            write_bytes,
            vectored,
            pending_polls,
        })
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], IoTapeError> {
        let end = add(self.offset, count)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(IoTapeError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, IoTapeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, IoTapeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| IoTapeError::Truncated)?,
        ))
    }
    fn size(&mut self) -> Result<usize, IoTapeError> {
        let n = u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| IoTapeError::Truncated)?,
        );
        usize::try_from(n).map_err(|_| IoTapeError::Overflow)
    }
    fn error(&mut self, same_os: bool) -> Result<Option<IoFailure>, IoTapeError> {
        let tag = self.byte()?;
        if tag == 0 {
            return Ok(None);
        }
        if tag > 2 {
            return Err(IoTapeError::Invalid("error tag"));
        }
        let kind = *KINDS
            .get(usize::from(self.byte()?))
            .ok_or(IoTapeError::UnsupportedErrorKind)?;
        let raw = if tag == 2 {
            let raw = i32::from_le_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| IoTapeError::Truncated)?,
            );
            if !same_os || io::Error::from_raw_os_error(raw).kind() != kind {
                return Err(IoTapeError::PlatformMismatch);
            }
            Some(raw)
        } else {
            None
        };
        Ok(Some(IoFailure { kind, raw }))
    }
}

#[cfg(test)]
#[path = "codec_inline_tests.rs"]
mod tests;
