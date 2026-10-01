//! The bounded, no-context-takeover RFC 7692 profile used by live connections.
//!
//! Negotiation is separate from the legacy generic handshake codec. Neither
//! an arbitrary extension string nor `validate_reserved_bits(false)` enables
//! decompression. Every message starts with a fresh 32 KiB DEFLATE dictionary.

use super::{Frame, HandshakeError, Opcode, WsError};
use crate::bytes::Bytes;

pub(super) const OFFER: &str = "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=15; client_max_window_bits=15";

#[derive(Default)]
struct Parameters {
    server_no_context: bool,
    client_no_context: bool,
    server_window: bool,
    client_window: bool,
}

fn mismatch(extensions: &[String]) -> HandshakeError {
    HandshakeError::ExtensionMismatch {
        requested: vec![OFFER.to_owned()],
        offered: extensions.to_vec(),
    }
}

fn parameters(value: &str, response: bool) -> Option<Parameters> {
    let mut fields = value.split(';').map(str::trim);
    if fields.next()? != "permessage-deflate" { return None; }
    let mut parsed = Parameters::default();
    for field in fields {
        let (name, value) = field.split_once('=').map_or((field, None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        });
        match name {
            "server_no_context_takeover" if value.is_none() && !parsed.server_no_context => parsed.server_no_context = true,
            "client_no_context_takeover" if value.is_none() && !parsed.client_no_context => parsed.client_no_context = true,
            "server_max_window_bits" if value.is_some_and(window_fifteen) && !parsed.server_window => parsed.server_window = true,
            "client_max_window_bits" if !parsed.client_window
                && (value.is_some_and(window_fifteen) || (!response && value.is_none())) => parsed.client_window = true,
            _ => return None,
        }
    }
    Some(parsed)
}

fn window_fifteen(value: &str) -> bool {
    let Some(quoted) = value.strip_prefix('"').and_then(|value| value.strip_suffix('"')) else {
        return value == "15";
    };
    let mut input = quoted.bytes();
    for expected in b"15" {
        let actual = match input.next() {
            Some(b'\\') => input.next(),
            other => other,
        };
        if actual != Some(*expected) { return false; }
    }
    input.next().is_none()
}

/// Normalize the selected offer before a live server publishes HTTP 101.
/// RFC 7692 permits both no-context-takeover parameters in the response even
/// when absent from the offer. Window parameters are emitted only if offered.
pub(crate) fn negotiate(extensions: &[String]) -> Result<Vec<String>, HandshakeError> {
    if extensions.is_empty() { return Ok(Vec::new()); }
    if !cfg!(feature = "compression") { return Err(mismatch(extensions)); }
    let mut selected = None;
    for extension in extensions {
        // Multiple permessage-deflate offers are alternatives, not a stack.
        // Unknown selected extensions have no live implementation.
        if extension.split(';').next().map(str::trim) != Some("permessage-deflate") {
            return Err(mismatch(extensions));
        }
        if let Some(parameters) = parameters(extension, false) {
            selected.get_or_insert(parameters);
        }
    }
    let Some(parameters) = selected else { return Err(mismatch(extensions)); };
    let mut value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover".to_owned();
    if parameters.server_window { value.push_str("; server_max_window_bits=15"); }
    if parameters.client_window { value.push_str("; client_max_window_bits=15"); }
    Ok(vec![value])
}

pub(super) fn negotiate_server(selected: &[String], offered: Option<&str>) -> Result<Vec<String>, HandshakeError> {
    if selected.iter().any(|value| value.split(';').next().map(str::trim) == Some("permessage-deflate")) {
        let mut alternatives: Vec<String> = offered.unwrap_or("").split(',')
            .map(str::trim).filter(|value| value.split(';').next().map(str::trim) == Some("permessage-deflate"))
            .map(str::to_owned).collect();
        alternatives.extend(selected.iter().filter(|value| value.split(';').next().map(str::trim) != Some("permessage-deflate")).cloned());
        negotiate(&alternatives)
    } else { negotiate(selected) }
}

/// Validate a completed negotiation; accepting takeover would require retaining
/// a dictionary, so an omitted mandatory no-takeover parameter fails closed.
pub(crate) fn negotiated(extensions: &[String]) -> Result<bool, HandshakeError> {
    negotiated_for_role(extensions, false)
}

pub(super) fn negotiated_client(extensions: &[String]) -> Result<bool, HandshakeError> {
    negotiated_for_role(extensions, true)
}

fn negotiated_for_role(extensions: &[String], client: bool) -> Result<bool, HandshakeError> {
    if extensions.is_empty() { return Ok(false); }
    if !cfg!(feature = "compression") || extensions.len() != 1 {
        return Err(mismatch(extensions));
    }
    match parameters(&extensions[0], true) {
        Some(parameters) if parameters.server_no_context && (client || parameters.client_no_context) => Ok(true),
        _ => Err(mismatch(extensions)),
    }
}

pub(super) fn outgoing(frame: Frame, enabled: bool, max_message: usize, max_encoded: usize) -> Result<Frame, WsError> {
    if !enabled || !matches!(frame.opcode, Opcode::Text | Opcode::Binary) { return Ok(frame); }
    if frame.payload.len() > max_message {
        return Err(WsError::PayloadTooLarge { size: frame.payload.len() as u64, max: max_message });
    }
    #[cfg(feature = "compression")]
    {
        let mut frame = frame;
        frame.payload = deflate(&frame.payload, max_encoded)?;
        frame.rsv1 = true;
        Ok(frame)
    }
    #[cfg(not(feature = "compression"))]
    {
        let _ = max_encoded;
        Err(WsError::ProtocolViolation("WebSocket compression feature is disabled"))
    }
}

pub(super) fn incoming(payload: Bytes, compressed: bool, max_message: usize) -> Result<Bytes, WsError> {
    if !compressed { return Ok(payload); }
    #[cfg(feature = "compression")]
    { inflate(&payload, max_message) }
    #[cfg(not(feature = "compression"))]
    {
        let _ = max_message;
        Err(WsError::ReservedBitsSet)
    }
}

#[cfg(feature = "compression")]
fn append_bounded(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), WsError> {
    let size = out.len().checked_add(bytes.len()).ok_or(WsError::PayloadTooLarge { size: u64::MAX, max })?;
    if size > max { return Err(WsError::PayloadTooLarge { size: size as u64, max }); }
    out.try_reserve(bytes.len()).map_err(|_| WsError::Io(std::io::Error::other("WebSocket compression allocation failed")))?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(feature = "compression")]
fn deflate(payload: &[u8], max: usize) -> Result<Bytes, WsError> {
    use flate2::{Compress, Compression, FlushCompress, Status};
    let mut encoder = Compress::new(Compression::fast(), false);
    let mut output = Vec::new();
    let mut offset = 0;
    loop {
        let mut chunk = [0; 4096];
        let before_in = encoder.total_in();
        let before_out = encoder.total_out();
        let status = encoder.compress(&payload[offset..], &mut chunk, FlushCompress::Sync)
            .map_err(|_| WsError::ProtocolViolation("WebSocket DEFLATE encoding failed"))?;
        let read = (encoder.total_in() - before_in) as usize;
        let written = (encoder.total_out() - before_out) as usize;
        offset += read;
        append_bounded(&mut output, &chunk[..written], max.saturating_add(4))?;
        if offset == payload.len() && written < chunk.len() {
            if !output.ends_with(&[0, 0, 255, 255]) { return Err(WsError::ProtocolViolation("WebSocket DEFLATE flush failed")); }
            output.truncate(output.len() - 4);
            return Ok(Bytes::from(output));
        }
        if status == Status::StreamEnd || (read == 0 && written == 0) {
            return Err(WsError::ProtocolViolation("WebSocket DEFLATE encoder made no progress"));
        }
    }
}

/// Largest DEFLATE back-reference distance (RFC 1951).
#[cfg(feature = "compression")]
const WINDOW: usize = 32 * 1024;

/// Decode one message and fail closed on references before its first byte.
///
/// No context takeover gives every message an empty window, so a reference
/// before the message start is invalid (RFC 7692 section 7.2.3.2). zlib
/// rejects it, but the pure-Rust backend reads its zeroed window instead.
/// Every section is therefore decoded over an explicit fill. With a 0x00 fill,
/// such a reference can only produce NUL bytes, so NUL-free output is proof
/// that none occurred. Otherwise the message is decoded again over a 0xFF fill,
/// and the two results differ exactly when a reference reached the fill.
///
/// Only the first `WINDOW` output bytes need either check. A reference reaches
/// at most `WINDOW` bytes back, so it can reach the fill only from an earlier
/// position. Every later byte is copied from message bytes, which both decodes
/// share once their first `WINDOW` bytes agree.
#[cfg(feature = "compression")]
fn inflate(payload: &[u8], max: usize) -> Result<Bytes, WsError> {
    let zero_filled = inflate_over(payload, max, 0x00, None)?;
    let head = &zero_filled[..zero_filled.len().min(WINDOW)];
    if !head.contains(&0) {
        return Ok(zero_filled);
    }
    // Compare the 0xFF-fill decode against the first one as it is produced,
    // instead of buffering a second copy, and stop after the head: a 64 MiB
    // message no longer pays a second 64 MiB decode (br-asupersync-ydis91).
    inflate_over(payload, max, 0xff, Some(head))?;
    Ok(zero_filled)
}

/// Decode `payload` over a `fill` window. With `reference`, output is compared
/// against it chunk by chunk and not retained, and decoding stops at the end
/// of `reference`; the result is then empty.
#[cfg(feature = "compression")]
fn inflate_over(
    payload: &[u8],
    max: usize,
    fill: u8,
    reference: Option<&[u8]>,
) -> Result<Bytes, WsError> {
    use flate2::{Decompress, FlushDecompress, Status};
    // Complete the removed sync-flush block, then append a final empty block.
    // Requiring StreamEnd at this exact boundary rejects truncated streams;
    // a successful partial flush alone does not prove a complete message.
    const SUFFIX: [u8; 9] = [0, 0, 255, 255, 1, 0, 0, 255, 255];
    let mut input = Vec::new();
    input.try_reserve_exact(payload.len().checked_add(SUFFIX.len()).ok_or(WsError::PayloadTooLarge { size: u64::MAX, max })?)
        .map_err(|_| WsError::Io(std::io::Error::other("WebSocket decompression allocation failed")))?;
    input.extend_from_slice(payload);
    input.extend_from_slice(&SUFFIX);
    let mut decoder = Decompress::new(false);
    prime_dictionary(&mut decoder, fill, &[])?;
    let references_before_message =
        || WsError::ProtocolViolation("WebSocket DEFLATE references data before the message");
    let mut output = Vec::new();
    // Decoded length so far. With a reference, the verified prefix
    // `reference[..produced]` stands in for `output`, which stays empty.
    let mut produced = 0usize;
    let mut offset = 0;
    let mut section_start = 0;
    let mut sections = 0;
    loop {
        let mut chunk = [0; 4096];
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder.decompress(&input[offset..], &mut chunk, FlushDecompress::None)
            .map_err(|_| WsError::ProtocolViolation("invalid WebSocket DEFLATE message"))?;
        let read = (decoder.total_in() - before_in) as usize;
        let written = (decoder.total_out() - before_out) as usize;
        offset += read;
        match reference {
            Some(reference) => {
                let end = produced.saturating_add(written).min(reference.len());
                let expected = reference
                    .get(produced..end)
                    .ok_or_else(references_before_message)?;
                if expected != &chunk[..end - produced] {
                    return Err(references_before_message());
                }
                if end == reference.len() {
                    return Ok(Bytes::new());
                }
            }
            None => append_bounded(&mut output, &chunk[..written], max)?,
        }
        produced += written;
        if status == Status::StreamEnd {
            sections += 1;
            // Includes the synthetic final section. This explicit resource cap
            // bounds window priming to about 8 MiB per decode.
            if sections > 256 { return Err(WsError::PayloadTooLarge { size: sections, max: 256 }); }
            if offset == section_start { return Err(WsError::ProtocolViolation("empty WebSocket DEFLATE progress")); }
            if offset == input.len() {
                if reference.is_some_and(|reference| reference.len() != produced) {
                    return Err(references_before_message());
                }
                return Ok(Bytes::from(output));
            }
            // RFC 7692 section 7.2.1 permits byte-aligned BFINAL sections in
            // one message. reset alone would lose that message's history.
            decoder.reset(false);
            let history = reference.map_or(output.as_slice(), |reference| &reference[..produced]);
            prime_dictionary(&mut decoder, fill, history)?;
            section_start = offset;
            continue;
        }
        if read == 0 && written == 0 {
            return Err(WsError::ProtocolViolation("truncated WebSocket DEFLATE message"));
        }
    }
}

#[cfg(feature = "compression")]
fn prime_dictionary(decoder: &mut flate2::Decompress, fill: u8, history: &[u8]) -> Result<(), WsError> {
    // The pure-Rust flate2 backend has no public set_dictionary. A non-final
    // stored block loads a full window through its normal validated path: the
    // message's last 32 KiB of history, preceded by `fill` where there is less.
    // Its output is discarded and never charged as application output.
    let history = &history[history.len().saturating_sub(WINDOW)..];
    let len = WINDOW as u16;
    let mut primer = Vec::with_capacity(WINDOW + 5);
    primer.push(0);
    primer.extend_from_slice(&len.to_le_bytes());
    primer.extend_from_slice(&(!len).to_le_bytes());
    primer.resize(5 + WINDOW - history.len(), fill);
    primer.extend_from_slice(history);
    let mut offset = 0;
    loop {
        let mut discard = [0; 4096];
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder.decompress(&primer[offset..], &mut discard, flate2::FlushDecompress::None)
            .map_err(|_| WsError::ProtocolViolation("WebSocket DEFLATE dictionary setup failed"))?;
        let read = (decoder.total_in() - before_in) as usize;
        let written = (decoder.total_out() - before_out) as usize;
        offset += read;
        if offset == primer.len() && decoder.total_out() == WINDOW as u64 { return Ok(()); }
        if status == flate2::Status::StreamEnd || (read == 0 && written == 0) {
            return Err(WsError::ProtocolViolation("WebSocket DEFLATE dictionary made no progress"));
        }
    }
}

#[cfg(all(test, feature = "compression"))]
mod tests {
    use super::*;

    #[test]
    fn permessage_deflate_negotiates_only_supported_parameters() {
        for offer in ["permessage-deflate", "permessage-deflate; client_max_window_bits", OFFER] {
            let selected = negotiate(&[offer.to_owned()]).unwrap();
            assert!(negotiated(&selected).unwrap());
        }
        for offer in ["permessage-deflate; server_max_window_bits=14", "permessage-deflate; client_max_window_bits=8",
            "permessage-deflate; server_no_context_takeover=1", "permessage-deflate; unknown", "x-unknown",
            "permessage-deflate; client_max_window_bits; client_max_window_bits=15"] {
            assert!(negotiate(&[offer.to_owned()]).is_err(), "{offer}");
        }
        assert!(negotiated(&["permessage-deflate".to_owned()]).is_err());
        assert!(negotiated(&["permessage-deflate; server_no_context_takeover".to_owned()]).is_err());
        assert!(negotiated(&[OFFER.to_owned(), OFFER.to_owned()]).is_err());
        assert!(!negotiated(&[]).unwrap());
        assert!(negotiated_client(&["permessage-deflate; server_no_context_takeover; server_max_window_bits=\"15\"".to_owned()]).unwrap());
        assert!(negotiate(&["permessage-deflate; client_max_window_bits=\"\\1\\5\"".to_owned()]).is_ok());
    }

    #[test]
    fn permessage_deflate_independent_rfc7692_vectors() {
        // RFC 7692 sections 7.2.3.1, .3, .4 and .5; these bytes are not
        // produced by the implementation's encoder.
        for payload in [
            &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00][..],
            &[0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00],
            &[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00],
            &[0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00],
        ] {
            assert_eq!(inflate(payload, 5).unwrap().as_ref(), b"Hello");
            assert!(matches!(inflate(payload, 4), Err(WsError::PayloadTooLarge { .. })));
        }
        assert!(inflate(&[0], 0).unwrap().is_empty());
        assert!(inflate(&[0xf2, 0x00, 0x11, 0x00, 0x00], 64).is_err(), "context-takeover references cannot cross message boundaries");
        assert!(inflate(&[0xff], 64).is_err());
        assert!(inflate(&[0xf2, 0x48], 64).is_err());
        assert!(inflate(&[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x42], 64).is_err());
        // Independently produced by Python zlib: first raw compressor finishes
        // "Hello" (Z_FINISH); a second raw compressor is initialized with
        // zdict=b"Hello", then emits "Hello" with Z_SYNC_FLUSH (tail removed).
        let cross_final = [0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0xf2, 0x00, 0x11, 0x00, 0x00];
        assert_eq!(inflate(&cross_final, 10).unwrap().as_ref(), b"HelloHello");
    }

    #[test]
    fn permessage_deflate_bounds_expansion_and_resets_every_message() {
        let empty = deflate(&[], 1).unwrap();
        assert_eq!(empty.as_ref(), &[0]);
        assert!(inflate(&empty, 0).unwrap().is_empty());
        assert!(matches!(deflate(&[], 0), Err(WsError::PayloadTooLarge { .. })));
        let input = vec![b'a'; 128 * 1024];
        let first = deflate(&input, input.len()).unwrap();
        let second = deflate(&input, input.len()).unwrap();
        assert_eq!(first, second);
        assert!(first.len() < 1024);
        assert_eq!(inflate(&first, input.len()).unwrap().as_ref(), input);
        assert!(matches!(inflate(&first, 1024), Err(WsError::PayloadTooLarge { .. })));
        assert!(deflate(&input, 2).is_err());
        // NUL output takes the second, 0xFF-filled decode; valid data decodes the same.
        let zeros = vec![0_u8; 4096];
        let packed = deflate(&zeros, zeros.len()).unwrap();
        assert_eq!(inflate(&packed, zeros.len()).unwrap().as_ref(), zeros.as_slice());
    }

    #[test]
    fn permessage_deflate_bounds_final_sections_including_terminator() {
        // Independent empty final stored blocks; the last zero byte starts
        // the non-final block completed by RFC 7692's restored flush tail.
        let mut message = [1, 0, 0, 255, 255].repeat(255);
        message.push(0);
        assert!(inflate(&message, 0).unwrap().is_empty());
        message.splice(..0, [1, 0, 0, 255, 255]);
        assert!(matches!(inflate(&message, 0), Err(WsError::PayloadTooLarge { size: 257, max: 256 })));
    }

    /// Raw DEFLATE bits, least significant first (RFC 1951 section 3.1.1).
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        used: usize,
    }

    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            for bit in 0..count {
                if self.used % 8 == 0 {
                    self.out.push(0);
                }
                *self.out.last_mut().unwrap() |= (((value >> bit) & 1) as u8) << (self.used % 8);
                self.used += 1;
            }
        }

        /// A Huffman code, most significant bit first.
        fn code(&mut self, code: u32, count: u32) {
            for bit in (0..count).rev() {
                self.put((code >> bit) & 1, 1);
            }
        }
    }

    /// A stored run of `run` bytes, then one fixed-Huffman match of length 3
    /// reaching 32 KiB back, then the flush header whose tail RFC 7692 removes.
    fn reach_back(run: usize, byte: u8) -> Vec<u8> {
        let mut bits = Bits::default();
        bits.put(0, 3);
        let len = u16::try_from(run).unwrap();
        bits.out.extend_from_slice(&len.to_le_bytes());
        bits.out.extend_from_slice(&(!len).to_le_bytes());
        bits.out.resize(bits.out.len() + run, byte);
        bits.used = bits.out.len() * 8;
        bits.put(0, 1);
        bits.put(1, 2);
        bits.code(1, 7);
        bits.code(29, 5);
        bits.put(8191, 13);
        bits.code(0, 7);
        bits.put(0, 3);
        bits.out
    }

    #[test]
    fn permessage_deflate_reference_check_covers_exactly_the_first_window() {
        // From position WINDOW - 1, a reference WINDOW back lands one byte
        // before the message.
        let before = reach_back(WINDOW - 1, b'a');
        assert!(matches!(
            inflate(&before, 1 << 20),
            Err(WsError::ProtocolViolation(reason)) if reason.contains("before the message")
        ));
        // From position WINDOW, it lands on the first message byte.
        let letters = reach_back(WINDOW, b'a');
        assert_eq!(
            inflate(&letters, 1 << 20).unwrap().as_ref(),
            vec![b'a'; WINDOW + 3]
        );
        let zeros = reach_back(WINDOW, 0);
        let decoded = inflate(&zeros, 1 << 20).unwrap();
        assert_eq!(decoded.as_ref(), vec![0; WINDOW + 3]);
        // The 0xFF-fill pass stops at the end of its reference. Output past
        // the first window is never compared again (br-asupersync-ydis91).
        let mut tail_differs = decoded.to_vec();
        *tail_differs.last_mut().unwrap() = 1;
        assert!(inflate_over(&zeros, 1 << 20, 0xff, Some(&tail_differs[..WINDOW])).is_ok());
        assert!(inflate_over(&zeros, 1 << 20, 0xff, Some(&tail_differs)).is_err());
    }
}
