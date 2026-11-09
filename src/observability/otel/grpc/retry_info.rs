//! Bounded, value-redacted admission of a collector's retry delay.
//!
//! This is a retry-policy parser, not a general rich-error decoder. Protobuf's
//! duplicate-field merging rules can hide competing throttle instructions, so
//! repeated singular fields and multiple `RetryInfo` records are refused. The
//! complete envelope is checked before any delay is returned.

use crate::grpc::Status;
use crate::grpc::protobuf::{
    ProtobufWireDecoder, ProtobufWireField, ProtobufWireLimits, ProtobufWireMessage, WireType,
};
use std::time::Duration;

// Status truncates details at its public cap without retaining a truncation
// marker. Refuse that boundary as well, so a valid prefix of an oversized
// envelope cannot authorize a retry after a later throttle was discarded.
const MAX_DETAILS_BYTES: usize = crate::grpc::status::MAX_STATUS_DETAILS_LEN - 1;
const MAX_FIELDS: usize = 256;
const MAX_DEPTH: usize = 8;
const MAX_TYPE_URL_BYTES: usize = 1024;
const MAX_DURATION_SECONDS: u64 = 315_576_000_000;

/// Return only a validated numeric `google.rpc.RetryInfo` delay.
///
/// Empty or absent details have no hint. Nonempty details must be a complete
/// `google.rpc.Status` with the same non-OK code as the native status. Unknown
/// `Any` types remain opaque; their URLs are never resolved. A present empty
/// `RetryInfo` uses protobuf's zero-duration default and remains distinguishable
/// from no hint. Failure carries no peer text, URL, or protobuf payload.
pub(super) fn retry_delay(status: &Status) -> Result<Option<Duration>, ()> {
    let Some(details) = status.details() else {
        return Ok(None);
    };
    if details.is_empty() {
        return Ok(None);
    }
    if status.is_ok() {
        return Err(());
    }

    let limits = ProtobufWireLimits::for_message_size_and_depth(MAX_DETAILS_BYTES, MAX_DEPTH)
        .with_max_fields(MAX_FIELDS)
        .with_max_work(MAX_DETAILS_BYTES.saturating_mul(4));
    let mut message = ProtobufWireMessage::new(details.as_ref(), limits).map_err(|_| ())?;
    let mut decoder = message.decoder();
    let mut code = None;
    let mut message_seen = false;
    let mut delay = None;

    while let Some(field) = decoder.next_field().map_err(|_| ())? {
        match field.field_number() {
            1 => {
                if code.is_some() {
                    return Err(());
                }
                code = Some(field.as_varint().map_err(|_| ())?);
            }
            2 => {
                if message_seen {
                    return Err(());
                }
                field.as_str().map_err(|_| ())?;
                message_seen = true;
            }
            3 => {
                let candidate =
                    any_retry_delay(&mut decoder.nested_message(&field).map_err(|_| ())?)?;
                if let Some(candidate) = candidate {
                    if delay.is_some() {
                        return Err(());
                    }
                    delay = Some(candidate);
                }
            }
            _ => skip_unknown(&mut decoder, &field)?,
        }
    }

    // An omitted proto3 code defaults to OK, which cannot describe this error.
    let expected = u64::try_from(status.code().as_i32()).map_err(|_| ())?;
    if code != Some(expected) {
        return Err(());
    }
    Ok(delay)
}

fn any_retry_delay(decoder: &mut ProtobufWireDecoder<'_, '_>) -> Result<Option<Duration>, ()> {
    let mut type_url = None;
    let mut value = None;
    while let Some(field) = decoder.next_field().map_err(|_| ())? {
        match field.field_number() {
            1 => {
                if type_url.is_some() {
                    return Err(());
                }
                let url = field.as_str().map_err(|_| ())?;
                if url.len() > MAX_TYPE_URL_BYTES {
                    return Err(());
                }
                type_url = Some(url);
            }
            2 => {
                if value.is_some() {
                    return Err(());
                }
                field.as_bytes().map_err(|_| ())?;
                value = Some(field);
            }
            _ => skip_unknown(decoder, &field)?,
        }
    }

    let is_retry_info = type_url.is_some_and(|url| {
        url.rsplit_once('/')
            .is_some_and(|(_, name)| name == "google.rpc.RetryInfo")
    });
    if !is_retry_info {
        return Ok(None);
    }
    let delay = if let Some(value) = value {
        decode_retry_info(&mut decoder.nested_message(&value).map_err(|_| ())?)?
    } else {
        Duration::ZERO
    };
    Ok(Some(delay))
}

fn decode_retry_info(decoder: &mut ProtobufWireDecoder<'_, '_>) -> Result<Duration, ()> {
    let mut delay = None;
    while let Some(field) = decoder.next_field().map_err(|_| ())? {
        if field.field_number() == 1 {
            if delay.is_some() {
                return Err(());
            }
            delay = Some(decode_duration(
                &mut decoder.nested_message(&field).map_err(|_| ())?,
            )?);
        } else {
            skip_unknown(decoder, &field)?;
        }
    }
    Ok(delay.unwrap_or(Duration::ZERO))
}

fn decode_duration(decoder: &mut ProtobufWireDecoder<'_, '_>) -> Result<Duration, ()> {
    let mut seconds = None;
    let mut nanos = None;
    while let Some(field) = decoder.next_field().map_err(|_| ())? {
        match field.field_number() {
            1 => {
                if seconds.is_some() {
                    return Err(());
                }
                let value = field.as_varint().map_err(|_| ())?;
                // A negative int64 is encoded as a large unsigned varint.
                if value > MAX_DURATION_SECONDS {
                    return Err(());
                }
                seconds = Some(value);
            }
            2 => {
                if nanos.is_some() {
                    return Err(());
                }
                let value = field.as_varint().map_err(|_| ())?;
                // This also excludes negative int32 and noncanonical wrapping
                // encodings; only the standard nonnegative range is admitted.
                if value >= 1_000_000_000 {
                    return Err(());
                }
                nanos = Some(u32::try_from(value).map_err(|_| ())?);
            }
            _ => skip_unknown(decoder, &field)?,
        }
    }
    Ok(Duration::new(seconds.unwrap_or(0), nanos.unwrap_or(0)))
}

fn skip_unknown<'a>(
    decoder: &mut ProtobufWireDecoder<'a, '_>,
    field: &ProtobufWireField<'a>,
) -> Result<(), ()> {
    if field.wire_type() == WireType::StartGroup {
        decoder.skip_group(field).map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "retry_info_tests.rs"]
mod tests;
