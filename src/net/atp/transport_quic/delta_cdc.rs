//! Negotiated content-defined chunking for native QUIC delta transfers.
//!
//! The fixed manifest keeps its wire meaning. A distinct authenticated
//! capability admits this layout before either peer builds or accepts it.

use super::{QUIC_DELTA_MAX_MANIFEST_CHUNKS, TransferManifest};
use crate::net::atp::transport_common::delta::{cdc, read_full_chunk};

#[cfg(any(feature = "tls", test))]
use super::{
    AuthMode, AuthenticatedSymbol, AuthenticationTag, Cx, Digest, Frame, FrameType,
    ObjectId, QuicHello, QuicHelloAck, QuicPreparedSource, QuicTransportError,
    SecurityContext, Sha256, Symbol, SymbolId, SymbolKind,
};

pub(super) const MANIFEST_SCHEMA: &str = "asupersync.atp.quic.cdc-chunk-manifest.v1";
#[cfg(any(feature = "tls", test))]
pub(super) const SELECTOR: &str = "authenticated_cdc_delta_chunks_v1";

/// Necessary size bound only: the builder also limits the actual chunk count.
/// This admits ordinary 100 MiB files without assuming every chunk is minimal.
pub(super) fn size_may_fit(size: u64) -> bool {
    size != 0
        && size.div_ceil(cdc::MAX_CHUNK_BYTES as u64) <= QUIC_DELTA_MAX_MANIFEST_CHUNKS
}

pub(super) fn is_cdc(manifest: &TransferManifest) -> bool {
    manifest
        .delta_manifest
        .as_ref()
        .is_some_and(|delta| delta.schema == MANIFEST_SCHEMA)
}

/// Use identical read boundaries for sender manifests, source revalidation,
/// no-op verification and baseline reuse. Neither mode stores a whole file.
pub(super) enum ChunkReader {
    Fixed { file: crate::fs::File, buffer: Vec<u8> },
    Cdc { reader: cdc::ChunkReader<crate::fs::File>, chunk: Vec<u8> },
}

impl ChunkReader {
    pub(super) fn new(file: crate::fs::File, chunk_size: usize, content_defined: bool) -> Self {
        if content_defined {
            Self::Cdc { reader: cdc::ChunkReader::new(file), chunk: Vec::new() }
        } else {
            Self::Fixed { file, buffer: vec![0; chunk_size] }
        }
    }

    pub(super) async fn next_chunk(&mut self) -> std::io::Result<Option<&[u8]>> {
        match self {
            Self::Fixed { file, buffer } => {
                let read = read_full_chunk(file, buffer).await?;
                Ok((read != 0).then(|| &buffer[..read]))
            }
            Self::Cdc { reader, chunk } => {
                let Some(next) = reader.next_chunk().await? else {
                    chunk.clear();
                    return Ok(None);
                };
                *chunk = next;
                Ok(Some(chunk.as_slice()))
            }
        }
    }
}

#[cfg(any(feature = "tls", test))]
pub(super) const CDC_HELLO_EXTENSION: u16 = 0x5153;
#[cfg(any(feature = "tls", test))]
pub(super) const CDC_ACK_EXTENSION: u16 = 0x5154;
#[cfg(any(feature = "tls", test))]
const CDC_HELLO_KEY: &[u8] = b"atp-quic-cdc-hello-v1";
#[cfg(any(feature = "tls", test))]
const CDC_ACK_KEY: &[u8] = b"atp-quic-cdc-ack-v1";

#[cfg(any(feature = "tls", test))]
fn capability_symbol(
    hello: &QuicHello,
    ack: Option<&QuicHelloAck>,
) -> Result<Symbol, QuicTransportError> {
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-QUIC-CDC-CAPABILITY-V1\0");
    let hello_bytes = serde_json::to_vec(hello).map_err(|error| {
        QuicTransportError::Control(format!("serialize QUIC CDC hello: {error}"))
    })?;
    super::quic_delta_hash_len_prefixed(&mut hasher, &hello_bytes);
    match ack {
        Some(ack) => {
            hasher.update([1]);
            let ack_bytes = serde_json::to_vec(ack).map_err(|error| {
                QuicTransportError::Control(format!("serialize QUIC CDC acknowledgement: {error}"))
            })?;
            super::quic_delta_hash_len_prefixed(&mut hasher, &ack_bytes);
        }
        None => hasher.update([0]),
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Symbol::new(
        SymbolId::new(ObjectId::new(0x4154_502d_5155_4943, 0x2d43_4443_2d43_4150), 0, 0),
        digest.to_vec(),
        SymbolKind::Source,
    ))
}

#[cfg(any(feature = "tls", test))]
fn require_hello(hello: &QuicHello) -> Result<(), QuicTransportError> {
    if hello.delta_transfer_nonce.is_none_or(|nonce| nonce.is_zero()) {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC CDC capability requires a fresh delta transfer nonce".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
fn require_ack(hello: &QuicHello, ack: &QuicHelloAck) -> Result<(), QuicTransportError> {
    require_hello(hello)?;
    if !ack.accepted
        || super::validate_quic_delta_ack(hello.delta_transfer_nonce, ack)?.is_none()
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC CDC acknowledgement requires an accepted bound delta handshake".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
fn sign_capability(
    frame: &mut Frame,
    context: &SecurityContext,
    extension: u16,
    key: &[u8],
    symbol: Symbol,
) -> Result<(), QuicTransportError> {
    if context.mode() != AuthMode::Strict {
        return Err(QuicTransportError::Config(
            "QUIC CDC capability requires strict delta authentication".to_string(),
        ));
    }
    let tag = context.derive_context(key).sign_symbol_tag(&symbol);
    frame.header.extensions.insert(extension, tag.as_bytes().to_vec());
    Ok(())
}

#[cfg(any(feature = "tls", test))]
fn verify_capability(
    bytes: &[u8],
    context: &SecurityContext,
    key: &[u8],
    symbol: Symbol,
) -> Result<(), QuicTransportError> {
    let tag = bytes.try_into().map_err(|_| {
        QuicTransportError::HandshakeRejected("malformed QUIC CDC capability".to_string())
    })?;
    let mut authenticated = AuthenticatedSymbol::from_parts(
        symbol, AuthenticationTag::from_bytes(tag),
    );
    if context.mode() != AuthMode::Strict
        || context.derive_context(key).verify_authenticated_symbol(&mut authenticated).is_err()
        || !authenticated.is_verified()
    {
        return Err(QuicTransportError::HandshakeRejected(
            "QUIC CDC capability authentication failed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "tls", test))]
pub(super) fn advertise_cdc(
    frame: &mut Frame,
    context: &SecurityContext,
    hello: &QuicHello,
) -> Result<(), QuicTransportError> {
    require_hello(hello)?;
    sign_capability(frame, context, CDC_HELLO_EXTENSION, CDC_HELLO_KEY,
        capability_symbol(hello, None)?)
}

#[cfg(any(feature = "tls", test))]
pub(super) fn cdc_offered(
    frame: &Frame,
    context: &SecurityContext,
    hello: &QuicHello,
) -> Result<bool, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&CDC_HELLO_EXTENSION) else {
        return Ok(false);
    };
    require_hello(hello)?;
    verify_capability(bytes, context, CDC_HELLO_KEY, capability_symbol(hello, None)?)?;
    Ok(true)
}

#[cfg(any(feature = "tls", test))]
pub(super) fn acknowledge_cdc(
    frame: &mut Frame,
    context: &SecurityContext,
    hello: &QuicHello,
    ack: &QuicHelloAck,
) -> Result<(), QuicTransportError> {
    require_ack(hello, ack)?;
    sign_capability(frame, context, CDC_ACK_EXTENSION, CDC_ACK_KEY,
        capability_symbol(hello, Some(ack))?)
}

#[cfg(any(feature = "tls", test))]
pub(super) fn cdc_acknowledged(
    frame: &Frame,
    context: Option<&SecurityContext>,
    hello: &QuicHello,
    ack: &QuicHelloAck,
    was_offered: bool,
) -> Result<bool, QuicTransportError> {
    let Some(bytes) = frame.header.extensions.get(&CDC_ACK_EXTENSION) else {
        return Ok(false);
    };
    if !was_offered {
        return Err(QuicTransportError::HandshakeRejected(
            "receiver acknowledged an unoffered QUIC CDC capability".to_string(),
        ));
    }
    require_ack(hello, ack)?;
    let context = context.ok_or_else(|| QuicTransportError::HandshakeRejected(
        "QUIC CDC acknowledgement has no strict authentication context".to_string(),
    ))?;
    verify_capability(bytes, context, CDC_ACK_KEY, capability_symbol(hello, Some(ack))?)?;
    Ok(true)
}

/// Replace only a negotiated session's prepared manifest. Failure to fit the
/// bounded wire envelope or chunk index retains its existing fixed manifest.
#[cfg(any(feature = "tls", test))]
pub(super) async fn select_manifest(
    cx: &Cx,
    prepared: &mut QuicPreparedSource,
) -> Result<(), QuicTransportError> {
    let manifest = &prepared.manifest;
    let Some(entry) = super::quic_delta_manifest_entry(manifest) else {
        return Ok(());
    };
    let [source] = prepared.entries.as_slice() else {
        return Ok(());
    };
    if manifest.delta_manifest.is_none() || !size_may_fit(entry.size) {
        return Ok(());
    }
    let Some(delta) = super::build_quic_delta_manifest_with_layout(
        cx, &manifest.merkle_root_hex, &source.abs_path, entry.index,
        &entry.rel_path, entry.size, &entry.sha256_hex, cdc::MAX_CHUNK_BYTES, true,
    ).await? else {
        cx.trace_with_fields("atp_quic.cdc_manifest_fallback", &[("reason", "chunk_count_budget")]);
        return Ok(());
    };
    let mut candidate = manifest.clone();
    candidate.delta_manifest = Some(delta);
    match super::json_frame(FrameType::ObjectManifest, &candidate) {
        Ok(frame) if frame.payload().len() <= usize::try_from(super::MAX_FRAME_SIZE)
            .unwrap_or(usize::MAX).saturating_sub(super::QUIC_DELTA_ENVELOPE_WIRE_BUDGET) => {
                prepared.manifest = candidate;
            }
        Ok(_) | Err(QuicTransportError::Frame(_)) => {
            cx.trace_with_fields("atp_quic.cdc_manifest_fallback", &[("reason", "authenticated_envelope_budget")]);
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
#[path = "delta_cdc_tests.rs"]
mod tests;
