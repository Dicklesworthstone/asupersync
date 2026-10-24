//! Sequenced control authentication for the explicit strict RQ delta surface.
//!
//! The signed ObjectRequest selects this subprotocol before either endpoint
//! installs it. Protocol-4 JSON payloads are unchanged. Directional keys bind
//! every later frame to the fresh delta session; symbols use a separate domain.

use super::{
    AuthMode, AuthenticatedSymbol, AuthenticationTag, Frame, ObjectId, RqDeltaSessionContext,
    RqError, SecurityContext, Sha256, Symbol, SymbolId, SymbolKind,
};
use sha2::Digest;

pub(super) const FULL_OBJECT_CONTROL_V1: &str = "full_object_authenticated_control_v1";

/// RQ-private extension: sequence (8 bytes), then HMAC tag (32 bytes).
const AUTH_EXTENSION: u16 = 0x5251;
const AUTH_EXTENSION_BYTES: usize = 8 + 32;

#[derive(Clone, Copy)]
pub(super) enum ControlRole {
    Sender,
    Receiver,
}

pub(super) struct AuthenticatedControl {
    send_context: SecurityContext,
    receive_context: SecurityContext,
    send_sequence: u64,
    receive_sequence: u64,
    failed: bool,
}

fn session_context(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    transfer_id: &str,
) -> Result<SecurityContext, RqError> {
    if context.mode() != AuthMode::Strict {
        return Err(RqError::Authentication(
            "authenticated full-object control requires a strict key".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-FULL-OBJECT-SESSION-V1\0");
    hasher.update(session.session_id);
    hasher.update(session.destination_root);
    super::rq_delta_hash_len_prefixed(&mut hasher, transfer_id.as_bytes());
    Ok(context.derive_context(&hasher.finalize()))
}

/// Source and repair symbols use this same fresh-session key.
pub(super) fn symbol_context(
    context: &SecurityContext,
    session: RqDeltaSessionContext,
    transfer_id: &str,
) -> Result<SecurityContext, RqError> {
    Ok(session_context(context, session, transfer_id)?
        .derive_context(b"atp-rq-full-object-symbols-v1"))
}

impl AuthenticatedControl {
    pub(super) fn new(
        context: &SecurityContext,
        session: RqDeltaSessionContext,
        transfer_id: &str,
        role: ControlRole,
    ) -> Result<Self, RqError> {
        let session = session_context(context, session, transfer_id)?;
        let sender = session.derive_context(b"atp-rq-full-object-sender-control-v1");
        let receiver = session.derive_context(b"atp-rq-full-object-receiver-control-v1");
        let (send_context, receive_context) = match role {
            ControlRole::Sender => (sender, receiver),
            ControlRole::Receiver => (receiver, sender),
        };
        Ok(Self {
            send_context,
            receive_context,
            send_sequence: 0,
            receive_sequence: 0,
            failed: false,
        })
    }

    pub(super) fn ensure_healthy(&self) -> Result<(), RqError> {
        if self.failed {
            return Err(RqError::Authentication(
                "authenticated full-object control is terminal after an incomplete or invalid frame"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn fail(&mut self) {
        self.failed = true;
    }

    /// Keep the stream unusable until write/flush completes. Dropping a
    /// partially written send must not let a retry append a different frame to
    /// an ambiguous prefix or reuse its sequence.
    pub(super) fn begin_flush(&mut self) -> Result<(), RqError> {
        self.ensure_healthy()?;
        self.failed = true;
        Ok(())
    }

    pub(super) fn finish_write(&mut self) {
        self.failed = false;
    }

    pub(super) fn prepare_send(&mut self, frame: &Frame) -> Result<Vec<u8>, RqError> {
        self.ensure_healthy()?;
        let result = self.prepare_send_inner(frame);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn prepare_send_inner(&mut self, frame: &Frame) -> Result<Vec<u8>, RqError> {
        if frame.header.extensions.contains_key(&AUTH_EXTENSION) {
            return Err(RqError::Authentication(
                "control frame already contains the reserved authentication extension".to_string(),
            ));
        }
        let next_sequence = self.send_sequence.checked_add(1).ok_or_else(|| {
            RqError::Authentication("authenticated control send sequence exhausted".to_string())
        })?;
        let symbol = frame_auth_symbol(frame, self.send_sequence)?;
        let tag = self.send_context.sign_symbol_tag(&symbol);
        let mut extension = Vec::with_capacity(AUTH_EXTENSION_BYTES);
        extension.extend_from_slice(&self.send_sequence.to_be_bytes());
        extension.extend_from_slice(tag.as_bytes());
        let mut authenticated = frame.clone();
        authenticated.header.extensions.insert(AUTH_EXTENSION, extension);
        let bytes = authenticated
            .to_wire_bytes()
            .map_err(|error| RqError::Frame(error.to_string()))?;
        self.send_sequence = next_sequence;
        self.failed = true;
        Ok(bytes)
    }

    pub(super) fn verify_received(&mut self, mut frame: Frame) -> Result<Frame, RqError> {
        self.ensure_healthy()?;
        if let Err(error) = self.verify_received_inner(&frame) {
            self.fail();
            return Err(error);
        }
        // A caller may echo KeepAlive: its outgoing direction must get a fresh
        // sequence and a tag under the other directional key.
        frame.header.extensions.remove(&AUTH_EXTENSION);
        Ok(frame)
    }

    fn verify_received_inner(&mut self, frame: &Frame) -> Result<(), RqError> {
        let extension = frame.header.extensions.get(&AUTH_EXTENSION).ok_or_else(|| {
            RqError::Authentication(
                "authenticated full-object control frame is missing its tag".to_string(),
            )
        })?;
        if extension.len() != AUTH_EXTENSION_BYTES {
            return Err(RqError::Authentication(
                "authenticated control extension has an invalid length".to_string(),
            ));
        }
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&extension[..8]);
        let sequence = u64::from_be_bytes(sequence_bytes);
        if sequence != self.receive_sequence {
            return Err(RqError::Authentication(
                "authenticated control sequence is replayed or out of order".to_string(),
            ));
        }
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            RqError::Authentication("authenticated control receive sequence exhausted".to_string())
        })?;
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&extension[8..]);
        let mut authenticated = AuthenticatedSymbol::from_parts(
            frame_auth_symbol(frame, sequence)?,
            AuthenticationTag::from_bytes(tag),
        );
        if self
            .receive_context
            .verify_authenticated_symbol(&mut authenticated)
            .is_err()
            || !authenticated.is_verified()
        {
            return Err(RqError::Authentication(
                "authenticated full-object control tag mismatch".to_string(),
            ));
        }
        self.receive_sequence = next_sequence;
        Ok(())
    }
}

fn frame_auth_symbol(frame: &Frame, sequence: u64) -> Result<Symbol, RqError> {
    if frame.header.payload_length.value()
        != u64::try_from(frame.payload.len()).unwrap_or(u64::MAX)
    {
        return Err(RqError::Authentication(
            "authenticated control payload length mismatch".to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-RQ-FULL-OBJECT-FRAME-V1\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(frame.version().0.to_be_bytes());
    hasher.update((frame.frame_type() as u16).to_be_bytes());
    super::rq_delta_hash_len_prefixed(&mut hasher, frame.payload());
    // Authenticate all other extensions in a stable order. The codec bounds
    // their count and size, as well as the payload and total frame size.
    let extensions: std::collections::BTreeMap<_, _> = frame
        .header
        .extensions
        .iter()
        .filter(|(id, _)| **id != AUTH_EXTENSION)
        .collect();
    hasher.update(u64::try_from(extensions.len()).unwrap_or(u64::MAX).to_be_bytes());
    for (id, value) in extensions {
        hasher.update(id.to_be_bytes());
        super::rq_delta_hash_len_prefixed(&mut hasher, value);
    }
    Ok(Symbol::new(
        SymbolId::new(
            ObjectId::new(0x4154_502d_5251_2d46, 0x554c_4c2d_4354_524c),
            0,
            0,
        ),
        hasher.finalize().to_vec(),
        SymbolKind::Source,
    ))
}

#[cfg(test)]
#[path = "authenticated_control_tests.rs"]
mod tests;
