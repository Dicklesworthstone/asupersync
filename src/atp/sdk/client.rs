//! ATP client bridge for SDK-side session and writer operations.

use super::{AtpConfig, AtpSession};
use crate::atp::object::{ContentId, ObjectId};
use crate::atp::writer::{AtpWriter, TransferProof, WriterConfig};
use crate::cx::Cx;
use crate::net::atp::protocol::outcome::AtpOutcome;
use crate::types::outcome::Outcome;
use sha2::{Digest, Sha256};

/// Internal ATP client implementation backed by a real SDK session.
#[derive(Debug, Clone)]
pub struct AtpClientImpl {
    session: AtpSession,
}

impl AtpClientImpl {
    /// Open a client with an explicit context and SDK configuration.
    pub async fn open(cx: &Cx, config: AtpConfig) -> AtpOutcome<Self> {
        match AtpSession::open(cx, config).await {
            Outcome::Ok(session) => Outcome::ok(Self { session }),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Borrow the underlying session for advanced operations.
    #[must_use]
    pub const fn session(&self) -> &AtpSession {
        &self.session
    }

    /// Create a writer for a remote peer using the session's writer policy.
    pub fn create_writer(
        &self,
        remote_peer: [u8; 32],
        writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        self.session.create_writer(remote_peer, writer_config)
    }

    /// Write a buffer by constructing a content-addressed writer and finalizing it.
    pub async fn write_buffer(
        &self,
        cx: &Cx,
        remote_peer: [u8; 32],
        data: &[u8],
        writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        self.session
            .write_buffer(cx, data, remote_peer, writer_config)
            .await
    }

    /// Create a deterministic object ID for client-local write preparation.
    #[must_use]
    pub fn object_id_for_buffer(data: &[u8]) -> ObjectId {
        let digest: [u8; 32] = Sha256::digest(data).into();
        ObjectId::content(ContentId::new(digest))
    }
}
