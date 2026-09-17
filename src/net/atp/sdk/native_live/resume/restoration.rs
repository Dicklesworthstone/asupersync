//! Read-only final-Proof recovery through the existing authenticated registry.
//!
//! A restored owner contains a trusted application receipt, not a writable sink.
//! It can exchange that receipt with the original client but cannot consume an
//! epoch or repeat publication. This is deliberately not partial-stream restore.

use super::{Capacity, ResumeSessionKey};
use super::super::{
    Budget, Credit, ResumableReceiver, ResumeError, ResumeReport, decode_offer,
    initial, offer,
};
use super::super::super::LiveStreamCommitSink;
use super::super::super::super::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceipt, Wire, authorize, bounded,
    encode_final, encode_prefix,
};
use crate::cx::Cx;
use crate::net::TcpStream;
use crate::net::atp::protocol::frames::FrameType;
use crate::tls::{TlsAcceptor, TlsStream};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A once-per-key factory decision made after mTLS and registry admission.
///
/// The application, not the peer, supplies this decision. Never turn a claimed
/// but unresolved operation into either variant merely to bypass a refusal.
#[derive(Debug)]
pub enum ResumeSessionInit<W> {
    /// A genuinely new operation, using the ordinary streaming/commit protocol.
    Fresh(W),
    /// Historical successful application commit for this exact client/nonce.
    ///
    /// The caller must validate protected durable history and any required
    /// current publication state before returning this. The SDK checks shape,
    /// nonce and limits, not the provenance or durability of an arbitrary value.
    /// No sink exists: incoming epochs are refused and commit is never invoked.
    /// The existing sender must retain its source-EOF state and validate the
    /// exact prefix/hash and final Proof; a completion flag alone is insufficient.
    Committed(LiveStreamReceipt),
}

pub(super) enum ServiceReceiver<W> {
    Live(Box<ResumableReceiver<W>>),
    Receipt(Box<ReceiptReceiver>),
}

pub(super) struct ReceiptReceiver {
    receipt: LiveStreamReceipt,
    config: LiveStreamConfig,
    offered: Option<Vec<u8>>,
    state: Vec<u8>,
    budget: Budget,
}

fn validate_receipt(
    nonce: [u8; 32], receipt: &LiveStreamReceipt, epoch_bytes: usize, maximum_bytes: u64,
) -> Result<(), LiveStreamError> {
    let prefix = &receipt.prefix;
    let empty_hash: [u8; 32] = Sha256::digest(b"").into();
    if prefix.stream_nonce != nonce || prefix.bytes > maximum_bytes
        || (prefix.bytes == 0) != (prefix.epochs == 0) || prefix.epochs > prefix.bytes
        || prefix.bytes > prefix.epochs.saturating_mul(epoch_bytes as u64)
        || (prefix.bytes == 0 && receipt.source_sha256 != empty_hash)
    {
        return Err(LiveStreamError::Configuration("restored receipt conflicts with key or limits"));
    }
    Ok(())
}

impl<W> ServiceReceiver<W> {
    pub(super) fn new(
        initialized: ResumeSessionInit<W>, key: ResumeSessionKey, acceptor: TlsAcceptor,
        config: LiveStreamConfig, maximum: u32, capacity: Arc<Capacity>,
    ) -> Result<Self, LiveStreamError> {
        let budget = Budget { used: 0, maximum, _credit: Credit::Shared { _capacity: capacity } };
        match initialized {
            ResumeSessionInit::Fresh(sink) => Ok(Self::Live(Box::new(ResumableReceiver {
                sink, listener: None, acceptor, expected_client: key.client, config,
                offered: None, agreed: None, prefix: None, hash: Sha256::new(), pending: None,
                sink_written_bytes: 0, final_receipt: None, commit_started: false, completed: None,
                failed: false, budget,
            }))),
            ResumeSessionInit::Committed(receipt) => {
                validate_receipt(key.nonce, &receipt, config.epoch_bytes, config.max_bytes)?;
                Ok(Self::Receipt(Box::new(ReceiptReceiver {
                    receipt, config, offered: None, state: Vec::new(), budget,
                })))
            }
        }
    }

    pub(super) fn failed(&self) -> bool {
        match self { Self::Live(receiver) => receiver.failed, Self::Receipt(_) => false }
    }

    pub(super) fn has_attempts(&self) -> bool {
        let budget = match self {
            Self::Live(receiver) => &receiver.budget,
            Self::Receipt(receiver) => &receiver.budget,
        };
        budget.used < budget.maximum
    }
}

impl<W: LiveStreamCommitSink + Unpin> ServiceReceiver<W> {
    pub(super) async fn attempt(
        &mut self, cx: &Cx, wire: &mut Wire<TlsStream<TcpStream>>, offered: &[u8],
    ) -> ResumeReport {
        match self {
            Self::Live(receiver) => {
                let reused = receiver.completed.is_some();
                let outcome = match authorize(cx).map_err(ResumeError::from).and_then(|()| receiver.budget.take()) {
                    Ok(()) => receiver.receive_wire(cx, wire, offered).await,
                    Err(error) => Err(error),
                };
                ResumeReport {
                    outcome, prefix: receiver.prefix.clone(), attempts: receiver.budget.used, receipt_reused: reused,
                    retained_epoch_bytes: receiver.pending.as_ref().map_or(0, |epoch| epoch.bytes().len()),
                    sink_written_bytes: receiver.sink_written_bytes, completed: receiver.completed.clone(),
                }
            }
            Self::Receipt(receiver) => {
                let outcome = match authorize(cx).map_err(ResumeError::from).and_then(|()| receiver.budget.take()) {
                    Ok(()) => receiver.receive_wire(cx, wire, offered).await,
                    Err(error) => Err(error),
                };
                ResumeReport {
                    outcome, prefix: Some(receiver.receipt.prefix.clone()), attempts: receiver.budget.used,
                    receipt_reused: true, retained_epoch_bytes: 0, sink_written_bytes: 0,
                    completed: Some(receiver.receipt.clone()),
                }
            }
        }
    }
}

impl ReceiptReceiver {
    fn response(&mut self, offered: &[u8]) -> Result<Vec<u8>, ResumeError> {
        if let Some(previous) = &self.offered {
            if previous != offered {
                return Err(ResumeError::Continuity("restored session offer changed"));
            }
            return Ok(self.state.clone());
        }
        let mut agreed = decode_offer(offered)?;
        if agreed.nonce != self.receipt.prefix.stream_nonce {
            return Err(ResumeError::Continuity("restored session nonce changed"));
        }
        agreed.epoch_bytes = agreed.epoch_bytes.min(self.config.epoch_bytes);
        agreed.max_bytes = agreed.max_bytes.min(self.config.max_bytes);
        // The durable receipt is authoritative history, not a synthesized hash
        // state. The sender additionally checks its original negotiated hello.
        validate_receipt(agreed.nonce, &self.receipt, agreed.epoch_bytes, agreed.max_bytes)?;
        if self.receipt.prefix.bytes == 0 && initial(&agreed) != self.receipt.prefix {
            return Err(ResumeError::Continuity("restored empty-stream hello changed"));
        }
        let mut state = offer(&agreed);
        state.extend_from_slice(&encode_prefix(&self.receipt.prefix));
        state.extend_from_slice(&self.receipt.source_sha256);
        state.push(1);
        self.offered = Some(offered.to_vec());
        self.state = state.clone();
        Ok(state)
    }

    async fn receive_wire(
        &mut self, cx: &Cx, wire: &mut Wire<TlsStream<TcpStream>>, offered: &[u8],
    ) -> Result<LiveStreamReceipt, ResumeError> {
        let state = self.response(offered)?;
        let timeout = self.config.operation_timeout;
        bounded(cx, timeout, "restored resume state", wire.send(FrameType::HandshakeAck, state)).await?;
        let frame = bounded(cx, timeout, "restored final commitment", wire.receive()).await?;
        let payload = encode_final(&self.receipt);
        if frame.frame_type() != FrameType::ObjectComplete || frame.payload() != payload {
            return Err(ResumeError::Continuity("restored session requires its exact final commitment"));
        }
        bounded(cx, timeout, "restored final Proof", wire.send(FrameType::Proof, payload)).await
            .map_err(|error| super::super::super::proof_failed(&self.receipt, error))?;
        Ok(self.receipt.clone())
    }
}

#[cfg(test)]
#[path = "restoration_tests.rs"]
mod tests;
