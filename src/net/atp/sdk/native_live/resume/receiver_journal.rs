//! Write-ahead receiver state and content-checked partial-sink recovery.
//!
//! Persist the exact pending epoch BEFORE its first sink write, then persist a
//! synchronized completed prefix BEFORE its ACK. Recovery rehashes that prefix
//! and compares every surviving tail byte against the pending epoch. It never
//! truncates a sink, trusts an arbitrary offset, or repeats an accepted write.
//!
//! Finalizing is deliberately distinct from Committed. A process lost between
//! application commit admission and its durable success record is unresolved:
//! restoration refuses it instead of invoking an uncertain commit again.
//! Journals contain plaintext pending data. Protect and bound their storage.

use super::{
    Budget, Credit, EPOCH_HEADER_BYTES, Hello, LiveStreamCommitSink, LiveStreamError,
    LiveStreamPrefix, LiveStreamReceipt, LiveStreamReceiver, NativeClientCertificateId,
    OFFER_BYTES, PendingEpoch, RESUMABLE_LIVE_ALPN, ResumableReceiver, ResumeError,
    ResumeReport, advance, authorize, bounded, decode_offer, digest, encode_prefix,
    initial, offer, validate_attempts,
};
use crate::cx::Cx;
use crate::io::{AsyncRead, ReadBuf};
use crate::net::TcpListener;
use crate::tls::TlsAcceptor;
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ATPRCV01";
const FIXED: usize = 285;
const MAX_EPOCH: usize = 65_536;
/// Maximum canonical snapshot, including one complete pending epoch and checksum.
pub const MAX_RECEIVER_CHECKPOINT_BYTES: usize = FIXED + EPOCH_HEADER_BYTES + MAX_EPOCH + 32;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid receiver checkpoint or retained sink")
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.receiver-checkpoint.v1");
    hash.update(bytes);
    hash.finalize().into()
}

/// Persisted application-effect boundary, not an assertion of sender delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiverCheckpointPhase {
    /// Data reception can continue after verifying the retained sink.
    Receiving,
    /// Publication may have started. No automatic restoration is permitted.
    Finalizing,
    /// Application commit was observed and persisted; only final Proof can repeat.
    Committed,
}

/// Exact client-bound continuation, including at most one plaintext pending epoch.
///
/// Checksums detect corruption, not malicious edits or rollback. The original
/// protected journal and exclusive sink ownership must survive process restart.
#[derive(Clone)]
pub struct ReceiverCheckpoint {
    client: NativeClientCertificateId,
    offered: [u8; OFFER_BYTES],
    agreed: [u8; OFFER_BYTES],
    prefix: LiveStreamPrefix,
    prefix_hash: [u8; 32],
    pending_hash: [u8; 32],
    used: u32,
    maximum: u32,
    phase: ReceiverCheckpointPhase,
    pending: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ReceiverCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverCheckpoint")
            .field("prefix_bytes", &self.prefix.bytes)
            .field("pending_bytes", &self.pending_bytes())
            .field("phase", &self.phase)
            .field("attempts", &self.used)
            .finish_non_exhaustive()
    }
}

impl ReceiverCheckpoint {
    fn capture<W>(receiver: &ResumableReceiver<W>) -> Result<Self, ResumeError> {
        if receiver.failed { return Err(ResumeError::LocalFailure); }
        let prefix = receiver.prefix.clone().ok_or(ResumeError::LocalFailure)?;
        let agreed = receiver.agreed.as_ref().ok_or(ResumeError::LocalFailure)?;
        let offered = receiver.offered.as_ref().ok_or(ResumeError::LocalFailure)?;
        let mut pending_hash = receiver.hash.clone();
        if let Some(pending) = &receiver.pending { pending_hash.update(pending.bytes()); }
        let saved = Self {
            client: receiver.expected_client,
            offered: offered.as_slice().try_into().map_err(|_| ResumeError::LocalFailure)?,
            agreed: offer(agreed).try_into().map_err(|_| ResumeError::LocalFailure)?,
            prefix, prefix_hash: digest(&receiver.hash), pending_hash: digest(&pending_hash),
            used: receiver.budget.used, maximum: receiver.budget.maximum,
            phase: if receiver.completed.is_some() { ReceiverCheckpointPhase::Committed }
                else if receiver.final_receipt.is_some() { ReceiverCheckpointPhase::Finalizing }
                else { ReceiverCheckpointPhase::Receiving },
            pending: Zeroizing::new(receiver.pending.as_ref().map_or_else(Vec::new, |p| p.payload.clone())),
        };
        saved.validate().map_err(LiveStreamError::from)?;
        Ok(saved)
    }

    /// Exact authenticated client. Restore additionally requires caller agreement.
    #[must_use]
    pub const fn client(&self) -> NativeClientCertificateId { self.client }
    /// Last checkpointed complete prefix. This is not whole-stream success.
    #[must_use]
    pub fn prefix(&self) -> &LiveStreamPrefix { &self.prefix }
    /// Maximum surviving tail length after this prefix; no other tail is accepted.
    #[must_use]
    pub fn pending_bytes(&self) -> usize { self.pending.len().saturating_sub(EPOCH_HEADER_BYTES) }
    /// Last recorded application-effect boundary.
    #[must_use]
    pub const fn phase(&self) -> ReceiverCheckpointPhase { self.phase }
    /// Previously admitted connection attempts; restoration does not reset these.
    #[must_use]
    pub const fn attempts(&self) -> u32 { self.used }
    /// Immutable original lifetime attempt ceiling.
    #[must_use]
    pub const fn maximum_attempts(&self) -> u32 { self.maximum }
    /// Historical local receipt, only after a persisted successful application commit.
    #[must_use]
    pub fn committed_receipt(&self) -> Option<LiveStreamReceipt> {
        (self.phase == ReceiverCheckpointPhase::Committed).then(|| self.receipt())
    }
    fn receipt(&self) -> LiveStreamReceipt {
        LiveStreamReceipt { prefix: self.prefix.clone(), source_sha256: self.prefix_hash }
    }

    fn validate(&self) -> io::Result<Hello> {
        let offered = decode_offer(&self.offered).map_err(|_| invalid())?;
        let agreed = decode_offer(&self.agreed).map_err(|_| invalid())?;
        let prefix = &self.prefix;
        if offered.nonce != agreed.nonce || prefix.stream_nonce != agreed.nonce
            || agreed.epoch_bytes > offered.epoch_bytes || agreed.max_bytes > offered.max_bytes
            || prefix.bytes > agreed.max_bytes || prefix.epochs > prefix.bytes
            || (prefix.bytes == 0) != (prefix.epochs == 0)
            || prefix.bytes > prefix.epochs.saturating_mul(agreed.epoch_bytes as u64)
            || validate_attempts(self.maximum).is_err() || self.used == 0 || self.used > self.maximum
            || self.pending.len() > EPOCH_HEADER_BYTES + MAX_EPOCH
        { return Err(invalid()); }
        if prefix.bytes == 0 && (*prefix != initial(&agreed) || self.prefix_hash != digest(&Sha256::new())) {
            return Err(invalid());
        }
        if self.pending.is_empty() {
            if self.pending_hash != self.prefix_hash { return Err(invalid()); }
        } else {
            if self.phase != ReceiverCheckpointPhase::Receiving { return Err(invalid()); }
            advance(prefix, &self.pending, agreed.epoch_bytes, agreed.max_bytes).map_err(|_| invalid())?;
        }
        Ok(agreed)
    }

    /// Export bounded sensitive plaintext, zeroized when this owned buffer drops.
    pub fn to_canonical_bytes(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(FIXED + self.pending.len() + 32));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.client.as_bytes());
        bytes.extend_from_slice(&self.offered);
        bytes.extend_from_slice(&self.agreed);
        bytes.extend_from_slice(&encode_prefix(&self.prefix));
        bytes.extend_from_slice(&self.prefix_hash);
        bytes.extend_from_slice(&self.pending_hash);
        bytes.extend_from_slice(&self.used.to_be_bytes());
        bytes.extend_from_slice(&self.maximum.to_be_bytes());
        bytes.push(match self.phase {
            ReceiverCheckpointPhase::Receiving => 0,
            ReceiverCheckpointPhase::Finalizing => 1,
            ReceiverCheckpointPhase::Committed => 2,
        });
        bytes.extend_from_slice(&(self.pending.len() as u32).to_be_bytes());
        debug_assert_eq!(bytes.len(), FIXED);
        bytes.extend_from_slice(&self.pending);
        let hash = checksum(&bytes);
        bytes.extend_from_slice(&hash);
        Ok(bytes)
    }

    /// Decode a complete bounded record. No trailing-data or partial-history fallback.
    pub fn from_canonical_bytes(bytes: &[u8]) -> io::Result<Self> {
        if !(FIXED + 32..=MAX_RECEIVER_CHECKPOINT_BYTES).contains(&bytes.len()) { return Err(invalid()); }
        let body = bytes.len() - 32;
        let length = u32::from_be_bytes(bytes[281..285].try_into().expect("bounded length")) as usize;
        if &bytes[..8] != MAGIC || length != body - FIXED || bytes[body..] != checksum(&bytes[..body]) {
            return Err(invalid());
        }
        let offered: [u8; OFFER_BYTES] = bytes[40..100].try_into().expect("bounded offer");
        let agreed: [u8; OFFER_BYTES] = bytes[100..160].try_into().expect("bounded agreement");
        let hello = decode_offer(&agreed).map_err(|_| invalid())?;
        let number = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("bounded number"));
        let saved = Self {
            client: NativeClientCertificateId::from_sha256(bytes[8..40].try_into().expect("bounded client")),
            offered, agreed,
            prefix: LiveStreamPrefix { stream_nonce: hello.nonce, epochs: number(160), bytes: number(168),
                chain: bytes[176..208].try_into().expect("bounded chain") },
            prefix_hash: bytes[208..240].try_into().expect("bounded hash"),
            pending_hash: bytes[240..272].try_into().expect("bounded pending hash"),
            used: u32::from_be_bytes(bytes[272..276].try_into().expect("bounded attempts")),
            maximum: u32::from_be_bytes(bytes[276..280].try_into().expect("bounded maximum")),
            phase: match bytes[280] {
                0 => ReceiverCheckpointPhase::Receiving,
                1 => ReceiverCheckpointPhase::Finalizing,
                2 => ReceiverCheckpointPhase::Committed,
                _ => return Err(invalid()),
            },
            pending: Zeroizing::new(bytes[FIXED..body].to_vec()),
        };
        saved.validate()?;
        Ok(saved)
    }

    /// Check one legal WAL transition; no skipped epoch, rebind, or erased uncertainty.
    pub fn validate_successor(&self, old: &Self) -> io::Result<()> {
        let agreed = self.validate()?;
        old.validate()?;
        if self.client != old.client || self.offered != old.offered || self.agreed != old.agreed
            || self.maximum != old.maximum || self.used < old.used
        { return Err(invalid()); }
        if self.prefix == old.prefix {
            if self.prefix_hash != old.prefix_hash { return Err(invalid()); }
            if !old.pending.is_empty() && (self.pending.as_slice() != old.pending.as_slice() || self.pending_hash != old.pending_hash) {
                return Err(invalid());
            }
            let legal = match old.phase {
                ReceiverCheckpointPhase::Receiving => self.phase != ReceiverCheckpointPhase::Committed,
                ReceiverCheckpointPhase::Finalizing => self.phase != ReceiverCheckpointPhase::Receiving,
                ReceiverCheckpointPhase::Committed => self.phase == ReceiverCheckpointPhase::Committed,
            };
            if !legal { return Err(invalid()); }
        } else {
            if old.pending.is_empty() || !self.pending.is_empty()
                || old.phase != ReceiverCheckpointPhase::Receiving || self.phase != ReceiverCheckpointPhase::Receiving
                || self.prefix != advance(&old.prefix, &old.pending, agreed.epoch_bytes, agreed.max_bytes).map_err(|_| invalid())?
                || self.prefix_hash != old.pending_hash
            { return Err(invalid()); }
        }
        Ok(())
    }

    async fn revalidate<R: AsyncRead + Unpin>(&self, source: &mut R) -> io::Result<(Sha256, Option<PendingEpoch>, u64)> {
        let agreed = self.validate()?;
        if self.phase == ReceiverCheckpointPhase::Finalizing {
            return Err(io::Error::other("receiver application commit remains unresolved"));
        }
        let mut hash = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0; MAX_EPOCH]);
        let mut remaining = self.prefix.bytes;
        while remaining != 0 {
            let window = usize::try_from(remaining).unwrap_or(usize::MAX).min(buffer.len());
            let count = read_checked(source, &mut buffer[..window]).await?;
            if count == 0 { return Err(invalid()); }
            hash.update(&buffer[..count]);
            remaining -= count as u64;
            crate::runtime::yield_now().await;
        }
        if digest(&hash) != self.prefix_hash { return Err(invalid()); }
        let mut written = 0;
        let pending = if self.pending.is_empty() { None } else {
            let bytes = &self.pending[EPOCH_HEADER_BYTES..];
            let mut entire = hash.clone();
            entire.update(bytes);
            if digest(&entire) != self.pending_hash { return Err(invalid()); }
            while written < bytes.len() {
                let count = read_checked(source, &mut buffer[..bytes.len() - written]).await?;
                if count == 0 { break; }
                if buffer[..count] != bytes[written..written + count] { return Err(invalid()); }
                written += count;
                crate::runtime::yield_now().await;
            }
            Some(PendingEpoch {
                payload: self.pending.to_vec(),
                next: advance(&self.prefix, &self.pending, agreed.epoch_bytes, agreed.max_bytes).map_err(|_| invalid())?,
                written,
            })
        };
        if read_checked(source, &mut buffer[..1]).await? != 0 { return Err(invalid()); }
        Ok((hash, pending, self.prefix.bytes + written as u64))
    }
}

async fn read_checked<R: AsyncRead + Unpin>(source: &mut R, bytes: &mut [u8]) -> io::Result<usize> {
    poll_fn(|cx| {
        let mut buffer = ReadBuf::new(bytes);
        match Pin::new(&mut *source).poll_read(cx, &mut buffer) {
            Poll::Pending if buffer.filled().is_empty() => Poll::Pending,
            Poll::Pending => Poll::Ready(Err(invalid())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
        }
    }).await
}

/// Receiver write-ahead persistence coupled to the actual sink.
///
/// Before returning Ok, synchronize all sink bytes in checkpoint.prefix(), then
/// persist this exact checkpoint. A pending epoch permits, but never requires,
/// additional surviving sink bytes matching a prefix of that epoch. A completed
/// prefix requires its entire bytes durable. Committed additionally records the
/// real successful application commit. Preserve a pending operation across dropped
/// waits; settle it before accepting a successor. Reject regression and bound history.
pub trait ReceiverCheckpointStore {
    /// Persist an exact, ordered checkpoint without invoking application commit.
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, checkpoint: &ReceiverCheckpoint) -> Poll<io::Result<()>>;
}

/// Persistence outcome retained independently of sink progress and local commit.
#[derive(Debug, thiserror::Error)]
#[error("receiver checkpoint did not permit the next protocol effect")]
pub struct ReceiverCheckpointPersistError {
    /// Storage ultimately succeeded, possibly after the operation was interrupted.
    pub stored: bool,
    /// Cancellation or timeout that caused a started persistence call to drain.
    pub interruption: Option<Box<LiveStreamError>>,
    /// Original store failure, never converted into a rollback claim.
    #[source]
    pub source: Option<io::Error>,
}

pub(super) type Store<'a> = Option<&'a mut (dyn ReceiverCheckpointStore + Send + Unpin)>;
struct Persist<'a> {
    store: &'a mut (dyn ReceiverCheckpointStore + Send + Unpin),
    checkpoint: &'a ReceiverCheckpoint,
    failed: &'a mut bool,
    started: bool,
}
impl Future for Persist<'_> {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.started = true;
        *this.failed = true;
        let result = Pin::new(&mut *this.store).poll_store(cx, this.checkpoint);
        *this.failed = matches!(&result, Poll::Ready(Err(_)));
        result
    }
}

impl<W: LiveStreamCommitSink + Unpin> ResumableReceiver<W> {
    pub(super) async fn checkpoint_boundary(&mut self, cx: &Cx, journal: &mut Store<'_>) -> Result<(), ResumeError> {
        let Some(store) = journal.as_mut() else { return Ok(()); };
        let checkpoint = ReceiverCheckpoint::capture(self)?;
        let mut operation = Persist { store: &mut **store, checkpoint: &checkpoint, failed: &mut self.failed, started: false };
        let observed = bounded(cx, self.config.operation_timeout, "receiver checkpoint", &mut operation).await;
        let (result, interruption) = match observed {
            Ok(()) => return Ok(()),
            Err(LiveStreamError::Io(error)) => (Err(error), None),
            Err(error) if !operation.started => {
                return Err(Box::new(ReceiverCheckpointPersistError {
                    stored: false, interruption: Some(Box::new(error)), source: None,
                }).into());
            }
            Err(error) => (operation.await, Some(Box::new(error))),
        };
        Err(Box::new(ReceiverCheckpointPersistError {
            stored: result.is_ok(), interruption, source: result.err(),
        }).into())
    }

    /// Receive one authenticated attempt with WAL barriers before writes and ACKs.
    ///
    /// Use the same store for every attempt. Ordinary receive explicitly bypasses
    /// persistence. A started store drains after cancellation/timeout; keep its
    /// owner and this receiver together in a scope-owned task until joined.
    pub async fn receive_journaled<S: ReceiverCheckpointStore + Send + Unpin>(
        &mut self, cx: &Cx, store: &mut S,
    ) -> ResumeReport {
        let receipt_reused = self.completed.is_some();
        let outcome = if self.failed { Err(ResumeError::LocalFailure) } else {
            match authorize(cx).map_err(ResumeError::from).and_then(|()| self.budget.take()) {
                Ok(()) => self.receive_inner_checkpointed(cx, Some(store)).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome, prefix: self.prefix.clone(), attempts: self.budget.used, receipt_reused,
            retained_epoch_bytes: self.pending.as_ref().map_or(0, |p| p.bytes().len()),
            sink_written_bytes: self.sink_written_bytes, completed: self.completed.clone(),
        }
    }
}

impl LiveStreamReceiver {
    /// Reconstruct one receiver from protected history and actual retained sink bytes.
    ///
    /// `retained` starts at byte zero and must describe this very sink; the sink
    /// must append at the verified physical end. The application owns exclusive
    /// access and validates persisted publication status. No file is truncated or
    /// repaired. Finalizing checkpoints are refused even when bytes look complete.
    /// Revalidation has one overall deadline and 64 KiB of scratch space. The
    /// original attempt ceiling is preserved. Fresh mTLS still gates every peer.
    pub async fn bind_restored_receiver<W: LiveStreamCommitSink + Unpin, R: AsyncRead + Unpin>(
        &self, cx: &Cx, address: SocketAddr, expected_client: NativeClientCertificateId,
        sink: W, mut retained: R, saved: ReceiverCheckpoint,
    ) -> Result<ResumableReceiver<W>, ResumeError> {
        authorize(cx)?;
        let agreed = saved.validate().map_err(LiveStreamError::from)?;
        if saved.client != expected_client { return Err(ResumeError::PeerIdentity); }
        if agreed.epoch_bytes > self.config.epoch_bytes || agreed.max_bytes > self.config.max_bytes {
            return Err(LiveStreamError::Configuration("receiver checkpoint exceeds current policy").into());
        }
        if saved.used >= saved.maximum { return Err(ResumeError::AttemptsExhausted); }
        let permit = self.admission.reserve()?;
        let (hash, pending, sink_written_bytes) = bounded(cx, self.config.operation_timeout,
            "receiver sink revalidation", saved.revalidate(&mut retained)).await?;
        drop(retained);
        let final_receipt = (saved.phase != ReceiverCheckpointPhase::Receiving).then(|| saved.receipt());
        let completed = saved.committed_receipt();
        let mut tls = (**self.acceptor.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        let listener = bounded(cx, self.config.operation_timeout, "restored receiver bind", TcpListener::bind(address)).await?;
        Ok(ResumableReceiver {
            sink, listener: Some(listener), acceptor: TlsAcceptor::new(tls), expected_client,
            config: self.config.clone(), offered: Some(saved.offered.to_vec()), agreed: Some(agreed),
            prefix: Some(saved.prefix), hash, pending, sink_written_bytes, final_receipt,
            commit_started: completed.is_some(), completed, failed: false,
            budget: Budget { used: saved.used, maximum: saved.maximum, _credit: Credit::Direct { _permit: permit } },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encode_epoch;

    fn sample() -> ReceiverCheckpoint {
        let hello = Hello { nonce: [7; 32], epoch_bytes: 8, max_bytes: 64 };
        let prefix = advance(&initial(&hello), &encode_epoch(&initial(&hello), b"prefix01"), 8, 64).unwrap();
        let pending = Zeroizing::new(encode_epoch(&prefix, b"abcdefgh"));
        ReceiverCheckpoint {
            client: NativeClientCertificateId::from_sha256([3; 32]),
            offered: offer(&hello).try_into().unwrap(), agreed: offer(&hello).try_into().unwrap(),
            prefix, prefix_hash: Sha256::digest(b"prefix01").into(),
            pending_hash: Sha256::digest(b"prefix01abcdefgh").into(),
            used: 1, maximum: 4, phase: ReceiverCheckpointPhase::Receiving, pending,
        }
    }
    fn flushed(old: &ReceiverCheckpoint) -> ReceiverCheckpoint {
        let mut saved = old.clone();
        let hello = saved.validate().unwrap();
        saved.prefix = advance(&old.prefix, &old.pending, hello.epoch_bytes, hello.max_bytes).unwrap();
        saved.prefix_hash = old.pending_hash;
        saved.pending = Zeroizing::new(Vec::new());
        saved
    }
    fn finish<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        let mut context = Context::from_waker(std::task::Waker::noop());
        for _ in 0..128 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) { return value; }
        }
        panic!("bounded in-memory revalidation did not complete");
    }

    #[test]
    fn canonical_receiver_checkpoint_roundtrips_exact_pending_bytes_and_client() {
        let saved = sample();
        let bytes = saved.to_canonical_bytes().unwrap();
        assert_eq!(MAX_RECEIVER_CHECKPOINT_BYTES, 65_933);
        assert_eq!(bytes.len(), FIXED + EPOCH_HEADER_BYTES + 8 + 32);
        let decoded = ReceiverCheckpoint::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_canonical_bytes().unwrap().as_slice(), bytes.as_slice());
        assert_eq!(decoded.client(), saved.client());
        assert_eq!(decoded.pending_bytes(), 8);
        assert_eq!(decoded.attempts(), 1);
        assert!(decoded.committed_receipt().is_none());
        assert!(!format!("{decoded:?}").contains("abcdefgh"));
    }

    #[test]
    fn receiver_decoder_refuses_torn_corrupt_oversized_and_noncanonical_data() {
        let valid = sample().to_canonical_bytes().unwrap();
        for end in 0..valid.len() { assert!(ReceiverCheckpoint::from_canonical_bytes(&valid[..end]).is_err()); }
        let mut longer = valid.to_vec(); longer.push(0);
        assert!(ReceiverCheckpoint::from_canonical_bytes(&longer).is_err());
        assert!(ReceiverCheckpoint::from_canonical_bytes(&vec![0; MAX_RECEIVER_CHECKPOINT_BYTES + 1]).is_err());
        for offset in [0, 32, 208, FIXED + EPOCH_HEADER_BYTES, valid.len() - 1] {
            let mut altered = valid.to_vec(); altered[offset] ^= 1;
            assert!(ReceiverCheckpoint::from_canonical_bytes(&altered).is_err());
        }
        for (offset, value) in [(280, 3), (284, 1)] {
            let mut altered = valid.to_vec(); altered[offset] = value;
            let body = altered.len() - 32; let hash = checksum(&altered[..body]);
            altered[body..].copy_from_slice(&hash);
            assert!(ReceiverCheckpoint::from_canonical_bytes(&altered).is_err());
        }
    }

    #[test]
    fn receiver_transitions_never_skip_wal_or_erase_commit_uncertainty() {
        let pending = sample();
        pending.validate_successor(&pending).unwrap();
        let stable = flushed(&pending); stable.validate_successor(&pending).unwrap();
        let mut committing = stable.clone(); committing.phase = ReceiverCheckpointPhase::Finalizing;
        committing.validate_successor(&stable).unwrap();
        let mut committed = committing.clone(); committed.phase = ReceiverCheckpointPhase::Committed;
        committed.validate_successor(&committing).unwrap();
        assert!(committed.validate_successor(&stable).is_err());
        assert!(stable.validate_successor(&committing).is_err());
        assert!(committing.validate_successor(&committed).is_err());
        assert!(pending.validate_successor(&stable).is_err());
        let mut wrong = stable; wrong.prefix.chain[0] ^= 1;
        assert!(wrong.validate_successor(&pending).is_err());
        let mut rebound = pending.clone(); rebound.client = NativeClientCertificateId::from_sha256([4; 32]);
        assert!(rebound.validate_successor(&pending).is_err());
        let mut retry = pending.clone(); retry.used += 1;
        retry.validate_successor(&pending).unwrap();
        assert!(pending.validate_successor(&retry).is_err());
    }

    #[test]
    fn every_surviving_pending_prefix_restores_its_actual_append_position() {
        let saved = sample();
        for tail in 0..=8 {
            let data = &b"prefix01abcdefgh"[..8 + tail];
            let (hash, pending, written) = finish(saved.revalidate(&mut &data[..])).unwrap();
            assert_eq!(digest(&hash), saved.prefix_hash);
            assert_eq!(written, (8 + tail) as u64);
            let pending = pending.unwrap();
            assert_eq!(pending.written, tail);
            assert_eq!(pending.bytes(), b"abcdefgh");
            assert_eq!(pending.next, flushed(&saved).prefix);
        }
    }

    #[test]
    fn revalidation_refuses_changed_prefix_tail_missing_bytes_and_unrecorded_suffix() {
        let saved = sample();
        for data in [b"prefix0".as_slice(), b"Xrefix01abc", b"prefix01abX", b"prefix01abcdefghX"] {
            assert!(finish(saved.revalidate(&mut &data[..])).is_err());
        }
        let stable = flushed(&saved);
        assert!(finish(stable.revalidate(&mut b"prefix01abcdefg".as_slice())).is_err());
        assert!(finish(stable.revalidate(&mut b"prefix01abcdefghX".as_slice())).is_err());
    }

    #[test]
    fn unresolved_publication_is_not_restarted_even_when_all_file_bytes_match() {
        let mut saved = flushed(&sample());
        saved.phase = ReceiverCheckpointPhase::Finalizing;
        assert!(finish(saved.revalidate(&mut b"prefix01abcdefgh".as_slice())).is_err());
        assert!(saved.committed_receipt().is_none());
        saved.phase = ReceiverCheckpointPhase::Committed;
        let (_, pending, written) = finish(saved.revalidate(&mut b"prefix01abcdefgh".as_slice())).unwrap();
        assert!(pending.is_none()); assert_eq!(written, 16);
        assert_eq!(saved.committed_receipt().unwrap().source_sha256, Sha256::digest(b"prefix01abcdefgh").as_slice());
    }
}

/// Private Unix data-file and bounded write-ahead journal ownership.
#[cfg(unix)]
#[path = "receiver_journal/file.rs"]
pub mod file;
