//! Write-ahead sender checkpoints for restart before source EOF.
//!
//! Save one pending epoch BEFORE sending it. After process loss the receiver can
//! be at the saved prefix or exactly that epoch ahead, never an arbitrary offset.
//! Restoration rereads and verifies the consumed source prefix before networking;
//! it requires a replayable source positioned at zero and a retained receiver.
//! This does not restore receiver process state or promise exactly-once effects.
//!
//! Checkpoints retain hashes and lengths, not source bytes. Protect their storage
//! and provenance. Checksums detect corruption, not malicious editing/rollback.

use super::{
    Budget, Credit, Hello, LiveStreamError, LiveStreamPrefix,
    LiveStreamReceipt, LiveStreamSender, OFFER_BYTES, PendingEpoch, RESUMABLE_LIVE_ALPN,
    ResumableSender, ResumeError, ResumeReport, advance, authorize, bounded, decode_offer,
    digest, encode_epoch, encode_prefix, initial, offer, validate_attempts,
};
use crate::cx::Cx;
use crate::io::{AsyncRead, ReadBuf};
use crate::tls::TlsConnector;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ATPSND01";
const FIXED: usize = 314;
const MAX_NAME: usize = 253;
const PENDING_BYTES: usize = 68;
/// Maximum encoded metadata snapshot, including one pending-epoch digest.
pub const MAX_SENDER_CHECKPOINT_BYTES: usize = FIXED + MAX_NAME + PENDING_BYTES + 32;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid sender checkpoint or source prefix")
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.sender-checkpoint.v1");
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, PartialEq, Eq)]
struct PendingIntent {
    bytes: u32,
    hash: [u8; 32],
    chain: [u8; 32],
}

/// Immutable local continuation, never delivery evidence or remote authority.
///
/// A snapshot retains the original endpoint, negotiated limits, server leaf pin,
/// acknowledged prefix and a possible pending epoch. Unread source bytes are not
/// captured: the application must provide the same stable source on restart.
#[derive(Clone)]
pub struct SenderCheckpoint {
    offered: [u8; OFFER_BYTES],
    agreed: [u8; OFFER_BYTES],
    prefix: LiveStreamPrefix,
    prefix_hash: [u8; 32],
    read_hash: [u8; 32],
    server: [u8; 32],
    remote: SocketAddr,
    domain: String,
    used: u32,
    maximum: u32,
    eof: bool,
    pending: Option<PendingIntent>,
}

impl fmt::Debug for SenderCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenderCheckpoint")
            .field("acknowledged_bytes", &self.prefix.bytes)
            .field("pending_bytes", &self.pending_bytes())
            .field("source_eof", &self.eof)
            .field("attempts", &self.used)
            .finish_non_exhaustive()
    }
}

impl SenderCheckpoint {
    pub(super) fn capture<R>(sender: &ResumableSender<R>) -> Result<Self, ResumeError> {
        if sender.failed { return Err(ResumeError::LocalFailure); }
        let agreed = sender.agreed.as_ref().ok_or(ResumeError::LocalFailure)?;
        let prefix = sender.prefix.clone().ok_or(ResumeError::LocalFailure)?;
        let mut read_hash = sender.hash.clone();
        if let Some(pending) = &sender.pending { read_hash.update(pending.bytes()); }
        let saved = Self {
            offered: offer(&sender.offered).try_into().map_err(|_| ResumeError::LocalFailure)?,
            agreed: offer(agreed).try_into().map_err(|_| ResumeError::LocalFailure)?,
            prefix, prefix_hash: digest(&sender.hash), read_hash: read_hash.finalize().into(),
            server: sender.peer.ok_or(ResumeError::PeerIdentity)?, remote: sender.remote,
            domain: sender.domain.clone(), used: sender.budget.used, maximum: sender.budget.maximum,
            eof: sender.final_receipt.is_some(),
            pending: sender.pending.as_ref().map(|p| PendingIntent {
                bytes: p.bytes().len() as u32, hash: Sha256::digest(p.bytes()).into(), chain: p.next.chain,
            }),
        };
        saved.validate().map_err(LiveStreamError::from)?;
        if sender.final_receipt.as_ref().is_some_and(|receipt| {
            receipt.prefix != saved.prefix || receipt.source_sha256 != saved.prefix_hash
        }) { return Err(ResumeError::LocalFailure); }
        Ok(saved)
    }

    /// Last acknowledged prefix, not a completed transfer.
    #[must_use]
    pub fn acknowledged_prefix(&self) -> &LiveStreamPrefix { &self.prefix }
    /// Source bytes to reread locally before continuing, including the pending epoch.
    #[must_use]
    pub fn source_position(&self) -> u64 { self.prefix.bytes + self.pending_bytes() as u64 }
    /// Pending data length, excluding its protocol header.
    #[must_use]
    pub fn pending_bytes(&self) -> usize { self.pending.as_ref().map_or(0, |pending| pending.bytes as usize) }
    /// True only for a captured real source EOF, not a peer completion flag.
    #[must_use]
    pub const fn source_eof(&self) -> bool { self.eof }
    /// Original destination; restore requires the caller to agree explicitly.
    #[must_use]
    pub const fn remote(&self) -> SocketAddr { self.remote }
    /// Saved cumulative admitted attempts.
    #[must_use]
    pub const fn attempts(&self) -> u32 { self.used }
    /// Original attempt ceiling; restore never resets it.
    #[must_use]
    pub const fn maximum_attempts(&self) -> u32 { self.maximum }

    fn validate(&self) -> io::Result<Hello> {
        let offered = decode_offer(&self.offered).map_err(|_| invalid())?;
        let agreed = decode_offer(&self.agreed).map_err(|_| invalid())?;
        let p = &self.prefix;
        if offered.nonce != agreed.nonce || p.stream_nonce != agreed.nonce
            || agreed.epoch_bytes > offered.epoch_bytes || agreed.max_bytes > offered.max_bytes
            || p.bytes > agreed.max_bytes || p.epochs > p.bytes
            || (p.bytes == 0) != (p.epochs == 0)
            || p.bytes > p.epochs.saturating_mul(agreed.epoch_bytes as u64)
            || self.domain.is_empty() || self.domain.len() > MAX_NAME || !self.domain.is_ascii()
            || ServerName::try_from(self.domain.clone()).is_err() || self.remote.port() == 0
            || validate_attempts(self.maximum).is_err() || self.used == 0 || self.used > self.maximum
            || (self.eof && self.pending.is_some())
        { return Err(invalid()); }
        if p.bytes == 0 && (*p != initial(&agreed) || self.prefix_hash != digest(&Sha256::new())) {
            return Err(invalid());
        }
        if let Some(pending) = &self.pending {
            if pending.bytes == 0 || pending.bytes as usize > agreed.epoch_bytes
                || p.bytes.checked_add(u64::from(pending.bytes)).is_none_or(|bytes| bytes > agreed.max_bytes)
                || p.epochs.checked_add(1).is_none()
            { return Err(invalid()); }
        } else if self.prefix_hash != self.read_hash { return Err(invalid()); }
        Ok(agreed)
    }

    /// Encode one bounded, checksummed snapshot. The returned plaintext buffer
    /// is zeroized on drop; copied/exported bytes remain the caller's concern.
    pub fn to_canonical_bytes(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(FIXED + self.domain.len() + PENDING_BYTES + 32));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.offered);
        bytes.extend_from_slice(&self.agreed);
        bytes.extend_from_slice(&encode_prefix(&self.prefix));
        bytes.extend_from_slice(&self.prefix_hash);
        bytes.extend_from_slice(&self.read_hash);
        bytes.extend_from_slice(&self.server);
        let mut address = [0; 27];
        match self.remote {
            SocketAddr::V4(remote) => {
                address[0] = 4; address[1..5].copy_from_slice(&remote.ip().octets());
            }
            SocketAddr::V6(remote) => {
                address[0] = 6; address[1..17].copy_from_slice(&remote.ip().octets());
                address[19..23].copy_from_slice(&remote.flowinfo().to_be_bytes());
                address[23..27].copy_from_slice(&remote.scope_id().to_be_bytes());
            }
        }
        address[17..19].copy_from_slice(&self.remote.port().to_be_bytes());
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&self.used.to_be_bytes());
        bytes.extend_from_slice(&self.maximum.to_be_bytes());
        bytes.push(u8::from(self.eof));
        bytes.extend_from_slice(&(self.domain.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(if self.pending.is_some() { PENDING_BYTES as u32 } else { 0 }).to_be_bytes());
        debug_assert_eq!(bytes.len(), FIXED);
        bytes.extend_from_slice(self.domain.as_bytes());
        if let Some(pending) = &self.pending {
            bytes.extend_from_slice(&pending.bytes.to_be_bytes());
            bytes.extend_from_slice(&pending.hash);
            bytes.extend_from_slice(&pending.chain);
        }
        let hash = checksum(&bytes); bytes.extend_from_slice(&hash);
        Ok(bytes)
    }

    /// Decode only complete bounded history. No usable-prefix fallback or repair.
    pub fn from_canonical_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < FIXED + 33 || bytes.len() > MAX_SENDER_CHECKPOINT_BYTES { return Err(invalid()); }
        let body = bytes.len() - 32;
        let name = usize::from(u16::from_be_bytes(bytes[308..310].try_into().expect("bounded name")));
        let pending = u32::from_be_bytes(bytes[310..314].try_into().expect("bounded pending")) as usize;
        if &bytes[..8] != MAGIC || name == 0 || name > MAX_NAME
            || (pending != 0 && pending != PENDING_BYTES) || body != FIXED + name + pending
            || bytes[307] > 1 || bytes[body..] != checksum(&bytes[..body])
        { return Err(invalid()); }
        let offered: [u8; OFFER_BYTES] = bytes[8..68].try_into().expect("bounded offer");
        let agreed: [u8; OFFER_BYTES] = bytes[68..128].try_into().expect("bounded agreement");
        let hello = decode_offer(&agreed).map_err(|_| invalid())?;
        let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("bounded u64"));
        let address = &bytes[272..299];
        let port = u16::from_be_bytes(address[17..19].try_into().expect("bounded port"));
        let remote = match address[0] {
            4 if address[5..17] == [0; 12] && address[19..27] == [0; 8] =>
                SocketAddr::from((Ipv4Addr::new(address[1], address[2], address[3], address[4]), port)),
            6 => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&address[1..17]).expect("bounded IPv6")), port,
                u32::from_be_bytes(address[19..23].try_into().expect("bounded flow")),
                u32::from_be_bytes(address[23..27].try_into().expect("bounded scope")),
            )),
            _ => return Err(invalid()),
        };
        let saved = Self {
            offered, agreed, remote,
            prefix: LiveStreamPrefix { stream_nonce: hello.nonce, epochs: u64_at(128), bytes: u64_at(136),
                chain: bytes[144..176].try_into().expect("bounded chain") },
            prefix_hash: bytes[176..208].try_into().expect("bounded hash"),
            read_hash: bytes[208..240].try_into().expect("bounded read hash"),
            server: bytes[240..272].try_into().expect("bounded pin"),
            used: u32::from_be_bytes(bytes[299..303].try_into().expect("bounded attempts")),
            maximum: u32::from_be_bytes(bytes[303..307].try_into().expect("bounded ceiling")),
            eof: bytes[307] == 1,
            domain: std::str::from_utf8(&bytes[FIXED..FIXED + name]).map_err(|_| invalid())?.to_owned(),
            pending: if pending == 0 { None } else {
                let part = &bytes[FIXED + name..body];
                Some(PendingIntent {
                    bytes: u32::from_be_bytes(part[..4].try_into().expect("bounded epoch length")),
                    hash: part[4..36].try_into().expect("bounded epoch digest"),
                    chain: part[36..68].try_into().expect("bounded next chain"),
                })
            },
        };
        saved.validate()?; Ok(saved)
    }

    /// Validate a journal transition, rejecting rebind, skipped epochs, changed
    /// pending input, lost EOF, and backwards attempt counters.
    pub fn validate_successor(&self, old: &Self) -> io::Result<()> {
        self.validate()?;
        old.validate()?;
        if self.offered != old.offered || self.agreed != old.agreed || self.remote != old.remote
            || self.domain != old.domain || self.server != old.server || self.maximum != old.maximum
            || self.used < old.used || (old.eof && !self.eof)
        { return Err(invalid()); }
        if self.prefix == old.prefix {
            if self.prefix_hash != old.prefix_hash
                || (old.pending.is_some() && (self.pending != old.pending || self.read_hash != old.read_hash))
            { return Err(invalid()); }
        } else {
            let pending = old.pending.as_ref().ok_or_else(invalid)?;
            if old.eof || self.prefix.epochs != old.prefix.epochs.checked_add(1).ok_or_else(invalid)?
                || self.prefix.bytes != old.prefix.bytes.checked_add(u64::from(pending.bytes)).ok_or_else(invalid)?
                || self.prefix.chain != pending.chain || self.prefix_hash != old.read_hash
            { return Err(invalid()); }
        }
        Ok(())
    }
}

/// Persistence for successive snapshots of one operation. Implementations must
/// reject another operation/regression, keep Pending state, and bound history.
/// Successful storage is not receipt of a remote ACK or final Proof.
pub trait SenderCheckpointStore {
    /// Persist the exact next snapshot. Repeating it must be idempotent.
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, checkpoint: &SenderCheckpoint) -> Poll<io::Result<()>>;
}

/// A journal barrier failed or was interrupted, so this step sent no new data.
#[derive(Debug, thiserror::Error)]
#[error("sender journal did not permit further transmission")]
pub struct SenderCheckpointPersistError {
    /// The store eventually succeeded, possibly after interruption.
    pub stored: bool,
    /// Cancellation/deadline that caused a started operation to be drained.
    pub interruption: Option<Box<LiveStreamError>>,
    /// Original storage failure, independently retained.
    #[source]
    pub source: Option<io::Error>,
}

struct Persist<'a, S: ?Sized> {
    store: &'a mut S, checkpoint: &'a SenderCheckpoint, failed: &'a mut bool, started: bool,
}
impl<S: SenderCheckpointStore + Unpin + ?Sized> Future for Persist<'_, S> {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.started = true;
        *this.failed = true; // A caught store panic cannot leave the sender usable.
        let result = Pin::new(&mut *this.store).poll_store(cx, this.checkpoint);
        *this.failed = matches!(&result, Poll::Ready(Err(_)));
        result
    }
}

pub(super) async fn persist<S: SenderCheckpointStore + Unpin + ?Sized>(
    cx: &Cx, timeout: Duration, store: &mut S, saved: &SenderCheckpoint, failed: &mut bool,
) -> Result<(), ResumeError> {
    let mut operation = Persist { store, checkpoint: saved, failed, started: false };
    let observed = bounded(cx, timeout, "sender epoch checkpoint", &mut operation).await;
    let (result, interruption) = match observed {
        Ok(()) => return Ok(()),
        Err(LiveStreamError::Io(error)) => (Err(error), None),
        Err(error) if !operation.started => {
            return Err(Box::new(SenderCheckpointPersistError {
                stored: false, interruption: Some(Box::new(error)), source: None,
            }).into());
        }
        Err(error) => (operation.await, Some(Box::new(error))),
    };
    Err(Box::new(SenderCheckpointPersistError {
        stored: result.is_ok(), interruption, source: result.err(),
    }).into())
}

impl<R: AsyncRead + Unpin> ResumableSender<R> {
    /// Persist before each epoch/final request and before reconnecting a saved
    /// operation. Keep this same store for every attempt; ordinary send bypasses
    /// journaling. Reopen its latest snapshot with a replayable source on restart.
    pub async fn send_journaled<S: SenderCheckpointStore + Send + Unpin>(
        &mut self, cx: &Cx, store: &mut S,
    ) -> ResumeReport {
        let reused = self.completed.is_some();
        let outcome = if let Some(receipt) = &self.completed { Ok(receipt.clone()) }
        else if self.failed { Err(ResumeError::LocalFailure) }
        else {
            match authorize(cx).map_err(ResumeError::from).and_then(|()| self.budget.take()) {
                Ok(()) => self.send_inner_journaled(cx, None, Some(store)).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome, prefix: self.prefix.clone(), attempts: self.budget.used, receipt_reused: reused,
            retained_epoch_bytes: self.pending.as_ref().map_or(0, |p| p.bytes().len()),
            sink_written_bytes: 0, completed: self.completed.clone(),
        }
    }
}

async fn read_checked<R: AsyncRead + Unpin>(source: &mut R, bytes: &mut [u8]) -> io::Result<usize> {
    poll_fn(|cx| {
        let mut out = ReadBuf::new(bytes);
        match Pin::new(&mut *source).poll_read(cx, &mut out) {
            Poll::Pending if out.filled().is_empty() => Poll::Pending,
            Poll::Pending => Poll::Ready(Err(invalid())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(out.filled().len())),
        }
    }).await
}

impl LiveStreamSender {
    /// Restore with a replayable source positioned at its beginning. Before any
    /// connection, reread/hash the acknowledged prefix and compare the pending
    /// bytes exactly. The source is returned positioned AFTER that pending epoch.
    /// Unread suffix stability remains the application's obligation.
    ///
    /// Current limits must cover the saved negotiation; endpoint/name/pin and
    /// cumulative attempt budget are preserved. Revalidation has one overall
    /// operation deadline and at most 64 KiB of buffering. Retain one exclusive
    /// journal owner and continue with send_journaled, not ordinary send.
    pub async fn restore_journaled_reader<R: AsyncRead + Unpin>(
        &self, cx: &Cx, remote: SocketAddr, mut source: R, saved: SenderCheckpoint,
    ) -> Result<ResumableSender<R>, ResumeError> {
        authorize(cx)?;
        let agreed = saved.validate().map_err(LiveStreamError::from)?;
        if remote != saved.remote || self.domain != saved.domain {
            return Err(ResumeError::Continuity("journal endpoint or TLS name changed"));
        }
        if agreed.max_bytes > self.config.max_bytes || agreed.epoch_bytes > self.config.epoch_bytes {
            return Err(LiveStreamError::Configuration("journal exceeds current transfer policy").into());
        }
        if saved.used >= saved.maximum { return Err(ResumeError::AttemptsExhausted); }
        let permit = self.admission.reserve()?;
        let mut hash = Sha256::new();
        let mut pending_payload = None;
        bounded(cx, self.config.operation_timeout, "sender source revalidation", async {
            let mut buffer = Zeroizing::new(vec![0; 65_536]);
            let mut remaining = saved.prefix.bytes;
            while remaining != 0 {
                let window = usize::try_from(remaining).unwrap_or(usize::MAX).min(buffer.len());
                let count = read_checked(&mut source, &mut buffer[..window]).await?;
                if count == 0 { return Err(invalid()); }
                hash.update(&buffer[..count]); remaining -= count as u64;
                crate::runtime::yield_now().await;
            }
            if digest(&hash) != saved.prefix_hash { return Err(invalid()); }
            let mut read_hash = hash.clone();
            if let Some(pending) = &saved.pending {
                let length = pending.bytes as usize;
                let mut offset = 0;
                while offset < length {
                    let count = read_checked(&mut source, &mut buffer[offset..length]).await?;
                    if count == 0 { return Err(invalid()); }
                    offset += count;
                    crate::runtime::yield_now().await;
                }
                let bytes = &buffer[..length];
                let hash: [u8; 32] = Sha256::digest(bytes).into();
                if hash != pending.hash { return Err(invalid()); }
                read_hash.update(bytes);
                let payload = encode_epoch(&saved.prefix, bytes);
                let next = advance(&saved.prefix, &payload, agreed.epoch_bytes, agreed.max_bytes)
                    .map_err(|_| invalid())?;
                if next.chain != pending.chain { return Err(invalid()); }
                pending_payload = Some(PendingEpoch { payload, next, written: 0 });
            }
            if digest(&read_hash) != saved.read_hash { return Err(invalid()); }
            if saved.eof && read_checked(&mut source, &mut buffer[..1]).await? != 0 { return Err(invalid()); }
            Ok(())
        }).await?;
        let pending = pending_payload;
        let final_receipt = saved.eof.then(|| LiveStreamReceipt {
            prefix: saved.prefix.clone(), source_sha256: saved.prefix_hash,
        });
        let offered = decode_offer(&saved.offered)?;
        let mut tls = (**self.connector.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        Ok(ResumableSender {
            source, connector: TlsConnector::new(tls), domain: self.domain.clone(), remote,
            config: self.config.clone(), offered, agreed: Some(agreed), peer: Some(saved.server),
            prefix: Some(saved.prefix), hash, pending, buffer: Vec::new(), final_receipt,
            completed: None, failed: false,
            budget: Budget { used: saved.used, maximum: saved.maximum, _credit: Credit::Direct { _permit: permit } },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SenderCheckpoint {
        let hello = Hello { nonce: [9; 32], epoch_bytes: 8, max_bytes: 64 };
        let first = encode_epoch(&initial(&hello), b"abcdefgh");
        let prefix = advance(&initial(&hello), &first, 8, 64).unwrap();
        let second = encode_epoch(&prefix, b"ijklmnop");
        let next = advance(&prefix, &second, 8, 64).unwrap();
        SenderCheckpoint {
            offered: offer(&hello).try_into().unwrap(), agreed: offer(&hello).try_into().unwrap(),
            prefix, prefix_hash: Sha256::digest(b"abcdefgh").into(),
            read_hash: Sha256::digest(b"abcdefghijklmnop").into(), server: [3; 32],
            remote: "127.0.0.1:9443".parse().unwrap(), domain: "localhost".to_owned(),
            used: 1, maximum: 4, eof: false,
            pending: Some(PendingIntent { bytes: 8, hash: Sha256::digest(b"ijklmnop").into(), chain: next.chain }),
        }
    }

    fn acknowledged(old: &SenderCheckpoint) -> SenderCheckpoint {
        let mut next = old.clone();
        next.prefix.epochs += 1;
        next.prefix.bytes += old.pending_bytes() as u64;
        next.prefix.chain = old.pending.as_ref().unwrap().chain;
        next.prefix_hash = old.read_hash;
        next.pending = None;
        next
    }

    #[test]
    fn bounded_metadata_roundtrip_keeps_pending_and_attempt_identity() {
        let saved = sample(); let bytes = saved.to_canonical_bytes().unwrap();
        assert_eq!(MAX_SENDER_CHECKPOINT_BYTES, 667);
        assert_eq!(bytes.len(), FIXED + "localhost".len() + PENDING_BYTES + 32);
        assert!(!bytes.windows(8).any(|window| window == b"ijklmnop"));
        let loaded = SenderCheckpoint::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(loaded.to_canonical_bytes().unwrap().as_slice(), bytes.as_slice());
        assert_eq!(loaded.source_position(), 16);
        assert_eq!(loaded.attempts(), 1); assert_eq!(loaded.maximum_attempts(), 4);
        assert!(!loaded.source_eof()); assert_eq!(loaded.pending_bytes(), 8);
        assert!(!format!("{loaded:?}").contains("localhost"));
    }

    #[test]
    fn decoder_rejects_torn_corrupt_and_noncanonical_records() {
        let bytes = sample().to_canonical_bytes().unwrap();
        for end in 0..bytes.len() { assert!(SenderCheckpoint::from_canonical_bytes(&bytes[..end]).is_err()); }
        let mut changed = bytes.to_vec(); changed.push(0);
        assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        for offset in [0, 32, 200, 310, bytes.len() - 1] {
            let mut changed = bytes.to_vec(); changed[offset] ^= 1;
            assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        }
        for (offset, value) in [(277, 1), (307, 2), (313, 67)] {
            let mut changed = bytes.to_vec(); changed[offset] = value;
            let body = changed.len() - 32; let hash = checksum(&changed[..body]);
            changed[body..].copy_from_slice(&hash);
            assert!(SenderCheckpoint::from_canonical_bytes(&changed).is_err());
        }
    }

    #[test]
    fn successors_cannot_rebind_skip_or_change_a_pending_epoch() {
        let old = sample(); old.validate_successor(&old).unwrap();
        let mut attempt = old.clone(); attempt.used += 1;
        attempt.validate_successor(&old).unwrap();
        let next = acknowledged(&old); next.validate_successor(&old).unwrap();
        for changed in [
            { let mut c = old.clone(); c.server[0] ^= 1; c },
            { let mut c = old.clone(); c.maximum += 1; c },
            { let mut c = old.clone(); c.pending.as_mut().unwrap().hash[0] ^= 1; c },
            { let mut c = old.clone(); c.read_hash[0] ^= 1; c },
            { let mut c = next.clone(); c.prefix.chain[0] ^= 1; c },
            { let mut c = next.clone(); c.prefix.bytes += 1; c },
        ] { assert!(changed.validate_successor(&old).is_err()); }
        assert!(old.validate_successor(&next).is_err());
        assert!(old.validate_successor(&attempt).is_err());
    }

    #[test]
    fn eof_is_sticky_and_cannot_coexist_with_pending_data() {
        let old = sample(); let mut eof = acknowledged(&old); eof.eof = true;
        eof.validate_successor(&old).unwrap();
        let roundtrip = SenderCheckpoint::from_canonical_bytes(&eof.to_canonical_bytes().unwrap()).unwrap();
        assert!(roundtrip.source_eof());
        let mut changed = eof.clone(); changed.eof = false;
        assert!(changed.validate_successor(&eof).is_err());
        let mut invalid = old; invalid.eof = true;
        assert!(invalid.to_canonical_bytes().is_err());
    }

    #[test]
    fn empty_state_is_bound_to_the_negotiated_hello_and_empty_hash() {
        let mut saved = sample(); let hello = decode_offer(&saved.agreed).unwrap();
        saved.prefix = initial(&hello); saved.prefix_hash = digest(&Sha256::new());
        saved.read_hash = saved.prefix_hash; saved.pending = None; saved.eof = true;
        saved.validate().unwrap();
        let mut bad = saved.clone(); bad.prefix.chain[0] ^= 1; assert!(bad.validate().is_err());
        saved.read_hash[0] ^= 1; assert!(saved.validate().is_err());
    }
}
