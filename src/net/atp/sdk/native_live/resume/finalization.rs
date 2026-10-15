//! Sender restart at the source-EOF boundary, without replaying source bytes.
//!
//! A checkpoint is an unconfirmed finalization intent, NEVER a delivery receipt.
//! Persist it before ObjectComplete can cause receiver publication. A restored
//! sender has no source and sends only hello/finalization metadata. It refuses
//! a receiver without the exact committed prefix, rather than uploading again.
//! Both sides may restart only if the receiver separately restores a committed
//! receipt. Partial receiver state and pre-EOF sender state are not restored.

use super::{
    Budget, Credit, Hello, LiveStreamConfig, LiveStreamError, LiveStreamPrefix, LiveStreamReceipt,
    LiveStreamSender, OFFER_BYTES, RESUMABLE_LIVE_ALPN, RESUME_BYTES, ResumableSender, ResumeError,
    ResumeReport, Wire, authorize, bounded, decode_offer, encode_final, expect, initial, offer,
    peer_certificate, validate_attempts,
};
use crate::cx::Cx;
use crate::io::AsyncRead;
use crate::net::TcpStream;
use crate::net::atp::protocol::frames::FrameType;
use crate::tls::TlsConnector;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

const MAGIC: &[u8; 8] = b"ATPFNL01";
const FIXED_BYTES: usize = 269;
const MAX_NAME_BYTES: usize = 253;
/// Largest version-1 checkpoint, including its checksum. No source data is encoded.
pub const MAX_FINAL_PROOF_CHECKPOINT_BYTES: usize = FIXED_BYTES + MAX_NAME_BYTES + 32;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid final-Proof checkpoint")
}
fn checksum(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.sender-final-checkpoint.v1");
    hash.update(body);
    hash.finalize().into()
}

/// Immutable, bounded finalization intent captured after real source EOF.
///
/// Protect exported bytes as local authority and sensitive transfer metadata.
/// The checksum detects corruption, not malicious editing or rollback. This
/// contains no source bytes, private keys, TLS traffic secrets or success flag.
#[derive(Clone)]
pub struct FinalProofCheckpoint {
    offered: [u8; OFFER_BYTES],
    agreed: [u8; OFFER_BYTES],
    receipt: LiveStreamReceipt,
    server_certificate: [u8; 32],
    remote: SocketAddr,
    domain: String,
}

impl fmt::Debug for FinalProofCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalProofCheckpoint")
            .finish_non_exhaustive()
    }
}

impl FinalProofCheckpoint {
    pub(super) fn capture<R>(sender: &ResumableSender<R>) -> Result<Self, ResumeError> {
        let agreed = sender.agreed.as_ref().ok_or(ResumeError::LocalFailure)?;
        let receipt = sender
            .final_receipt
            .clone()
            .ok_or(ResumeError::LocalFailure)?;
        if sender.failed
            || sender.pending.is_some()
            || sender.prefix.as_ref() != Some(&receipt.prefix)
        {
            return Err(ResumeError::LocalFailure);
        }
        let saved = Self {
            offered: offer(&sender.offered)
                .try_into()
                .map_err(|_| ResumeError::LocalFailure)?,
            agreed: offer(agreed)
                .try_into()
                .map_err(|_| ResumeError::LocalFailure)?,
            receipt,
            server_certificate: sender.peer.ok_or(ResumeError::PeerIdentity)?,
            remote: sender.remote,
            domain: sender.domain.clone(),
        };
        saved.validate().map_err(LiveStreamError::from)?;
        Ok(saved)
    }

    /// Actual data length/hash/chain to finalize. This is NOT peer acknowledgment.
    #[must_use]
    pub fn intent(&self) -> &LiveStreamReceipt {
        &self.receipt
    }

    /// Original explicit destination. Restoring additionally requires caller agreement.
    #[must_use]
    pub const fn remote(&self) -> SocketAddr {
        self.remote
    }

    fn validate(&self) -> io::Result<Hello> {
        let offered = decode_offer(&self.offered).map_err(|_| invalid())?;
        let agreed = decode_offer(&self.agreed).map_err(|_| invalid())?;
        let prefix = &self.receipt.prefix;
        if offered.nonce != agreed.nonce
            || prefix.stream_nonce != agreed.nonce
            || agreed.epoch_bytes > offered.epoch_bytes
            || agreed.max_bytes > offered.max_bytes
            || prefix.bytes > agreed.max_bytes
            || prefix.epochs > prefix.bytes
            || (prefix.epochs == 0) != (prefix.bytes == 0)
            || prefix.bytes > prefix.epochs.saturating_mul(agreed.epoch_bytes as u64)
            || self.domain.is_empty()
            || self.domain.len() > MAX_NAME_BYTES
            || !self.domain.is_ascii()
            || self.remote.port() == 0
            || ServerName::try_from(self.domain.clone()).is_err()
        {
            return Err(invalid());
        }
        if prefix.bytes == 0 {
            let empty: [u8; 32] = Sha256::digest(b"").into();
            if *prefix != initial(&agreed) || self.receipt.source_sha256 != empty {
                return Err(invalid());
            }
        }
        Ok(agreed)
    }

    /// Canonical version-1 bytes, at most 554 bytes. Plaintext; protect all copies.
    pub fn to_canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.domain.len() + 32);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.offered);
        bytes.extend_from_slice(&self.agreed);
        bytes.extend_from_slice(&encode_final(&self.receipt));
        bytes.extend_from_slice(&self.server_certificate);
        let mut address = [0; 27];
        match self.remote {
            SocketAddr::V4(remote) => {
                address[0] = 4;
                address[1..5].copy_from_slice(&remote.ip().octets());
            }
            SocketAddr::V6(remote) => {
                address[0] = 6;
                address[1..17].copy_from_slice(&remote.ip().octets());
                address[19..23].copy_from_slice(&remote.flowinfo().to_be_bytes());
                address[23..27].copy_from_slice(&remote.scope_id().to_be_bytes());
            }
        }
        address[17..19].copy_from_slice(&self.remote.port().to_be_bytes());
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&(self.domain.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(&checksum(&bytes));
        Ok(bytes)
    }

    /// Decode bounded, complete local history; no networking, fallback, or repair.
    pub fn from_canonical_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < FIXED_BYTES + 33 || bytes.len() > MAX_FINAL_PROOF_CHECKPOINT_BYTES {
            return Err(invalid());
        }
        let body = bytes.len() - 32;
        let name_len = usize::from(u16::from_be_bytes([bytes[267], bytes[268]]));
        if &bytes[..8] != MAGIC
            || name_len == 0
            || name_len > MAX_NAME_BYTES
            || body != FIXED_BYTES + name_len
            || bytes[body..] != checksum(&bytes[..body])
        {
            return Err(invalid());
        }
        let offered: [u8; OFFER_BYTES] = bytes[8..68].try_into().map_err(|_| invalid())?;
        let agreed: [u8; OFFER_BYTES] = bytes[68..128].try_into().map_err(|_| invalid())?;
        let hello = decode_offer(&agreed).map_err(|_| invalid())?;
        let number =
            |start| u64::from_be_bytes(bytes[start..start + 8].try_into().expect("bounded field"));
        let address = &bytes[240..267];
        let port = u16::from_be_bytes([address[17], address[18]]);
        let remote = match address[0] {
            4 if address[5..17] == [0; 12] && address[19..27] == [0; 8] => SocketAddr::from((
                Ipv4Addr::new(address[1], address[2], address[3], address[4]),
                port,
            )),
            6 => {
                let octets: [u8; 16] = address[1..17].try_into().map_err(|_| invalid())?;
                let flow = u32::from_be_bytes(address[19..23].try_into().expect("bounded flow"));
                let scope = u32::from_be_bytes(address[23..27].try_into().expect("bounded scope"));
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, flow, scope))
            }
            _ => return Err(invalid()),
        };
        let saved = Self {
            offered,
            agreed,
            remote,
            receipt: LiveStreamReceipt {
                prefix: LiveStreamPrefix {
                    stream_nonce: hello.nonce,
                    epochs: number(128),
                    bytes: number(136),
                    chain: bytes[144..176].try_into().map_err(|_| invalid())?,
                },
                source_sha256: bytes[176..208].try_into().map_err(|_| invalid())?,
            },
            server_certificate: bytes[208..240].try_into().map_err(|_| invalid())?,
            domain: std::str::from_utf8(&bytes[FIXED_BYTES..body])
                .map_err(|_| invalid())?
                .to_owned(),
        };
        saved.validate()?;
        Ok(saved)
    }

    fn check_remote_state(&self, state: &[u8]) -> Result<(), ResumeError> {
        if state.len() != RESUME_BYTES
            || state[..OFFER_BYTES] != self.agreed
            || state[OFFER_BYTES..RESUME_BYTES - 1] != encode_final(&self.receipt)
            || state[RESUME_BYTES - 1] != 1
        {
            return Err(ResumeError::Continuity(
                "receiver has not committed the exact saved final prefix",
            ));
        }
        Ok(())
    }
}

/// Local persistence barrier before a sender's first possible ObjectComplete.
///
/// Repeated attempts supply the identical checkpoint. Implementations must keep
/// in-flight state across Pending/dropped waits and reject a different intent.
/// Ok must mean the implementation's documented persistence boundary completed;
/// it never means remote success. A started operation is drained on cooperative
/// cancellation/timeout, so it must remain driveable without fresh Cx authority.
pub trait FinalProofStore {
    /// Persist the exact source-EOF intent, registering a waker while Pending.
    fn poll_store(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        checkpoint: &FinalProofCheckpoint,
    ) -> Poll<io::Result<()>>;
}

/// Independent storage and interruption outcomes. Finalization was not sent.
#[derive(Debug, thiserror::Error)]
#[error("sender final checkpoint did not permit finalization")]
pub struct FinalProofPersistError {
    /// Successful persistence despite interruption does not mean peer success.
    pub stored: bool,
    /// Cancellation or timeout that triggered draining, if one was observed.
    pub interruption: Option<Box<LiveStreamError>>,
    /// The actual storage error, preserved even when interruption also occurred.
    #[source]
    pub source: Option<io::Error>,
}

struct Store<'a, S: ?Sized> {
    store: &'a mut S,
    checkpoint: &'a FinalProofCheckpoint,
    started: bool,
}
impl<S: FinalProofStore + Unpin + ?Sized> Future for Store<'_, S> {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.started = true;
        Pin::new(&mut *this.store).poll_store(cx, this.checkpoint)
    }
}

pub(super) async fn persist<S: FinalProofStore + Unpin + ?Sized>(
    cx: &Cx,
    timeout: Duration,
    store: &mut S,
    checkpoint: &FinalProofCheckpoint,
) -> Result<(), ResumeError> {
    let mut operation = std::pin::pin!(Store {
        store,
        checkpoint,
        started: false
    });
    let observed = bounded(cx, timeout, "sender final checkpoint", operation.as_mut()).await;
    let (stored, interruption, source) = match observed {
        Ok(()) => return Ok(()),
        Err(LiveStreamError::Io(error)) => (false, None, Some(error)),
        Err(error) if !operation.as_ref().get_ref().started => (false, Some(Box::new(error)), None),
        Err(error) => match operation.as_mut().await {
            Ok(()) => (true, Some(Box::new(error)), None),
            Err(source) => (false, Some(Box::new(error)), Some(source)),
        },
    };
    Err(Box::new(FinalProofPersistError {
        stored,
        interruption,
        source,
    })
    .into())
}

impl<R: AsyncRead + Unpin> ResumableSender<R> {
    /// Send normally, but persist source-EOF state before requesting publication.
    ///
    /// Existing send remains unchanged and does not persist anything. Use this
    /// method for EVERY attempt of a checkpointed operation. A storage failure
    /// withholds ObjectComplete; earlier flushed epochs are not rolled back.
    /// Hard drop provides no report; retain the session/store and join its owner.
    pub async fn send_checkpointed<S: FinalProofStore + Send + Unpin>(
        &mut self,
        cx: &Cx,
        store: &mut S,
    ) -> ResumeReport {
        let receipt_reused = self.completed.is_some();
        let outcome = if let Some(receipt) = &self.completed {
            Ok(receipt.clone())
        } else if self.failed {
            Err(ResumeError::LocalFailure)
        } else {
            match authorize(cx)
                .map_err(ResumeError::from)
                .and_then(|()| self.budget.take())
            {
                Ok(()) => self.send_inner(cx, Some(store)).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome,
            prefix: self.prefix.clone(),
            attempts: self.budget.used,
            receipt_reused,
            retained_epoch_bytes: self.pending.as_ref().map_or(0, |epoch| epoch.bytes().len()),
            sink_written_bytes: 0,
            completed: self.completed.clone(),
        }
    }
}

/// Source-free finalization owner. Completion still requires a fresh exact Proof.
///
/// Its finite attempt budget and SDK credit survive dropped attempt futures;
/// creating a new owner is a new explicit recovery budget, not a persisted retry
/// counter. Keep one owner in a scope and join it; no automatic retry is performed.
pub struct FinalProofSender {
    checkpoint: FinalProofCheckpoint,
    connector: TlsConnector,
    config: LiveStreamConfig,
    budget: Budget,
    completed: bool,
}
impl fmt::Debug for FinalProofSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalProofSender")
            .field("attempts", &self.budget.used)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl LiveStreamSender {
    /// Restore only finalization, using newly provisioned mTLS credentials.
    ///
    /// Requires explicit agreement with the original endpoint and TLS name and
    /// enforces current size/epoch ceilings. The saved server leaf pin remains
    /// mandatory IN ADDITION to current WebPKI validation. The receiver still
    /// authorizes the client certificate. No source, socket or random nonce is
    /// created here. Protected checkpoint provenance is the caller's obligation.
    pub fn restore_final_proof(
        &self,
        cx: &Cx,
        remote: SocketAddr,
        checkpoint: FinalProofCheckpoint,
        max_attempts: u32,
    ) -> Result<FinalProofSender, ResumeError> {
        authorize(cx)?;
        validate_attempts(max_attempts)?;
        let agreed = checkpoint.validate().map_err(LiveStreamError::from)?;
        if checkpoint.remote != remote || checkpoint.domain != self.domain {
            return Err(ResumeError::Continuity(
                "checkpoint endpoint or TLS name changed",
            ));
        }
        if checkpoint.receipt.prefix.bytes > self.config.max_bytes
            || agreed.epoch_bytes > self.config.epoch_bytes
        {
            return Err(LiveStreamError::Configuration(
                "checkpoint exceeds current transfer policy",
            )
            .into());
        }
        let permit = self.admission.reserve()?;
        let mut tls = (**self.connector.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        Ok(FinalProofSender {
            checkpoint,
            connector: TlsConnector::new(tls),
            config: self.config.clone(),
            budget: Budget {
                used: 0,
                maximum: max_attempts,
                _credit: Credit::Direct { _permit: permit },
            },
            completed: false,
        })
    }
}

impl FinalProofSender {
    /// Recover a previously committed final Proof. Never transmits ObjectData.
    /// An incomplete remote state is refused, even for an empty object: recovery
    /// cannot accidentally initiate another publication under changed credentials.
    pub async fn send(&mut self, cx: &Cx) -> ResumeReport {
        let reused = self.completed;
        let outcome = if reused {
            Ok(self.checkpoint.receipt.clone())
        } else {
            match authorize(cx)
                .map_err(ResumeError::from)
                .and_then(|()| self.budget.take())
            {
                Ok(()) => self.attempt(cx).await,
                Err(error) => Err(error),
            }
        };
        ResumeReport {
            outcome,
            prefix: Some(self.checkpoint.receipt.prefix.clone()),
            attempts: self.budget.used,
            receipt_reused: reused,
            retained_epoch_bytes: 0,
            sink_written_bytes: 0,
            completed: self.completed.then(|| self.checkpoint.receipt.clone()),
        }
    }

    async fn attempt(&mut self, cx: &Cx) -> Result<LiveStreamReceipt, ResumeError> {
        let timeout = self.config.operation_timeout;
        let saved = &self.checkpoint;
        let tcp = bounded(
            cx,
            timeout,
            "final recovery connect",
            TcpStream::connect(saved.remote),
        )
        .await?;
        let tls = bounded(
            cx,
            timeout,
            "final recovery TLS",
            self.connector.connect(&saved.domain, tcp),
        )
        .await?;
        if peer_certificate(&tls)? != saved.server_certificate {
            return Err(ResumeError::PeerIdentity);
        }
        let mut wire = Wire::new(tls);
        bounded(
            cx,
            timeout,
            "final recovery hello",
            wire.send(FrameType::Handshake, saved.offered.to_vec()),
        )
        .await?;
        let state = bounded(cx, timeout, "final recovery state", wire.receive()).await?;
        saved.check_remote_state(expect(&state, FrameType::HandshakeAck)?)?;
        let payload = encode_final(&saved.receipt);
        bounded(
            cx,
            timeout,
            "final recovery request",
            wire.send(FrameType::ObjectComplete, payload.clone()),
        )
        .await?;
        let proof = bounded(cx, timeout, "final recovery Proof", wire.receive()).await?;
        if expect(&proof, FrameType::Proof)? != payload {
            return Err(ResumeError::Continuity("wrong recovered final Proof"));
        }
        self.completed = true;
        Ok(saved.receipt.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved() -> FinalProofCheckpoint {
        let hello = Hello {
            nonce: [7; 32],
            epoch_bytes: 8,
            max_bytes: 64,
        };
        let prefix = initial(&hello);
        FinalProofCheckpoint {
            offered: offer(&hello).try_into().unwrap(),
            agreed: offer(&hello).try_into().unwrap(),
            receipt: LiveStreamReceipt {
                prefix,
                source_sha256: Sha256::digest(b"").into(),
            },
            server_certificate: [9; 32],
            remote: "127.0.0.1:8443".parse().unwrap(),
            domain: "localhost".to_owned(),
        }
    }

    #[test]
    fn checkpoint_roundtrip_preserves_ipv4_and_scoped_ipv6() {
        for remote in [
            "127.0.0.1:8443".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 17, 23)),
        ] {
            let original = FinalProofCheckpoint { remote, ..saved() };
            let bytes = original.to_canonical_bytes().unwrap();
            assert!(bytes.len() <= MAX_FINAL_PROOF_CHECKPOINT_BYTES);
            let loaded = FinalProofCheckpoint::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(loaded.remote(), remote);
            assert_eq!(loaded.intent(), original.intent());
            assert_eq!(loaded.to_canonical_bytes().unwrap(), bytes);
            assert!(!format!("{loaded:?}").contains("localhost"));
        }
    }

    #[test]
    fn every_truncation_corruption_and_trailing_byte_is_refused() {
        let bytes = saved().to_canonical_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(FinalProofCheckpoint::from_canonical_bytes(&bytes[..end]).is_err());
        }
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(FinalProofCheckpoint::from_canonical_bytes(&changed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(FinalProofCheckpoint::from_canonical_bytes(&trailing).is_err());
        assert!(
            FinalProofCheckpoint::from_canonical_bytes(&vec![
                0;
                MAX_FINAL_PROOF_CHECKPOINT_BYTES + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn recomputed_checksums_do_not_bypass_shape_or_canonical_address_validation() {
        let bytes = saved().to_canonical_bytes().unwrap();
        // Empty hash/chain, epoch count, nonce agreement, address padding and name length.
        for index in [128, 144, 176, 8 + 16, 245, 267] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let body = changed.len() - 32;
            let digest = checksum(&changed[..body]);
            changed[body..].copy_from_slice(&digest);
            assert!(
                FinalProofCheckpoint::from_canonical_bytes(&changed).is_err(),
                "field {index}"
            );
        }
    }

    #[test]
    fn remote_completion_flag_never_substitutes_for_exact_final_prefix() {
        let saved = saved();
        let mut state = saved.agreed.to_vec();
        state.extend_from_slice(&encode_final(saved.intent()));
        state.push(0);
        assert!(saved.check_remote_state(&state).is_err());
        state[140] = 1;
        assert!(saved.check_remote_state(&state).is_ok());
        state[140] = 2;
        assert!(saved.check_remote_state(&state).is_err());
        state[140] = 1;
        for index in 0..140 {
            let mut changed = state.clone();
            changed[index] ^= 1;
            assert!(saved.check_remote_state(&changed).is_err());
        }
    }
}

/// Explicit private-file persistence for the source-EOF checkpoint.
#[cfg(unix)]
#[path = "finalization/file.rs"]
pub mod file;
