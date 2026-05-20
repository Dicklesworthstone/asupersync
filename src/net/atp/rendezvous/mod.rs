//! Rendezvous exchange model for ATP candidate sharing.

use crate::net::atp::stun::ObservedEndpoint;
use std::collections::{BTreeMap, BTreeSet};

/// ATP peer identity used by rendezvous candidate exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct a peer id from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPeerId`] when all bytes are zero.
    pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::MalformedPeerId);
        }
        Ok(Self(bytes))
    }

    /// Return canonical peer id bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Transfer-scoped nonce for one rendezvous session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferNonce(u128);

impl TransferNonce {
    /// Construct a non-zero transfer nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, Error> {
        if raw == 0 {
            return Err(Error::ZeroNonce);
        }
        Ok(Self(raw))
    }

    /// Return the raw nonce value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Candidate-scoped nonce used for replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateNonce(u128);

impl CandidateNonce {
    /// Construct a non-zero candidate nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, Error> {
        if raw == 0 {
            return Err(Error::ZeroNonce);
        }
        Ok(Self(raw))
    }

    /// Return the raw nonce value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Candidate transport advertised through rendezvous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateTransport {
    /// Direct UDP candidate.
    Udp,
    /// Relay candidate.
    Relay,
    /// IPv6 direct candidate.
    Ipv6,
}

/// Path candidate advertised to peers through rendezvous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    endpoint: ObservedEndpoint,
    transport: CandidateTransport,
    expires_at_micros: u64,
}

impl Candidate {
    /// Build a candidate endpoint.
    #[must_use]
    pub const fn new(
        endpoint: ObservedEndpoint,
        transport: CandidateTransport,
        expires_at_micros: u64,
    ) -> Self {
        Self {
            endpoint,
            transport,
            expires_at_micros,
        }
    }

    /// Advertised endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &ObservedEndpoint {
        &self.endpoint
    }

    /// Transport for the candidate.
    #[must_use]
    pub const fn transport(&self) -> CandidateTransport {
        self.transport
    }

    /// Expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }
}

/// Opaque candidate signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSignature(Vec<u8>);

impl CandidateSignature {
    /// Construct a non-empty opaque signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] when `bytes` is empty.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self(bytes))
    }

    /// Signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Signed rendezvous candidate from one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCandidate {
    peer_id: PeerId,
    transfer_nonce: TransferNonce,
    candidate_nonce: CandidateNonce,
    candidate: Candidate,
    signature: CandidateSignature,
}

impl SignedCandidate {
    /// Build a signed candidate value.
    #[must_use]
    pub const fn new(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
        candidate: Candidate,
        signature: CandidateSignature,
    ) -> Self {
        Self {
            peer_id,
            transfer_nonce,
            candidate_nonce,
            candidate,
            signature,
        }
    }

    /// Peer that signed the candidate.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Transfer nonce this candidate belongs to.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Candidate replay nonce.
    #[must_use]
    pub const fn candidate_nonce(&self) -> CandidateNonce {
        self.candidate_nonce
    }

    /// Candidate endpoint and transport.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// Opaque candidate signature.
    #[must_use]
    pub const fn signature(&self) -> &CandidateSignature {
        &self.signature
    }
}

/// Signature verifier used by the rendezvous service.
pub trait CandidateSignatureVerifier {
    /// Return true when the candidate signature is accepted.
    fn verify(&self, candidate: &SignedCandidate) -> bool;
}

impl<F> CandidateSignatureVerifier for F
where
    F: Fn(&SignedCandidate) -> bool,
{
    fn verify(&self, candidate: &SignedCandidate) -> bool {
        self(candidate)
    }
}

/// Quotas for one rendezvous session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Maximum candidates accepted per peer.
    pub max_candidates_per_peer: usize,
    /// Maximum total candidates accepted in one session.
    pub max_total_candidates: usize,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_candidates_per_peer: 8,
            max_total_candidates: 32,
        }
    }
}

/// One transfer rendezvous session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    nonce: TransferNonce,
    expires_at_micros: u64,
    quotas: Quotas,
    candidates: Vec<SignedCandidate>,
    seen_candidate_nonces: BTreeSet<(PeerId, CandidateNonce)>,
}

impl Session {
    /// Open a rendezvous session.
    #[must_use]
    pub fn new(nonce: TransferNonce, expires_at_micros: u64, quotas: Quotas) -> Self {
        Self {
            nonce,
            expires_at_micros,
            quotas,
            candidates: Vec::new(),
            seen_candidate_nonces: BTreeSet::new(),
        }
    }

    /// Transfer nonce for this session.
    #[must_use]
    pub const fn nonce(&self) -> TransferNonce {
        self.nonce
    }

    /// Session expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Accepted candidates.
    #[must_use]
    pub fn candidates(&self) -> &[SignedCandidate] {
        &self.candidates
    }

    fn is_expired(&self, now_micros: u64) -> bool {
        now_micros >= self.expires_at_micros
    }

    fn peer_candidate_count(&self, peer_id: PeerId) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.peer_id == peer_id)
            .count()
    }
}

/// In-memory rendezvous validator for deterministic tests and service logic.
#[derive(Debug, Default)]
pub struct Service {
    sessions: BTreeMap<TransferNonce, Session>,
}

impl Service {
    /// Construct an empty service.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    /// Open or replace a session.
    pub fn open_session(&mut self, session: Session) {
        self.sessions.insert(session.nonce, session);
    }

    /// Return a session by nonce.
    #[must_use]
    pub fn session(&self, nonce: TransferNonce) -> Option<&Session> {
        self.sessions.get(&nonce)
    }

    /// Validate and record one signed candidate.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the session is missing or expired, the
    /// candidate is expired, the signature verifier rejects it, the candidate
    /// nonce was already used for this peer, or quotas would be exceeded.
    pub fn register_candidate<V>(
        &mut self,
        now_micros: u64,
        signed: SignedCandidate,
        verifier: &V,
    ) -> Result<(), Error>
    where
        V: CandidateSignatureVerifier,
    {
        let session = self
            .sessions
            .get_mut(&signed.transfer_nonce)
            .ok_or(Error::UnknownSession)?;

        if session.is_expired(now_micros) {
            return Err(Error::ExpiredSession);
        }
        if now_micros >= signed.candidate.expires_at_micros {
            return Err(Error::ExpiredCandidate);
        }
        if !verifier.verify(&signed) {
            return Err(Error::InvalidSignature);
        }
        if session
            .seen_candidate_nonces
            .contains(&(signed.peer_id, signed.candidate_nonce))
        {
            return Err(Error::NonceReplay);
        }
        if session.candidates.len() >= session.quotas.max_total_candidates {
            return Err(Error::QuotaExceeded);
        }
        if session.peer_candidate_count(signed.peer_id) >= session.quotas.max_candidates_per_peer {
            return Err(Error::QuotaExceeded);
        }

        session
            .seen_candidate_nonces
            .insert((signed.peer_id, signed.candidate_nonce));
        session.candidates.push(signed);
        Ok(())
    }
}

/// Rendezvous validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Peer id was malformed.
    #[error("malformed peer id")]
    MalformedPeerId,
    /// Nonce value was zero.
    #[error("nonce is zero")]
    ZeroNonce,
    /// Candidate signature was invalid.
    #[error("invalid candidate signature")]
    InvalidSignature,
    /// Candidate transfer nonce did not match an open session.
    #[error("unknown rendezvous session")]
    UnknownSession,
    /// Rendezvous session has expired.
    #[error("rendezvous session expired")]
    ExpiredSession,
    /// Candidate has expired.
    #[error("candidate expired")]
    ExpiredCandidate,
    /// Candidate nonce was replayed by the same peer.
    #[error("candidate nonce replay")]
    NonceReplay,
    /// Session or peer quota would be exceeded.
    #[error("rendezvous quota exceeded")]
    QuotaExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::stun::{EndpointFamily, ObservedEndpoint};

    fn peer(byte: u8) -> PeerId {
        PeerId::new([byte; 32]).expect("peer id")
    }

    fn nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn candidate_nonce(raw: u128) -> CandidateNonce {
        CandidateNonce::new(raw).expect("candidate nonce")
    }

    fn endpoint(port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, "198.51.100.10", port).expect("endpoint")
    }

    fn signed_candidate(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
    ) -> SignedCandidate {
        SignedCandidate::new(
            peer_id,
            transfer_nonce,
            candidate_nonce,
            Candidate::new(endpoint(50_000), CandidateTransport::Udp, 1_000),
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        )
    }

    #[test]
    fn accepts_valid_signed_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        service
            .register_candidate(10, signed, &|candidate: &SignedCandidate| {
                candidate.signature().bytes() == [1, 2, 3]
            })
            .expect("accepted");

        assert_eq!(
            service
                .session(transfer_nonce)
                .expect("session")
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_malformed_peer_id_and_zero_nonces() {
        assert_eq!(
            PeerId::new([0; 32]).expect_err("zero peer"),
            Error::MalformedPeerId
        );
        assert_eq!(
            TransferNonce::new(0).expect_err("zero transfer"),
            Error::ZeroNonce
        );
        assert_eq!(
            CandidateNonce::new(0).expect_err("zero candidate"),
            Error::ZeroNonce
        );
    }

    #[test]
    fn rejects_bad_signature_and_nonce_replay() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(10, signed.clone(), &|_: &SignedCandidate| false)
                .expect_err("bad signature"),
            Error::InvalidSignature
        );

        service
            .register_candidate(10, signed.clone(), &|_: &SignedCandidate| true)
            .expect("first use");
        assert_eq!(
            service
                .register_candidate(10, signed, &|_: &SignedCandidate| true)
                .expect_err("replay"),
            Error::NonceReplay
        );
    }

    #[test]
    fn rejects_expired_session_and_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 20, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(20, signed, &|_: &SignedCandidate| true)
                .expect_err("expired session"),
            Error::ExpiredSession
        );

        let live_nonce = nonce(8);
        service.open_session(Session::new(live_nonce, 1_000, Quotas::default()));
        let expired_candidate = SignedCandidate::new(
            peer(1),
            live_nonce,
            candidate_nonce(10),
            Candidate::new(endpoint(50_001), CandidateTransport::Udp, 20),
            CandidateSignature::new(vec![1]).expect("signature"),
        );
        assert_eq!(
            service
                .register_candidate(20, expired_candidate, &|_: &SignedCandidate| true)
                .expect_err("expired candidate"),
            Error::ExpiredCandidate
        );
    }

    #[test]
    fn enforces_peer_and_total_quotas() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 1,
                max_total_candidates: 2,
            },
        ));

        service
            .register_candidate(
                10,
                signed_candidate(peer(1), transfer_nonce, candidate_nonce(1)),
                &|_: &SignedCandidate| true,
            )
            .expect("first peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(1), transfer_nonce, candidate_nonce(2)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("peer quota"),
            Error::QuotaExceeded
        );

        service
            .register_candidate(
                10,
                signed_candidate(peer(2), transfer_nonce, candidate_nonce(3)),
                &|_: &SignedCandidate| true,
            )
            .expect("second peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(3), transfer_nonce, candidate_nonce(4)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("total quota"),
            Error::QuotaExceeded
        );
    }
}
