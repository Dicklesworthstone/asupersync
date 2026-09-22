//! Opt-in authenticated transport for the experimental PBFT normal-case path.
//!
//! Every packet signs its exact encoded bytes, including protocol version,
//! membership context, author, recipient, and payload length. Signature
//! verification precedes JSON decoding; author binding precedes consensus
//! admission. Keys and the
//! cluster incarnation come from the caller; this module generates no keys,
//! opens no sockets, and spawns no tasks.
//!
//! This is message authentication, NOT encryption, client authentication,
//! durable replay protection, or a Byzantine-fault-tolerance signoff. Exact
//! retransmissions are intentionally accepted: PBFT vote sets and application
//! receipts handle duplicates. A deployment must coordinate a new incarnation
//! after losing protocol/application state; reusing an old incarnation permits
//! old signed traffic to replay. View-change and new-view packets remain
//! unsupported. The unauthenticated legacy APIs remain unchanged.

use super::pbft::{PbftMessage, PbftTransport};
use super::types::ReplicaId;
use crate::error::{Error, ErrorKind, Result};
use nkeys::{KeyPair, KeyPairType};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"ASPBFT01";
const MEMBERSHIP_DOMAIN: &[u8] = b"asupersync::pbft::membership::v1\0";
const HEADER_LEN: usize = 52;
const SIGNATURE_LEN: usize = 64;
const BROADCAST: u32 = u32::MAX;
const MAX_MEMBERS: usize = 4096;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// A redacted refusal at the PBFT authentication boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PbftAuthError {
    /// The cluster identifier, roster, or payload limit is invalid.
    #[error("invalid PBFT authentication configuration")]
    Configuration,
    /// A roster entry is not a canonical public User NKey.
    #[error("invalid PBFT replica public key")]
    PublicKey,
    /// Two replica slots share one signing identity.
    #[error("PBFT replica public keys must be distinct")]
    DuplicateKey,
    /// The supplied signer cannot sign as its configured replica.
    #[error("PBFT signing key does not match the local replica")]
    SigningKey,
    /// An identifier is noncanonical, outside the roster, or claims another author.
    #[error("PBFT packet author is not authorized for this message")]
    Author,
    /// The packet is addressed to another replica or reflects a local message.
    #[error("PBFT packet recipient does not match this replica")]
    Recipient,
    /// The packet belongs to another cluster, incarnation, or ordered key roster.
    #[error("PBFT packet membership context mismatch")]
    Membership,
    /// The packet is truncated, has trailing bytes, or uses an unknown version.
    #[error("invalid PBFT authenticated packet framing")]
    Framing,
    /// The serialized message exceeds the explicitly configured bound.
    #[error("PBFT authenticated payload exceeds its configured limit")]
    PayloadTooLarge,
    /// The signature does not verify under the pinned author's key.
    #[error("PBFT packet signature verification failed")]
    Signature,
    /// A signed payload is not a supported PBFT message encoding.
    #[error("invalid PBFT message encoding")]
    Encoding,
    /// Authentication does not make the unfinished view-change protocol usable.
    #[error("PBFT authenticated view-change and new-view are unsupported")]
    UnsupportedPhase,
}

fn protocol_error(error: PbftAuthError) -> Error {
    Error::new(ErrorKind::InvalidInput).with_message(error.to_string())
}

/// Immutable, ordered replica keys bound to an explicit cluster incarnation.
///
/// Slot `i` is the canonical decimal replica id `i`. Only public User NKeys
/// are retained. Reordering/replacing keys, changing the cluster id, or changing
/// the incarnation changes the signed context. This is a static membership,
/// not an online reconfiguration or key-rotation protocol.
#[derive(Clone)]
pub struct PbftMembership {
    keys: Arc<Vec<KeyPair>>,
    context: [u8; 32],
}

impl fmt::Debug for PbftMembership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PbftMembership")
            .field("replica_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl PbftMembership {
    /// Pin a nonempty roster of at most 4096 distinct canonical User public keys.
    ///
    /// `cluster_id` must be nonzero and identify this deployment. The caller
    /// owns incarnation persistence and coordinated changes after state loss.
    pub fn new(
        cluster_id: [u8; 32],
        incarnation: u64,
        public_keys: &[String],
    ) -> std::result::Result<Self, PbftAuthError> {
        if cluster_id == [0; 32] || public_keys.is_empty() || public_keys.len() > MAX_MEMBERS {
            return Err(PbftAuthError::Configuration);
        }
        let count = u32::try_from(public_keys.len()).map_err(|_| PbftAuthError::Configuration)?;
        let mut hash = Sha256::new();
        hash.update(MEMBERSHIP_DOMAIN);
        hash.update(cluster_id);
        hash.update(incarnation.to_be_bytes());
        hash.update(count.to_be_bytes());
        let mut seen = HashSet::with_capacity(public_keys.len());
        let mut keys = Vec::with_capacity(public_keys.len());
        for public in public_keys {
            // Bound even the key parser's input; do not accept seed/private forms.
            if public.len() != 56 {
                return Err(PbftAuthError::PublicKey);
            }
            let key = KeyPair::from_public_key(public).map_err(|_| PbftAuthError::PublicKey)?;
            if key.key_pair_type() != KeyPairType::User || key.public_key() != *public {
                return Err(PbftAuthError::PublicKey);
            }
            if !seen.insert(public.as_str()) {
                return Err(PbftAuthError::DuplicateKey);
            }
            // Every public key has the same validated width and canonical role.
            hash.update(public.as_bytes());
            keys.push(key);
        }
        Ok(Self {
            keys: Arc::new(keys),
            context: hash.finalize().into(),
        })
    }

    /// Number of independently pinned replicas.
    #[must_use]
    pub fn replica_count(&self) -> usize {
        self.keys.len()
    }

    /// Public domain-separation digest carried by every packet.
    #[must_use]
    pub const fn context(&self) -> [u8; 32] {
        self.context
    }

    fn index(&self, replica: &ReplicaId) -> std::result::Result<u32, PbftAuthError> {
        // All accepted ids are at most four digits at the current roster bound.
        if replica.as_str().len() > 4 {
            return Err(PbftAuthError::Author);
        }
        let index = replica
            .as_str()
            .parse::<u32>()
            .map_err(|_| PbftAuthError::Author)?;
        if index as usize >= self.keys.len() || index.to_string() != replica.as_str() {
            return Err(PbftAuthError::Author);
        }
        Ok(index)
    }
}

/// Signing and verification authority for exactly one replica and membership.
///
/// Debug output never includes signing material or message contents. The
/// caller supplies an existing key; no ambient entropy or secret export occurs.
pub struct PbftAuthenticator {
    membership: PbftMembership,
    local: ReplicaId,
    index: u32,
    signer: KeyPair,
    max_payload_bytes: usize,
}

impl fmt::Debug for PbftAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PbftAuthenticator")
            .field("local", &self.local)
            .field("membership", &self.membership)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish_non_exhaustive()
    }
}

impl PbftAuthenticator {
    /// Validate signing ownership and a payload bound in `1..=16 MiB`.
    ///
    /// A public-only key is refused here, before any transport operation.
    pub fn new(
        membership: PbftMembership,
        local: ReplicaId,
        signer: KeyPair,
        max_payload_bytes: usize,
    ) -> std::result::Result<Self, PbftAuthError> {
        if max_payload_bytes == 0 || max_payload_bytes > MAX_PAYLOAD {
            return Err(PbftAuthError::Configuration);
        }
        let index = membership.index(&local)?;
        let verifier = &membership.keys[index as usize];
        if signer.key_pair_type() != KeyPairType::User
            || signer.public_key() != verifier.public_key()
        {
            return Err(PbftAuthError::SigningKey);
        }
        // Exercise signing without extracting/copying a private seed. This
        // transcript cannot be mistaken for a packet (different fixed prefix).
        let proof = signer
            .sign(&membership.context)
            .map_err(|_| PbftAuthError::SigningKey)?;
        verifier
            .verify(&membership.context, &proof)
            .map_err(|_| PbftAuthError::SigningKey)?;
        Ok(Self {
            membership,
            local,
            index,
            signer,
            max_payload_bytes,
        })
    }

    /// Canonical local replica id, bound to the signing key.
    #[must_use]
    pub fn local_replica(&self) -> &ReplicaId {
        &self.local
    }

    /// Pinned static membership.
    #[must_use]
    pub fn membership(&self) -> &PbftMembership {
        &self.membership
    }

    /// Maximum complete packet length, including the fixed header/signature.
    #[must_use]
    pub const fn max_packet_bytes(&self) -> usize {
        HEADER_LEN + self.max_payload_bytes + SIGNATURE_LEN
    }

    /// Sign a supported message for one replica, or for broadcast (`None`).
    ///
    /// Serialization writes into a bounded sink, so an oversized operation is
    /// rejected while encoding rather than after building an unbounded buffer.
    pub fn seal(
        &self,
        recipient: Option<&ReplicaId>,
        message: &PbftMessage,
    ) -> std::result::Result<Vec<u8>, PbftAuthError> {
        self.validate_author(self.index, message)?;
        let audience = recipient.map_or(Ok(BROADCAST), |id| self.membership.index(id))?;
        if audience == self.index {
            return Err(PbftAuthError::Recipient);
        }
        let mut payload = LimitedPayload {
            bytes: Vec::new(),
            limit: self.max_payload_bytes,
        };
        serde_json::to_writer(&mut payload, message).map_err(|_| PbftAuthError::PayloadTooLarge)?;
        let length =
            u32::try_from(payload.bytes.len()).map_err(|_| PbftAuthError::PayloadTooLarge)?;
        let mut packet = Vec::with_capacity(HEADER_LEN + payload.bytes.len() + SIGNATURE_LEN);
        packet.extend_from_slice(MAGIC);
        packet.extend_from_slice(&self.membership.context);
        packet.extend_from_slice(&self.index.to_be_bytes());
        packet.extend_from_slice(&audience.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&payload.bytes);
        let signature = self
            .signer
            .sign(&packet)
            .map_err(|_| PbftAuthError::SigningKey)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(PbftAuthError::SigningKey);
        }
        packet.extend_from_slice(&signature);
        Ok(packet)
    }

    /// Verify the exact wire transcript before decoding its bounded payload.
    ///
    /// Unknown authors, reflected/unintended traffic, tampering, configuration
    /// replay, truncation, and trailing bytes never reach the protocol engine.
    pub fn open(&self, packet: &[u8]) -> std::result::Result<PbftMessage, PbftAuthError> {
        if packet.len() > self.max_packet_bytes() {
            return Err(PbftAuthError::PayloadTooLarge);
        }
        if packet.len() < HEADER_LEN + SIGNATURE_LEN || &packet[..8] != MAGIC {
            return Err(PbftAuthError::Framing);
        }
        if packet[8..40] != self.membership.context {
            return Err(PbftAuthError::Membership);
        }
        let sender = u32::from_be_bytes(
            packet[40..44].try_into().map_err(|_| PbftAuthError::Framing)?,
        );
        let audience = u32::from_be_bytes(
            packet[44..48].try_into().map_err(|_| PbftAuthError::Framing)?,
        );
        let length = u32::from_be_bytes(
            packet[48..52].try_into().map_err(|_| PbftAuthError::Framing)?,
        );
        let length = usize::try_from(length).map_err(|_| PbftAuthError::PayloadTooLarge)?;
        if length > self.max_payload_bytes {
            return Err(PbftAuthError::PayloadTooLarge);
        }
        if packet.len() != HEADER_LEN + length + SIGNATURE_LEN {
            return Err(PbftAuthError::Framing);
        }
        let key = self
            .membership
            .keys
            .get(sender as usize)
            .ok_or(PbftAuthError::Author)?;
        if sender == self.index || (audience != BROADCAST && audience != self.index) {
            return Err(PbftAuthError::Recipient);
        }
        let (transcript, signature) = packet.split_at(HEADER_LEN + length);
        key.verify(transcript, signature)
            .map_err(|_| PbftAuthError::Signature)?;
        let message = serde_json::from_slice(&packet[HEADER_LEN..HEADER_LEN + length])
            .map_err(|_| PbftAuthError::Encoding)?;
        self.validate_author(sender, &message)?;
        Ok(message)
    }

    fn validate_author(
        &self,
        sender: u32,
        message: &PbftMessage,
    ) -> std::result::Result<(), PbftAuthError> {
        match message {
            // This authenticates the forwarding replica, NOT the client_id.
            PbftMessage::Request(_) => Ok(()),
            PbftMessage::PrePrepare { replica_id, view, .. } => {
                if self.membership.index(replica_id)? != sender
                    || view.primary(self.membership.replica_count()) != sender as usize
                {
                    return Err(PbftAuthError::Author);
                }
                Ok(())
            }
            PbftMessage::Prepare { replica_id, .. } | PbftMessage::Commit { replica_id, .. } => {
                if self.membership.index(replica_id)? != sender {
                    return Err(PbftAuthError::Author);
                }
                Ok(())
            }
            PbftMessage::ViewChange { .. } | PbftMessage::NewView { .. } => {
                Err(PbftAuthError::UnsupportedPhase)
            }
        }
    }
}

struct LimitedPayload {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedPayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PBFT payload limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Packet I/O beneath the authenticated PBFT adapter.
///
/// Implementations must bound receive allocation by `max_packet_bytes`, exclude
/// the local replica from broadcasts, and preserve packet boundaries. They own
/// framing, routing, connection lifecycle, and cancellation of partial I/O. An
/// error or a dropped send future does NOT prove nondelivery to any peer.
pub trait PbftPacketTransport: Send + Sync {
    /// Send a complete packet to one configured replica.
    fn send_packet(
        &self,
        recipient: &ReplicaId,
        packet: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Broadcast one complete packet, excluding the local replica.
    fn broadcast_packet(
        &self,
        packet: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Receive one packet with an allocation/size bound supplied before I/O.
    fn receive_packet(
        &self,
        max_packet_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// A [`PbftTransport`] that signs every send and verifies every receive.
///
/// Use the same local id and replica count when constructing the execution
/// driver. Only traffic through this adapter is authenticated: directly calling
/// the legacy driver's `process_message` is still a trusted, unsigned API.
pub struct AuthenticatedPbftTransport<T> {
    packets: T,
    auth: Arc<PbftAuthenticator>,
}

impl<T> AuthenticatedPbftTransport<T> {
    /// Attach explicit signing authority to an existing packet transport.
    #[must_use]
    pub fn new(packets: T, auth: Arc<PbftAuthenticator>) -> Self {
        Self { packets, auth }
    }

    /// Authentication context used on both directions of this transport.
    #[must_use]
    pub fn authenticator(&self) -> &PbftAuthenticator {
        &self.auth
    }
}

impl<T: PbftPacketTransport> PbftTransport for AuthenticatedPbftTransport<T> {
    async fn send_to_replica(&self, replica_id: &ReplicaId, message: PbftMessage) -> Result<()> {
        let packet = self
            .auth
            .seal(Some(replica_id), &message)
            .map_err(protocol_error)?;
        self.packets.send_packet(replica_id, packet).await
    }

    async fn broadcast(&self, message: PbftMessage) -> Result<()> {
        let packet = self.auth.seal(None, &message).map_err(protocol_error)?;
        self.packets.broadcast_packet(packet).await
    }

    async fn receive(&self) -> Result<PbftMessage> {
        let packet = self
            .packets
            .receive_packet(self.auth.max_packet_bytes())
            .await?;
        self.auth.open(&packet).map_err(protocol_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{
        ConsensusBatch, ConsensusRequest, MessageDigest, SequenceNumber, ViewNumber,
    };
    use crate::types::Time;
    use std::sync::Mutex;

    fn key(index: u8) -> KeyPair {
        let seed: [u8; 32] = Sha256::digest([index; 32]).into();
        KeyPair::new_from_raw(KeyPairType::User, seed).expect("fixture key")
    }

    fn roster() -> Vec<String> {
        (0..4).map(|i| key(i).public_key()).collect()
    }

    fn auth(index: u8, limit: usize) -> PbftAuthenticator {
        PbftAuthenticator::new(
            PbftMembership::new([7; 32], 19, &roster()).unwrap(),
            ReplicaId::new(index.to_string()), key(index), limit,
        ).unwrap()
    }

    fn request() -> ConsensusRequest {
        ConsensusRequest::new("client".into(), Time::from_millis(9), b"actual operation".to_vec())
    }

    fn vote(sender: &str) -> PbftMessage {
        PbftMessage::Prepare {
            view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
            digest: MessageDigest::from_bytes([5; 32]), replica_id: ReplicaId::new(sender.into()),
        }
    }

    fn forged_payload(signer: &PbftAuthenticator, message: &PbftMessage) -> Vec<u8> {
        // Deliberately bypass seal's author check to test RECEIVER enforcement.
        let payload = serde_json::to_vec(message).unwrap();
        let mut packet = MAGIC.to_vec();
        packet.extend_from_slice(&signer.membership.context);
        packet.extend_from_slice(&signer.index.to_be_bytes());
        packet.extend_from_slice(&BROADCAST.to_be_bytes());
        packet.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&payload);
        let signature = signer.signer.sign(&packet).unwrap();
        packet.extend_from_slice(&signature);
        packet
    }

    #[test]
    fn wire_golden_matches_independent_ed25519_implementation() {
        // Generated independently with Python cryptography/OpenSSL Ed25519,
        // SHA-256, RFC 4648 Base32, and CRC16/XMODEM, not by this Rust codec.
        let expected = hex::decode(concat!(
            "41535042465430310f6949ea0453c75e0bdc948621c35def771570bfea1c2c85c5d259101c814692",
            "00000000ffffffff0000007f7b2250726570617265223a7b2276696577223a302c2273657175656e",
            "6365223a312c22646967657374223a5b352c352c352c352c352c352c352c352c352c352c352c",
            "352c352c352c352c352c352c352c352c352c352c352c352c352c352c352c352c352c352c352c",
            "352c355d2c227265706c6963615f6964223a2230227d7d3b4f8749ec61df5099a1e17a79cee96d",
            "792931b6d11fe4e4e7129e4008d5126ceda654bb622fbb10338f944b77ca268a0677de6ec9e6c",
            "980c74d88638ed07e03",
        )).unwrap();
        assert_eq!(auth(0, 4096).seal(None, &vote("0")).unwrap(), expected);
        assert!(auth(1, 4096).open(&expected).is_ok());
    }

    #[test]
    fn authenticated_normal_case_round_trips_and_permits_exact_retransmission() {
        let sender = auth(0, 4096);
        let receiver = auth(1, 4096);
        let batch = ConsensusBatch::new(vec![request()]);
        let messages = [
            PbftMessage::Request(request()),
            PbftMessage::PrePrepare {
                view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
                digest: MessageDigest::of(&batch).unwrap(), batch, replica_id: ReplicaId::new("0".into()),
            },
            vote("0"),
            PbftMessage::Commit {
                view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
                digest: MessageDigest::from_bytes([5; 32]), replica_id: ReplicaId::new("0".into()),
            },
        ];
        for message in messages {
            let packet = sender.seal(None, &message).unwrap();
            for _ in 0..2 {
                let decoded = receiver.open(&packet).unwrap();
                assert_eq!(serde_json::to_vec(&decoded).unwrap(), serde_json::to_vec(&message).unwrap());
            }
            assert_eq!(packet, sender.seal(None, &message).unwrap());
        }
    }

    #[test]
    fn every_wire_byte_is_bound_and_every_truncation_is_rejected() {
        let sender = auth(0, 4096);
        let receiver = auth(1, 4096);
        let packet = sender.seal(None, &vote("0")).unwrap();
        for index in 0..packet.len() {
            let mut corrupt = packet.clone();
            corrupt[index] ^= 1;
            assert!(receiver.open(&corrupt).is_err(), "tampered byte {index}");
            assert!(receiver.open(&packet[..index]).is_err(), "truncated at {index}");
        }
        let mut trailing = packet;
        trailing.push(0);
        assert_eq!(receiver.open(&trailing).unwrap_err(), PbftAuthError::Framing);
    }

    #[test]
    fn cluster_incarnation_and_ordered_roster_are_all_bound() {
        let packet = auth(0, 4096).seal(None, &vote("0")).unwrap();
        let mut reordered = roster();
        reordered.swap(2, 3);
        let mut replaced = roster();
        replaced[3] = key(9).public_key();
        for membership in [
            PbftMembership::new([8; 32], 19, &roster()).unwrap(),
            PbftMembership::new([7; 32], 20, &roster()).unwrap(),
            PbftMembership::new([7; 32], 19, &reordered).unwrap(),
            PbftMembership::new([7; 32], 19, &replaced).unwrap(),
        ] {
            let receiver = PbftAuthenticator::new(membership, ReplicaId::new("1".into()), key(1), 4096).unwrap();
            assert_eq!(receiver.open(&packet).unwrap_err(), PbftAuthError::Membership);
        }
    }

    #[test]
    fn signer_cannot_claim_another_replica_even_with_a_valid_signature() {
        let sender = auth(0, 4096);
        let receiver = auth(1, 4096);
        for author in ["2", "00", "+0", "4", "-1", ""] {
            assert_eq!(sender.seal(None, &vote(author)).unwrap_err(), PbftAuthError::Author);
            assert_eq!(receiver.open(&forged_payload(&sender, &vote(author))).unwrap_err(), PbftAuthError::Author);
        }
        let backup = auth(2, 4096);
        let batch = ConsensusBatch::new(vec![request()]);
        let proposal = PbftMessage::PrePrepare {
            view: ViewNumber::new(0), sequence: SequenceNumber::new(1),
            digest: MessageDigest::of(&batch).unwrap(), batch, replica_id: ReplicaId::new("2".into()),
        };
        assert_eq!(receiver.open(&forged_payload(&backup, &proposal)).unwrap_err(), PbftAuthError::Author);
    }

    #[test]
    fn invalid_keys_duplicate_slots_and_public_only_signers_fail_before_io() {
        let keys = roster();
        assert!(PbftMembership::new([0; 32], 1, &keys).is_err());
        assert!(PbftMembership::new([7; 32], 1, &[]).is_err());
        assert!(PbftMembership::new([7; 32], 1, &vec![keys[0].clone(); MAX_MEMBERS + 1]).is_err());
        let duplicate = vec![keys[0].clone(), keys[0].clone()];
        assert_eq!(PbftMembership::new([7; 32], 1, &duplicate).unwrap_err(), PbftAuthError::DuplicateKey);
        let account = KeyPair::new_from_raw(KeyPairType::Account, [3; 32]).unwrap();
        for invalid in ["not a key".into(), key(0).seed().unwrap(), account.public_key(), keys[0].to_lowercase()] {
            assert_eq!(PbftMembership::new([7; 32], 1, &[invalid]).unwrap_err(), PbftAuthError::PublicKey);
        }
        let membership = PbftMembership::new([7; 32], 1, &keys).unwrap();
        let public_only = KeyPair::from_public_key(&keys[0]).unwrap();
        assert_eq!(PbftAuthenticator::new(membership.clone(), ReplicaId::new("0".into()), public_only, 4096).unwrap_err(), PbftAuthError::SigningKey);
        assert_eq!(PbftAuthenticator::new(membership.clone(), ReplicaId::new("0".into()), key(2), 4096).unwrap_err(), PbftAuthError::SigningKey);
        for limit in [0, MAX_PAYLOAD + 1, usize::MAX] {
            assert_eq!(PbftAuthenticator::new(membership.clone(), ReplicaId::new("0".into()), key(0), limit).unwrap_err(), PbftAuthError::Configuration);
        }
    }

    #[test]
    fn outsider_signatures_unknown_authors_and_unsigned_json_are_rejected() {
        let sender = auth(0, 4096);
        let receiver = auth(1, 4096);
        let mut packet = sender.seal(None, &vote("0")).unwrap();
        packet.truncate(packet.len() - SIGNATURE_LEN);
        packet.extend_from_slice(&key(9).sign(&packet).unwrap());
        assert_eq!(receiver.open(&packet).unwrap_err(), PbftAuthError::Signature);
        packet[40..44].copy_from_slice(&99_u32.to_be_bytes());
        assert_eq!(receiver.open(&packet).unwrap_err(), PbftAuthError::Author);
        assert!(receiver.open(&serde_json::to_vec(&vote("0")).unwrap()).is_err());
    }

    #[test]
    fn directed_packets_cannot_be_redirected_or_reflected() {
        let sender = auth(0, 4096);
        let intended = ReplicaId::new("1".into());
        let packet = sender.seal(Some(&intended), &PbftMessage::Request(request())).unwrap();
        assert!(auth(1, 4096).open(&packet).is_ok());
        assert_eq!(auth(2, 4096).open(&packet).unwrap_err(), PbftAuthError::Recipient);
        assert_eq!(sender.open(&packet).unwrap_err(), PbftAuthError::Recipient);
        assert_eq!(sender.seal(Some(sender.local_replica()), &vote("0")).unwrap_err(), PbftAuthError::Recipient);
    }

    #[test]
    fn bounds_are_enforced_on_encoding_declared_length_and_actual_length() {
        let message = PbftMessage::Request(request());
        let size = serde_json::to_vec(&message).unwrap().len();
        let packet = auth(0, size).seal(None, &message).unwrap();
        assert!(auth(1, size).open(&packet).is_ok());
        assert_eq!(auth(0, size - 1).seal(None, &message).unwrap_err(), PbftAuthError::PayloadTooLarge);
        assert_eq!(auth(1, size - 1).open(&packet).unwrap_err(), PbftAuthError::PayloadTooLarge);
        let mut declared = packet;
        declared[48..52].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(auth(1, 4096).open(&declared).unwrap_err(), PbftAuthError::PayloadTooLarge);
        let mut sink = LimitedPayload { bytes: Vec::new(), limit: 2 };
        assert!(sink.write_all(&[1, 2, 3]).is_err());
        assert!(sink.bytes.is_empty());
    }

    #[test]
    fn authenticated_but_unsupported_view_changes_are_still_refused() {
        let sender = auth(0, 4096);
        let receiver = auth(1, 4096);
        let messages = [
            PbftMessage::ViewChange { new_view: ViewNumber::new(1), replica_id: ReplicaId::new("0".into()), certificates: Vec::new() },
            PbftMessage::NewView { view: ViewNumber::new(1), view_change_msgs: Vec::new(), preprepare_msgs: Vec::new() },
        ];
        for message in messages {
            assert_eq!(sender.seal(None, &message).unwrap_err(), PbftAuthError::UnsupportedPhase);
            assert_eq!(receiver.open(&forged_payload(&sender, &message)).unwrap_err(), PbftAuthError::UnsupportedPhase);
        }
    }

    #[test]
    fn diagnostics_do_not_export_the_signing_seed() {
        let signer = key(0);
        let seed = signer.seed().unwrap();
        let authority = auth(0, 4096);
        assert!(!format!("{authority:?}").contains(&seed));
        assert!(!format!("{:?}", authority.membership()).contains(&seed));
    }

    #[derive(Default)]
    struct PacketHarness {
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Vec<u8>>,
        bound: Mutex<usize>,
    }

    impl PbftPacketTransport for Arc<PacketHarness> {
        async fn send_packet(&self, _recipient: &ReplicaId, packet: Vec<u8>) -> Result<()> {
            self.sent.lock().unwrap().push(packet);
            Ok(())
        }
        async fn broadcast_packet(&self, packet: Vec<u8>) -> Result<()> {
            self.sent.lock().unwrap().push(packet);
            Ok(())
        }
        async fn receive_packet(&self, max_packet_bytes: usize) -> Result<Vec<u8>> {
            *self.bound.lock().unwrap() = max_packet_bytes;
            Ok(std::mem::take(&mut *self.incoming.lock().unwrap()))
        }
    }

    #[test]
    fn transport_signs_actual_sends_and_verifies_actual_receives() {
        let wire = Arc::new(PacketHarness::default());
        let sender = AuthenticatedPbftTransport::new(Arc::clone(&wire), Arc::new(auth(0, 4096)));
        futures_lite::future::block_on(sender.broadcast(vote("0"))).unwrap();
        let packet = wire.sent.lock().unwrap().pop().unwrap();
        assert!(auth(1, 4096).open(&packet).is_ok());
        *wire.incoming.lock().unwrap() = packet;
        let receiver = AuthenticatedPbftTransport::new(Arc::clone(&wire), Arc::new(auth(1, 4096)));
        assert!(futures_lite::future::block_on(receiver.receive()).is_ok());
        assert_eq!(*wire.bound.lock().unwrap(), receiver.auth.max_packet_bytes());
        *wire.incoming.lock().unwrap() = vec![0; receiver.auth.max_packet_bytes() + 1];
        assert!(futures_lite::future::block_on(receiver.receive()).is_err());
        assert!(futures_lite::future::block_on(sender.broadcast(vote("2"))).is_err());
        assert!(wire.sent.lock().unwrap().is_empty());
    }
}
