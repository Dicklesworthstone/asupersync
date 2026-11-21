//! Negotiated v2 graph commitments carried outside legacy ATP JSON payloads.
//!
//! A new sender offers v2 in its handshake. A receiver accepts only the exact
//! supported record; an old peer ignores the extension and stays on v1. After
//! acceptance, the object manifest MUST carry a v2 commitment, and every
//! successful receive path must verify it before publication or an in-sync
//! reply. A committed proof echoes the verified root, which the sender checks
//! against its retained commitment. Legacy roots and transfer ids remain
//! unchanged for resume/delta compatibility. These commitments provide integrity,
//! not peer authentication
//! or protection against an active attacker stripping an unauthenticated hello.

use super::streaming::{EntryDigest, StreamingError, flat_merkle_root_v2_from_digests, hex_encode};
use crate::net::atp::protocol::frames::Frame;

/// Handshake extension offering the v2 graph transcript.
pub const MERKLE_V2_OFFER_EXTENSION: u16 = 0x0104;
/// Handshake-ack extension accepting the v2 graph transcript.
pub const MERKLE_V2_ACCEPT_EXTENSION: u16 = 0x0105;
/// Object-manifest or successful-proof extension containing the v2 root.
pub const MERKLE_V2_ROOT_EXTENSION: u16 = 0x0106;

// Extension record version followed by the graph transcript version.
const V2_RECORD: [u8; 2] = [1, 2];

/// A negotiated commitment could not be interpreted or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MerkleNegotiationError {
    #[error("malformed or unsupported Merkle v2 acceptance")]
    MalformedAccept,
    #[error("negotiated Merkle v2 commitment is missing")]
    MissingCommitment,
    #[error("Merkle v2 commitment was sent without negotiation")]
    UnexpectedCommitment,
    #[error("malformed or unsupported Merkle v2 commitment")]
    MalformedCommitment,
    #[error("invalid Merkle v2 transfer digests: {0}")]
    InvalidDigests(#[from] StreamingError),
    #[error("Merkle v2 commitment mismatch: expected {expected}, computed {computed}")]
    Mismatch { expected: String, computed: String },
}

/// Offer v2 without changing the handshake's JSON or protocol identity.
pub fn offer_v2(hello: &mut Frame) {
    hello
        .header
        .extensions
        .insert(MERKLE_V2_OFFER_EXTENSION, V2_RECORD.to_vec());
}

/// Accept an exact supported offer and record whether v2 is now required.
///
/// Unknown offers are ignored so a future peer can still negotiate v1. Once
/// this returns true, absent or malformed commitment records are errors.
pub fn accept_v2(hello: &Frame, ack: &mut Frame) -> bool {
    let supported = hello
        .header
        .extensions
        .get(&MERKLE_V2_OFFER_EXTENSION)
        .is_some_and(|bytes| bytes.as_slice() == V2_RECORD);
    if supported {
        ack.header
            .extensions
            .insert(MERKLE_V2_ACCEPT_EXTENSION, V2_RECORD.to_vec());
    }
    supported
}

/// Read the reply to a sender's v2 offer. No reply means a legacy peer.
///
/// A present but malformed reply fails closed instead of letting the sender
/// and receiver disagree about whether the manifest needs a v2 commitment.
pub fn accepted_v2(ack: &Frame) -> Result<bool, MerkleNegotiationError> {
    match ack.header.extensions.get(&MERKLE_V2_ACCEPT_EXTENSION) {
        None => Ok(false),
        Some(bytes) if bytes.as_slice() == V2_RECORD => Ok(true),
        Some(_) => Err(MerkleNegotiationError::MalformedAccept),
    }
}

/// Attach a v2 root to an object manifest or a verified successful proof.
pub fn attach_root_v2(
    manifest: &mut Frame,
    root: &str,
) -> Result<(), MerkleNegotiationError> {
    let mut record = vec![0; V2_RECORD.len() + 32];
    record[..V2_RECORD.len()].copy_from_slice(&V2_RECORD);
    hex::decode_to_slice(root, &mut record[V2_RECORD.len()..])
        .map_err(|_| MerkleNegotiationError::MalformedCommitment)?;
    manifest
        .header
        .extensions
        .insert(MERKLE_V2_ROOT_EXTENSION, record);
    Ok(())
}

/// Require exactly one well-formed commitment after v2 was negotiated.
pub fn expected_root_v2(
    manifest: &Frame,
    negotiated: bool,
) -> Result<Option<String>, MerkleNegotiationError> {
    match (
        negotiated,
        manifest.header.extensions.get(&MERKLE_V2_ROOT_EXTENSION),
    ) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(MerkleNegotiationError::UnexpectedCommitment),
        (true, None) => Err(MerkleNegotiationError::MissingCommitment),
        (true, Some(record))
            if record.len() == V2_RECORD.len() + 32
                && record[..V2_RECORD.len()] == V2_RECORD =>
        {
            Ok(Some(hex_encode(&record[V2_RECORD.len()..])))
        }
        (true, Some(_)) => Err(MerkleNegotiationError::MalformedCommitment),
    }
}

/// Verify the received content before publication or an already-in-sync reply.
/// Legacy sessions do not compute or require a v2 transcript.
pub fn verify_root_v2(
    entries: &[EntryDigest],
    expected: Option<&str>,
) -> Result<(), MerkleNegotiationError> {
    if let Some(expected) = expected {
        let computed = flat_merkle_root_v2_from_digests(entries)?;
        if computed != expected {
            return Err(MerkleNegotiationError::Mismatch {
                expected: expected.to_string(),
                computed,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::{ContentId, ObjectId};
    use crate::bytes::BytesMut;
    use crate::codec::{Decoder, Encoder};
    use crate::net::atp::protocol::codec::AtpFrameCodec;
    use crate::net::atp::protocol::frames::FrameType;
    use sha2::{Digest, Sha256};

    fn frame(kind: FrameType) -> Frame {
        Frame::empty(kind).expect("empty ATP frame")
    }

    fn digest(path: &str, content: &[u8]) -> EntryDigest {
        EntryDigest {
            rel_path: path.to_string(),
            size: content.len() as u64,
            content_id: ObjectId::content(ContentId::from_bytes(content)),
            content_sha256: Sha256::digest(content).into(),
        }
    }

    #[test]
    fn merkle_and_codec_extension_ids_are_disjoint() {
        let mut seen = std::collections::BTreeSet::new();
        for id in super::super::codec::ASSIGNED_EXTENSION_IDS.into_iter().chain([
            MERKLE_V2_OFFER_EXTENSION,
            MERKLE_V2_ACCEPT_EXTENSION,
            MERKLE_V2_ROOT_EXTENSION,
        ]) {
            assert!(seen.insert(id), "duplicate ATP extension id: {id}");
        }
    }

    #[test]
    fn new_peers_require_the_commitment_and_preserve_frame_payloads() {
        let mut hello = frame(FrameType::Handshake);
        let mut ack = frame(FrameType::HandshakeAck);
        offer_v2(&mut hello);
        assert!(accept_v2(&hello, &mut ack));
        assert_eq!(accepted_v2(&ack), Ok(true));

        let entries = vec![digest("file", b"payload")];
        let root = flat_merkle_root_v2_from_digests(&entries).expect("valid digests");
        let mut manifest = frame(FrameType::ObjectManifest);
        assert_eq!(
            expected_root_v2(&manifest, true),
            Err(MerkleNegotiationError::MissingCommitment)
        );
        attach_root_v2(&mut manifest, &root).expect("attach root");

        // Exercise the actual binary header carrier; strict JSON peers see no
        // new field and the legacy frame payload remains byte-identical.
        let mut bytes = BytesMut::new();
        let mut codec = AtpFrameCodec::new();
        codec.encode(manifest.clone(), &mut bytes).expect("encode");
        let decoded = codec.decode(&mut bytes).expect("decode").expect("frame");
        assert_eq!(decoded.payload, manifest.payload);
        let expected = expected_root_v2(&decoded, true).expect("commitment");
        assert_eq!(expected.as_deref(), Some(root.as_str()));
        verify_root_v2(&entries, expected.as_deref()).expect("matching content");
        assert!(matches!(
            verify_root_v2(&[digest("renamed", b"payload")], expected.as_deref()),
            Err(MerkleNegotiationError::Mismatch { .. })
        ));
    }

    #[test]
    fn old_sender_and_old_receiver_both_keep_legacy_behavior() {
        let old_hello = frame(FrameType::Handshake);
        let mut new_ack = frame(FrameType::HandshakeAck);
        assert!(!accept_v2(&old_hello, &mut new_ack));
        assert!(new_ack.header.extensions.is_empty());

        let mut new_hello = frame(FrameType::Handshake);
        offer_v2(&mut new_hello);
        let old_ack = frame(FrameType::HandshakeAck);
        assert_eq!(accepted_v2(&old_ack), Ok(false));
        let legacy_manifest = frame(FrameType::ObjectManifest);
        assert_eq!(expected_root_v2(&legacy_manifest, false), Ok(None));
        assert_eq!(verify_root_v2(&[], None), Ok(()));
    }

    #[test]
    fn unknown_offers_do_not_negotiate_but_malformed_accepts_are_fatal() {
        for record in [vec![], vec![1], vec![2, 2], vec![1, 3], vec![1, 2, 0]] {
            let mut hello = frame(FrameType::Handshake);
            hello
                .header
                .extensions
                .insert(MERKLE_V2_OFFER_EXTENSION, record.clone());
            let mut ack = frame(FrameType::HandshakeAck);
            assert!(!accept_v2(&hello, &mut ack));
            assert!(ack.header.extensions.is_empty());
            ack.header
                .extensions
                .insert(MERKLE_V2_ACCEPT_EXTENSION, record);
            assert_eq!(
                accepted_v2(&ack),
                Err(MerkleNegotiationError::MalformedAccept)
            );
        }
    }

    #[test]
    fn negotiated_records_cannot_be_omitted_truncated_or_unsolicited() {
        let mut manifest = frame(FrameType::ObjectManifest);
        attach_root_v2(&mut manifest, &"ab".repeat(32)).expect("valid root");
        assert_eq!(
            expected_root_v2(&manifest, false),
            Err(MerkleNegotiationError::UnexpectedCommitment)
        );
        for length in [0, 1, 2, 33, 35, 64] {
            manifest
                .header
                .extensions
                .insert(MERKLE_V2_ROOT_EXTENSION, vec![0; length]);
            assert_eq!(
                expected_root_v2(&manifest, true),
                Err(MerkleNegotiationError::MalformedCommitment)
            );
        }
        for prefix in [[0, 2], [1, 1], [2, 2]] {
            let mut record = vec![0; 34];
            record[..2].copy_from_slice(&prefix);
            manifest
                .header
                .extensions
                .insert(MERKLE_V2_ROOT_EXTENSION, record);
            assert_eq!(
                expected_root_v2(&manifest, true),
                Err(MerkleNegotiationError::MalformedCommitment)
            );
        }
        assert_eq!(
            attach_root_v2(&mut manifest, "not a root"),
            Err(MerkleNegotiationError::MalformedCommitment)
        );
    }
}
