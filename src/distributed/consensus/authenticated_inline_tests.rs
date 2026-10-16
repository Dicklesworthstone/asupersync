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
