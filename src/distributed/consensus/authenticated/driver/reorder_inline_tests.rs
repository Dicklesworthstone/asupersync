    use super::*;

    fn vote(sequence: u64, author: u32, commit: bool, tag: u8) -> PbftMessage {
        let view = ViewNumber::new(0);
        let sequence = SequenceNumber::new(sequence);
        let digest = MessageDigest::from_bytes([tag; 32]);
        let replica_id = ReplicaId::new(author.to_string());
        if commit { PbftMessage::Commit { view, sequence, digest, replica_id } }
        else { PbftMessage::Prepare { view, sequence, digest, replica_id } }
    }

    #[test]
    fn votes_wait_for_installed_matching_proposal_and_acknowledgement() {
        let mut inbox = ReorderBuffer::default();
        inbox.vote(&vote(1, 2, true, 7)).unwrap();
        inbox.vote(&vote(1, 0, false, 7)).unwrap();
        inbox.vote(&vote(1, 3, false, 8)).unwrap();
        assert!(inbox.next().is_none());
        let digest = MessageDigest::from_bytes([7; 32]);
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &digest, false, None).unwrap();
        assert!(inbox.next().is_none());
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &digest, true, None).unwrap();
        let first = inbox.next().unwrap();
        assert_eq!(first.phase, 0);
        // Dropping a selected delivery must not consume the obligation to apply it.
        #[allow(clippy::drop_non_drop)] // the explicit discard is the scenario under test
        drop(first);
        let first = inbox.next().unwrap();
        assert_eq!(first.author, 0);
        inbox.acknowledge(&first);
        let second = inbox.next().unwrap();
        assert_eq!(second.phase, 1);
        inbox.acknowledge(&second);
        assert!(inbox.next().is_none());
        assert_eq!(inbox.votes, 3);
        inbox.prune(SequenceNumber(1));
        assert!(inbox.slots.is_empty());
        assert_eq!(inbox.votes, 0);
    }

    #[test]
    fn duplicate_flood_and_equivocation_do_not_expand_or_replace_votes() {
        let mut inbox = ReorderBuffer::default();
        for _ in 0..10_000 { inbox.vote(&vote(1, 2, false, 7)).unwrap(); }
        assert_eq!(inbox.votes, 1);
        assert_eq!(inbox.vote(&vote(1, 2, false, 8)), Err(PbftIngressOutcome::Equivocation(SequenceNumber(1))));
        inbox.proposal(ViewNumber(0), SequenceNumber(1), &MessageDigest::from_bytes([7; 32]), true, None).unwrap();
        assert_eq!(inbox.next().unwrap().digest, MessageDigest::from_bytes([7; 32]));
        assert_eq!(inbox.proposal(ViewNumber(0), SequenceNumber(1), &MessageDigest::from_bytes([9; 32]), true, None), Err(PbftIngressOutcome::Equivocation(SequenceNumber(1))));
    }

    #[test]
    fn global_vote_cap_and_sequence_window_are_enforced_before_insertion() {
        let mut inbox = ReorderBuffer::default();
        for sequence in 1..=WINDOW {
            for author in 0..64 {
                inbox.vote(&vote(sequence, author, false, 7)).unwrap();
                inbox.vote(&vote(sequence, author, true, 7)).unwrap();
            }
        }
        assert_eq!(inbox.votes, MAX_VOTES);
        assert_eq!(inbox.vote(&vote(1, 65, false, 7)), Err(PbftIngressOutcome::BufferFull));
        assert_eq!(inbox.vote(&vote(WINDOW + 1, 0, false, 7)), Err(PbftIngressOutcome::OutsideWindow(SequenceNumber(WINDOW + 1))));
        assert_eq!(inbox.slots.len(), WINDOW as usize);
        inbox.prune(SequenceNumber(1));
        inbox.vote(&vote(WINDOW + 1, 0, false, 7)).unwrap();
        assert_eq!(inbox.votes, MAX_VOTES - 128 + 1);
        inbox.prune(SequenceNumber(u64::MAX - 1));
        assert!(inbox.vote(&vote(u64::MAX, 0, false, 7)).is_err());
        assert!(inbox.slots.is_empty());
    }

    #[test]
    fn full_primary_window_still_admits_exact_retry_then_reopens_after_progress() {
        let mut inbox = ReorderBuffer::default();
        let request = MessageDigest::from_bytes([4; 32]);
        inbox.proposal(ViewNumber(0), SequenceNumber(WINDOW), &MessageDigest::from_bytes([7; 32]), true, Some(request.clone())).unwrap();
        assert!(inbox.can_propose(&request));
        assert!(!inbox.can_propose(&MessageDigest::from_bytes([5; 32])));
        inbox.prune(SequenceNumber(1));
        assert!(inbox.can_propose(&MessageDigest::from_bytes([5; 32])));
    }
