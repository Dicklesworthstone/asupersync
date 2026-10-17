    use super::*;

    fn roundtrip(old: &[u8], new: &[u8], block: usize) -> Vec<SubDeltaOp> {
        let ops = sub_delta(old, new, block);
        let rebuilt = apply(old, &ops).expect("apply");
        assert_eq!(rebuilt, new, "round trip must be byte-identical");
        ops
    }

    fn literal_bytes(ops: &[SubDeltaOp]) -> usize {
        ops.iter()
            .map(|op| match op {
                SubDeltaOp::Literal(b) => b.len(),
                SubDeltaOp::Copy { .. } => 0,
            })
            .sum()
    }

    #[test]
    fn malformed_zero_width_signature_is_noncanonical_and_cannot_stall_diff() {
        let mut signature = signature(&[0x5a; 64], 64);
        assert!(signature.has_canonical_shape(64, 64));

        signature.block_size = 0;
        signature.blocks[0].weak = RollingWeak::new(&[]).digest();
        signature.blocks[0].strong = strong_checksum(&[]);
        signature.blocks[0].len = 0;
        assert!(!signature.has_canonical_shape(64, 64));

        let new = b"untrusted peer input";
        assert_eq!(
            diff(new, &signature),
            vec![SubDeltaOp::Literal(new.to_vec())],
            "malformed zero-width signatures must make finite literal progress"
        );
    }

    #[test]
    fn identical_buffers_are_all_copy_zero_literal() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 31) as u8).collect();
        let ops = roundtrip(&old, &old, 1024);
        assert_eq!(
            literal_bytes(&ops),
            0,
            "identical content sends no literals"
        );
        assert_eq!(
            ops,
            vec![SubDeltaOp::Copy {
                old_offset: 0,
                len: old.len() as u32,
            }],
            "adjacent matching blocks should encode as one copy run"
        );
        assert_eq!(wire_bytes(&ops), 10);
    }

    #[test]
    fn duplicate_blocks_prefer_contiguous_copy_run() {
        let old = b"AAAARRRRRRRRDDDD";
        let ops = roundtrip(old, old, 4);

        assert_eq!(
            ops,
            vec![SubDeltaOp::Copy {
                old_offset: 0,
                len: u32::try_from(old.len()).expect("fixture fits u32"),
            }],
            "duplicate matches must follow the contiguous old range"
        );
    }

    #[test]
    fn duplicate_blocks_prefer_position_after_pending_literal() {
        let old = b"AAAARRRRRRRRDDDD";
        let new = b"AAAAXXXXRRRRDDDD";
        let ops = roundtrip(old, new, 4);

        assert_eq!(
            ops,
            vec![
                SubDeltaOp::Copy {
                    old_offset: 0,
                    len: 4,
                },
                SubDeltaOp::Literal(b"XXXX".to_vec()),
                SubDeltaOp::Copy {
                    old_offset: 8,
                    len: 8,
                },
            ],
            "a pending literal must break continuity so the positional duplicate can start a new copy run"
        );
    }

    #[test]
    fn append_only_copies_old_then_literal_tail() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 17 + 3) as u8).collect();
        let mut new = old.clone();
        new.extend_from_slice(&[0xAB; 200]);
        let ops = roundtrip(&old, &new, 1024);
        // The 8192 old bytes (8 full blocks) are copied; only the 200 appended
        // bytes are literal.
        assert_eq!(literal_bytes(&ops), 200);
        assert_eq!(
            ops,
            vec![
                SubDeltaOp::Copy {
                    old_offset: 0,
                    len: old.len() as u32,
                },
                SubDeltaOp::Literal(vec![0xAB; 200]),
            ],
            "append should not pay one copy op per reused block"
        );
    }

    #[test]
    fn small_edit_sends_only_a_few_literal_blocks_not_whole_chunk() {
        let old: Vec<u8> = (0..16384u32).map(|i| (i * 7 + 1) as u8).collect();
        let mut new = old.clone();
        // Flip 10 bytes in the middle (within one 1 KiB block).
        for k in 0..10 {
            new[8000 + k] ^= 0xFF;
        }
        let ops = roundtrip(&old, &new, 1024);
        // The change touches ~one block; literal must be far below the whole
        // 16 KiB chunk (the E-RESYNC-4 waste this fix kills).
        assert!(
            literal_bytes(&ops) <= 2 * 1024,
            "literal {} should be ~one block, not the whole chunk",
            literal_bytes(&ops)
        );
        assert!(
            wire_bytes(&ops) < new.len(),
            "wire must beat shipping the whole chunk"
        );
    }

    #[test]
    fn insert_shifts_content_but_stays_byte_identical_and_compact() {
        // Insertion shifts all following bytes — the rolling checksum must re-sync
        // on block boundaries (shift resistance), so most old blocks still copy.
        let old: Vec<u8> = (0..16384u32).map(|i| (i * 13 + 5) as u8).collect();
        let mut new = old[..6000].to_vec();
        new.extend_from_slice(&[0xCD; 137]); // inserted run
        new.extend_from_slice(&old[6000..]);
        let ops = roundtrip(&old, &new, 1024);
        // Far less than the whole new buffer is literal (only the inserted region
        // plus boundary slack).
        assert!(
            literal_bytes(&ops) < new.len() / 2,
            "insert literal {} should be well below half the buffer",
            literal_bytes(&ops)
        );
    }

    #[test]
    fn disjoint_buffers_are_all_literal_and_still_exact() {
        let old: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let new: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(251).wrapping_add(99)) as u8)
            .collect();
        let ops = roundtrip(&old, &new, 1024);
        assert_eq!(
            literal_bytes(&ops),
            new.len(),
            "no shared blocks → all literal"
        );
    }

    #[test]
    fn weak_collision_uses_strong_checksum_to_choose_copy_source() {
        // For len=4, deltas [1, -2, 1, 0] preserve both rsync weak sums:
        // sum(delta)=0 and weighted_sum(delta)=4*1 + 3*(-2) + 2*1 = 0.
        // The blocks therefore collide weakly but differ strongly.
        let weak_a = [10u8, 20, 30, 40];
        let weak_b = [11u8, 18, 31, 40];
        assert_eq!(
            RollingWeak::new(&weak_a).digest(),
            RollingWeak::new(&weak_b).digest(),
            "test fixture must create a weak-checksum collision"
        );
        assert_ne!(
            strong_checksum(&weak_a),
            strong_checksum(&weak_b),
            "strong checksum must disambiguate the collision"
        );

        let old = [weak_a, weak_b].concat();
        let sig = signature(&old, 4);
        let ops = diff(&weak_b, &sig);

        assert_eq!(
            ops,
            vec![SubDeltaOp::Copy {
                old_offset: 4,
                len: 4,
            }],
            "diff must copy the strong-matching second block, not the first weak hit"
        );
        assert_eq!(apply(&old, &ops).expect("apply"), weak_b);
    }

    #[test]
    fn weak_only_match_falls_back_to_literal() {
        let old_block = [10u8, 20, 30, 40];
        let weak_collision_without_strong_match = [12u8, 16, 32, 40];
        assert_eq!(
            RollingWeak::new(&old_block).digest(),
            RollingWeak::new(&weak_collision_without_strong_match).digest(),
            "test fixture must create a weak-checksum collision"
        );
        assert_ne!(
            strong_checksum(&old_block),
            strong_checksum(&weak_collision_without_strong_match),
            "fixture must not be a strong match"
        );

        let sig = signature(&old_block, 4);
        let ops = diff(&weak_collision_without_strong_match, &sig);

        assert_eq!(
            ops,
            vec![SubDeltaOp::Literal(
                weak_collision_without_strong_match.to_vec()
            )],
            "a weak-only hit must not produce a copy op"
        );
        assert_eq!(
            apply(&old_block, &ops).expect("apply"),
            weak_collision_without_strong_match
        );
    }

    #[test]
    fn empty_and_short_buffers_roundtrip() {
        assert_eq!(apply(b"old", &sub_delta(b"old", b"", 1024)).unwrap(), b"");
        assert_eq!(
            apply(b"", &sub_delta(b"", b"new bytes", 1024)).unwrap(),
            b"new bytes"
        );
        // new shorter than block_size → single literal.
        let ops = sub_delta(b"abcdefgh", b"xyz", 1024);
        assert_eq!(apply(b"abcdefgh", &ops).unwrap(), b"xyz");
    }

    #[test]
    fn copy_out_of_range_is_rejected_fail_closed() {
        let ops = vec![SubDeltaOp::Copy {
            old_offset: 100,
            len: 50,
        }];
        assert!(matches!(
            apply(b"short", &ops),
            Err(SubDeltaError::CopyOutOfRange { .. })
        ));
    }

    #[test]
    fn reconstruct_verified_accepts_correct_hash_and_rejects_tampered() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 11 + 2) as u8).collect();
        let mut new = old.clone();
        for k in 0..40 {
            new[4000 + k] ^= 0x5A;
        }
        let expected: [u8; 32] = Sha256::digest(&new).into();
        let ops = sub_delta(&old, &new, 1024);

        // Correct hash → reconstructs the new chunk.
        let rebuilt = reconstruct_verified(&old, &ops, &expected).expect("verified reconstruct");
        assert_eq!(rebuilt, new);

        // Tampered op stream (drop the literal that carried the edit) → the
        // whole-chunk hash check catches it: fail-closed, no bytes committed.
        let tampered: Vec<SubDeltaOp> = ops
            .into_iter()
            .filter(|op| !matches!(op, SubDeltaOp::Literal(_)))
            .collect();
        assert!(matches!(
            reconstruct_verified(&old, &tampered, &expected),
            Err(SubDeltaError::HashMismatch { .. })
        ));

        // A wrong expected hash also fails closed even with the right ops.
        let wrong = [0u8; 32];
        assert!(matches!(
            reconstruct_verified(&old, &sub_delta(&old, &new, 1024), &wrong),
            Err(SubDeltaError::HashMismatch { .. })
        ));
    }

    #[test]
    fn signature_and_ops_serde_roundtrip_and_still_reconstruct() {
        // The protocol sends the signature (receiver->sender) and the op stream
        // (sender->receiver), so both must survive serialization unchanged and
        // still reconstruct the new chunk byte-identically.
        let old: Vec<u8> = (0..4096u32).map(|i| (i * 5 + 1) as u8).collect();
        let mut new = old.clone();
        new.extend_from_slice(b"appended-tail");
        let sig = signature(&old, 1024);
        let ops = diff(&new, &sig);

        let sig2: SubBlockSignature =
            serde_json::from_slice(&serde_json::to_vec(&sig).expect("ser sig")).expect("de sig");
        assert_eq!(sig, sig2);

        let ops2: Vec<SubDeltaOp> =
            serde_json::from_slice(&serde_json::to_vec(&ops).expect("ser ops")).expect("de ops");
        assert_eq!(ops, ops2);
        assert_eq!(apply(&old, &ops2).expect("apply"), new);
    }

    #[test]
    fn rolling_weak_matches_fresh_computation() {
        let data: Vec<u8> = (0..2048u32).map(|i| (i * 91 + 7) as u8).collect();
        let block = 512usize;
        let mut rolling = RollingWeak::new(&data[0..block]);
        for start in 0..(data.len() - block) {
            let fresh = RollingWeak::new(&data[start..start + block]).digest();
            assert_eq!(rolling.digest(), fresh, "rolling weak diverged at {start}");
            rolling.roll(data[start], data[start + block]);
        }
    }
