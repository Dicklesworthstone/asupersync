    use super::*;
    use crate::types::TaskId;
    use crate::util::entropy_replay::RecordingEntropy;
    use crate::util::{ArenaIndex, DetEntropy, EntropySource};
    use std::sync::Arc;

    fn limits() -> EntropyTapeDecodeLimits {
        EntropyTapeDecodeLimits::new(8192, EntropyCaptureLimits::new(32, 1024, 8), 8192)
    }

    fn tape() -> EntropyTape {
        let capture =
            RecordingEntropy::new(Arc::new(DetEntropy::new(42)), limits().capture).unwrap();
        capture.fill_bytes(&mut []);
        let child = capture.fork(TaskId::from_arena(ArenaIndex::new(4, 7)));
        capture.next_u64();
        child.fill_bytes(&mut [0; 17]);
        capture.finish().unwrap()
    }

    fn resign(bytes: &mut [u8]) {
        let end = bytes.len() - CHECKSUM;
        let digest = checksum(&bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }

    #[test]
    fn canonical_roundtrip_is_identical_and_debug_is_redacted() {
        let tape = tape();
        let bytes = tape.to_canonical_bytes(8192).unwrap();
        let decoded = EntropyTape::from_canonical_bytes(bytes.as_ref(), limits()).unwrap();
        assert_eq!(
            (decoded.calls(), decoded.bytes(), decoded.streams()),
            (4, 25, 2)
        );
        assert_eq!(
            decoded.to_canonical_bytes(8192).unwrap().as_ref(),
            bytes.as_ref()
        );
        assert!(format!("{bytes:?}").starts_with("EntropyTapeBytes { encoded_bytes:"));
        assert!(!format!("{tape:?}").contains('['));
    }

    #[test]
    fn truncation_and_every_single_byte_corruption_fail_closed() {
        let bytes = tape().to_canonical_bytes(8192).unwrap();
        for length in 0..bytes.as_ref().len() {
            assert!(
                EntropyTape::from_canonical_bytes(&bytes.as_ref()[..length], limits()).is_err()
            );
        }
        for index in 0..bytes.as_ref().len() {
            let mut corrupted = bytes.as_ref().to_vec();
            corrupted[index] ^= 1;
            assert!(EntropyTape::from_canonical_bytes(&corrupted, limits()).is_err());
        }
    }

    #[test]
    fn all_resource_limits_are_checked_and_do_not_admit_partial_tapes() {
        let tape = tape();
        let bytes = tape.to_canonical_bytes(8192).unwrap();
        assert!(matches!(
            tape.to_canonical_bytes(bytes.as_ref().len() - 1),
            Err(EntropyTapeError::Limit("encoded bytes"))
        ));
        let mut cases = [limits(); 5];
        cases[0].max_encoded_bytes = bytes.as_ref().len() - 1;
        cases[1].capture.max_calls = 3;
        cases[2].capture.max_bytes = 24;
        cases[3].capture.max_streams = 1;
        cases[4].max_decoded_bytes = 1;
        for bound in cases {
            assert!(matches!(
                EntropyTape::from_canonical_bytes(bytes.as_ref(), bound),
                Err(EntropyTapeError::Limit(_))
            ));
        }
    }

    #[test]
    fn forged_topology_counts_and_trailing_bytes_fail_even_with_a_valid_checksum() {
        let bytes = tape().to_canonical_bytes(8192).unwrap();
        // Root: count (8), empty Bytes (9), Fork tag + task (9), child (8).
        let child_at = HEADER + 8 + 9 + 9;
        let mut cyclic = bytes.as_ref().to_vec();
        cyclic[child_at..child_at + 8].copy_from_slice(&0u64.to_le_bytes());
        resign(&mut cyclic);
        assert!(matches!(
            EntropyTape::from_canonical_bytes(&cyclic, limits()),
            Err(EntropyTapeError::Invalid("fork topology"))
        ));
        let mut counts = bytes.as_ref().to_vec();
        counts[28..36].copy_from_slice(&24u64.to_le_bytes());
        resign(&mut counts);
        assert!(EntropyTape::from_canonical_bytes(&counts, limits()).is_err());
        let mut extra = bytes.as_ref().to_vec();
        extra.insert(extra.len() - CHECKSUM, 0);
        resign(&mut extra);
        assert!(matches!(
            EntropyTape::from_canonical_bytes(&extra, limits()),
            Err(EntropyTapeError::Invalid("trailing bytes"))
        ));
    }

    #[test]
    fn empty_capture_is_valid_but_a_missing_root_is_not() {
        let tape = EntropyTape {
            streams: vec![Vec::new()],
            calls: 0,
            bytes: 0,
        };
        let bytes = tape.to_canonical_bytes(8192).unwrap();
        let decoded = EntropyTape::from_canonical_bytes(bytes.as_ref(), limits()).unwrap();
        decoded.replay().verify_complete().unwrap();
        let mut invalid = bytes.as_ref().to_vec();
        invalid[12..20].copy_from_slice(&0u64.to_le_bytes());
        resign(&mut invalid);
        assert!(matches!(
            EntropyTape::from_canonical_bytes(&invalid, limits()),
            Err(EntropyTapeError::Invalid("missing root"))
        ));
    }
