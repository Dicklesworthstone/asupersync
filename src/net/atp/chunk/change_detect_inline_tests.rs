    use super::*;

    fn sig(size: u64, mtime: u64, ctime: u64) -> FileSignature {
        FileSignature::new(size, mtime, ctime)
    }

    #[test]
    fn unchanged_when_size_and_mtime_match() {
        let prior = sig(4096, 1_000, 500);
        let current = sig(4096, 1_000, 500);
        assert_eq!(classify(Some(&prior), &current), ChangeVerdict::Unchanged);
        assert!(classify(Some(&prior), &current).is_skippable());
    }

    #[test]
    fn ctime_only_change_is_ignored() {
        // chmod/chown bump ctime but not content — must NOT force a re-hash.
        let prior = sig(4096, 1_000, 500);
        let current = sig(4096, 1_000, 9_999); // ctime differs, size+mtime same
        assert_eq!(classify(Some(&prior), &current), ChangeVerdict::Unchanged);
    }

    #[test]
    fn mtime_change_is_suspect() {
        let prior = sig(4096, 1_000, 500);
        let current = sig(4096, 2_000, 500);
        assert_eq!(
            classify(Some(&prior), &current),
            ChangeVerdict::SuspectChanged
        );
    }

    #[test]
    fn size_change_is_suspect() {
        let prior = sig(4096, 1_000, 500);
        let current = sig(8192, 1_000, 500);
        assert_eq!(
            classify(Some(&prior), &current),
            ChangeVerdict::SuspectChanged
        );
    }

    #[test]
    fn no_prior_is_suspect() {
        let current = sig(4096, 1_000, 500);
        assert_eq!(classify(None, &current), ChangeVerdict::SuspectChanged);
        assert!(!classify(None, &current).is_skippable());
    }

    #[test]
    fn simhash_is_deterministic_and_order_independent() {
        let a = simhash64([1u64, 2, 3, 4]);
        let b = simhash64([4u64, 3, 2, 1]);
        assert_eq!(a, b, "simhash must not depend on feature order");
        assert_eq!(simhash64(std::iter::empty()), 0);
    }

    #[test]
    fn identical_chunk_sets_are_a_perfect_rename_match() {
        // A pure rename: identical content → identical chunk-ids → similarity 1.0.
        let ids = [[7u8; 32], [9u8; 32], [11u8; 32]];
        let prior = simhash_of_chunk_ids(ids.iter());
        let renamed = simhash_of_chunk_ids(ids.iter());
        assert_eq!(prior, renamed);
        assert!((hamming_similarity(prior, renamed) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn small_edit_stays_highly_similar() {
        let base: Vec<[u8; 32]> = (0..32u8).map(|i| [i; 32]).collect();
        let mut edited = base.clone();
        edited[0] = [200u8; 32]; // one chunk changed out of 32
        let h_base = simhash_of_chunk_ids(base.iter());
        let h_edited = simhash_of_chunk_ids(edited.iter());
        assert!(
            hamming_similarity(h_base, h_edited) > 0.7,
            "a one-chunk edit should remain a strong delta candidate"
        );
    }

    #[test]
    fn best_rename_source_picks_the_nearest_above_threshold() {
        let current = 0xfeed_face_cafe_beefu64;
        let near = current ^ 0x0000_0000_0000_0001;
        let far = current ^ 0x0000_0000_0000_ffff;

        let candidates = [("old/far.bin", far), ("old/near.bin", near)];
        let m = best_rename_source(current, candidates.iter().map(|(p, h)| (*p, *h)), 0.6)
            .expect("a near match clears the threshold");
        assert_eq!(m.prior_path, "old/near.bin");
    }

    #[test]
    fn best_rename_source_returns_none_when_nothing_is_similar_enough() {
        let current = simhash_of_chunk_ids([[1u8; 32], [2u8; 32]].iter());
        let far = simhash_of_chunk_ids([[200u8; 32], [201u8; 32]].iter());
        assert!(best_rename_source(current, [("old/x", far)], 0.95).is_none());
    }
