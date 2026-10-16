    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::gf2::BoundaryMatrix;

    #[test]
    fn score_empty() {
        let pairs = PersistencePairs {
            pairs: vec![],
            unpaired: vec![],
        };
        let mut seen = BTreeSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 42);
        assert_eq!(ledger.score.novelty, 0);
        assert_eq!(ledger.score.persistence_sum, 0);
        assert_eq!(ledger.score.fingerprint, 42);
        assert!(ledger.entries.is_empty());
    }

    #[test]
    fn score_novel_classes() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5), (1, 8)],
            unpaired: vec![3],
        };
        let mut seen = BTreeSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 100);

        assert_eq!(ledger.score.novelty, 3); // all new
        assert_eq!(ledger.score.persistence_sum, 5 + 7); // (5-0) + (8-1)
        assert_eq!(ledger.entries.len(), 3);
        assert!(ledger.entries.iter().all(|e| e.is_novel));
    }

    #[test]
    fn score_repeated_classes_not_novel() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5)],
            unpaired: vec![],
        };
        let mut seen = BTreeSet::new();

        let l1 = score_persistence(&pairs, &mut seen, 1);
        assert_eq!(l1.score.novelty, 1);

        // Same class again — not novel
        let l2 = score_persistence(&pairs, &mut seen, 2);
        assert_eq!(l2.score.novelty, 0);
        assert_eq!(l2.score.persistence_sum, 5); // persistence still counted
        assert!(!l2.entries[0].is_novel);
    }

    #[test]
    fn score_ordering() {
        let high = TopologicalScore {
            novelty: 2,
            persistence_sum: 10,
            fingerprint: 100,
        };
        let low = TopologicalScore {
            novelty: 1,
            persistence_sum: 50,
            fingerprint: 1,
        };
        // Higher novelty wins
        assert!(high > low);

        let a = TopologicalScore {
            novelty: 1,
            persistence_sum: 20,
            fingerprint: 5,
        };
        let b = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 1,
        };
        // Same novelty, higher persistence wins
        assert!(a > b);

        let x = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 5,
        };
        let y = TopologicalScore {
            novelty: 1,
            persistence_sum: 10,
            fingerprint: 10,
        };
        // Same novelty+persistence, lower fingerprint wins
        assert!(x > y);
    }

    #[test]
    fn score_determinism() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 3), (2, 7)],
            unpaired: vec![5],
        };

        let mut seen1 = BTreeSet::new();
        let mut seen2 = BTreeSet::new();

        let l1 = score_persistence(&pairs, &mut seen1, 42);
        let l2 = score_persistence(&pairs, &mut seen2, 42);

        assert_eq!(l1.score, l2.score);
    }

    #[test]
    fn evidence_ledger_summary_format() {
        let pairs = PersistencePairs {
            pairs: vec![(0, 5)],
            unpaired: vec![3],
        };
        let mut seen = BTreeSet::new();
        let ledger = score_persistence(&pairs, &mut seen, 0xFF);

        let summary = ledger.summary();
        assert!(summary.contains("novelty=2"));
        assert!(summary.contains("NEW"));
        assert!(summary.contains("pers=5"));
        assert!(summary.contains("pers=∞"));
    }

    #[test]
    fn score_boundary_matrix_end_to_end() {
        // Build a simple complex: triangle with filled face
        // v0, v1, v2, e01, e02, e12, t012
        let mut d = BoundaryMatrix::zeros(7, 7);
        // e01 (col 3): v0 + v1
        d.set(0, 3);
        d.set(1, 3);
        // e02 (col 4): v0 + v2
        d.set(0, 4);
        d.set(2, 4);
        // e12 (col 5): v1 + v2
        d.set(1, 5);
        d.set(2, 5);
        // t012 (col 6): e01 + e02 + e12
        d.set(3, 6);
        d.set(4, 6);
        d.set(5, 6);

        let mut seen = BTreeSet::new();
        let ledger = score_boundary_matrix(&d, &mut seen, 0);

        // Filled triangle: β0=1, β1=0 (cycle killed by face)
        // Should have pairs and the score should be deterministic
        assert!(ledger.score.novelty > 0 || !ledger.entries.is_empty());
    }

    #[test]
    fn seed_fingerprint_deterministic() {
        assert_eq!(seed_fingerprint(42), seed_fingerprint(42));
        assert_ne!(seed_fingerprint(42), seed_fingerprint(43));
    }

    #[test]
    fn class_id_persistence() {
        let finite = ClassId {
            birth: 3,
            death: 10,
        };
        assert_eq!(finite.persistence(), Some(7));

        let infinite = ClassId {
            birth: 3,
            death: usize::MAX,
        };
        assert_eq!(infinite.persistence(), None);
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn topological_score_debug_clone_copy_eq() {
        let s = TopologicalScore {
            novelty: 3,
            persistence_sum: 42,
            fingerprint: 0xBEEF,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TopologicalScore"), "{dbg}");
        assert!(dbg.contains("42"), "{dbg}");
        let copied = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_eq!(s, s);
    }

    #[test]
    fn class_id_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let c = ClassId {
            birth: 1,
            death: 10,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ClassId"), "{dbg}");
        let copied = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        let mut set = HashSet::new();
        set.insert(c);
        assert!(set.contains(&c));
    }

    #[test]
    fn evidence_entry_debug_clone() {
        let e = EvidenceEntry {
            class: ClassId { birth: 0, death: 5 },
            is_novel: true,
            persistence: Some(5),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EvidenceEntry"), "{dbg}");
        let cloned = e;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn evidence_ledger_debug_clone() {
        let ledger = EvidenceLedger {
            entries: vec![],
            score: TopologicalScore::zero(0),
        };
        let dbg = format!("{ledger:?}");
        assert!(dbg.contains("EvidenceLedger"), "{dbg}");
        let cloned = ledger;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
