    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

    fn init_test() {
        init_test_logging();
    }

    fn dedup_race_join_ledger() -> ExplanationLedger {
        let mut before_dag = PlanDag::new();
        let shared = before_dag.leaf("shared");
        let left = before_dag.leaf("left");
        let right = before_dag.leaf("right");
        let join_a = before_dag.join(vec![shared, left]);
        let join_b = before_dag.join(vec![shared, right]);
        let race = before_dag.race(vec![join_a, join_b]);
        before_dag.set_root(race);

        let mut after_dag = before_dag.clone();
        let (_, cert) = after_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        cert.explain(&before_dag, &after_dag)
    }

    #[test]
    fn hash_deterministic_across_calls() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let h1 = PlanHash::of(&dag);
        let h2 = PlanHash::of(&dag);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_dags_produce_different_hashes() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join = dag1.join(vec![a, b]);
        dag1.set_root(join);

        let mut dag2 = PlanDag::new();
        let c = dag2.leaf("c");
        let d = dag2.leaf("d");
        let race = dag2.race(vec![c, d]);
        dag2.set_root(race);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn child_order_matters() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join1 = dag1.join(vec![a, b]);
        dag1.set_root(join1);

        let mut dag2 = PlanDag::new();
        let a2 = dag2.leaf("a");
        let b2 = dag2.leaf("b");
        let join2 = dag2.join(vec![b2, a2]);
        dag2.set_root(join2);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn timeout_duration_affects_hash() {
        init_test();
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let t1 = dag1.timeout(a, Duration::from_secs(1));
        dag1.set_root(t1);

        let mut dag2 = PlanDag::new();
        let a2 = dag2.leaf("a");
        let t2 = dag2.timeout(a2, Duration::from_secs(2));
        dag2.set_root(t2);

        assert_ne!(PlanHash::of(&dag1), PlanHash::of(&dag2));
    }

    #[test]
    fn certified_rewrite_produces_valid_certificate() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert_eq!(report.steps().len(), 1);
        assert_eq!(cert.steps.len(), 1);
        assert_eq!(cert.version, CertificateVersion::CURRENT);
        assert_eq!(cert.policy, RewritePolicy::conservative());
        assert_ne!(cert.before_hash, cert.after_hash);
        assert!(!cert.is_identity());

        // Verify against post-rewrite DAG.
        assert!(verify(&cert, &dag).is_ok());
    }

    #[test]
    fn identity_rewrite_produces_identity_certificate() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        assert!(verify(&cert, &dag).is_ok());
    }

    #[test]
    fn verify_detects_hash_mismatch() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_report, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        // Mutate the DAG after certification.
        dag.leaf("extra");

        let result = verify(&cert, &dag);
        assert!(result.is_err());
        assert!(matches!(result, Err(VerifyError::HashMismatch { .. })));
    }

    #[test]
    fn verify_detects_node_count_mismatch() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_report, mut cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        cert.after_node_count += 1;

        let result = verify(&cert, &dag);
        assert!(matches!(result, Err(VerifyError::NodeCountMismatch { .. })));
    }

    #[test]
    fn certificate_fingerprint_is_deterministic() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let fp1 = cert.fingerprint();
        let fp2 = cert.fingerprint();
        assert_eq!(fp1, fp2);
        assert!(
            fp1.as_bytes().iter().any(|b| *b != 0),
            "fingerprint must not be all-zero"
        );
    }

    #[test]
    fn version_mismatch_detected() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let (_, mut cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        cert.version = CertificateVersion::from_number(99);

        let result = verify(&cert, &dag);
        assert!(matches!(result, Err(VerifyError::VersionMismatch { .. })));
    }

    #[test]
    fn verify_steps_accepts_valid_rewrite() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(verify_steps(&cert, &dag).is_ok());
    }

    #[test]
    fn verify_steps_rejects_missing_after_node() {
        init_test();
        // Create a valid DedupRaceJoin structure (Race of Joins with shared child)
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared"); // node 0
        let left = dag.leaf("left"); // node 1
        let right = dag.leaf("right"); // node 2
        let join_a = dag.join(vec![shared, left]); // node 3
        let join_b = dag.join(vec![shared, right]); // node 4
        let race = dag.race(vec![join_a, join_b]); // node 5
        dag.set_root(race);

        // Create certificate with valid before (the race) but non-existent after
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 6,
            after_node_count: 6,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: PlanId::new(999), // doesn't exist
                detail: "missing-after-node".to_string(),
            }],
        };

        let result = verify_steps(&cert, &dag);
        assert!(matches!(
            result,
            Err(StepVerifyError::MissingAfterNode { .. })
        ));
    }

    #[test]
    fn verify_steps_rejects_wrong_after_shape() {
        init_test();
        // Create a valid DedupRaceJoin structure (Race of Joins with shared child)
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared"); // node 0
        let left = dag.leaf("left"); // node 1
        let right = dag.leaf("right"); // node 2
        let join_a = dag.join(vec![shared, left]); // node 3
        let join_b = dag.join(vec![shared, right]); // node 4
        let race = dag.race(vec![join_a, join_b]); // node 5
        dag.set_root(race);

        // Create certificate with valid before (the race) but wrong after shape (a Leaf)
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: 6,
            after_node_count: 6,
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: shared, // points to a Leaf, not a Join
                detail: "leaf-after-node".to_string(),
            }],
        };

        let result = verify_steps(&cert, &dag);
        assert!(matches!(
            result,
            Err(StepVerifyError::InvalidAfterShape { .. })
        ));
    }

    #[test]
    fn verify_rejects_invalid_step_structure() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::DedupRaceJoin,
                before: race,
                after: shared,
                detail: "invalid-step-shape".to_string(),
            }],
        };

        let result = verify(&cert, &dag);
        assert!(matches!(
            result,
            Err(VerifyError::InvalidStep(
                StepVerifyError::InvalidAfterShape { .. }
            ))
        ));
    }

    #[test]
    fn verify_steps_identity_passes() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        assert!(verify_steps(&cert, &dag).is_ok());
    }

    // -----------------------------------------------------------------------
    // Certificate minimization tests (bd-35xx)
    // -----------------------------------------------------------------------

    #[test]
    fn minimize_removes_noop_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let (_, base_cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        // Inject a no-op step (before == after).
        let mut cert = base_cert;
        cert.steps.push(CertifiedStep {
            rule: RewriteRule::JoinAssoc,
            before: a,
            after: a,
            detail: "no-op".to_string(),
        });
        assert_eq!(cert.steps.len(), 1);

        let minimized = cert.minimize();
        assert!(minimized.steps.is_empty());
    }

    #[test]
    fn minimize_removes_inverse_commute_pair() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let hash = PlanHash::of(&dag);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 3,
            after_node_count: 3,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(2),
                    after: PlanId::new(3),
                    detail: "commute forward".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(3),
                    after: PlanId::new(2),
                    detail: "commute back".to_string(),
                },
            ],
        };

        let minimized = cert.minimize();
        assert!(minimized.steps.is_empty());
    }

    #[test]
    fn minimize_removes_consecutive_duplicates() {
        init_test();
        let hash = PlanHash::from_u64_seed(0x1234);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 4,
            after_node_count: 4,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "assoc".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "assoc dup".to_string(),
                },
            ],
        };

        let minimized = cert.minimize();
        assert_eq!(minimized.steps.len(), 1);
    }

    #[test]
    fn minimize_preserves_non_redundant_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let minimized = cert.minimize();
        assert_eq!(minimized.steps.len(), cert.steps.len());
        assert_eq!(minimized.before_hash, cert.before_hash);
        assert_eq!(minimized.after_hash, cert.after_hash);
    }

    #[test]
    fn compact_certificate_strips_details() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert_eq!(compact.steps.len(), cert.steps.len());
        assert_eq!(compact.version, cert.version);
        assert_eq!(compact.before_hash, cert.before_hash);
        assert_eq!(compact.after_hash, cert.after_hash);

        for (cs, fs) in compact.steps.iter().zip(cert.steps.iter()) {
            assert_eq!(cs.rule, fs.rule as u8);
            assert_eq!(cs.before, u32::try_from(fs.before.index()).unwrap());
            assert_eq!(cs.after, u32::try_from(fs.after.index()).unwrap());
        }
    }

    #[test]
    fn compact_byte_size_bound_is_tight() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        let bound = compact.byte_size_bound();
        // 1 step => 81 + 9 = 90 bytes
        assert_eq!(
            bound,
            CompactCertificate::HEADER_SIZE + CompactStep::WIRE_SIZE
        );
        assert_eq!(bound, 90);
    }

    #[test]
    fn certificate_within_linear_bound() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert!(compact.is_within_linear_bound());
    }

    #[test]
    fn identity_certificate_compact_is_minimal() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        assert!(cert.is_identity());
        let compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        assert!(compact.steps.is_empty());
        assert_eq!(compact.byte_size_bound(), CompactCertificate::HEADER_SIZE);
        assert!(compact.is_within_linear_bound());
    }

    #[test]
    fn minimize_then_compact_reduces_size() {
        init_test();
        let hash = PlanHash::from_u64_seed(0xABCD);
        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 5,
            after_node_count: 5,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::RaceCommute,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "commute".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::RaceCommute,
                    before: PlanId::new(1),
                    after: PlanId::new(0),
                    detail: "un-commute".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(2),
                    after: PlanId::new(3),
                    detail: "assoc".to_string(),
                },
            ],
        };

        let raw_compact = cert
            .compact()
            .expect("compact certificate fits u32 wire format");
        let minimized_compact = cert
            .minimize()
            .compact()
            .expect("compact certificate fits u32 wire format");

        assert_eq!(raw_compact.steps.len(), 3);
        assert_eq!(minimized_compact.steps.len(), 1);
        assert!(minimized_compact.byte_size_bound() < raw_compact.byte_size_bound());
    }

    #[test]
    fn compact_rejects_node_count_overflow() {
        init_test();
        if usize::BITS <= u32::BITS {
            return;
        }

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::from_u64_seed(0xABCD),
            after_hash: PlanHash::from_u64_seed(0xABCD),
            before_node_count: (u32::MAX as usize) + 1,
            after_node_count: 1,
            steps: Vec::new(),
        };

        let err = cert.compact().expect_err("overflow must be rejected");
        assert_eq!(
            err,
            CompactCertificateError::NodeCountOverflow {
                field: "before_node_count",
                value: (u32::MAX as usize) + 1,
            }
        );
    }

    #[test]
    fn compact_rejects_step_node_overflow() {
        init_test();
        if usize::BITS <= u32::BITS {
            return;
        }

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: PlanHash::from_u64_seed(0x1234),
            after_hash: PlanHash::from_u64_seed(0x1234),
            before_node_count: 1,
            after_node_count: 1,
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinAssoc,
                before: PlanId::new((u32::MAX as usize) + 1),
                after: PlanId::new(0),
                detail: "overflow".to_string(),
            }],
        };

        let err = cert.compact().expect_err("overflow must be rejected");
        assert_eq!(
            err,
            CompactCertificateError::StepNodeOverflow {
                step: 0,
                field: "before",
                value: (u32::MAX as usize) + 1,
            }
        );
    }

    // -----------------------------------------------------------------------
    // Explanation ledger tests (bd-1rup)
    // -----------------------------------------------------------------------

    #[test]
    fn dag_cost_snapshot_counts_nodes() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let race = dag.race(vec![join, c]);
        dag.set_root(race);

        let snap = DagCostSnapshot::of(&dag);
        assert_eq!(snap.node_count, 5);
        assert_eq!(snap.joins, 1);
        assert_eq!(snap.races, 1);
        assert_eq!(snap.timeouts, 0);
        assert_eq!(snap.depth, 3); // race -> join -> leaf
    }

    #[test]
    fn dag_depth_handles_timeout() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_secs(1));
        dag.set_root(t);

        let snap = DagCostSnapshot::of(&dag);
        assert_eq!(snap.depth, 2); // timeout -> leaf
        assert_eq!(snap.timeouts, 1);
    }

    #[test]
    fn explain_produces_entries_for_each_step() {
        init_test();
        let mut before_dag = PlanDag::new();
        let shared = before_dag.leaf("shared");
        let left = before_dag.leaf("left");
        let right = before_dag.leaf("right");
        let join_a = before_dag.join(vec![shared, left]);
        let join_b = before_dag.join(vec![shared, right]);
        let race = before_dag.race(vec![join_a, join_b]);
        before_dag.set_root(race);

        let mut after_dag = before_dag.clone();
        let (_, cert) = after_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let ledger = cert.explain(&before_dag, &after_dag);
        assert_eq!(ledger.entries.len(), cert.steps.len());
        assert_eq!(ledger.entries[0].law, "Race-Join Deduplication");
        assert!(!ledger.entries[0].side_conditions.is_empty());
    }

    #[test]
    fn explain_identity_is_empty() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let before_dag = dag.clone();
        let (_, cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let ledger = cert.explain(&before_dag, &dag);
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.before.node_count, ledger.after.node_count);
    }

    #[test]
    fn explain_render_is_deterministic() {
        init_test();
        let ledger = dedup_race_join_ledger();
        let r1 = ledger.render();
        let r2 = ledger.render();
        assert_eq!(r1, r2);
        assert!(r1.contains("Plan Rewrite Explanation"));
        assert!(r1.contains("Race-Join Deduplication"));
        assert!(r1.contains("Before:"));
        assert!(r1.contains("After:"));
        assert!(r1.contains("Delta:"));
    }

    #[test]
    fn explain_shows_cost_delta() {
        init_test();
        let ledger = dedup_race_join_ledger();
        // DedupRaceJoin adds nodes (the new Join+Race structure), so after >= before.
        assert!(ledger.after.node_count >= ledger.before.node_count);
        // The render should show the delta.
        let rendered = ledger.render();
        assert!(rendered.contains("nodes="));
        assert!(rendered.contains("depth="));
    }

    #[test]
    fn explain_render_snapshot_dedup_race_join() {
        init_test();
        let ledger = dedup_race_join_ledger();

        insta::assert_snapshot!("plan_certificate_dedup_race_join_render", ledger.render());
    }

    #[test]
    fn plan_hash_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);
        let h = PlanHash::of(&dag);

        let dbg = format!("{h:?}");
        assert!(dbg.contains("PlanHash"));

        let h2 = h;
        assert_eq!(h, h2);

        // Copy
        let h3 = h;
        assert_eq!(h, h3);

        // Hash: usable in HashSet
        let mut set = HashSet::new();
        set.insert(h);
        assert!(set.contains(&h));
    }

    #[test]
    fn certificate_version_debug_clone_copy_eq() {
        let v = CertificateVersion::CURRENT;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("CertificateVersion"));

        let v2 = v;
        assert_eq!(v, v2);

        let v3 = v;
        assert_eq!(v, v3);
    }

    #[test]
    fn compact_step_debug_clone_copy_eq() {
        let s = CompactStep {
            rule: 1,
            before: 10,
            after: 20,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CompactStep"));

        let s2 = s;
        assert_eq!(s, s2);

        let s3 = s;
        assert_eq!(s, s3);
    }

    // -----------------------------------------------------------------------
    // Comprehensive Golden Artifact Tests for latency_algebra certificate format
    // -----------------------------------------------------------------------

    #[test]
    fn golden_certificate_join_associativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.join(vec![a, b]);
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::JoinAssoc]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_join_associativity_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_race_associativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.race(vec![a, b]);
        let outer = dag.race(vec![inner, c]);
        dag.set_root(outer);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::RaceAssoc]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_race_associativity_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_timeout_minimization_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner_timeout = dag.timeout(a, Duration::from_millis(200));
        let outer_timeout = dag.timeout(inner_timeout, Duration::from_millis(100));
        dag.set_root(outer_timeout);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::TimeoutMin]);

        let ledger = cert.explain(&before_dag, &dag);
        insta::assert_snapshot!(
            "plan_certificate_timeout_minimization_render",
            ledger.render()
        );
    }

    #[test]
    fn golden_certificate_join_commutativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::JoinCommute]);

        if !cert.is_identity() {
            let ledger = cert.explain(&before_dag, &dag);
            insta::assert_snapshot!(
                "plan_certificate_join_commutativity_render",
                ledger.render()
            );
        }
    }

    #[test]
    fn golden_certificate_race_commutativity_render() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("option_a");
        let b = dag.leaf("option_b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let before_dag = dag.clone();
        let (_, cert) =
            dag.apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::RaceCommute]);

        if !cert.is_identity() {
            let ledger = cert.explain(&before_dag, &dag);
            insta::assert_snapshot!(
                "plan_certificate_race_commutativity_render",
                ledger.render()
            );
        }
    }

    #[test]
    fn golden_certificate_compact_format_variations() {
        init_test();

        // Identity certificate (no rewrites)
        let mut dag = PlanDag::new();
        let a = dag.leaf("isolated");
        dag.set_root(a);

        let (_, identity_cert) = dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let identity_compact = identity_cert.compact().unwrap();
        insta::assert_debug_snapshot!("plan_certificate_identity_compact", identity_compact);

        // Multi-step certificate
        let mut complex_dag = PlanDag::new();
        let shared = complex_dag.leaf("shared");
        let left = complex_dag.leaf("left");
        let right = complex_dag.leaf("right");
        let extra = complex_dag.leaf("extra");

        let join_a = complex_dag.join(vec![shared, left]);
        let join_b = complex_dag.join(vec![shared, right]);
        let inner_race = complex_dag.race(vec![join_a, join_b]);
        let outer_join = complex_dag.join(vec![inner_race, extra]);
        complex_dag.set_root(outer_join);

        let (_, multi_cert) = complex_dag.apply_rewrites_certified(
            RewritePolicy::assume_all(),
            &[RewriteRule::DedupRaceJoin, RewriteRule::JoinAssoc],
        );

        if !multi_cert.steps.is_empty() {
            let multi_compact = multi_cert.compact().unwrap();
            insta::assert_debug_snapshot!("plan_certificate_multi_step_compact", multi_compact);
        }
    }

    #[test]
    fn golden_certificate_fingerprints() {
        init_test();

        // Different certificates should have different fingerprints
        let mut dag1 = PlanDag::new();
        let a = dag1.leaf("a");
        let b = dag1.leaf("b");
        let join1 = dag1.join(vec![a, b]);
        dag1.set_root(join1);

        let mut dag2 = PlanDag::new();
        let x = dag2.leaf("x");
        let y = dag2.leaf("y");
        let race2 = dag2.race(vec![x, y]);
        dag2.set_root(race2);

        let (_, cert1) =
            dag1.apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::JoinAssoc]);

        let (_, cert2) =
            dag2.apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::RaceAssoc]);

        let fingerprint1 = cert1.fingerprint();
        let fingerprint2 = cert2.fingerprint();

        // Capture fingerprints as stable golden artifacts.
        // br-asupersync-eyb1s5: 64-character hex digest replaces the
        // u64 16-char hex format. Snapshot files must be regenerated.
        insta::assert_snapshot!("plan_certificate_join_fingerprint", fingerprint1.to_hex());

        insta::assert_snapshot!("plan_certificate_race_fingerprint", fingerprint2.to_hex());

        assert_ne!(
            fingerprint1, fingerprint2,
            "Different certificates should have different fingerprints"
        );
    }

    #[test]
    fn golden_certificate_policy_variations() {
        init_test();

        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        // Conservative policy
        let before_dag = dag.clone();
        let mut conservative_dag = dag.clone();
        let (_, conservative_cert) = conservative_dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);

        let conservative_ledger = conservative_cert.explain(&before_dag, &conservative_dag);
        insta::assert_snapshot!(
            "plan_certificate_conservative_policy_render",
            conservative_ledger.render()
        );

        // Permissive policy
        let mut permissive_dag = dag.clone();
        let (_, permissive_cert) = permissive_dag
            .apply_rewrites_certified(RewritePolicy::assume_all(), &[RewriteRule::DedupRaceJoin]);

        let permissive_ledger = permissive_cert.explain(&before_dag, &permissive_dag);
        insta::assert_snapshot!(
            "plan_certificate_permissive_policy_render",
            permissive_ledger.render()
        );
    }

    #[test]
    fn golden_certificate_minimization_effects() {
        init_test();

        // Create certificate with redundant steps
        let hash = PlanHash::from_u64_seed(0xDEADBEEF);
        let cert_with_redundancy = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::conservative(),
            before_hash: hash,
            after_hash: hash,
            before_node_count: 4,
            after_node_count: 4,
            steps: vec![
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(0),
                    after: PlanId::new(1),
                    detail: "commute forward".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinAssoc,
                    before: PlanId::new(2),
                    after: PlanId::new(2), // no-op
                    detail: "no-op associativity".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::JoinCommute,
                    before: PlanId::new(1),
                    after: PlanId::new(0),
                    detail: "commute back (inverse)".to_string(),
                },
                CertifiedStep {
                    rule: RewriteRule::RaceAssoc,
                    before: PlanId::new(3),
                    after: PlanId::new(4),
                    detail: "meaningful step".to_string(),
                },
            ],
        };

        let minimized = cert_with_redundancy.minimize();

        // Capture before and after minimization.
        // br-asupersync-eyb1s5: fingerprint is now a 32-byte SHA-256 hex
        // digest. Snapshot files must be regenerated.
        insta::assert_snapshot!(
            "plan_certificate_before_minimization",
            format!(
                "steps: {}\nfingerprint: {}",
                cert_with_redundancy.steps.len(),
                cert_with_redundancy.fingerprint().to_hex()
            )
        );

        insta::assert_snapshot!(
            "plan_certificate_after_minimization",
            format!(
                "steps: {}\nfingerprint: {}",
                minimized.steps.len(),
                minimized.fingerprint().to_hex()
            )
        );
    }

    #[test]
    fn golden_certificate_dag_cost_snapshots() {
        init_test();

        // Complex DAG with all node types
        let mut dag = PlanDag::new();
        let a = dag.leaf("service_a");
        let b = dag.leaf("service_b");
        let c = dag.leaf("service_c");

        let timeout_a = dag.timeout(a, Duration::from_millis(500));
        let join_ab = dag.join(vec![timeout_a, b]);
        let race_abc = dag.race(vec![join_ab, c]);
        let timeout_root = dag.timeout(race_abc, Duration::from_secs(2));
        dag.set_root(timeout_root);

        let snapshot = DagCostSnapshot::of(&dag);

        insta::assert_snapshot!(
            "plan_certificate_dag_cost_snapshot",
            format!(
                "node_count: {}\njoins: {}\nraces: {}\ntimeouts: {}\ndepth: {}",
                snapshot.node_count,
                snapshot.joins,
                snapshot.races,
                snapshot.timeouts,
                snapshot.depth
            )
        );
    }

    #[test]
    fn golden_certificate_plan_hash_stability() {
        init_test();

        // Create several DAGs and capture their stable hashes
        let test_cases = [
            ("single_leaf", vec![("a", None)]),
            (
                "simple_join",
                vec![("a", None), ("b", None), ("join_ab", Some("join"))],
            ),
            (
                "simple_race",
                vec![("x", None), ("y", None), ("race_xy", Some("race"))],
            ),
            (
                "nested_timeout",
                vec![
                    ("task", None),
                    ("timeout_inner", Some("timeout")),
                    ("timeout_outer", Some("timeout")),
                ],
            ),
        ];

        let mut hash_outputs = Vec::new();

        for (name, nodes) in test_cases {
            let mut dag = PlanDag::new();
            let mut node_ids = Vec::new();

            for (label, node_type) in nodes {
                let id = match node_type {
                    None => dag.leaf(label),
                    Some("join") => {
                        assert!(node_ids.len() >= 2, "Need at least 2 nodes for join");
                        dag.join(node_ids.clone())
                    }
                    Some("race") => {
                        assert!(node_ids.len() >= 2, "Need at least 2 nodes for race");
                        dag.race(node_ids.clone())
                    }
                    Some("timeout") => {
                        assert!(!node_ids.is_empty(), "Need a child for timeout");
                        dag.timeout(node_ids[node_ids.len() - 1], Duration::from_millis(100))
                    }
                    _ => panic!("Unknown node type"),
                };
                node_ids.push(id);
            }

            if !node_ids.is_empty() {
                dag.set_root(node_ids[node_ids.len() - 1]);
            }

            let hash = PlanHash::of(&dag);
            // br-asupersync-eyb1s5: snapshot the full SHA-256 hex digest
            // instead of a truncated u64. The snapshot file must be
            // regenerated (cargo insta accept) once on this commit.
            hash_outputs.push(format!("{}: {}", name, hash.to_hex()));
        }

        insta::assert_snapshot!("plan_certificate_hash_stability", hash_outputs.join("\n"));
    }

    // -----------------------------------------------------------------------
    // br-asupersync-kpd3k3: replay-style multiset check on Commute rules
    // -----------------------------------------------------------------------

    #[test]
    fn join_commute_rejects_forged_after_with_unrelated_children() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let before = dag.join(vec![a, b]);
        let after = dag.join(vec![x, y]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinCommute,
                before,
                after,
                detail: "forged JoinCommute".to_string(),
            }],
        };

        match verify_steps(&cert, &dag) {
            Err(StepVerifyError::InvalidAfterShape { .. }) => {}
            other => panic!("expected InvalidAfterShape, got {other:?}"),
        }
    }

    #[test]
    fn race_commute_rejects_forged_after_with_unrelated_children() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let before = dag.race(vec![a, b]);
        let after = dag.race(vec![x, y]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::RaceCommute,
                before,
                after,
                detail: "forged RaceCommute".to_string(),
            }],
        };

        match verify_steps(&cert, &dag) {
            Err(StepVerifyError::InvalidAfterShape { .. }) => {}
            other => panic!("expected InvalidAfterShape, got {other:?}"),
        }
    }

    #[test]
    fn join_commute_accepts_legitimate_permutation() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let before = dag.join(vec![c, a, b]);
        let after = dag.join(vec![a, b, c]);
        dag.set_root(before);

        let cert = RewriteCertificate {
            version: CertificateVersion::CURRENT,
            policy: RewritePolicy::assume_all(),
            before_hash: PlanHash::of(&dag),
            after_hash: PlanHash::of(&dag),
            before_node_count: dag.nodes.len(),
            after_node_count: dag.nodes.len(),
            steps: vec![CertifiedStep {
                rule: RewriteRule::JoinCommute,
                before,
                after,
                detail: "legitimate JoinCommute permutation".to_string(),
            }],
        };

        verify_steps(&cert, &dag)
            .expect("legitimate JoinCommute permutation must verify (multiset preserved)");
    }
