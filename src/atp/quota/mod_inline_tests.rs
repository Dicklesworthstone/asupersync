    use super::*;

    #[test]
    fn quota_reserve_and_release_are_accounted() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Cache, QuotaLimit::new(100, 2));

        ledger
            .reserve(
                "cache-a",
                QuotaAllocation::one_record(QuotaBucket::Cache, 40),
            )
            .unwrap(); // ubs:ignore - test oracle
        ledger
            .reserve(
                "cache-b",
                QuotaAllocation::one_record(QuotaBucket::Cache, 50),
            )
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            ledger.usage(QuotaBucket::Cache),
            QuotaUsage {
                bytes: 90,
                records: 2
            }
        );
        assert_eq!(
            ledger.release("cache-a").unwrap(),
            QuotaAllocation::one_record(QuotaBucket::Cache, 40)
        );
        assert_eq!(
            ledger.usage(QuotaBucket::Cache),
            QuotaUsage {
                bytes: 50,
                records: 1
            }
        );
    }

    #[test]
    fn quota_exhaustion_fails_before_mutating_usage() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(10, 1));
        ledger
            .reserve(
                "mail-a",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 8),
            )
            .unwrap(); // ubs:ignore - test oracle

        let err = ledger
            .reserve(
                "mail-b",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 1),
            )
            .unwrap_err(); // ubs:ignore - test oracle

        assert!(matches!(
            err,
            QuotaError::Exhausted {
                bucket: QuotaBucket::Mailbox,
                ..
            }
        ));
        assert_eq!(
            ledger.usage(QuotaBucket::Mailbox),
            QuotaUsage {
                bytes: 8,
                records: 1
            }
        );
        assert_eq!(ledger.allocation_count(), 1);
    }

    #[test]
    fn retention_uses_explicit_expiry_and_max_age() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(QuotaBucket::Traces, RetentionRule::max_age(10));
        let records = vec![
            RetentionRecord {
                record_id: "new".to_string(),
                bucket: QuotaBucket::Traces,
                clock: RetentionClock::new(0, 95),
            },
            RetentionRecord {
                record_id: "old".to_string(),
                bucket: QuotaBucket::Traces,
                clock: RetentionClock::new(0, 80),
            },
            RetentionRecord {
                record_id: "explicit".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 99).with_expiry(100),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["explicit".to_string(), "old".to_string()]
        );
    }

    #[test]
    fn retention_enforces_max_records_by_oldest_update() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(
            QuotaBucket::Diagnostics,
            RetentionRule {
                max_age_secs: None,
                max_records: Some(2),
                honor_explicit_expiry: true,
            },
        );
        let records = vec![
            RetentionRecord {
                record_id: "middle".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 20),
            },
            RetentionRecord {
                record_id: "oldest".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 10),
            },
            RetentionRecord {
                record_id: "newest".to_string(),
                bucket: QuotaBucket::Diagnostics,
                clock: RetentionClock::new(0, 30),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["oldest".to_string()]
        );
    }

    #[test]
    fn retention_max_records_ignores_already_expired_records() {
        let mut policy = RetentionPolicy::daemon_defaults();
        policy.set_rule(
            QuotaBucket::Mailbox,
            RetentionRule {
                max_age_secs: None,
                max_records: Some(1),
                honor_explicit_expiry: true,
            },
        );
        let records = vec![
            RetentionRecord {
                record_id: "live-older".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 10),
            },
            RetentionRecord {
                record_id: "expired-newer".to_string(),
                bucket: QuotaBucket::Mailbox,
                clock: RetentionClock::new(0, 30).with_expiry(100),
            },
        ];

        assert_eq!(
            policy.expired_records(&records, 100),
            vec!["expired-newer".to_string()]
        );
    }

    #[test]
    fn quota_rows_are_deterministic() {
        let mut ledger = QuotaLedger::new();
        ledger.set_limit(QuotaBucket::Traces, QuotaLimit::new(10, 10));
        ledger.set_limit(QuotaBucket::Cache, QuotaLimit::new(20, 20));

        let rows = ledger.rows();
        assert_eq!(rows[0].bucket, QuotaBucket::Cache);
        assert_eq!(rows[1].bucket, QuotaBucket::Traces);
    }
