    use super::*;
    use crate::atp::quota::{QuotaLimit, QuotaUsage};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn receive_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Receive).collect()
    }

    fn cache_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Cache).collect()
    }

    fn seed_actions() -> BTreeSet<AllowAction> {
        std::iter::once(AllowAction::Seed).collect()
    }

    fn offer(item_id: &str, path: &str, bytes_total: u64) -> InboxOffer {
        InboxOffer {
            item_id: item_id.to_string(),
            object_root: digest(7),
            source_peer: "peer-abcdefghijklmnopqrstuvwxyz".to_string(),
            destination_path: PathBuf::from(path),
            bytes_total,
            manifest_epoch: 3,
            offered_at_epoch_secs: 10,
        }
    }

    fn mailbox_evidence() -> MailboxTamperEvidence {
        MailboxTamperEvidence {
            manifest_root: digest(1),
            stored_object_digest: digest(2),
            manifest_epoch: 7,
            sequence: 42,
            content_length: 4096,
            expires_at_epoch_secs: 100,
            previous_record_digest: Some(digest(3)),
        }
    }

    fn mailbox_receipt() -> MailboxRetrievalReceipt {
        MailboxRetrievalReceipt {
            manifest_root: digest(1),
            stored_object_digest: digest(2),
            manifest_epoch: 7,
            sequence: 42,
            bytes_returned: 4096,
            retrieved_at_epoch_secs: 99,
        }
    }

    fn mailbox_store_request(mailbox_id: &str, stored_bytes: u64) -> MailboxStoreRequest {
        MailboxStoreRequest {
            mailbox_id: mailbox_id.to_string(),
            privacy_policy: MailboxPrivacyPolicy::encrypted(),
            evidence: MailboxTamperEvidence {
                manifest_root: digest(7),
                stored_object_digest: digest(8),
                manifest_epoch: 3,
                sequence: 1,
                content_length: stored_bytes,
                expires_at_epoch_secs: 100,
                previous_record_digest: None,
            },
            stored_bytes,
        }
    }

    fn stored_mailbox_receipt(bytes_returned: u64) -> MailboxRetrievalReceipt {
        MailboxRetrievalReceipt {
            manifest_root: digest(7),
            stored_object_digest: digest(8),
            manifest_epoch: 3,
            sequence: 1,
            bytes_returned,
            retrieved_at_epoch_secs: 12,
        }
    }

    #[test]
    fn mailbox_privacy_policy_requires_encryption_or_public_policy() {
        let encrypted = MailboxPrivacyPolicy::encrypted();
        assert_eq!(
            encrypted.storage_class,
            MailboxStorageClass::EndToEndEncrypted
        );
        encrypted.validate().unwrap(); // ubs:ignore - test oracle

        let mut broken_private = MailboxPrivacyPolicy::encrypted();
        broken_private.encrypted_at_rest = false;
        assert_eq!(
            broken_private.validate().unwrap_err(), // ubs:ignore - test oracle
            MailboxSecurityError::MissingEncryption
        );

        let public = MailboxPrivacyPolicy::explicitly_public("policy:public-fixture");
        public.validate().unwrap(); // ubs:ignore - test oracle
        assert_eq!(
            MailboxPrivacyPolicy::explicitly_public("  ")
                .validate()
                .unwrap_err(), // ubs:ignore - test oracle
            MailboxSecurityError::MissingPublicPolicy
        );

        let redacted = MailboxPrivacyPolicy {
            metadata_peer_visible_chars: 4,
            ..MailboxPrivacyPolicy::encrypted()
        }
        .redact_peer("peer-abcdefghijklmnopqrstuvwxyz");
        assert_eq!(redacted, "peer...");
    }

    #[test]
    fn mailbox_tamper_evidence_rejects_bad_retrievals() {
        let evidence = mailbox_evidence();
        let receipt = mailbox_receipt();
        evidence.validate_retrieval(&receipt, Some(41)).unwrap(); // ubs:ignore - test oracle

        let mut tampered = mailbox_receipt();
        tampered.stored_object_digest = digest(9);
        assert_eq!(
            evidence.validate_retrieval(&tampered, Some(41)),
            Err(MailboxSecurityError::DigestMismatch {
                field: "stored_object_digest"
            })
        );

        let mut replayed = mailbox_receipt();
        replayed.sequence = 41;
        assert_eq!(
            evidence.validate_retrieval(&replayed, Some(41)),
            Err(MailboxSecurityError::Replay {
                last_seen_sequence: Some(41),
                observed_sequence: 41,
            })
        );

        let mut truncated = mailbox_receipt();
        truncated.bytes_returned = 1024;
        assert_eq!(
            evidence.validate_retrieval(&truncated, Some(41)),
            Err(MailboxSecurityError::Truncated {
                expected_bytes: 4096,
                observed_bytes: 1024,
            })
        );

        let mut stale = mailbox_receipt();
        stale.retrieved_at_epoch_secs = 101;
        assert_eq!(
            evidence.validate_retrieval(&stale, Some(41)),
            Err(MailboxSecurityError::StaleEntry {
                expired_at_epoch_secs: 100,
                observed_epoch_secs: 101,
            })
        );
    }

    #[test]
    fn encrypted_mailbox_store_charges_quota_and_records_tamper_evidence() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::MailboxStored);
        assert_eq!(item.grant_id.as_deref(), Some("grant-1"));
        assert_eq!(
            quota.usage(QuotaBucket::Mailbox),
            QuotaUsage {
                bytes: 128,
                records: 1
            }
        );

        let record = inbox.mailbox_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.mailbox_id, "mailbox-1");
        assert_eq!(record.allocation_record_id, "mailbox-1");
        assert_eq!(record.redacted_source_peer, "peer-abc...");
        assert_eq!(record.evidence.stored_object_digest, digest(8));

        let receipt = stored_mailbox_receipt(128);
        record.validate_retrieval(&receipt, None).unwrap(); // ubs:ignore - test oracle
    }

    #[test]
    fn mailbox_get_pending_validates_receipt_before_active_receive() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle

        inbox
            .start_mailbox_retrieval("mailbox-1", &stored_mailbox_receipt(128), None, 13)
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.bytes_received, 128);
        assert_eq!(item.updated_epoch_secs, 13);
    }

    #[test]
    fn mailbox_get_pending_rejects_replay_even_without_caller_sequence() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle
        let receipt = stored_mailbox_receipt(128);
        inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 13)
            .unwrap(); // ubs:ignore - test oracle

        let err = inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 14)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::Replay {
                last_seen_sequence: Some(1),
                observed_sequence: 1
            })
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.bytes_received, 128);
        assert_eq!(item.updated_epoch_secs, 13);
    }

    #[test]
    fn mailbox_get_pending_rejects_tampered_receipt_without_state_change() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap(); // ubs:ignore - test oracle
        let mut receipt = stored_mailbox_receipt(128);
        receipt.stored_object_digest = digest(9);

        let err = inbox
            .start_mailbox_retrieval("mailbox-1", &receipt, None, 13)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::DigestMismatch {
                field: "stored_object_digest"
            })
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::MailboxStored);
        assert_eq!(item.bytes_received, 0);
        assert_eq!(item.updated_epoch_secs, 11);
    }

    #[test]
    fn mailbox_store_rejects_plain_private_storage_before_quota_mutation() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(1024, 4));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        let mut request = mailbox_store_request("mailbox-1", 128);
        request.privacy_policy.encrypted_at_rest = false;

        let err = inbox
            .store_mailbox("in-1", "grant-1", request, &mut quota, 11)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::MailboxSecurity(MailboxSecurityError::MissingEncryption)
        );
        assert_eq!(inbox.list()[0].state, InboxState::Offered); // ubs:ignore - test oracle
        assert_eq!(quota.usage(QuotaBucket::Mailbox), QuotaUsage::default());
        assert!(inbox.mailbox_records().is_empty());
    }

    #[test]
    fn mailbox_store_rejects_quota_exhaustion_before_state_transition() {
        let mut inbox = LocalInbox::new();
        let mut quota = QuotaLedger::new();
        quota.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(64, 1));
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        let err = inbox
            .store_mailbox(
                "in-1",
                "grant-1",
                mailbox_store_request("mailbox-1", 128),
                &mut quota,
                11,
            )
            .unwrap_err(); // ubs:ignore - test oracle

        assert!(matches!(
            err,
            InboxError::Quota(QuotaError::Exhausted {
                bucket: QuotaBucket::Mailbox,
                ..
            })
        ));
        assert_eq!(inbox.list()[0].state, InboxState::Offered); // ubs:ignore - test oracle
        assert_eq!(quota.usage(QuotaBucket::Mailbox), QuotaUsage::default());
    }

    #[test]
    fn unattended_receive_requires_matching_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(
            ReceiveGrant::new(
                "grant-1",
                "peer-a",
                receive_actions(),
                GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
            )
            .with_quota(GrantQuota {
                max_bytes: Some(512),
                max_items: Some(1),
            }),
        );

        inbox.start_receive("in-1", "grant-1", 11).unwrap(); // ubs:ignore - test oracle
        inbox.record_progress("in-1", 128, 12).unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Completed);
        assert_eq!(item.grant_id.as_deref(), Some("grant-1"));
    }

    #[test]
    fn policy_enforcement_rejects_unauthorized_path() {
        let mut inbox = LocalInbox::new();
        inbox.offer(offer("in-1", "/tmp/outside", 64)).unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "grant-1",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));

        let err = inbox.start_receive("in-1", "grant-1", 11).unwrap_err();
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "grant-1".to_string(),
                action: AllowAction::Receive,
            }
        );
    }

    #[test]
    fn cache_verified_records_manifest_root_and_authorizing_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(ReceiveGrant::new(
            "cache-grant",
            "peer-a",
            cache_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.start_receive("in-1", "receive-grant", 11).unwrap(); // ubs:ignore - test oracle

        inbox
            .cache_verified("in-1", "cache-grant", "artifact", 128, 12)
            .unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Cached);
        assert_eq!(item.grant_id.as_deref(), Some("cache-grant"));

        let record = inbox.cache_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.item_id, "in-1");
        assert_eq!(record.object_root, digest(7));
        assert_eq!(record.manifest_epoch, 3);
        assert_eq!(record.object_type, "artifact");
        assert_eq!(record.bytes, 128);
        assert_eq!(record.cache_grant_id, "cache-grant");
        assert_eq!(record.seed_grant_id, None);
        assert_eq!(record.cached_at_epoch_secs, 12);
    }

    #[test]
    fn cache_verified_rejects_expired_or_mismatched_grants_without_state_change() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(
            ReceiveGrant::new(
                "expired-cache-grant",
                "peer-a",
                cache_actions(),
                GrantScope::Cache {
                    object_types: std::iter::once("artifact".to_string()).collect(),
                    max_bytes: Some(512),
                },
            )
            .with_expiry(11),
        );
        inbox.start_receive("in-1", "receive-grant", 10).unwrap(); // ubs:ignore - test oracle

        let err = inbox
            .cache_verified("in-1", "expired-cache-grant", "artifact", 128, 12)
            .unwrap_err(); // ubs:ignore - test oracle

        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "expired-cache-grant".to_string(),
                action: AllowAction::Cache,
            }
        );
        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Active);
        assert_eq!(item.grant_id.as_deref(), Some("receive-grant"));
        assert!(inbox.cache_records().is_empty());
    }

    #[test]
    fn seed_cached_requires_active_seed_grant() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 128))
            .unwrap(); // ubs:ignore - test oracle
        inbox.allow(ReceiveGrant::new(
            "receive-grant",
            "peer-a",
            receive_actions(),
            GrantScope::PathPrefix(PathBuf::from("/data/inbox")),
        ));
        inbox.allow(ReceiveGrant::new(
            "cache-grant",
            "peer-a",
            cache_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.allow(
            ReceiveGrant::new(
                "expired-seed-grant",
                "peer-a",
                seed_actions(),
                GrantScope::ObjectGraph(digest(7)),
            )
            .with_expiry(12),
        );
        inbox.allow(ReceiveGrant::new(
            "seed-grant",
            "peer-a",
            seed_actions(),
            GrantScope::ObjectGraph(digest(7)),
        ));
        inbox.start_receive("in-1", "receive-grant", 10).unwrap(); // ubs:ignore - test oracle
        inbox
            .cache_verified("in-1", "cache-grant", "artifact", 128, 11)
            .unwrap(); // ubs:ignore - test oracle

        let err = inbox.seed_cached("in-1", "cache-grant", 13).unwrap_err(); // ubs:ignore - test oracle
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "cache-grant".to_string(),
                action: AllowAction::Seed,
            }
        );
        let err = inbox
            .seed_cached("in-1", "expired-seed-grant", 13)
            .unwrap_err(); // ubs:ignore - test oracle
        assert_eq!(
            err,
            InboxError::Unauthorized {
                grant_id: "expired-seed-grant".to_string(),
                action: AllowAction::Seed,
            }
        );

        inbox.seed_cached("in-1", "seed-grant", 14).unwrap(); // ubs:ignore - test oracle

        let item = inbox.list()[0]; // ubs:ignore - test oracle
        assert_eq!(item.state, InboxState::Seeded);
        assert_eq!(item.grant_id.as_deref(), Some("seed-grant"));
        let record = inbox.cache_records()[0]; // ubs:ignore - test oracle
        assert_eq!(record.cache_grant_id, "cache-grant");
        assert_eq!(record.seed_grant_id.as_deref(), Some("seed-grant"));
        assert_eq!(record.seeded_at_epoch_secs, Some(14));
    }

    #[test]
    fn state_transitions_cover_mailbox_cache_seed_and_cancel() {
        let mut inbox = LocalInbox::new();
        inbox
            .offer(offer("in-1", "/data/inbox/project", 64))
            .unwrap(); // ubs:ignore - test oracle

        inbox
            .transition("in-1", InboxState::MailboxStored, 11)
            .unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Cached, 12).unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Seeded, 13).unwrap(); // ubs:ignore - test oracle
        inbox.transition("in-1", InboxState::Completed, 14).unwrap(); // ubs:ignore - test oracle

        let diagnostics = inbox.diagnostics();
        assert_eq!(diagnostics.completed_count, 1);
        assert_eq!(diagnostics.mailbox_stored_count, 0);
    }

    #[test]
    fn json_and_human_output_are_stable_and_redacted() {
        let mut inbox = LocalInbox::new();
        inbox.offer(offer("b", "/data/inbox/b", 2)).unwrap(); // ubs:ignore - test oracle
        inbox.offer(offer("a", "/data/inbox/a", 1)).unwrap(); // ubs:ignore - test oracle

        let human = inbox.human_rows();
        assert_eq!(human[0], "id state bytes source destination");
        assert!(human[1].starts_with("a offered 0/1 peer-abc..."));
        assert!(human[2].starts_with("b offered 0/2 peer-abc..."));

        let json = inbox.json_lines().unwrap(); // ubs:ignore - test oracle
        assert!(json[0].contains("\"item_id\":\"a\""));
        assert!(!json[0].contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn daemon_diagnostics_have_stable_rows() {
        let diagnostics = DaemonDiagnostics {
            active_transfers: 1,
            path_count: 2,
            repair_sessions: 3,
            disk_available_bytes: Some(4096),
            journal_entries: 4,
            grant_count: 5,
            cache_entries: 6,
            inbox_items: 7,
            platform: "linux-x86_64-secret".to_string(),
            service_lifecycle: "running".to_string(),
        };

        let rows = diagnostics.stable_human_lines();
        assert_eq!(rows[0], "lifecycle running");
        assert_eq!(rows[1], "platform linux-x8...");
        assert!(rows.contains(&"disk_available_bytes 4096".to_string()));
    }
