    use super::*;

    fn test_object_id(name: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(name))
    }

    fn test_root(seed: u8) -> MerkleRoot {
        let mut hash = [0; 32];
        hash[0] = seed;
        MerkleRoot::new(hash)
    }

    fn test_auth_key() -> AuthKey {
        AuthKey::from_seed(42)
    }

    fn unsigned_tag() -> AuthenticationTag {
        AuthenticationTag::zero()
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), unique))
    }

    #[test]
    fn journal_file_name_contract_matches_generation_parser() {
        assert_eq!(journal_file_name(0), "journal_gen_000000.dat");
        assert_eq!(journal_file_name(42), "journal_gen_000042.dat");
        assert_eq!(parse_journal_generation(&journal_file_name(42)), Some(42));
        assert_eq!(parse_journal_generation("journal_42.dat"), None);
        assert_eq!(parse_journal_generation("journal_gen_000042.tmp"), None);
    }

    #[test]
    fn checked_u32_len_rejects_oversized_field_without_panic() {
        let err = checked_u32_len(u32::MAX as usize + 1, "source_chunks")
            .expect_err("oversized fields must become serialization errors");
        assert!(matches!(err, JournalError::Serialization(_)));
        assert!(err.to_string().contains("source_chunks"));
    }

    #[test]
    fn repair_decode_rejects_unbacked_source_count_before_allocation() {
        for count in [1024_u32, u32::MAX] {
            let mut payload = vec![5];
            put_string(&mut payload, "repair");
            put_u64(&mut payload, 0);
            put_u64(&mut payload, 4096);
            payload.extend_from_slice(&count.to_le_bytes());
            let err = JournalRecord::decode_payload(&payload).unwrap_err();
            assert!(matches!(err, JournalError::Deserialization(_)));
            assert!(
                err.to_string()
                    .contains("source count exceeds remaining payload")
            );
        }
    }

    #[test]
    fn repair_decode_preserves_valid_empty_and_nonempty_sources() {
        for source_chunks in [vec![], vec![0, 4096, u64::MAX]] {
            let record = JournalRecord::RepairDecode {
                transfer_id: "repair".to_string(),
                chunk_offset: 8192,
                chunk_size: 4096,
                source_chunks,
                timestamp: 42,
                auth_tag: unsigned_tag(),
            };
            let payload = record.encode_payload();
            let decoded = JournalRecord::decode_payload(&payload).unwrap();
            assert_eq!(decoded.encode_payload(), payload);
            assert!(JournalRecord::decode_payload(&payload[..payload.len() - 1]).is_err());
        }
    }

    #[test]
    fn test_journal_entry_creation() {
        let record = JournalRecord::Offer {
            transfer_id: "test_transfer".to_string(),
            object_id: test_object_id(b"test_object"),
            manifest_root: test_root(1),
            total_size: 1024,
            timestamp: 1234567890,
            auth_tag: unsigned_tag(),
        }
        .with_signature(&test_auth_key());

        let entry = JournalEntry::new(0, record);
        assert_eq!(entry.sequence, 0);
        assert!(entry.validate_checksum());
    }

    #[test]
    fn test_journal_append() {
        let temp_dir = std::env::temp_dir().join("test_journal");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config, test_auth_key()).unwrap();

        let record = JournalRecord::Accept {
            transfer_id: "test_transfer".to_string(),
            peer_id: "peer123".to_string(),
            timestamp: 1234567890,
            auth_tag: unsigned_tag(),
        };

        let sequence = journal.append(record).unwrap();
        assert_eq!(sequence, 0);

        let stats = journal.get_stats();
        assert_eq!(stats.sequence, 1);
        assert_eq!(stats.recent_entries_count, 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn force_sync_append_is_recoverable_before_explicit_flush_or_drop() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_journal_force_sync_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            force_sync: true,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        let sequence = journal
            .append(JournalRecord::Accept {
                transfer_id: "durable_transfer".to_string(),
                peer_id: "peer123".to_string(),
                timestamp: 1234567890,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        assert_eq!(sequence, 0);
        assert_eq!(journal.get_stats().sequence, 1);

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.sequence, 1);
        assert_eq!(recovered_stats.recent_entries_count, 1);

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn non_force_sync_append_is_recoverable_before_explicit_flush_or_drop() {
        let temp_dir = unique_temp_dir("test_journal_non_force_sync");
        let config = JournalConfig {
            base_dir: temp_dir,
            force_sync: false,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        let sequence = journal
            .append(JournalRecord::Accept {
                transfer_id: "buffered_transfer".to_string(),
                peer_id: "peer123".to_string(),
                timestamp: 1234567890,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        assert_eq!(sequence, 0);
        assert_eq!(journal.get_stats().sequence, 1);

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.sequence, 1);
        assert_eq!(recovered_stats.recent_entries_count, 1);
    }

    #[test]
    fn recovery_io_failure_refuses_reopen_without_resetting_existing_progress() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("journal_recovery_io_failure"),
            ..Default::default()
        };
        {
            let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
            journal
                .append(JournalRecord::Accept {
                    transfer_id: "existing".to_string(),
                    peer_id: "peer".to_string(),
                    timestamp: 1,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal.flush().unwrap();
        }
        let original_path = journal_file_path(&config.base_dir, 0);
        let original = std::fs::read(&original_path).unwrap();
        // A directory at a generation path causes a real open/read error,
        // including when tests run as root (unlike permission-bit fixtures).
        let unreadable = journal_file_path(&config.base_dir, 1);
        std::fs::create_dir(&unreadable).unwrap();
        assert!(matches!(
            AppendJournal::new(config.clone(), test_auth_key()),
            Outcome::Err(JournalError::FileOpen(_) | JournalError::ReadFailure(_))
        ));
        assert_eq!(std::fs::read(&original_path).unwrap(), original);
        assert!(unreadable.is_dir());
        assert!(!journal_file_path(&config.base_dir, 2).exists());
    }

    #[test]
    fn recovery_directory_scan_failure_is_not_an_empty_journal() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("journal_recovery_scan_failure"),
            ..Default::default()
        };
        let mut journal = AppendJournal::new(config, test_auth_key()).unwrap();
        let non_directory = journal.config.base_dir.join("not_a_directory");
        std::fs::write(&non_directory, b"preserve").unwrap();
        journal.config.base_dir = non_directory.clone();
        assert!(matches!(
            journal.recover_from_disk(),
            Outcome::Err(JournalError::DirectoryRead(_))
        ));
        assert_eq!(std::fs::read(non_directory).unwrap(), b"preserve");
    }

    #[test]
    #[cfg(unix)]
    fn generation_metadata_errors_are_not_missing_history() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("journal_metadata_error"),
            ..Default::default()
        };
        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        journal
            .append(JournalRecord::Accept {
                transfer_id: "metadata-error".to_string(),
                peer_id: "peer".to_string(),
                timestamp: 1,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal.flush().unwrap();
        let original_path = journal_file_path(&config.base_dir, 0);
        let original = std::fs::read(&original_path).unwrap();
        let unreadable_path = journal_file_path(&config.base_dir, 1);
        // A self-referential symlink produces a real metadata error even for
        // privileged test runners, unlike a mode-bit permission fixture.
        std::os::unix::fs::symlink(journal_file_name(1), &unreadable_path).unwrap();
        assert!(unreadable_path.try_exists().is_err());
        journal.generation = 1;
        assert!(matches!(
            journal.read_all_entries_from_disk(),
            Outcome::Err(JournalError::ReadFailure(_))
        ));
        assert!(matches!(
            AppendJournal::new(config.clone(), test_auth_key()),
            Outcome::Err(JournalError::ReadFailure(_))
        ));
        assert_eq!(std::fs::read(original_path).unwrap(), original);
        assert!(
            std::fs::symlink_metadata(unreadable_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!journal_file_path(&config.base_dir, 2).exists());
    }

    #[test]
    fn interior_frame_corruption_refuses_without_breaking_eof_tail_recovery() {
        for bad_checksum in [false, true] {
            for has_following_frame in [false, true] {
                for sealed in [false, true] {
                    let config = JournalConfig {
                        base_dir: unique_temp_dir("interior_journal_corruption"),
                        ..Default::default()
                    };
                    let record = JournalRecord::Accept {
                        transfer_id: "interior-corruption".to_string(),
                        peer_id: "peer".to_string(),
                        timestamp: 1,
                        auth_tag: unsigned_tag(),
                    };
                    let frame = |sequence| {
                        let entry = JournalEntry::try_new(
                            sequence,
                            record.clone().with_signature(&test_auth_key()),
                        )
                        .unwrap();
                        let encoded = entry.encode();
                        let mut frame =
                            u32::try_from(encoded.len()).unwrap().to_le_bytes().to_vec();
                        frame.extend_from_slice(&encoded);
                        frame
                    };
                    let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
                    journal.append(record.clone()).unwrap();
                    journal.flush().unwrap();
                    let path = journal_file_path(&config.base_dir, 0);
                    let mut bytes = std::fs::read(&path).unwrap();
                    let mut damaged = frame(1);
                    if bad_checksum {
                        damaged[4 + 8] ^= 1;
                    } else {
                        // Payload tag follows the frame prefix and entry header.
                        damaged[4 + 16] = u8::MAX;
                    }
                    bytes.extend_from_slice(&damaged);
                    if has_following_frame {
                        bytes.extend_from_slice(&frame(2));
                    }
                    drop(journal);
                    std::fs::write(&path, &bytes).unwrap();
                    if sealed {
                        std::fs::write(journal_file_path(&config.base_dir, 1), []).unwrap();
                    }
                    let recovered = AppendJournal::new(config.clone(), test_auth_key());
                    if has_following_frame {
                        assert!(matches!(
                            (bad_checksum, recovered),
                            (true, Outcome::Err(JournalError::ChecksumMismatch(1)))
                                | (false, Outcome::Err(JournalError::Deserialization(_)))
                        ));
                    } else {
                        let mut recovered = recovered.unwrap();
                        assert_eq!(recovered.get_stats().generation, 1);
                        assert_eq!(recovered.append(record).unwrap(), 1);
                        recovered.flush().unwrap();
                        let restarted = AppendJournal::new(config, test_auth_key()).unwrap();
                        let entries = restarted.read_all_entries_from_disk().unwrap();
                        assert_eq!(entries.len(), 2);
                        assert_eq!(entries[0].sequence, 0);
                        assert_eq!(entries[1].sequence, 1);
                    }
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                }
            }
        }
    }

    #[test]
    fn exhausted_journal_counters_refuse_without_mutating_disk() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("exhausted_journal_sequence"),
            max_journal_size: u64::MAX,
            ..Default::default()
        };
        let record = JournalRecord::Accept {
            transfer_id: "sequence-boundary".to_string(),
            peer_id: "peer".to_string(),
            timestamp: 1,
            auth_tag: unsigned_tag(),
        };
        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        journal.sequence = u64::MAX - 1;
        assert_eq!(journal.append(record.clone()).unwrap(), u64::MAX - 1);
        journal.flush().unwrap();
        let path = journal_file_path(&config.base_dir, 0);
        let original = std::fs::read(&path).unwrap();
        assert!(matches!(
            journal.append(record.clone()),
            Outcome::Err(JournalError::Serialization(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let mut reopened = AppendJournal::new(config, test_auth_key()).unwrap();
        assert_eq!(reopened.get_stats().sequence, u64::MAX);
        assert!(matches!(
            reopened.append(record.clone()),
            Outcome::Err(JournalError::Serialization(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let exhausted = JournalConfig {
            base_dir: unique_temp_dir("exhausted_recovered_sequence"),
            ..Default::default()
        };
        std::fs::create_dir_all(&exhausted.base_dir).unwrap();
        let entry =
            JournalEntry::try_new(u64::MAX, record.with_signature(&test_auth_key())).unwrap();
        let encoded = entry.encode();
        let mut frame = u32::try_from(encoded.len()).unwrap().to_le_bytes().to_vec();
        frame.extend_from_slice(&encoded);
        let path = journal_file_path(&exhausted.base_dir, 0);
        std::fs::write(&path, &frame).unwrap();
        assert!(matches!(
            AppendJournal::new(exhausted, test_auth_key()),
            Outcome::Err(JournalError::Deserialization(_))
        ));
        assert_eq!(std::fs::read(path).unwrap(), frame);

        let exhausted = JournalConfig {
            base_dir: unique_temp_dir("exhausted_journal_generation"),
            ..Default::default()
        };
        std::fs::create_dir_all(&exhausted.base_dir).unwrap();
        let path = journal_file_path(&exhausted.base_dir, u64::MAX);
        std::fs::write(&path, [1_u8]).unwrap();
        assert!(matches!(
            AppendJournal::new(exhausted, test_auth_key()),
            Outcome::Err(JournalError::Deserialization(_))
        ));
        assert_eq!(std::fs::read(path).unwrap(), [1_u8]);
    }

    #[test]
    fn sparse_generation_numbers_preserve_recovery_order_and_read_frontier() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("sparse_journal_generations"),
            max_journal_size: u64::MAX,
            ..Default::default()
        };
        let record = |peer: &str| JournalRecord::Accept {
            transfer_id: "sparse-generations".to_string(),
            peer_id: peer.to_string(),
            timestamp: 1,
            auth_tag: unsigned_tag(),
        };
        let mut original = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        assert_eq!(original.append(record("first")).unwrap(), 0);
        original.flush().unwrap();

        let high_generation = 1_u64 << 40;
        std::fs::write(journal_file_path(&config.base_dir, high_generation), []).unwrap();
        let mut recovered = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        assert_eq!(recovered.get_stats().generation, high_generation);
        assert_eq!(recovered.append(record("second")).unwrap(), 1);
        recovered.flush().unwrap();

        let entries = recovered.read_all_entries_from_disk().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
        assert!(
            matches!(&entries[0].record, JournalRecord::Accept { peer_id, .. } if peer_id == "first")
        );
        assert!(
            matches!(&entries[1].record, JournalRecord::Accept { peer_id, .. } if peer_id == "second")
        );
        // A pre-existing reader does not silently advance its own frontier.
        assert_eq!(original.read_all_entries_from_disk().unwrap().len(), 1);
        let reopened = AppendJournal::new(config, test_auth_key()).unwrap();
        assert_eq!(reopened.get_stats().sequence, 2);
        assert_eq!(
            reopened
                .get_transfer_entries("sparse-generations")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn native_recovery_io_refusal_preserves_bitmap_before_quarantine() {
        use crate::atp::journal::{ChunkBitmap, RecoveryError, recover_journal_and_bitmap};
        use crate::runtime::RuntimeBuilder;

        for unreadable_generation in [false, true] {
            let base = unique_temp_dir("native_journal_recovery_io");
            let journal_dir = base.join("journal");
            let bitmap_dir = base.join("bitmaps");
            std::fs::create_dir_all(&journal_dir).unwrap();
            std::fs::create_dir_all(&bitmap_dir).unwrap();
            let journal_path = journal_file_path(&journal_dir, 0);
            if unreadable_generation {
                std::fs::create_dir(&journal_path).unwrap();
            }
            let bitmap_path = bitmap_dir.join("transfer_existing.bitmap");
            let bytes = ChunkBitmap::new("existing".to_string(), 1024, 512, 1).serialize_to_bytes();
            std::fs::write(&bitmap_path, &bytes).unwrap();
            let runtime = RuntimeBuilder::current_thread()
                .blocking_threads(1, 1)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = crate::Cx::current().expect("native root context");
                let result =
                    recover_journal_and_bitmap(&cx, &journal_path, &bitmap_dir, &test_auth_key())
                        .await;
                let quarantine_path = bitmap_path.with_extension("bitmap.stale");
                if unreadable_generation {
                    assert!(matches!(result, Err(RecoveryError::JournalCorrupted(_))));
                    assert_eq!(std::fs::read(&bitmap_path).unwrap(), bytes);
                    assert!(!quarantine_path.exists());
                    assert!(journal_path.is_dir());
                } else {
                    let (_, bitmaps) = result.expect("empty journal is valid recovery");
                    assert!(bitmaps.is_empty());
                    assert!(!bitmap_path.exists());
                    assert_eq!(std::fs::read(quarantine_path).unwrap(), bytes);
                }
            });
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(3)));
        }
    }

    #[test]
    fn torn_length_prefix_rotates_and_preserves_later_appends_across_restarts() {
        for prefix_len in 0..4 {
            let config = JournalConfig {
                base_dir: unique_temp_dir("torn_length_prefix"),
                ..Default::default()
            };
            let record = |peer: &str| JournalRecord::Accept {
                transfer_id: "torn-prefix".to_string(),
                peer_id: peer.to_string(),
                timestamp: 42,
                auth_tag: unsigned_tag(),
            };
            {
                let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
                assert_eq!(journal.append(record("before")).unwrap(), 0);
                journal.flush().unwrap();
            }
            let original = journal_file_path(&config.base_dir, 0);
            {
                let mut file = OpenOptions::new().append(true).open(&original).unwrap();
                file.write_all(&128_u32.to_le_bytes()[..prefix_len])
                    .unwrap();
                file.sync_all().unwrap();
            }
            let original_bytes = std::fs::read(&original).unwrap();
            {
                let mut recovered = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
                assert_eq!(recovered.get_stats().generation, u64::from(prefix_len != 0));
                assert_eq!(recovered.append(record("after")).unwrap(), 1);
                recovered.flush().unwrap();
            }
            if prefix_len != 0 {
                assert_eq!(std::fs::read(&original).unwrap(), original_bytes);
            }
            let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
            let entries = recovered.get_transfer_entries("torn-prefix").unwrap();
            assert_eq!(entries.len(), 2, "prefix length {prefix_len}");
            assert_eq!(entries[0].sequence, 0);
            assert_eq!(entries[1].sequence, 1);
            assert_eq!(
                entries[1].record,
                record("after").with_signature(&test_auth_key())
            );
        }
    }

    #[test]
    fn test_journal_recovery() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_journal_recovery_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        // Create and populate journal
        {
            let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();

            journal
                .append(JournalRecord::Offer {
                    transfer_id: "test1".to_string(),
                    object_id: test_object_id(b"obj1"),
                    manifest_root: test_root(1),
                    total_size: 1024,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            journal
                .append(JournalRecord::Accept {
                    transfer_id: "test1".to_string(),
                    peer_id: "peer1".to_string(),
                    timestamp: 1001,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            journal.flush().unwrap();
        }

        // Recover and verify
        {
            let journal = AppendJournal::new(config, test_auth_key()).unwrap();
            let stats = journal.get_stats();
            assert_eq!(stats.sequence, 2);
            assert_eq!(stats.recent_entries_count, 2);
        }

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_transfer_entries() {
        let temp_dir = std::env::temp_dir().join("test_transfer_entries");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config, test_auth_key()).unwrap();

        // Add entries for different transfers
        journal
            .append(JournalRecord::Offer {
                transfer_id: "transfer_a".to_string(),
                object_id: test_object_id(b"obj_a"),
                manifest_root: test_root(1),
                total_size: 1024,
                timestamp: 1000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "transfer_b".to_string(),
                object_id: test_object_id(b"obj_b"),
                manifest_root: test_root(4),
                total_size: 2048,
                timestamp: 1001,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal
            .append(JournalRecord::Accept {
                transfer_id: "transfer_a".to_string(),
                peer_id: "peer1".to_string(),
                timestamp: 1002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        // Get entries for specific transfer
        let transfer_a_entries = journal.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(transfer_a_entries.len(), 2);

        let transfer_b_entries = journal.get_transfer_entries("transfer_b").unwrap();
        assert_eq!(transfer_b_entries.len(), 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn transfer_index_returns_entries_outside_recent_cache() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_transfer_index_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir,
            recent_entries_limit: 1,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();

        for (transfer_id, timestamp) in [
            ("transfer_a", 1000),
            ("transfer_b", 1001),
            ("transfer_a", 1002),
        ] {
            journal
                .append(JournalRecord::Accept {
                    transfer_id: transfer_id.to_string(),
                    peer_id: "peer1".to_string(),
                    timestamp,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        assert_eq!(journal.recent_entries.len(), 1);
        let transfer_a_entries = journal.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(
            transfer_a_entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );

        journal.flush().unwrap();
        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        assert_eq!(recovered.recent_entries.len(), 1);
        let recovered_transfer_a_entries = recovered.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(
            recovered_transfer_a_entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn resume_summary_reconstructs_durable_chunks_after_recovery() {
        let temp_dir = unique_temp_dir("test_resume_summary_recovery");
        let key = test_auth_key();
        let config = JournalConfig {
            base_dir: temp_dir,
            ..Default::default()
        };

        {
            let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
            journal
                .append(JournalRecord::Offer {
                    transfer_id: "resume_a".to_string(),
                    object_id: test_object_id(b"resume_a"),
                    manifest_root: test_root(7),
                    total_size: 4096,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            for (chunk_offset, chunk_size, hash_seed, timestamp) in
                [(0, 512, 1, 1001), (512, 512, 2, 1003), (2048, 512, 3, 1005)]
            {
                journal
                    .append(JournalRecord::ChunkVerified {
                        transfer_id: "resume_a".to_string(),
                        chunk_offset,
                        chunk_size,
                        verified_hash: [hash_seed; 32],
                        timestamp,
                        auth_tag: unsigned_tag(),
                    })
                    .unwrap();
                journal
                    .append(JournalRecord::ChunkWritten {
                        transfer_id: "resume_a".to_string(),
                        chunk_offset,
                        chunk_size,
                        file_path: format!("stage/{chunk_offset}"),
                        timestamp: timestamp + 1,
                        auth_tag: unsigned_tag(),
                    })
                    .unwrap();
            }

            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: "resume_a".to_string(),
                    chunk_offset: 3072,
                    chunk_size: 512,
                    verified_hash: [4; 32],
                    timestamp: 1007,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal.flush().unwrap();
        }

        let recovered = AppendJournal::new(config, key).unwrap();
        let summary = recovered.get_resume_summary("resume_a").unwrap();

        assert!(summary.is_resumable());
        assert_eq!(summary.status, TransferResumeStatus::Resumable);
        assert_eq!(summary.total_size, Some(4096));
        assert_eq!(summary.durable_bytes, 1536);
        assert_eq!(summary.contiguous_prefix_bytes, 1024);
        assert_eq!(
            summary
                .durable_chunks
                .iter()
                .map(|chunk| (chunk.chunk_offset, chunk.chunk_size, chunk.chunk_hash[0]))
                .collect::<Vec<_>>(),
            vec![(0, 512, 1), (512, 512, 2), (2048, 512, 3)]
        );
        assert_eq!(summary.last_sequence, Some(7));
    }

    #[test]
    fn resume_summary_fail_closes_for_terminal_states() {
        let temp_dir = unique_temp_dir("test_resume_summary_terminal");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        for transfer_id in ["cancelled", "rolled_back"] {
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.to_string(),
                    chunk_offset: 0,
                    chunk_size: 128,
                    verified_hash: [9; 32],
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.to_string(),
                    chunk_offset: 0,
                    chunk_size: 128,
                    file_path: "stage/0".to_string(),
                    timestamp: 2001,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }
        journal
            .append(JournalRecord::Cancellation {
                transfer_id: "cancelled".to_string(),
                reason: "operator stop".to_string(),
                timestamp: 2002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::Rollback {
                transfer_id: "rolled_back".to_string(),
                rollback_reason: "hash mismatch".to_string(),
                checkpoint_sequence: 1,
                timestamp: 2003,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        let cancelled = journal.get_resume_summary("cancelled").unwrap();
        assert_eq!(
            cancelled.status,
            TransferResumeStatus::Cancelled {
                reason: "operator stop".to_string()
            }
        );
        assert_eq!(cancelled.durable_chunks, Vec::new());
        assert_eq!(cancelled.contiguous_prefix_bytes, 0);

        let rolled_back = journal.get_resume_summary("rolled_back").unwrap();
        assert_eq!(
            rolled_back.status,
            TransferResumeStatus::RolledBack {
                reason: "hash mismatch".to_string(),
                checkpoint_sequence: 1,
            }
        );
        assert_eq!(rolled_back.durable_bytes, 0);
        assert!(!rolled_back.is_resumable());
    }

    #[test]
    fn resume_summary_rejects_crc_valid_records_signed_with_wrong_key() {
        let config = JournalConfig {
            base_dir: unique_temp_dir("test_resume_summary_wrong_key"),
            ..Default::default()
        };
        {
            let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: "wrong_key".to_string(),
                    chunk_offset: 0,
                    chunk_size: 4096,
                    verified_hash: [7; 32],
                    timestamp: 1,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: "wrong_key".to_string(),
                    chunk_offset: 0,
                    chunk_size: 4096,
                    file_path: "stage/0".to_string(),
                    timestamp: 2,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal.flush().unwrap();
        }
        let trusted = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        assert_eq!(
            trusted
                .get_resume_summary("wrong_key")
                .unwrap()
                .durable_bytes,
            4096
        );
        let untrusted = AppendJournal::new(config, AuthKey::from_seed(43)).unwrap();
        let entries = untrusted.get_transfer_entries("wrong_key").unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(JournalEntry::validate_checksum));
        match untrusted.get_resume_summary("wrong_key") {
            Outcome::Err(JournalError::Deserialization(message)) => {
                assert!(message.contains("authentication failed"));
            }
            other => panic!("expected unauthenticated progress rejection, got {other:?}"),
        }
    }

    #[test]
    fn resume_summary_rejects_overlapping_durable_chunks() {
        let temp_dir = unique_temp_dir("test_resume_summary_overlap");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "overlap".to_string(),
                object_id: test_object_id(b"overlap"),
                manifest_root: test_root(8),
                total_size: 128,
                timestamp: 3000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        for (chunk_offset, hash_seed) in [(0, 1), (8, 2)] {
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: "overlap".to_string(),
                    chunk_offset,
                    chunk_size: 16,
                    verified_hash: [hash_seed; 32],
                    timestamp: 3001 + chunk_offset,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: "overlap".to_string(),
                    chunk_offset,
                    chunk_size: 16,
                    file_path: format!("stage/{chunk_offset}"),
                    timestamp: 3002 + chunk_offset,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        match journal.get_resume_summary("overlap") {
            Outcome::Err(err) => {
                assert!(matches!(err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("overlap"));
            }
            other => panic!("expected overlap to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn resume_summary_rejects_conflicting_offer_total_size() {
        let temp_dir = unique_temp_dir("test_resume_summary_offer_conflict");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        for (total_size, timestamp) in [(1024, 4000), (2048, 4001)] {
            journal
                .append(JournalRecord::Offer {
                    transfer_id: "offer_conflict".to_string(),
                    object_id: test_object_id(b"offer_conflict"),
                    manifest_root: test_root(9),
                    total_size,
                    timestamp,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        match journal.get_resume_summary("offer_conflict") {
            Outcome::Err(err) => {
                assert!(matches!(&err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("total_size conflict"));
            }
            other => panic!("expected conflicting offer sizes to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn resume_summary_rejects_conflicting_verified_chunk_hash() {
        let temp_dir = unique_temp_dir("test_resume_summary_hash_conflict");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "hash_conflict".to_string(),
                object_id: test_object_id(b"hash_conflict"),
                manifest_root: test_root(10),
                total_size: 512,
                timestamp: 5000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkVerified {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                verified_hash: [1; 32],
                timestamp: 5001,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkWritten {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                file_path: "stage/0".to_string(),
                timestamp: 5002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkVerified {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                verified_hash: [2; 32],
                timestamp: 5003,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        match journal.get_resume_summary("hash_conflict") {
            Outcome::Err(err) => {
                assert!(matches!(&err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("verified hash conflict"));
            }
            other => panic!("expected conflicting chunk hashes to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn compaction_boundary_is_signed_and_verifiable() {
        let temp_dir = unique_temp_dir("test_compaction_boundary");
        let key = test_auth_key();
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            max_journal_size: u64::MAX,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
        journal
            .append(JournalRecord::Accept {
                transfer_id: "transfer_a".to_string(),
                peer_id: "peer1".to_string(),
                timestamp: 1000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal.compact().unwrap();
        let boundary = journal
            .recent_entries
            .iter()
            .find(|entry| matches!(entry.record, JournalRecord::CompactionBoundary { .. }))
            .expect("compaction writes boundary entry");

        assert!(!boundary.record.auth_tag().is_zero());
        assert!(boundary.record.verify_signature(&key));
        assert_eq!(journal.get_stats().generation, 1);
        assert!(
            journal_file_path(&temp_dir, 1).exists(),
            "compaction must create the next generation before reporting success"
        );

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.generation, 1);
        assert_eq!(recovered_stats.sequence, 2);
    }
