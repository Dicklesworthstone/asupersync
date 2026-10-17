    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::file::write_trace;
    use crate::trace::replay::CompactTaskId;
    use std::io::{Seek, SeekFrom};
    use tempfile::NamedTempFile;

    fn sample_events(count: u64) -> Vec<ReplayEvent> {
        (0..count)
            .map(|i| ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i * 100, // Monotonically increasing
            })
            .collect()
    }

    #[test]
    fn verify_valid_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.verified_events, 100);
        assert_eq!(result.declared_events, 100);
        assert!(result.metadata().is_some());
        assert!(result.completed);
    }

    #[test]
    fn verify_empty_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        write_trace(path, &metadata, &[]).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(result.is_valid());
        assert_eq!(result.verified_events, 0);
        assert_eq!(result.declared_events, 0);
    }

    #[test]
    fn detect_invalid_magic() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write garbage (must be >= HEADER_SIZE + 8 = 27 bytes to pass size check)
        std::fs::write(path, b"NOT A TRACE FILE - EXTRA PADDING HERE!").unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.has_fatal_issues());
        assert!(matches!(
            result.issues().first(),
            Some(IntegrityIssue::InvalidMagic { .. })
        ));
    }

    #[test]
    fn detect_truncated_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a valid trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Truncate the file
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let original_size = file.metadata().unwrap().len();
        file.set_len(original_size / 2).unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.verified_events < 100);
        assert!(result.issues().iter().any(|i| matches!(
            i,
            IntegrityIssue::Truncated { .. } | IntegrityIssue::EventCountMismatch { .. }
        )));
    }

    #[test]
    fn detect_file_too_small() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write too little data
        std::fs::write(path, b"short").unwrap();

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        assert!(result.has_fatal_issues());
        assert!(matches!(
            result.issues().first(),
            Some(IntegrityIssue::FileTooSmall { .. })
        ));
    }

    #[test]
    fn detect_timeline_non_monotonic() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        // Create events with non-monotonic timestamps
        let events = vec![
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(0),
                at_tick: 100,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 50, // Goes backwards!
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 200,
            },
        ];
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::strict()).unwrap();

        assert!(!result.is_valid());
        assert!(
            result
                .issues()
                .iter()
                .any(|i| matches!(i, IntegrityIssue::TimelineNonMonotonic { at_event: 1, .. }))
        );
    }

    #[test]
    fn quick_verification() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(1000);
        write_trace(path, &metadata, &events).unwrap();

        // Quick verification should be fast (doesn't read events)
        let is_valid = is_trace_valid_quick(path).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn find_first_corruption_none() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        let first = find_first_corruption(path).unwrap();
        assert!(first.is_none());
    }

    #[test]
    fn current_v3_truncation_is_not_checksum_admitted() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        // Write a valid trace
        let metadata = TraceMetadata::new(42);
        let events = sample_events(100);
        write_trace(path, &metadata, &events).unwrap();

        // Truncate to corrupt the end
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let original_size = file.metadata().unwrap().len();
        file.set_len(original_size - 100).unwrap();
        drop(file);

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        // Some records can decode before truncation, but v3 authenticates the
        // complete event stream and therefore admits no prefix as safe replay.
        assert!(result.verified_events > 0);
        assert!(result.verified_events < 100);
        assert!(!result.is_partially_usable());
        assert_eq!(result.safe_event_count(), 0);
    }

    #[test]
    fn verification_result_display() {
        let mut result = VerificationResult::new(1000);
        result.declared_events = 100;
        result.verified_events = 100;

        let display = format!("{result}");
        assert!(display.contains("valid"));
        assert!(display.contains("100 events"));

        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        });
        result.verified_events = 50;

        let display = format!("{result}");
        assert!(display.contains("1 issue"));
        assert!(display.contains("50/100"));
    }

    #[test]
    fn issue_severity() {
        assert_eq!(
            IntegrityIssue::InvalidMagic { found: [0; 11] }.severity(),
            IssueSeverity::Fatal
        );
        assert_eq!(
            IntegrityIssue::Truncated { at_event: 0 }.severity(),
            IssueSeverity::Error
        );
        assert_eq!(
            IntegrityIssue::InvalidEvent {
                index: 0,
                message: "test".to_string()
            }
            .severity(),
            IssueSeverity::Error
        );
    }

    #[test]
    fn corrupted_event_detection() {
        use std::io::Write;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(10);

        // Write a complete valid trace first
        write_trace(path, &metadata, &events).unwrap();

        // Now corrupt the file by appending garbage after valid events
        // We'll overwrite some bytes in the middle of the file
        {
            let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

            // Seek to somewhere in the middle of the events section
            // and write garbage to corrupt an event
            let file_size = file.metadata().unwrap().len();
            // Seek to about 3/4 of the file (into event data)
            file.seek(SeekFrom::Start(file_size * 3 / 4)).unwrap();

            // Write garbage that will corrupt event deserialization
            file.write_all(b"CORRUPTED_DATA_HERE!").unwrap();
        }

        let result = verify_trace(path, &VerificationOptions::default()).unwrap();

        assert!(!result.is_valid());
        // Should have read some events before hitting corruption
        assert!(result.verified_events > 0);
        assert!(result.verified_events < 10);
    }

    // ── IntegrityIssue Display for all variants ────────────────────

    #[test]
    fn display_file_too_small() {
        let issue = IntegrityIssue::FileTooSmall {
            actual: 5,
            expected: 27,
        };
        let s = format!("{issue}");
        assert!(s.contains("5 bytes"));
        assert!(s.contains("at least 27"));
    }

    #[test]
    fn display_invalid_magic() {
        let issue = IntegrityIssue::InvalidMagic { found: [0; 11] };
        let s = format!("{issue}");
        assert!(s.contains("invalid magic"));
    }

    #[test]
    fn display_unsupported_version() {
        let issue = IntegrityIssue::UnsupportedVersion {
            found: 99,
            max_supported: 1,
        };
        let s = format!("{issue}");
        assert!(s.contains("99"));
        assert!(s.contains("max supported: 1"));
    }

    #[test]
    fn display_unsupported_flags() {
        let issue = IntegrityIssue::UnsupportedFlags { flags: 0xFF };
        let s = format!("{issue}");
        assert!(s.contains("flags"));
    }

    #[test]
    fn display_schema_mismatch() {
        let issue = IntegrityIssue::SchemaMismatch {
            found: 5,
            expected: 1,
        };
        let s = format!("{issue}");
        assert!(s.contains("found 5"));
        assert!(s.contains("expected 1"));
    }

    #[test]
    fn display_invalid_metadata() {
        let issue = IntegrityIssue::InvalidMetadata {
            message: "bad data".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("bad data"));
    }

    #[test]
    fn display_event_count_mismatch() {
        let issue = IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        };
        let s = format!("{issue}");
        assert!(s.contains("declared 100"));
        assert!(s.contains("actual 50"));
    }

    #[test]
    fn display_invalid_event() {
        let issue = IntegrityIssue::InvalidEvent {
            index: 42,
            message: "corrupt".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("index 42"));
        assert!(s.contains("corrupt"));
    }

    #[test]
    fn display_truncated() {
        let issue = IntegrityIssue::Truncated { at_event: 7 };
        let s = format!("{issue}");
        assert!(s.contains("truncated"));
        assert!(s.contains("event 7"));
    }

    #[test]
    fn display_timeline_non_monotonic() {
        let issue = IntegrityIssue::TimelineNonMonotonic {
            at_event: 3,
            prev_time: 100,
            curr_time: 50,
        };
        let s = format!("{issue}");
        assert!(s.contains("event 3"));
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn display_io_error() {
        let issue = IntegrityIssue::IoError {
            message: "disk failure".into(),
        };
        let s = format!("{issue}");
        assert!(s.contains("disk failure"));
    }

    // ── Severity for all variants ──────────────────────────────────

    #[test]
    fn severity_fatal_variants() {
        let fatal = [
            IntegrityIssue::FileTooSmall {
                actual: 0,
                expected: 27,
            },
            IntegrityIssue::InvalidMagic { found: [0; 11] },
            IntegrityIssue::UnsupportedVersion {
                found: 99,
                max_supported: 1,
            },
            IntegrityIssue::InvalidMetadata {
                message: "bad".into(),
            },
        ];
        for issue in &fatal {
            assert_eq!(issue.severity(), IssueSeverity::Fatal, "for {issue}");
            assert!(issue.is_fatal(), "for {issue}");
        }
    }

    #[test]
    fn severity_error_variants() {
        let errors = [
            IntegrityIssue::UnsupportedFlags { flags: 0xFF },
            IntegrityIssue::SchemaMismatch {
                found: 5,
                expected: 1,
            },
            IntegrityIssue::EventCountMismatch {
                declared: 100,
                actual: 50,
            },
            IntegrityIssue::Truncated { at_event: 0 },
            IntegrityIssue::InvalidEvent {
                index: 0,
                message: "bad".into(),
            },
            IntegrityIssue::TimelineNonMonotonic {
                at_event: 0,
                prev_time: 100,
                curr_time: 50,
            },
            IntegrityIssue::IoError {
                message: "err".into(),
            },
        ];
        for issue in &errors {
            assert_eq!(issue.severity(), IssueSeverity::Error, "for {issue}");
            assert!(!issue.is_fatal(), "for {issue}");
        }
    }

    // ── IssueSeverity ordering ─────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(IssueSeverity::Warning < IssueSeverity::Error);
        assert!(IssueSeverity::Error < IssueSeverity::Fatal);
    }

    // ── VerificationOptions ────────────────────────────────────────

    #[test]
    fn options_default_values() {
        let opts = VerificationOptions::default();
        assert!(!opts.check_monotonicity);
        assert!(!opts.fail_fast);
        assert_eq!(opts.max_issues, 100);
        assert!(opts.verify_events);
    }

    #[test]
    fn options_quick_values() {
        let opts = VerificationOptions::quick();
        assert!(!opts.check_monotonicity);
        assert!(opts.fail_fast);
        assert_eq!(opts.max_issues, 1);
        assert!(!opts.verify_events);
    }

    #[test]
    fn options_strict_values() {
        let opts = VerificationOptions::strict();
        assert!(opts.check_monotonicity);
        assert!(!opts.fail_fast);
        assert_eq!(opts.max_issues, 1000);
        assert!(opts.verify_events);
    }

    #[test]
    fn options_with_monotonicity() {
        let opts = VerificationOptions::default().with_monotonicity(true);
        assert!(opts.check_monotonicity);
    }

    #[test]
    fn options_with_fail_fast() {
        let opts = VerificationOptions::default().with_fail_fast(true);
        assert!(opts.fail_fast);
    }

    // ── VerificationResult queries ─────────────────────────────────

    #[test]
    fn result_safe_event_count_zero_on_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        assert_eq!(result.safe_event_count(), 0);
    }

    #[test]
    fn result_safe_event_count_nonzero_without_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        assert_eq!(result.safe_event_count(), 50);
    }

    #[test]
    fn result_fatal_issues_iterator() {
        let mut result = VerificationResult::new(100);
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        result.add_issue(IntegrityIssue::Truncated { at_event: 0 });
        result.add_issue(IntegrityIssue::InvalidMetadata {
            message: "bad".into(),
        });

        assert_eq!(result.fatal_issues().count(), 2);
    }

    #[test]
    fn result_is_partially_usable_true() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        assert!(result.is_partially_usable());
    }

    #[test]
    fn result_is_partially_usable_false_on_fatal() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::InvalidMagic { found: [0; 11] });
        assert!(!result.is_partially_usable());
    }

    #[test]
    fn result_is_partially_usable_false_on_zero_events() {
        let mut result = VerificationResult::new(100);
        result.verified_events = 0;
        result.add_issue(IntegrityIssue::Truncated { at_event: 0 });
        assert!(!result.is_partially_usable());
    }

    // ── Missing file ───────────────────────────────────────────────

    #[test]
    fn verify_missing_file_returns_io_error() {
        let result = verify_trace(
            "/tmp/definitely_not_a_real_trace_file_123456789.bin",
            &VerificationOptions::default(),
        );
        assert!(result.is_err());
    }

    // ── Quick verification on invalid file ─────────────────────────

    #[test]
    fn quick_invalid_file() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        std::fs::write(path, b"NOT A TRACE FILE - EXTRA PADDING!").unwrap();

        let is_valid = is_trace_valid_quick(path).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn quick_verification_rejects_nonfatal_flag_issue() {
        let temp = NamedTempFile::new().unwrap();
        write_trace(temp.path(), &TraceMetadata::new(42), &[]).unwrap();
        let mut invalid_flags = std::fs::read(temp.path()).unwrap();
        invalid_flags[13..15].copy_from_slice(&0x8000u16.to_le_bytes());
        std::fs::write(temp.path(), invalid_flags).unwrap();
        assert!(!is_trace_valid_quick(temp.path()).unwrap());
    }

    // ── Display for valid and invalid result ───────────────────────

    #[test]
    fn display_valid_result() {
        let mut result = VerificationResult::new(500);
        result.verified_events = 10;
        let s = format!("{result}");
        assert!(s.contains("valid"));
        assert!(s.contains("10 events"));
        assert!(s.contains("500 bytes"));
    }

    #[test]
    fn display_invalid_result_multiple_issues() {
        let mut result = VerificationResult::new(500);
        result.declared_events = 100;
        result.verified_events = 50;
        result.add_issue(IntegrityIssue::Truncated { at_event: 50 });
        result.add_issue(IntegrityIssue::EventCountMismatch {
            declared: 100,
            actual: 50,
        });
        let s = format!("{result}");
        assert!(s.contains("2 issue(s)"));
        assert!(s.contains("50/100"));
    }

    // ── Strict verification on valid trace passes ──────────────────

    #[test]
    fn strict_verification_on_valid_monotonic_trace() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(50); // These are already monotonic (at_tick: i * 100)
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::strict()).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.verified_events, 50);
    }

    // ── Quick verification on valid trace skips events ──────────────

    #[test]
    fn quick_verification_skips_events() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let metadata = TraceMetadata::new(42);
        let events = sample_events(500);
        write_trace(path, &metadata, &events).unwrap();

        let result = verify_trace(path, &VerificationOptions::quick()).unwrap();
        // Quick doesn't verify events, so verified_events comes from count_events
        assert!(result.completed);
        assert!(!result.has_fatal_issues());
    }
