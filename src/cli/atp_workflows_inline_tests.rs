    use super::*;
    use crate::cli::output::OutputFormat;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn test_workflow_coordinator_creation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json);
            assert!(coordinator.is_ok());
        });
    }

    #[test]
    fn test_content_hash_computation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();
            let content = b"test content";
            let hash1 = coordinator.compute_content_hash(content);
            let hash2 = coordinator.compute_content_hash(content);
            assert_eq!(hash1, hash2);
            // The persisted artifact format stores the bare lowercase hex
            // SHA-256 digest (64 chars), compared verbatim against
            // `artifact.content_hash` on restore; a `sha256:` prefix would
            // change that on-disk format.
            assert_eq!(hash1.len(), 64, "bare hex SHA-256: {hash1}");
            assert!(
                hash1
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
            assert_eq!(
                hash1, "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
                "SHA-256 of b\"test content\""
            );
        });
    }

    #[test]
    fn test_retention_duration_parsing() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

            let duration_7d = coordinator.parse_retention_duration("7d");
            assert_eq!(duration_7d, Some(Duration::from_secs(7 * 24 * 60 * 60)));

            let duration_permanent = coordinator.parse_retention_duration("permanent");
            assert_eq!(duration_permanent, None);

            let duration_invalid = coordinator.parse_retention_duration("invalid");
            assert_eq!(duration_invalid, None);
        });
    }
