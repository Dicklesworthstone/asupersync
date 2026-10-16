    use super::*;

    #[test]
    fn test_spec_requirement_new() {
        let req = SpecRequirement::new("3.2.1", "Region close waits for children");
        assert_eq!(req.section, "3.2.1");
        assert_eq!(req.description, "Region close waits for children");
        assert!(req.category.is_none());
        assert_eq!(req.priority, 1);
    }

    #[test]
    fn test_spec_requirement_with_category() {
        let req = SpecRequirement::new("3.2.1", "Test")
            .with_category("regions")
            .with_priority(5);
        assert_eq!(req.category, Some("regions".to_string()));
        assert_eq!(req.priority, 5);
    }

    #[test]
    fn test_traceability_entry_new() {
        let entry = TraceabilityEntry::new("3.2.1", "Requirement", "test_foo", "tests/foo.rs", 42);
        assert_eq!(entry.spec_section, "3.2.1");
        assert_eq!(entry.test_name, "test_foo");
        assert_eq!(entry.test_file, PathBuf::from("tests/foo.rs"));
        assert_eq!(entry.test_line, 42);
    }

    #[test]
    fn test_empty_matrix_coverage() {
        let mut matrix = TraceabilityMatrix::empty();
        assert_eq!(matrix.coverage_percentage(), 100.0);
    }

    #[test]
    fn test_matrix_with_requirements_no_tests() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        assert_eq!(matrix.coverage_percentage(), 0.0);
        assert_eq!(matrix.missing_sections().len(), 2);
    }

    #[test]
    fn test_matrix_partial_coverage() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);

        assert_eq!(matrix.coverage_percentage(), 50.0);
        assert_eq!(matrix.missing_sections(), vec!["3.2.2".to_string()]);
    }

    #[test]
    fn test_matrix_full_coverage() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);
        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);

        assert_eq!(matrix.coverage_percentage(), 100.0);
        assert!(matrix.missing_sections().is_empty());
    }

    #[test]
    fn test_coverage_stats() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
            SpecRequirement::new("3.2.3", "Req 3"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);
        matrix.add_test_mapping("3.2.1", "test_req1_extra", "tests/test.rs", 15);
        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);

        let stats = matrix.coverage_stats();
        assert_eq!(stats.total_requirements, 3);
        assert_eq!(stats.covered_requirements, 2);
        assert_eq!(stats.missing_requirements, 1);
        assert_eq!(stats.total_tests, 3);
        assert!((stats.coverage_percentage - 66.666).abs() < 0.1);
    }

    #[test]
    fn test_meets_threshold() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);

        assert!(matrix.meets_threshold(50.0));
        assert!(!matrix.meets_threshold(51.0));
    }

    #[test]
    fn test_builder() {
        let matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .requirement("3.2.2", "Req 2")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        assert_eq!(matrix.requirements.len(), 2);
        assert_eq!(matrix.entries.len(), 1);
    }

    #[test]
    fn test_markdown_output() {
        let mut matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Region close waits")
            .requirement("3.2.2", "No orphan tasks")
            .test("3.2.1", "test_region_close", "tests/region.rs", 42)
            .build();

        let md = matrix.to_markdown();
        assert!(md.contains("# Specification Traceability Matrix"));
        assert!(md.contains("3.2.1"));
        assert!(md.contains("Region close waits"));
        assert!(md.contains("test_region_close"));
        assert!(md.contains("MISSING"));
    }

    #[test]
    fn test_json_roundtrip() {
        let matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        let json = matrix.to_json().unwrap();
        let loaded = TraceabilityMatrix::from_json(&json).unwrap();

        assert_eq!(matrix.requirements.len(), loaded.requirements.len());
        assert_eq!(matrix.entries.len(), loaded.entries.len());
    }

    #[test]
    fn test_ci_report() {
        let mut matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .requirement("3.2.2", "Req 2")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        let report = matrix.ci_report();
        assert!(!report.passed);
        assert_eq!(report.missing_sections, vec!["3.2.2".to_string()]);

        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);
        let report = matrix.ci_report();
        assert!(report.passed);
        assert!(report.missing_sections.is_empty());
    }

    #[test]
    fn test_scan_conformance_attributes_basic() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("example.rs");
        let contents = concat!(
            "#[conformance(spec = \"3.2.1\", requirement = \"Region close waits\")]\n",
            "#[test]\n",
            "fn test_region_close() {}\n"
        );
        std::fs::write(&file, contents).unwrap();

        let scan = scan_conformance_attributes(std::slice::from_ref(&file)).unwrap();
        assert!(scan.warnings.is_empty());
        assert_eq!(scan.entries.len(), 1);
        let entry = &scan.entries[0];
        assert_eq!(entry.spec_section, "3.2.1");
        assert_eq!(entry.requirement, "Region close waits");
        assert_eq!(entry.test_name, "test_region_close");
        assert_eq!(entry.test_line, 3);
    }

    #[test]
    fn test_scan_multiple_conformance_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("example.rs");
        let contents = concat!(
            "#[conformance(spec = \"3.2.1\", requirement = \"Region close waits\")]\n",
            "#[conformance(spec = \"3.2.2\", requirement = \"No orphan tasks\")]\n",
            "#[test]\n",
            "fn test_region_close() {}\n"
        );
        std::fs::write(&file, contents).unwrap();

        let scan = scan_conformance_attributes(std::slice::from_ref(&file)).unwrap();
        assert!(scan.warnings.is_empty());
        assert_eq!(scan.entries.len(), 2);
        assert!(
            scan.entries
                .iter()
                .any(|entry| entry.spec_section == "3.2.1")
        );
        assert!(
            scan.entries
                .iter()
                .any(|entry| entry.spec_section == "3.2.2")
        );
    }
