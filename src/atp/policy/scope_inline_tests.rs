    use super::*;
    use crate::atp::object::ContentId;

    fn string_set(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn test_object_id(id: u32) -> ObjectId {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&id.to_le_bytes());
        ObjectId::content(ContentId::new(bytes))
    }

    #[test]
    fn resource_scope_object_coverage() {
        let object_id = test_object_id(1);
        let scope = ResourceScope::Object(object_id.clone());

        assert!(scope.covers_object(&object_id));
        assert!(!scope.covers_object(&test_object_id(2)));
    }

    #[test]
    fn path_scope_pattern_matching() {
        let scope = PathScope::new("/data/**".to_string(), true);
        let path1 = AtpPath::from_str("/data/file.txt").expect("path");
        let path2 = AtpPath::from_str("/data/subdir/file.txt").expect("path");
        let path3 = AtpPath::from_str("/other/file.txt").expect("path");

        assert!(scope.matches(&path1));
        assert!(scope.matches(&path2));
        assert!(!scope.matches(&path3));
    }

    #[test]
    fn atp_path_rejects_non_normalized_logical_paths() {
        assert!(AtpPath::from_str("/").is_ok());
        assert!(AtpPath::from_str("/inbox/message").is_ok());

        for path in [
            "",
            "relative/path",
            "/data/./file",
            "/data/../file",
            "/data//file",
            "/data/file/",
            "/data\\file",
        ] {
            assert!(AtpPath::from_str(path).is_err(), "{path} should reject");
        }
    }

    #[test]
    fn path_scope_recursive_literal_respects_segment_boundaries() {
        let scope = PathScope::new("/data".to_string(), true);
        let root = AtpPath::from_str("/data").expect("path");
        let child = AtpPath::from_str("/data/file.txt").expect("path");
        let sibling_prefix = AtpPath::from_str("/database/file.txt").expect("path");

        assert!(scope.matches(&root));
        assert!(scope.matches(&child));
        assert!(!scope.matches(&sibling_prefix));
    }

    #[test]
    fn path_scope_single_star_does_not_cross_segments() {
        let scope = PathScope::new("/team/*/inbox/**".to_string(), false);
        let allowed = AtpPath::from_str("/team/alpha/inbox/a/b").expect("path");
        let too_deep = AtpPath::from_str("/team/alpha/beta/inbox/a").expect("path");

        assert!(scope.matches(&allowed));
        assert!(!scope.matches(&too_deep));
    }

    #[test]
    fn path_scope_exclusions() {
        let mut exclusions = HashSet::new();
        exclusions.insert("/data/secret/**".to_string());

        let scope = PathScope::with_exclusions("/data/**".to_string(), true, exclusions);
        let allowed = AtpPath::from_str("/data/public/file.txt").expect("path");
        let excluded = AtpPath::from_str("/data/secret/private.txt").expect("path");

        assert!(scope.matches(&allowed));
        assert!(!scope.matches(&excluded));
    }

    #[test]
    fn path_scope_literal_exclusion_covers_excluded_subtree() {
        // br-asupersync-2ykdhb: a LITERAL (non-glob) exclusion must deny the
        // whole excluded subtree, not just the exact path. Previously the
        // exclusion check used exact-only literal matching while the recursive
        // inclusion covered descendants, so an operator carve-out silently
        // failed open below the excluded root (fail-open authorization bypass:
        // a recursive grant of /data excluding /data/secret still granted
        // /data/secret/private.txt). The prior test only exercised the glob
        // form (/data/secret/**), which masked the literal case.
        let mut exclusions = HashSet::new();
        exclusions.insert("/data/secret".to_string()); // literal, no wildcard

        let scope = PathScope::with_exclusions("/data".to_string(), true, exclusions);

        let allowed = AtpPath::from_str("/data/public/file.txt").expect("path");
        let excluded_exact = AtpPath::from_str("/data/secret").expect("path");
        let excluded_descendant = AtpPath::from_str("/data/secret/private.txt").expect("path");
        let excluded_deep = AtpPath::from_str("/data/secret/sub/dir/key.pem").expect("path");
        // A sibling that merely shares the excluded prefix as a string must NOT
        // be over-denied — segment-boundary correctness, mirroring inclusion.
        let sibling_prefix = AtpPath::from_str("/data/secretstuff/file.txt").expect("path");

        assert!(scope.matches(&allowed), "unexcluded subtree stays granted");
        assert!(!scope.matches(&excluded_exact), "exact excluded path denied");
        assert!(
            !scope.matches(&excluded_descendant),
            "descendant of a literal exclusion must be denied (was fail-open)"
        );
        assert!(
            !scope.matches(&excluded_deep),
            "deep descendant of a literal exclusion must be denied"
        );
        assert!(
            scope.matches(&sibling_prefix),
            "prefix sibling of the exclusion must not be over-denied"
        );
    }

    #[test]
    fn scope_constraints_validation() {
        let constraints = ScopeConstraints {
            max_transfer_size: Some(1024),
            max_bandwidth: Some(1000),
            allowed_hours: Some((9, 17)), // 9 AM to 5 PM UTC
            ..Default::default()
        };

        assert!(constraints.check_transfer_size(512));
        assert!(!constraints.check_transfer_size(2048));

        assert!(constraints.check_bandwidth(500));
        assert!(!constraints.check_bandwidth(2000));
    }

    #[test]
    fn resource_scope_digest_stability() {
        let scope1 = ResourceScope::Object(test_object_id(1));
        let scope2 = ResourceScope::Object(test_object_id(1));
        let scope3 = ResourceScope::Object(test_object_id(2));

        assert_eq!(scope1.digest(), scope2.digest());
        assert_ne!(scope1.digest(), scope3.digest());
    }

    #[test]
    fn resource_scope_digest_frames_variable_length_sets() {
        let relay1 = ResourceScope::Relay {
            destinations: string_set(&["ab", "c"]),
        };
        let relay2 = ResourceScope::Relay {
            destinations: string_set(&["a", "bc"]),
        };

        assert_ne!(relay1.digest(), relay2.digest());

        let cache1 = ResourceScope::Cache {
            object_types: string_set(&["ab", "c"]),
            max_size_bytes: None,
        };
        let cache2 = ResourceScope::Cache {
            object_types: string_set(&["a", "bc"]),
            max_size_bytes: None,
        };

        assert_ne!(cache1.digest(), cache2.digest());
    }

    #[test]
    fn path_scope_digest_frames_exclusions() {
        let scope1 =
            PathScope::with_exclusions("/data/**".to_string(), true, string_set(&["/ab", "/c"]));
        let scope2 =
            PathScope::with_exclusions("/data/**".to_string(), true, string_set(&["/a", "/bc"]));

        assert_ne!(scope1.digest(), scope2.digest());
    }

    #[test]
    fn scope_constraints_digest_frames_options_and_fields() {
        let no_ip_constraint = ScopeConstraints::default();
        let deny_all_ips = ScopeConstraints {
            allowed_ips: Some(HashSet::new()),
            ..Default::default()
        };
        assert_ne!(no_ip_constraint.digest(), deny_all_ips.digest());

        let transfer = ScopeConstraints {
            max_transfer_size: Some(1),
            ..Default::default()
        };
        let bandwidth = ScopeConstraints {
            max_bandwidth: Some(1),
            ..Default::default()
        };
        assert_ne!(transfer.digest(), bandwidth.digest());
    }

    #[test]
    fn scope_constraints_invalid_allowed_hours_fail_closed() {
        let constraints = ScopeConstraints {
            allowed_hours: Some((24, 24)),
            ..Default::default()
        };

        assert!(!constraints.check_time_allowed());
    }

    #[test]
    fn glob_match_handles_multiple_wildcards_and_question_marks() {
        assert!(glob_match("/team/*/inbox/**", "/team/alpha/inbox/a/b"));
        assert!(glob_match("10.0.?.*", "10.0.1.42"));
        assert!(!glob_match("/team/*/inbox/**", "/team/alpha/outbox/a"));
    }
