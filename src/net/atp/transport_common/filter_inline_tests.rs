    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match(b"*.tmp", b"a.tmp"));
        assert!(!glob_match(b"*.tmp", b"a.txt"));
        assert!(glob_match(b"file?.log", b"file3.log"));
        assert!(!glob_match(b"file?.log", b"file33.log"));
        // '*' does not cross '/'.
        assert!(!glob_match(b"*.rs", b"a/b.rs"));
        assert!(glob_match(b"a/*.rs", b"a/b.rs"));
        assert!(!glob_match(b"a/*.rs", b"a/b/c.rs"));
    }

    #[test]
    fn glob_double_star() {
        // bare ** crosses '/'.
        assert!(glob_match(b"a/**", b"a/b/c"));
        // **/ matches zero or more dirs.
        assert!(glob_match(b"src/**/*.rs", b"src/a.rs"));
        assert!(glob_match(b"src/**/*.rs", b"src/a/b.rs"));
        assert!(!glob_match(b"src/**/*.rs", b"other/a.rs"));
        assert!(glob_match(b"**/x", b"x"));
        assert!(glob_match(b"**/x", b"a/b/x"));
    }

    #[test]
    fn basename_and_anchoring() {
        // Non-anchored *.tmp matches at any depth (basename).
        let r = FilterRule::exclude("*.tmp");
        assert!(r.matches("a/b/c.tmp", false));
        assert!(r.matches("c.tmp", false));
        assert!(!r.matches("c.txt", false));
        // Anchored (internal slash) matches the whole path only.
        let a = FilterRule::exclude("build/out");
        assert!(a.matches("build/out", true));
        assert!(!a.matches("x/build/out", true));
    }

    #[test]
    fn dir_only_rule() {
        let r = FilterRule::exclude("target/");
        assert!(r.matches("target", true)); // a dir named target, any depth
        assert!(r.matches("a/target", true));
        assert!(!r.matches("target", false)); // a *file* named target is not matched
    }

    #[test]
    fn first_match_wins_includes_rescue() {
        // Include a needed file before the broad exclude rescues it.
        let fs = FilterSet::with_rules(vec![
            FilterRule::include("keep/needed.tmp"),
            FilterRule::exclude("*.tmp"),
        ]);
        assert_eq!(
            fs.decision("keep/needed.tmp", false),
            FilterDecision::Include
        );
        assert_eq!(fs.decision("other.tmp", false), FilterDecision::Exclude);
        // Unmatched -> default include.
        assert_eq!(fs.decision("src/main.rs", false), FilterDecision::Include);
    }

    #[test]
    fn parse_rsync_style_lines() {
        let fs = FilterSet::parse(["# comment", "", "+ keep/needed.tmp", "- *.tmp", "- target/"])
            .unwrap();
        assert_eq!(fs.len(), 3);
        assert!(fs.is_included("keep/needed.tmp", false));
        assert!(!fs.is_included("a/b.tmp", false));
        assert!(!fs.is_included("a/target", true));
    }

    #[test]
    fn parse_rejects_bad_lines() {
        assert!(matches!(
            FilterSet::parse(["nope pattern"]),
            Err(FilterError::UnknownAction(_))
        ));
        assert!(matches!(
            FilterSet::parse(["-   "]),
            Err(FilterError::EmptyPattern(_))
        ));
    }

    #[test]
    fn select_prunes_excluded_directory_subtree_but_keeps_a_needed_subdir() {
        // Acceptance: exclude target/ and *.tmp but include a needed subdir.
        let fs = FilterSet::with_rules(vec![
            FilterRule::include("src/keep/"),
            FilterRule::exclude("target/"),
            FilterRule::exclude("*.tmp"),
        ]);
        let entries = vec![
            ("src".to_string(), true),
            ("src/main.rs".to_string(), false),
            ("src/keep".to_string(), true),
            ("src/keep/important.rs".to_string(), false),
            ("src/scratch.tmp".to_string(), false),
            ("target".to_string(), true),
            ("target/app".to_string(), false),
            ("target/debug".to_string(), true),
            ("target/debug/app".to_string(), false),
        ];
        let selected = fs.select(&entries);
        assert_eq!(
            selected,
            vec![
                "src".to_string(),
                "src/main.rs".to_string(),
                "src/keep".to_string(),
                "src/keep/important.rs".to_string(),
            ]
        );
        // target/ subtree fully pruned; *.tmp dropped; src/keep included.
        assert!(!selected.iter().any(|p| p.starts_with("target")));
        assert!(!selected.iter().any(|p| {
            std::path::Path::new(p)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
        }));
    }

    #[test]
    fn empty_filter_includes_everything() {
        let fs = FilterSet::new();
        assert!(fs.is_empty());
        assert!(fs.is_included("anything/at/all.tmp", false));
        assert!(fs.is_included("target", true));
    }

    #[test]
    fn is_under_semantics() {
        assert!(is_under("target", "target"));
        assert!(is_under("target/a", "target"));
        assert!(is_under("target/a/b", "target"));
        assert!(!is_under("targetx", "target"));
        assert!(!is_under("other/target", "target"));
    }

    #[test]
    fn is_path_included_prunes_files_under_excluded_dirs() {
        let fs = FilterSet::with_rules(vec![
            FilterRule::exclude("target/"),
            FilterRule::exclude("*.tmp"),
        ]);
        assert!(fs.is_path_included("src/main.rs"));
        assert!(fs.is_path_included("a/b/c.rs"));
        // A file under the excluded `target/` directory is pruned even though its
        // own basename matches nothing.
        assert!(!fs.is_path_included("target/debug/app"));
        // A *.tmp file anywhere is excluded.
        assert!(!fs.is_path_included("a/b/c.tmp"));
    }

    #[test]
    fn is_path_included_rescue_needs_ancestor_includes() {
        let fs = FilterSet::with_rules(vec![
            FilterRule::include("logs/"),
            FilterRule::include("logs/keep.tmp"),
            FilterRule::exclude("*.tmp"),
        ]);
        // The ancestor `logs/` include keeps the dir, then the explicit include
        // rescues the file from the broad `*.tmp` exclude.
        assert!(fs.is_path_included("logs/keep.tmp"));
        assert!(!fs.is_path_included("other/x.tmp"));
    }
