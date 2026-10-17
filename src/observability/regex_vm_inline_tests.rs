    use super::super::regex_boundaries::FoldBoundaryLimits;
    use super::super::regex_ir::{IR_SCHEMA_VERSION, State};
    use super::super::regex_lowering::lower;
    use super::super::regex_semantics::SemanticLimits;
    use super::super::regex_syntax::{LexerLimits, ParserLimits, SourceSpan};
    use super::*;
    use proptest::prelude::*;

    fn lower_default(pattern: &str) -> Program {
        lower(
            pattern,
            LexerLimits::default(),
            ParserLimits::default(),
            SemanticLimits::default(),
            FoldBoundaryLimits::default(),
            CompileLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} must lower: {error}"))
    }

    fn execute(pattern: &str, haystack: &str) -> VmOutcome {
        execute_full(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
    }

    fn search(pattern: &str, haystack: &str) -> VmMatch {
        execute_search(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
        .matched
        .unwrap_or_else(|| panic!("{pattern:?} must match {haystack:?}"))
    }

    fn iterate(pattern: &str, haystack: &str, policy: IterationPolicy) -> VmIterationOutcome {
        execute_find_iter(
            &lower_default(pattern),
            haystack,
            CompileLimits::default(),
            policy,
            IterationVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{pattern:?} on {haystack:?}: {error}"))
    }

    fn span() -> SourceSpan {
        SourceSpan {
            byte_start: 0,
            byte_end: 0,
            scalar_start: 0,
            scalar_end: 0,
        }
    }

    fn compile_pattern(pattern: &str) -> PrivateCompiledPattern {
        PrivateCompiledPattern::compile(pattern, PrivateCompileLimits::default())
            .unwrap_or_else(|error| panic!("private facade rejected {pattern:?}: {error}"))
    }

    fn replace(pattern: &str, haystack: &str, template: &str) -> ReplacementOutcome {
        compile_pattern(pattern)
            .replace_all(
                haystack,
                template,
                IterationVmLimits::default(),
                ReplacementLimits::default(),
            )
            .unwrap_or_else(|error| {
                panic!("replacement {pattern:?} on {haystack:?} with {template:?}: {error}")
            })
    }

    #[test]
    fn replacement_golden_rows_cover_captures_literals_and_iteration() {
        for (pattern, haystack, template, expected) in [
            ("a", "bab", "X", "bXb"),
            ("a", "bab", "", "bb"),
            (
                "(?P<left>a)(?<right>b)?",
                "ab a",
                "<$0:$1:${2}:$left:${right}>",
                "<ab:a:b:a:b> <a:a::a:>",
            ),
            ("(a)+", "aaa", "[$1]", "[a]"),
            ("(a)?b", "b ab", "<$1>", "<> <a>"),
            ("z", "éa", "$0", "éa"),
            ("", "éa", "X", "XéXaX"),
            ("a*", "baa", "_", "_b_"),
            ("(?P<κ>a)", "a", "${κ}", "a"),
        ] {
            assert_eq!(replace(pattern, haystack, template).output, expected);
        }
    }

    #[test]
    fn compatible_replacement_templates_are_total_and_match_incumbent_edges() {
        let compiled = compile_pattern("(a)");
        let incumbent = regex::Regex::new("(a)").expect("incumbent pattern");
        for (template, expected) in [
            ("$0", "a"),
            ("${0}", "a"),
            ("$1", "a"),
            ("${1}", "a"),
            ("$missing", ""),
            ("$99", ""),
            ("$$", "$"),
            ("$$$1", "$a"),
            (r"\$1", r"\a"),
            ("$1a", ""),
            ("${1}a", "aa"),
            ("$", "$"),
            ("$!", "$!"),
            ("$é", "$é"),
            ("${name", "${name"),
            ("${}", ""),
            ("$184467440737095516160", ""),
        ] {
            let candidate = compiled
                .replace_all(
                    "a",
                    template,
                    IterationVmLimits::default(),
                    ReplacementLimits::default(),
                )
                .unwrap_or_else(|error| panic!("compatible template {template:?}: {error}"));
            let incumbent_output = incumbent.replace_all("a", template).into_owned();
            assert_eq!(candidate.output, expected, "candidate {template:?}");
            assert_eq!(candidate.output, incumbent_output, "incumbent {template:?}");
        }
    }

    #[test]
    fn strict_replacement_parser_is_explicit_typed_and_secret_safe() {
        let compiled = compile_pattern("(?P<private_capture_canary>a)");
        for (template, kind) in [
            (
                "${private_template_canary",
                ReplacementErrorKind::MalformedReference,
            ),
            (
                "$unknown_private_canary",
                ReplacementErrorKind::UnknownCapture,
            ),
            (
                "$184467440737095516160",
                ReplacementErrorKind::CaptureIndexOverflow,
            ),
        ] {
            compiled
                .parse_replacement(template, ReplacementLimits::default())
                .expect("compatibility parser remains total");
            let error = compiled
                .parse_replacement_strict(template, ReplacementLimits::default())
                .expect_err("strict parser must diagnose the reference");
            assert_eq!(error.kind, kind);
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains("private_template_canary"));
                assert!(!rendered.contains("unknown_private_canary"));
                assert!(!rendered.contains("private_capture_canary"));
            }
        }
        let compiled_debug = format!("{compiled:?}");
        assert!(compiled_debug.contains("accounted_capture_metadata_bytes"));
        assert!(!compiled_debug.contains("private_capture_canary"));
    }

    #[test]
    fn replacement_ceilings_are_exact_and_zero_use_accepts_zero() {
        let compiled = compile_pattern("(a)");
        let baseline = compiled
            .replace_all(
                "a-a",
                "<$1>",
                IterationVmLimits::default(),
                ReplacementLimits::default(),
            )
            .expect("baseline replacement");
        let exact = ReplacementLimits {
            max_template_bytes: baseline.resources.template_bytes,
            max_tokens: baseline.resources.tokens,
            max_output_bytes: baseline.resources.output_bytes,
            max_work_units: baseline.resources.work_units,
        };
        assert_eq!(
            compiled
                .replace_all("a-a", "<$1>", IterationVmLimits::default(), exact)
                .expect("exact ceilings pass"),
            baseline
        );

        for (limits, kind) in [
            (
                ReplacementLimits {
                    max_template_bytes: exact.max_template_bytes - 1,
                    ..exact
                },
                ReplacementErrorKind::TemplateLimit,
            ),
            (
                ReplacementLimits {
                    max_tokens: exact.max_tokens - 1,
                    ..exact
                },
                ReplacementErrorKind::TokenLimit,
            ),
            (
                ReplacementLimits {
                    max_output_bytes: exact.max_output_bytes - 1,
                    ..exact
                },
                ReplacementErrorKind::OutputLimit,
            ),
            (
                ReplacementLimits {
                    max_work_units: exact.max_work_units - 1,
                    ..exact
                },
                ReplacementErrorKind::WorkLimit,
            ),
        ] {
            let error = compiled
                .replace_all("a-a", "<$1>", IterationVmLimits::default(), limits)
                .expect_err("one-below ceiling fails");
            let ReplacementOperationError::Template(error) = error else {
                panic!("replacement ceiling must not become a VM error");
            };
            assert_eq!(error.kind, kind);
        }

        let zero = compile_pattern("z")
            .replace_all(
                "",
                "",
                IterationVmLimits::default(),
                ReplacementLimits {
                    max_template_bytes: 0,
                    max_tokens: 0,
                    max_output_bytes: 0,
                    max_work_units: 0,
                },
            )
            .expect("genuinely empty replacement accepts exact zero ceilings");
        assert_eq!(zero.output, "");
        assert_eq!(zero.resources.output_bytes, 0);
        assert_eq!(zero.resources.work_units, 0);
    }

    #[test]
    fn replacement_preflight_rejects_invalid_spans_before_allocating_output() {
        let compiled = compile_pattern("(a)");
        let template = compiled
            .parse_replacement("$1", ReplacementLimits::default())
            .expect("template");
        let outcome = |matches| VmIterationOutcome {
            matches,
            resources: IterationVmResources::new(0),
            execution_fingerprint: 0,
            trace: Vec::new(),
            trace_truncated: false,
        };

        for (haystack, matches, kind) in [
            (
                "aa",
                vec![
                    VmMatch {
                        span: CaptureSpan { start: 0, end: 2 },
                        captures: vec![Some(CaptureSpan { start: 0, end: 1 })],
                    },
                    VmMatch {
                        span: CaptureSpan { start: 1, end: 2 },
                        captures: vec![Some(CaptureSpan { start: 1, end: 2 })],
                    },
                ],
                ReplacementErrorKind::OverlappingMatch,
            ),
            (
                "é",
                vec![VmMatch {
                    span: CaptureSpan { start: 1, end: 2 },
                    captures: vec![None],
                }],
                ReplacementErrorKind::InvalidMatchBoundary,
            ),
            (
                "aa",
                vec![VmMatch {
                    span: CaptureSpan { start: 0, end: 1 },
                    captures: vec![Some(CaptureSpan { start: 0, end: 2 })],
                }],
                ReplacementErrorKind::InvalidMatchBoundary,
            ),
        ] {
            let error = template
                .expand(haystack, &outcome(matches), ReplacementLimits::default())
                .expect_err("invalid replacement span must fail closed");
            assert_eq!(error.kind, kind);
        }
    }

    proptest! {
        #[test]
        fn compatible_replacement_matches_regex_1_13(
            pattern in prop::sample::select(vec![
                "a", "(a)", "(a)?b", "(?P<left>a)(b)?", "", "a*", "é", "(ab|a)",
            ]),
            haystack in prop::collection::vec(
                prop::sample::select(vec!['a', 'b', 'é', '$', '_', ' ']),
                0..24,
            ).prop_map(|chars| chars.into_iter().collect::<String>()),
            template in prop::sample::select(vec![
                "", "X", "$0", "$1", "${1}", "$left", "${left}", "$missing",
                "$99", "$$", "$$$1", "$1a", "${1}a", "$", "$!", "$é",
                "${name", "${}", "$184467440737095516160", r"\$1",
            ]),
        ) {
            let incumbent = regex::Regex::new(pattern)
                .expect("incumbent accepts bounded pattern")
                .replace_all(&haystack, template)
                .into_owned();
            let candidate = compile_pattern(pattern)
                .replace_all(
                    &haystack,
                    template,
                    IterationVmLimits::default(),
                    ReplacementLimits::default(),
                )
                .expect("candidate replacement");
            prop_assert_eq!(candidate.output, incumbent);
        }
    }

    #[test]
    fn private_pattern_config_round_trips_and_loads_every_candidate_surface() {
        let pattern = "(?P<private_roundtrip_name>a)(b)?";
        let mut config = PrivatePatternConfig::new(pattern);
        config.compile_limits.lexer.max_tokens -= 1;
        config.compile_limits.parser.max_nesting -= 1;
        config.compile_limits.semantic.max_semantic_atoms -= 1;
        config.compile_limits.fold_boundary.max_fold_atoms -= 1;
        config.compile_limits.ir.max_states -= 1;
        config.iteration_limits.capture.vm.max_input_bytes -= 1;
        config.iteration_limits.max_matches -= 1;
        config.replacement_limits.max_output_bytes -= 1;
        let encoded = config.to_json().expect("serialize private pattern recipe");
        assert!(encoded.contains(pattern));
        assert_eq!(
            encoded,
            config.to_json().expect("serialization is deterministic")
        );
        assert!(
            DEFAULT_MAX_PRIVATE_PATTERN_CONFIG_BYTES
                >= config
                    .compile_limits
                    .lexer
                    .max_pattern_bytes
                    .saturating_mul(6)
                    .saturating_add(4 * 1024),
            "default document ceiling covers worst-case JSON escaping"
        );
        let encode_limit = config
            .to_json_with_document_limit(encoded.len() - 1)
            .expect_err("serializer does not emit above its document ceiling");
        assert_eq!(
            encode_limit.kind,
            PrivatePatternConfigErrorKind::DocumentLimit
        );
        assert_eq!(
            (encode_limit.actual, encode_limit.limit),
            (
                u64::try_from(encoded.len()).ok(),
                u64::try_from(encoded.len() - 1).ok()
            )
        );

        let decoded: PrivatePatternConfig =
            serde_json::from_str(&encoded).expect("decode explicit config document");
        assert_eq!(decoded, config);
        assert_eq!(
            decoded.to_json().expect("decoded recipe serializes"),
            encoded
        );
        let loaded = PrivatePatternConfig::load_json(&encoded).expect("compile-on-load recipe");
        PrivatePatternConfig::load_json_with_document_limit(&encoded, encoded.len())
            .expect("exact document ceiling passes");
        let document_limit =
            PrivatePatternConfig::load_json_with_document_limit(&encoded, encoded.len() - 1)
                .expect_err("one-below document ceiling fails before decoding");
        assert_eq!(
            document_limit.kind,
            PrivatePatternConfigErrorKind::DocumentLimit
        );
        assert_eq!(
            (document_limit.actual, document_limit.limit),
            (
                u64::try_from(encoded.len()).ok(),
                u64::try_from(encoded.len() - 1).ok()
            )
        );
        assert!(loaded.is_match("zab").expect("configured match"));
        assert_eq!(
            loaded.find("zab").expect("configured find"),
            Some(CaptureSpan { start: 1, end: 3 })
        );
        assert_eq!(
            loaded
                .captures("zab")
                .expect("configured captures")
                .expect("selected match")
                .captures,
            vec![
                Some(CaptureSpan { start: 1, end: 2 }),
                Some(CaptureSpan { start: 2, end: 3 }),
            ]
        );
        assert_eq!(
            loaded
                .find_iter("ab a", IterationPolicy::NonOverlapping)
                .expect("configured iteration")
                .matches
                .len(),
            2
        );
        assert_eq!(
            loaded
                .replace_all("ab a", "<$private_roundtrip_name>")
                .expect("configured replacement")
                .output,
            "<a> <a>"
        );

        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("pattern_bytes"));
        let loaded_debug = format!("{loaded:?}");
        for rendered in [config_debug, loaded_debug] {
            assert!(!rendered.contains(pattern));
            assert!(!rendered.contains("private_roundtrip_name"));
        }
    }

    #[test]
    fn private_pattern_config_rejects_invalid_documents_atomically_and_secret_safely() {
        let malformed_document =
            r#"{"schema_version":1,"pattern":"private_json_canary","compile_limits":}"#;
        let malformed = PrivatePatternConfig::load_json(malformed_document)
            .expect_err("malformed JSON must not yield a partial recipe");
        assert_eq!(malformed.kind, PrivatePatternConfigErrorKind::Decode);

        let mut unknown_value =
            serde_json::to_value(PrivatePatternConfig::new("a")).expect("serialize config value");
        unknown_value
            .as_object_mut()
            .expect("config object")
            .insert("private_unknown_canary".to_owned(), serde_json::json!(true));
        let unknown_document = serde_json::to_string(&unknown_value).expect("unknown field JSON");
        let unknown = PrivatePatternConfig::load_json(&unknown_document)
            .expect_err("unknown fields must fail closed");
        assert_eq!(unknown.kind, PrivatePatternConfigErrorKind::Decode);

        let mut nested_unknown_value =
            serde_json::to_value(PrivatePatternConfig::new("a")).expect("serialize config value");
        nested_unknown_value["iteration_limits"]["capture"]["vm"]
            .as_object_mut()
            .expect("nested VM limit object")
            .insert(
                "private_nested_unknown_canary".to_owned(),
                serde_json::json!(true),
            );
        let nested_unknown_document =
            serde_json::to_string(&nested_unknown_value).expect("nested unknown field JSON");
        let nested_unknown = PrivatePatternConfig::load_json(&nested_unknown_document)
            .expect_err("nested unknown fields must fail closed");
        assert_eq!(nested_unknown.kind, PrivatePatternConfigErrorKind::Decode);

        let mut missing_value =
            serde_json::to_value(PrivatePatternConfig::new("private_missing_canary"))
                .expect("serialize config value");
        missing_value
            .as_object_mut()
            .expect("config object")
            .remove("compile_limits");
        let missing_document = serde_json::to_string(&missing_value).expect("missing field JSON");
        let missing = PrivatePatternConfig::load_json(&missing_document)
            .expect_err("missing fields must fail closed");
        assert_eq!(missing.kind, PrivatePatternConfigErrorKind::Decode);

        let mut unsupported = PrivatePatternConfig::new("a");
        unsupported.schema_version = PRIVATE_PATTERN_CONFIG_SCHEMA_VERSION + 1;
        let unsupported = PrivatePatternConfig::load(unsupported)
            .expect_err("unsupported schema must not compile");
        assert_eq!(
            unsupported.kind,
            PrivatePatternConfigErrorKind::UnsupportedSchema
        );

        let mut invalid_limits = PrivatePatternConfig::new("a");
        invalid_limits.iteration_limits.max_matches = 0;
        let invalid_limits = PrivatePatternConfig::load(invalid_limits)
            .expect_err("invalid execution limits must not compile");
        assert_eq!(
            invalid_limits.kind,
            PrivatePatternConfigErrorKind::InvalidIterationLimits
        );
        assert_eq!(invalid_limits.field, Some("iteration.max_matches"));
        assert_eq!(
            (invalid_limits.actual, invalid_limits.limit),
            (Some(0), Some(1))
        );

        let invalid_pattern = "private_compile_canary\\";
        let compile = PrivatePatternConfig::load(PrivatePatternConfig::new(invalid_pattern))
            .expect_err("invalid pattern must not yield a partial compiled value");
        assert_eq!(compile.kind, PrivatePatternConfigErrorKind::Compile);

        let prior = PrivatePatternConfig::load(PrivatePatternConfig::new("a+"))
            .expect("load prior pattern");
        let _ = PrivatePatternConfig::load(PrivatePatternConfig::new("("))
            .expect_err("later invalid load fails");
        assert!(prior.is_match("zaaa").expect("prior load remains reusable"));

        let mut zero_replacement = PrivatePatternConfig::new("z");
        zero_replacement.replacement_limits = ReplacementLimits {
            max_template_bytes: 0,
            max_tokens: 0,
            max_output_bytes: 0,
            max_work_units: 0,
        };
        let zero_replacement = PrivatePatternConfig::load(zero_replacement)
            .expect("zero replacement ceilings are valid when the operation uses zero");
        assert_eq!(
            zero_replacement
                .replace_all("", "")
                .expect("zero-use replacement")
                .output,
            ""
        );

        for (error, canary) in [
            (malformed, "private_json_canary"),
            (unknown, "private_unknown_canary"),
            (nested_unknown, "private_nested_unknown_canary"),
            (missing, "private_missing_canary"),
            (compile, "private_compile_canary"),
        ] {
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(!rendered.contains(canary));
            }
        }
    }

    #[test]
    fn loaded_private_pattern_is_reusable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoadedPrivatePattern>();

        let loaded = std::sync::Arc::new(
            PrivatePatternConfig::load(PrivatePatternConfig::new("(?P<value>a+)"))
                .expect("load shared pattern"),
        );
        let start = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..8 {
                let loaded = std::sync::Arc::clone(&loaded);
                let worker_start = std::sync::Arc::clone(&start);
                let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                    let (lock, ready) = &*worker_start;
                    let started = lock.lock().expect("shared start gate");
                    drop(
                        ready
                            .wait_while(started, |started| !*started)
                            .expect("shared start gate wait"),
                    );
                    for _ in 0..32 {
                        assert!(loaded.is_match("zaaa").expect("shared match"));
                        assert_eq!(
                            loaded
                                .replace_all("zaaa", "<$value>")
                                .expect("shared replacement")
                                .output,
                            "z<aaa>"
                        );
                    }
                });
                match worker {
                    Ok(join) => joins.push(join),
                    Err(error) => {
                        let (lock, ready) = &*start;
                        *lock.lock().expect("release start gate after spawn failure") = true;
                        ready.notify_all();
                        panic!("failed to spawn shared config worker: {error}");
                    }
                }
            }
            let (lock, ready) = &*start;
            *lock.lock().expect("release shared start gate") = true;
            ready.notify_all();
            for join in joins {
                join.join().expect("shared config worker");
            }
        });
    }

    fn private_cache(limits: PrivatePatternCacheLimits) -> PrivatePatternCache {
        PrivatePatternCache::new(limits).expect("valid private cache limits")
    }

    #[test]
    fn private_pattern_cache_limits_and_failures_are_atomic_and_secret_safe() {
        let invalid = PrivatePatternCache::new(PrivatePatternCacheLimits {
            max_entries: 0,
            ..PrivatePatternCacheLimits::default()
        })
        .expect_err("zero entry limit is invalid");
        assert_eq!(invalid.kind, PrivatePatternCacheErrorKind::InvalidLimits);

        let pattern_limited = private_cache(PrivatePatternCacheLimits {
            max_pattern_bytes: 1,
            ..PrivatePatternCacheLimits::default()
        });
        let private_pattern = "private-cache-pattern-canary";
        let limited = pattern_limited
            .get_or_compile(PrivatePatternConfig::new(private_pattern))
            .expect_err("pattern ceiling fails before compile");
        assert_eq!(limited.kind, PrivatePatternCacheErrorKind::PatternLimit);
        assert_eq!(pattern_limited.snapshot().entries, 0);

        let byte_limited = private_cache(PrivatePatternCacheLimits {
            max_live_accounted_bytes: ACCOUNTED_PRIVATE_PATTERN_RESIDENT_OVERHEAD_BYTES,
            ..PrivatePatternCacheLimits::default()
        });
        let oversized = byte_limited
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect_err("compiled resident cannot exceed the live-byte ceiling");
        assert_eq!(oversized.kind, PrivatePatternCacheErrorKind::EntryTooLarge);
        assert_eq!(byte_limited.snapshot().entries, 0);
        assert_eq!(byte_limited.snapshot().live_accounted_bytes, 0);
        assert_eq!(byte_limited.snapshot().inflight_compiles, 0);
        assert_eq!(byte_limited.snapshot().inflight_compile_accounted_bytes, 0);

        let cache = private_cache(PrivatePatternCacheLimits::default());
        let malformed_pattern = "private-cache-malformed-canary\\";
        let malformed = cache
            .get_or_compile(PrivatePatternConfig::new(malformed_pattern))
            .expect_err("malformed pattern is never negative-cached");
        assert_eq!(malformed.kind, PrivatePatternCacheErrorKind::Config);
        assert_eq!(
            malformed.config_error.map(|error| error.kind),
            Some(PrivatePatternConfigErrorKind::Compile)
        );
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().inflight_compiles, 0);
        assert_eq!(cache.snapshot().inflight_compile_accounted_bytes, 0);
        let debug_pattern = "(?P<private_cache_debug_canary>a)";
        let debug_lease = cache
            .get_or_compile(PrivatePatternConfig::new(debug_pattern))
            .expect("admit debug canary pattern");
        for rendered in [
            limited.to_string(),
            format!("{limited:?}"),
            malformed.to_string(),
            format!("{malformed:?}"),
            format!("{cache:?}"),
            format!("{debug_lease:?}"),
        ] {
            assert!(!rendered.contains(private_pattern));
            assert!(!rendered.contains("private-cache-malformed-canary"));
            assert!(!rendered.contains("private_cache_debug_canary"));
        }
        cache.shutdown();
        drop(debug_lease);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_lru_eviction_tracks_evicted_leases_until_drop() {
        let cache = private_cache(PrivatePatternCacheLimits {
            max_entries: 2,
            ..PrivatePatternCacheLimits::default()
        });
        let first = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit first pattern");
        let second = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect("admit second pattern");
        let second_bytes = second.accounted_live_bytes();
        let second_weak = Arc::downgrade(&second.resident);

        let first_hit = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("refresh first as most recently used");
        drop(first_hit);
        let third = cache
            .get_or_compile(PrivatePatternConfig::new("c"))
            .expect("third pattern evicts least-recently-used second entry");
        let after_eviction = cache.snapshot();
        assert_eq!(after_eviction.entries, 2);
        assert_eq!(after_eviction.hits, 1);
        assert_eq!(after_eviction.evictions, 1);
        assert!(second_weak.upgrade().is_some());
        assert!(second.is_match("b").expect("evicted lease remains usable"));

        let live_before_second_drop = after_eviction.live_accounted_bytes;
        drop(second);
        assert!(second_weak.upgrade().is_none());
        assert_eq!(
            cache.snapshot().live_accounted_bytes,
            live_before_second_drop - second_bytes
        );

        cache.clear();
        let after_clear = cache.snapshot();
        assert_eq!(after_clear.entries, 0);
        assert!(after_clear.live_accounted_bytes > 0);
        assert!(
            first
                .is_match("a")
                .expect("cleared first lease remains usable")
        );
        assert!(
            third
                .is_match("c")
                .expect("cleared third lease remains usable")
        );
        drop(first);
        drop(third);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_pinned_capacity_refusal_preserves_existing_entry() {
        let sizing_cache = private_cache(PrivatePatternCacheLimits::default());
        let sizing = sizing_cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("measure deterministic resident charge");
        let one_resident = sizing.accounted_live_bytes();
        sizing_cache.shutdown();
        drop(sizing);
        assert_eq!(sizing_cache.snapshot().live_accounted_bytes, 0);

        let cache = private_cache(PrivatePatternCacheLimits {
            max_entries: 2,
            max_live_accounted_bytes: one_resident,
            ..PrivatePatternCacheLimits::default()
        });
        let admitted = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit one resident");
        let mut distinct_config = PrivatePatternConfig::new("a");
        distinct_config.iteration_limits.max_matches -= 1;
        let refused = cache
            .get_or_compile(distinct_config)
            .expect_err("active lease pins the complete live-byte budget");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::CapacityPinned);
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.live_accounted_bytes, one_resident);
        assert_eq!(snapshot.evictions, 0, "failed admission is non-destructive");
        assert!(
            admitted
                .is_match("za")
                .expect("existing resident survives refusal")
        );
        cache.shutdown();
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().live_accounted_bytes, one_resident);
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_duplicate_compile_race_admits_one_exact_winner() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 2,
            max_inflight_compile_accounted_bytes: 3 * 1024 * 1024 * 1024,
            ..PrivatePatternCacheLimits::default()
        }));
        let before_admission = Arc::new(std::sync::Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let before_admission = Arc::clone(&before_admission);
                std::thread::spawn(move || {
                    let mut probe = |checkpoint| {
                        if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                            before_admission.wait();
                        }
                        false
                    };
                    let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
                    let lease = cache
                        .get_or_compile_with_admission_control(
                            PrivatePatternConfig::new("(?P<value>a+)"),
                            &mut control,
                        )
                        .expect("racing compile returns admitted winner");
                    assert!(lease.is_match("zaaa").expect("winner is usable"));
                })
            })
            .collect::<Vec<_>>();
        before_admission.wait();
        for handle in handles {
            handle.join().expect("duplicate compile worker joins");
        }

        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.misses, 2);
        assert_eq!(snapshot.compilations, 2);
        assert_eq!(snapshot.admissions, 1);
        assert_eq!(snapshot.duplicate_compiles, 1);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_inflight_compile_ceiling_fails_closed() {
        let default_reservation =
            private_pattern_compile_reservation_bytes(&PrivatePatternConfig::new("a"))
                .expect("default compile reservation is representable");
        assert_eq!(DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES, 1);
        assert!(
            default_reservation
                <= DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES
        );
        assert!(
            default_reservation.saturating_mul(2)
                > DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES,
            "the default count must not advertise concurrency rejected by the byte ceiling"
        );

        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 1,
            ..PrivatePatternCacheLimits::default()
        }));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx
                        .send(())
                        .expect("announce occupied compile slot");
                    release_rx.recv().expect("release occupied compile slot");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a+"),
                &mut control,
            )
        });

        compiled_rx.recv().expect("first compile occupies slot");
        assert_eq!(cache.snapshot().inflight_compiles, 1);
        let refused = cache
            .get_or_compile(PrivatePatternConfig::new("b+"))
            .expect_err("second concurrent compile exceeds explicit ceiling");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::CompileCapacity);
        assert_eq!(cache.snapshot().entries, 0);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);

        release_tx.send(()).expect("release first compile");
        let admitted = worker
            .join()
            .expect("compile-capacity worker joins")
            .expect("first compile admits");
        assert!(admitted.is_match("aaa").expect("first resident is usable"));
        assert_eq!(cache.snapshot().inflight_compiles, 0);
        assert_eq!(cache.snapshot().inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_inflight_compile_byte_ceiling_releases_exactly() {
        let config = PrivatePatternConfig::new("a+");
        let reservation = private_pattern_compile_reservation_bytes(&config)
            .expect("default compile reservation is representable");
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_inflight_compiles: 2,
            max_inflight_compile_accounted_bytes: reservation,
            ..PrivatePatternCacheLimits::default()
        }));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx
                        .send(())
                        .expect("announce occupied compile-byte budget");
                    release_rx
                        .recv()
                        .expect("release occupied compile-byte budget");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(config, &mut control)
        });

        compiled_rx
            .recv()
            .expect("first compile occupies byte reservation");
        let occupied = cache.snapshot();
        assert_eq!(occupied.inflight_compiles, 1);
        assert_eq!(occupied.inflight_compile_accounted_bytes, reservation);
        let refused = cache
            .get_or_compile(PrivatePatternConfig::new("b+"))
            .expect_err("second compile exceeds aggregate byte reservation");
        assert_eq!(
            refused.kind,
            PrivatePatternCacheErrorKind::CompileMemoryCapacity
        );
        assert_eq!(cache.snapshot().inflight_compiles, 1);
        assert_eq!(
            cache.snapshot().inflight_compile_accounted_bytes,
            reservation
        );

        release_tx.send(()).expect("release first byte reservation");
        let admitted = worker
            .join()
            .expect("compile-byte worker joins")
            .expect("first compile admits");
        let released = cache.snapshot();
        assert_eq!(released.inflight_compiles, 0);
        assert_eq!(released.inflight_compile_accounted_bytes, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_lookup_work_and_closed_precedence_fail_closed() {
        let pattern = "a".repeat(1024);
        let exact_hit_work = u64::try_from(pattern.len() * 3).expect("bounded lookup work")
            + ACCOUNTED_PRIVATE_PATTERN_LOOKUP_ENTRY_WORK_UNITS;
        let cache = private_cache(PrivatePatternCacheLimits {
            max_lookup_work_units: exact_hit_work - 1,
            ..PrivatePatternCacheLimits::default()
        });
        let lease = cache
            .get_or_compile(PrivatePatternConfig::new(pattern.clone()))
            .expect("first bounded lookup and admission");
        let work_limited = cache
            .get_or_compile(PrivatePatternConfig::new(pattern))
            .expect_err("exact collision-safe verification obeys lookup ceiling");
        assert_eq!(
            work_limited.kind,
            PrivatePatternCacheErrorKind::LookupWorkLimit
        );
        assert_eq!(cache.snapshot().hits, 0);
        assert_eq!(cache.snapshot().entries, 1);

        cache.shutdown();
        let closed = cache
            .get_or_compile(PrivatePatternConfig::new("z".repeat(2 * 1024 * 1024)))
            .expect_err("closed refusal precedes pattern-length diagnostics");
        assert_eq!(closed.kind, PrivatePatternCacheErrorKind::Closed);
        assert_eq!((closed.actual, closed.limit), (None, None));
        drop(lease);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_cancellation_callbacks_are_outside_lock_and_never_admit() {
        let cache = private_cache(PrivatePatternCacheLimits::default());
        let mut precompile_probe = |checkpoint| {
            let snapshot = cache.snapshot();
            assert_eq!(snapshot.entries, 0, "callback can re-enter cache snapshot");
            checkpoint == PrivatePatternCacheCheckpoint::Compile
        };
        let mut precompile_control =
            PrivatePatternCacheAdmissionControl::new(&mut precompile_probe);
        let precompile = cache
            .get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a"),
                &mut precompile_control,
            )
            .expect_err("precompile cancellation refuses work");
        assert_eq!(precompile.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            precompile_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Compile)
        );
        assert_eq!(cache.snapshot().compilations, 0);

        let mut preadmission_probe = |checkpoint| {
            let snapshot = cache.snapshot();
            assert_eq!(snapshot.entries, 0, "post-compile callback holds no lock");
            checkpoint == PrivatePatternCacheCheckpoint::Admission
        };
        let mut preadmission_control =
            PrivatePatternCacheAdmissionControl::new(&mut preadmission_probe);
        let preadmission = cache
            .get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a"),
                &mut preadmission_control,
            )
            .expect_err("post-compile cancellation discards result");
        assert_eq!(preadmission.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            preadmission_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Admission)
        );
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.live_accounted_bytes, 0);
        assert_eq!(snapshot.compilations, 1);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);

        let admitted = cache
            .get_or_compile(PrivatePatternConfig::new("a"))
            .expect("admit cache-hit cancellation fixture");
        let mut hit_probe = |checkpoint| checkpoint == PrivatePatternCacheCheckpoint::Lookup;
        let mut hit_control = PrivatePatternCacheAdmissionControl::new(&mut hit_probe);
        let hit_cancelled = cache
            .get_or_compile_with_admission_control(PrivatePatternConfig::new("a"), &mut hit_control)
            .expect_err("lookup cancellation takes precedence over cache hit");
        assert_eq!(hit_cancelled.kind, PrivatePatternCacheErrorKind::Cancelled);
        assert_eq!(
            hit_control.cancelled_at(),
            Some(PrivatePatternCacheCheckpoint::Lookup)
        );
        assert_eq!(cache.snapshot().hits, 0);
        cache.shutdown();
        drop(admitted);
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_pattern_cache_shutdown_wins_inflight_admission_and_is_idempotent() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits::default()));
        let (compiled_tx, compiled_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let worker_cache = Arc::clone(&cache);
        let worker = std::thread::spawn(move || {
            let mut probe = |checkpoint| {
                if checkpoint == PrivatePatternCacheCheckpoint::Admission {
                    compiled_tx.send(()).expect("announce compiled result");
                    release_rx.recv().expect("release admission probe");
                }
                false
            };
            let mut control = PrivatePatternCacheAdmissionControl::new(&mut probe);
            worker_cache.get_or_compile_with_admission_control(
                PrivatePatternConfig::new("a+"),
                &mut control,
            )
        });

        compiled_rx
            .recv()
            .expect("worker reached pre-admission state");
        cache.shutdown();
        cache.shutdown();
        release_tx.send(()).expect("release worker");
        let refused = worker
            .join()
            .expect("in-flight compile worker joins")
            .expect_err("closed cache refuses the compiled result");
        assert_eq!(refused.kind, PrivatePatternCacheErrorKind::Closed);
        let snapshot = cache.snapshot();
        assert!(snapshot.closed);
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.live_accounted_bytes, 0);
        assert_eq!(snapshot.inflight_compiles, 0);
        assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);
        let later = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect_err("closed cache refuses later lookup");
        assert_eq!(later.kind, PrivatePatternCacheErrorKind::Closed);
    }

    #[test]
    fn private_pattern_cache_eviction_races_controlled_use_without_leak() {
        let cache = Arc::new(private_cache(PrivatePatternCacheLimits {
            max_entries: 1,
            ..PrivatePatternCacheLimits::default()
        }));
        let lease = cache
            .get_or_compile(PrivatePatternConfig::new("(a+)"))
            .expect("admit controlled-use pattern");
        let weak = Arc::downgrade(&lease.resident);
        let worker_lease = lease.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (go_tx, go_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            ready_tx.send(()).expect("announce held lease");
            go_rx.recv().expect("begin controlled use");
            let mut probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 3;
            let mut control = VmCancellationControl::new(3, &mut probe).expect("valid control");
            let private_haystack = "r3_6_probe-aaaa";
            assert_eq!(
                private_haystack.find('a'),
                Some(private_haystack.len() - 4),
                "controlled-use premise has no earlier match"
            );
            let error = worker_lease
                .find_iter_with_control(
                    private_haystack,
                    IterationPolicy::NonOverlapping,
                    &mut control,
                )
                .expect_err("controlled use cancels after eviction");
            assert_eq!(error.kind, VmErrorKind::Cancelled);
        });

        ready_rx.recv().expect("worker holds resident lease");
        let replacement = cache
            .get_or_compile(PrivatePatternConfig::new("b"))
            .expect("evict held resident while preserving its lease");
        assert_eq!(cache.snapshot().entries, 1);
        assert!(weak.upgrade().is_some());
        go_tx.send(()).expect("release controlled use");
        worker.join().expect("controlled-use worker joins");
        assert!(
            lease
                .is_match("zaaa")
                .expect("evicted original remains usable")
        );

        cache.shutdown();
        drop(replacement);
        drop(lease);
        assert!(weak.upgrade().is_none());
        assert_eq!(cache.snapshot().live_accounted_bytes, 0);
    }

    #[test]
    fn private_compiled_pattern_compiles_once_without_retaining_source_text() {
        let pattern = "(?P<r3_5_private_compiled_pattern_canary>a)?b";
        let compiled = compile_pattern(pattern);
        let rendered = format!("{compiled:?}");
        assert!(rendered.contains("PrivateCompiledPattern"));
        assert!(rendered.contains("capture_slots"));
        assert!(!rendered.contains(pattern));
        assert!(!rendered.contains("r3_5_private_compiled_pattern_canary"));

        let malformed = "r3_5_private_compiled_error_canary\\";
        let error = PrivateCompiledPattern::compile(malformed, PrivateCompileLimits::default())
            .expect_err("trailing escape must fail during private compilation");
        assert_eq!(error.code(), "RGX-LEX-E003");
        for diagnostic in [error.to_string(), format!("{error:?}")] {
            assert!(!diagnostic.contains(malformed));
            assert!(!diagnostic.contains("r3_5_private_compiled_error_canary"));
        }
    }

    #[test]
    fn private_compiled_pattern_match_find_captures_and_reuse_are_exact() {
        let priority = compile_pattern("(a|ab)");
        assert!(
            priority
                .is_match("zab", CaptureVmLimits::default())
                .expect("match query")
        );
        assert!(
            !priority
                .is_match("zzz", CaptureVmLimits::default())
                .expect("no-match query")
        );
        assert_eq!(
            priority
                .find("zab", CaptureVmLimits::default())
                .expect("leftmost find"),
            Some(CaptureSpan { start: 1, end: 2 })
        );
        for _ in 0..16 {
            let selected = priority
                .captures("zab", CaptureVmLimits::default())
                .expect("reused capture query")
                .expect("priority pattern matches");
            assert_eq!(selected.span, CaptureSpan { start: 1, end: 2 });
            assert_eq!(
                selected.captures,
                vec![Some(CaptureSpan { start: 1, end: 2 })]
            );
        }

        let participation = compile_pattern("(a)?b");
        let absent = participation
            .captures("b", CaptureVmLimits::default())
            .expect("optional capture query")
            .expect("whole expression matches");
        assert_eq!(absent.span, CaptureSpan { start: 0, end: 1 });
        assert_eq!(absent.captures, vec![None]);

        let empty = compile_pattern("");
        assert_eq!(
            empty
                .find("é", CaptureVmLimits::default())
                .expect("zero-width find"),
            Some(CaptureSpan { start: 0, end: 0 })
        );
    }

    #[test]
    fn private_compiled_pattern_iteration_is_stable_and_unicode_safe() {
        let overlapping = compile_pattern("aba");
        let non_overlapping = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
            )
            .expect("non-overlapping iteration");
        assert_eq!(
            non_overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![CaptureSpan { start: 0, end: 3 }]
        );
        let first = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::Overlapping,
                IterationVmLimits::default(),
            )
            .expect("overlapping iteration");
        let second = overlapping
            .find_iter(
                "ababa",
                IterationPolicy::Overlapping,
                IterationVmLimits::default(),
            )
            .expect("replayed overlapping iteration");
        assert_eq!(
            first.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 3 },
                CaptureSpan { start: 2, end: 5 },
            ]
        );
        assert_eq!(first, second);

        let empty = compile_pattern("");
        let zero_width = empty
            .find_iter(
                "éa",
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
            )
            .expect("zero-width Unicode iteration");
        assert_eq!(
            zero_width.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 2, end: 2 },
                CaptureSpan { start: 3, end: 3 },
            ]
        );
    }

    #[test]
    fn private_compiled_pattern_limits_cancel_exactly_and_leave_it_reusable() {
        let compiled = compile_pattern("(a+)");
        let input = compiled
            .is_match(
                "four",
                CaptureVmLimits {
                    vm: VmLimits {
                        max_input_bytes: 3,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
            )
            .expect_err("input ceiling must fail closed");
        assert_eq!(input.kind, VmErrorKind::InputLimit);
        assert_eq!((input.actual, input.limit), (Some(4), Some(3)));

        let seen_keys = compiled.program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE;
        let base_memory = capture_base_memory_bytes(
            seen_keys,
            seen_keys.min(DEFAULT_MAX_THREADS_PER_OFFSET),
            compiled.program.capture_slots,
            DEFAULT_MAX_TRACE_EVENTS,
        )
        .expect("bounded capture base memory");
        let memory = compiled
            .captures(
                "a",
                CaptureVmLimits {
                    vm: VmLimits {
                        max_memory_bytes: base_memory - 1,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
            )
            .expect_err("base memory ceiling must fail closed");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);
        assert_eq!(
            (memory.actual, memory.limit),
            (Some(base_memory), Some(base_memory - 1))
        );

        let work = compiled
            .find_iter(
                "a a",
                IterationPolicy::NonOverlapping,
                IterationVmLimits {
                    capture: CaptureVmLimits {
                        vm: VmLimits {
                            max_work_units: 1,
                            ..VmLimits::default()
                        },
                        ..CaptureVmLimits::default()
                    },
                    ..IterationVmLimits::default()
                },
            )
            .expect_err("aggregate work ceiling must fail closed");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);

        let match_limit = compiled
            .find_iter(
                "a a",
                IterationPolicy::NonOverlapping,
                IterationVmLimits {
                    max_matches: 1,
                    ..IterationVmLimits::default()
                },
            )
            .expect_err("second match exceeds the aggregate ceiling");
        assert_eq!(match_limit.kind, VmErrorKind::MatchLimit);
        assert_eq!((match_limit.actual, match_limit.limit), (Some(2), Some(1)));

        let private_haystack = "r3_5_probe-aaaa";
        assert_eq!(
            private_haystack.find('a'),
            Some(private_haystack.len() - 4),
            "the reuse probe must have no earlier match"
        );
        let mut probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 3;
        let mut control =
            VmCancellationControl::new(3, &mut probe).expect("valid cancellation control");
        let cancelled = compiled
            .find_iter_with_control(
                private_haystack,
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
                &mut control,
            )
            .expect_err("third aggregate checkpoint cancels iteration");
        assert_eq!(cancelled.kind, VmErrorKind::Cancelled);
        assert_eq!(control.cancelled_at().map(|point| point.sequence), Some(3));
        assert!(!cancelled.to_string().contains(private_haystack));
        assert_eq!(
            compiled
                .find(private_haystack, CaptureVmLimits::default())
                .expect("compiled pattern remains reusable after cancellation"),
            Some(CaptureSpan {
                start: private_haystack.len() - 4,
                end: private_haystack.len(),
            })
        );
    }

    #[test]
    fn private_compiled_pattern_is_immutable_send_sync_for_shared_use() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrivateCompiledPattern>();

        let compiled = std::sync::Arc::new(compile_pattern("(ab|a)"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let handles = (0..8)
            .map(|_| {
                let compiled = std::sync::Arc::clone(&compiled);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..32 {
                        let matched = compiled
                            .captures("zab", CaptureVmLimits::default())
                            .expect("shared capture query")
                            .expect("shared pattern matches");
                        assert_eq!(matched.span, CaptureSpan { start: 1, end: 3 });
                        assert_eq!(
                            matched.captures,
                            vec![Some(CaptureSpan { start: 1, end: 3 })]
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for handle in handles {
            handle.join().expect("shared query worker must not panic");
        }
    }

    #[test]
    fn leftmost_alternation_and_greedy_lazy_priority_are_exact() {
        let first = search("(a|ab)", "zab");
        assert_eq!(first.span, CaptureSpan { start: 1, end: 2 });
        assert_eq!(first.captures, vec![Some(CaptureSpan { start: 1, end: 2 })]);

        let longest_first = search("(ab|a)", "zab");
        assert_eq!(longest_first.span, CaptureSpan { start: 1, end: 3 });
        assert_eq!(
            longest_first.captures,
            vec![Some(CaptureSpan { start: 1, end: 3 })]
        );

        let greedy = search("(a+)", "zaaab");
        assert_eq!(greedy.span, CaptureSpan { start: 1, end: 4 });
        assert_eq!(
            greedy.captures,
            vec![Some(CaptureSpan { start: 1, end: 4 })]
        );

        let lazy = search("(a+?)", "zaaab");
        assert_eq!(lazy.span, CaptureSpan { start: 1, end: 2 });
        assert_eq!(lazy.captures, vec![Some(CaptureSpan { start: 1, end: 2 })]);
    }

    #[test]
    fn capture_participation_empty_repeated_and_unicode_spans_are_exact() {
        let unmatched = search("(a)?b", "b");
        assert_eq!(unmatched.span, CaptureSpan { start: 0, end: 1 });
        assert_eq!(unmatched.captures, vec![None]);

        let empty = search("(a*)", "");
        assert_eq!(empty.span, CaptureSpan { start: 0, end: 0 });
        assert_eq!(empty.captures, vec![Some(CaptureSpan { start: 0, end: 0 })]);

        let repeated = search("(a)+", "aaa");
        assert_eq!(repeated.span, CaptureSpan { start: 0, end: 3 });
        assert_eq!(
            repeated.captures,
            vec![Some(CaptureSpan { start: 2, end: 3 })]
        );

        let unicode = search("(é+)", "xééy");
        assert_eq!(unicode.span, CaptureSpan { start: 1, end: 5 });
        assert_eq!(
            unicode.captures,
            vec![Some(CaptureSpan { start: 1, end: 5 })]
        );
    }

    #[test]
    fn full_capture_mode_rejects_a_preferred_prefix_before_a_complete_fallback() {
        let program = lower_default("(a|ab)");
        let outcome = execute_captures_full(
            &program,
            "ab",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("full capture execution");
        let matched = outcome.matched.expect("fallback reaches the full end");
        assert_eq!(matched.span, CaptureSpan { start: 0, end: 2 });
        assert_eq!(
            matched.captures,
            vec![Some(CaptureSpan { start: 0, end: 2 })]
        );
    }

    #[test]
    fn capture_history_and_memory_limits_fail_closed_without_input_disclosure() {
        assert!(
            u64::try_from(core::mem::size_of::<CaptureThread>()).expect("thread size fits u64")
                <= ACCOUNTED_CAPTURE_THREAD_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<CaptureHistoryNode>())
                .expect("history-node size fits u64")
                <= ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<usize>()).expect("key size fits u64")
                <= ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<Option<CaptureSpan>>())
                .expect("capture result size fits u64")
                <= ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES * 2
        );

        let program = lower_default("(a)+");
        let history = execute_search(
            &program,
            "private-capture-canary-aaa",
            CompileLimits::default(),
            CaptureVmLimits {
                max_capture_history_nodes: 1,
                ..CaptureVmLimits::default()
            },
        )
        .expect_err("history ceiling");
        assert_eq!(history.kind, VmErrorKind::CaptureHistoryLimit);
        assert!(!history.to_string().contains("private-capture-canary"));

        let base_memory = capture_base_memory_bytes(
            program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE,
            (program.states.len() * CAPTURE_SEEN_KEYS_PER_STATE)
                .min(DEFAULT_MAX_THREADS_PER_OFFSET),
            program.capture_slots,
            DEFAULT_MAX_TRACE_EVENTS,
        )
        .expect("bounded base memory");
        let memory = execute_search(
            &program,
            "a",
            CompileLimits::default(),
            CaptureVmLimits {
                vm: VmLimits {
                    max_memory_bytes: base_memory,
                    ..VmLimits::default()
                },
                ..CaptureVmLimits::default()
            },
        )
        .expect_err("first Save exceeds base-only memory");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);
    }

    #[test]
    fn one_shot_is_match_and_iteration_adapters_preserve_captures() {
        let program = lower_default("(a)?b");
        let present = execute_search(
            &program,
            "b",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("one-shot match");
        assert!(present.is_match());
        assert_eq!(
            present.matched.expect("selected match").captures,
            vec![None]
        );

        let absent = execute_search(
            &program,
            "zzz",
            CompileLimits::default(),
            CaptureVmLimits::default(),
        )
        .expect("one-shot miss");
        assert!(!absent.is_match());

        let iterated = iterate("(a)?b", "b ab", IterationPolicy::NonOverlapping);
        assert_eq!(
            iterated.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 1 },
                CaptureSpan { start: 2, end: 4 },
            ]
        );
        assert_eq!(iterated.matches[0].captures, vec![None]);
        assert_eq!(
            iterated.matches[1].captures,
            vec![Some(CaptureSpan { start: 2, end: 3 })]
        );
    }

    #[test]
    fn overlap_policy_resumes_after_start_without_duplicate_matches() {
        let non_overlapping = iterate("aba", "ababa", IterationPolicy::NonOverlapping);
        assert_eq!(
            non_overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![CaptureSpan { start: 0, end: 3 }]
        );

        let overlapping = iterate("aba", "ababa", IterationPolicy::Overlapping);
        assert_eq!(
            overlapping.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 3 },
                CaptureSpan { start: 2, end: 5 },
            ]
        );
        assert_eq!(overlapping.resources.overlap_advances, 2);
        assert_eq!(
            overlapping.trace.last().expect("terminal miss").matched,
            None
        );
    }

    #[test]
    fn zero_width_iteration_advances_by_complete_unicode_scalars_and_stops_at_end() {
        let first = iterate("", "éa", IterationPolicy::NonOverlapping);
        let second = iterate("", "éa", IterationPolicy::NonOverlapping);
        assert_eq!(
            first.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 2, end: 2 },
                CaptureSpan { start: 3, end: 3 },
            ]
        );
        assert_eq!(first.resources.zero_width_advances, 2);
        assert_eq!(first.resources.search_attempts, 3);
        assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
        assert_eq!(first.resources, second.resources);
        assert_eq!(first.trace, second.trace);
        assert_eq!(
            first
                .trace
                .iter()
                .map(|event| event.search_start)
                .collect::<Vec<_>>(),
            vec![0, 2, 3]
        );

        let adjacent = iterate("a*", "baa", IterationPolicy::NonOverlapping);
        assert_eq!(
            adjacent.replacement_spans().collect::<Vec<_>>(),
            vec![
                CaptureSpan { start: 0, end: 0 },
                CaptureSpan { start: 1, end: 3 },
            ]
        );
        let discarded = adjacent.trace.last().expect("discarded terminal empty");
        assert_eq!(discarded.matched, Some(CaptureSpan { start: 3, end: 3 }));
        assert!(discarded.discarded_adjacent_empty);
        assert_eq!(discarded.next_search_start, None);
    }

    #[test]
    fn iteration_match_work_memory_and_trace_limits_fail_closed() {
        assert!(
            u64::try_from(core::mem::size_of::<VmMatch>()).expect("match size fits")
                <= ACCOUNTED_ITERATION_MATCH_BYTES
        );
        assert!(
            u64::try_from(core::mem::size_of::<IterationTraceEvent>())
                .expect("iteration event size fits")
                <= ACCOUNTED_ITERATION_TRACE_EVENT_BYTES
        );

        let empty = lower_default("");
        let limit = execute_find_iter(
            &empty,
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 1,
                ..IterationVmLimits::default()
            },
        )
        .expect_err("second empty match exceeds limit");
        assert_eq!(limit.kind, VmErrorKind::MatchLimit);
        assert_eq!(limit.actual, Some(2));
        assert_eq!(limit.limit, Some(1));

        let exact = execute_find_iter(
            &lower_default("a"),
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 1,
                ..IterationVmLimits::default()
            },
        )
        .expect("one match at the exact ceiling");
        assert_eq!(exact.matches.len(), 1);

        let invalid = execute_find_iter(
            &empty,
            "",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                max_matches: 0,
                ..IterationVmLimits::default()
            },
        )
        .expect_err("zero match ceiling is invalid");
        assert_eq!(invalid.kind, VmErrorKind::InvalidLimits);

        let work = execute_find_iter(
            &lower_default("a"),
            "a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits {
                capture: CaptureVmLimits {
                    vm: VmLimits {
                        max_work_units: 1,
                        ..VmLimits::default()
                    },
                    ..CaptureVmLimits::default()
                },
                ..IterationVmLimits::default()
            },
        )
        .expect_err("aggregate work limit");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);
    }

    #[test]
    fn explicit_cancellation_is_exact_private_and_leaves_programs_reusable() {
        let mut invalid_probe = |_: VmCancellationCheckpoint| false;
        let invalid = VmCancellationControl::new(0, &mut invalid_probe);
        assert!(matches!(
            invalid,
            Err(VmError {
                kind: VmErrorKind::InvalidLimits,
                ..
            })
        ));

        let full_program = lower_default("a*");
        let full_haystack = "a".repeat(64);
        let ordinary = execute_full(
            &full_program,
            &full_haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("ordinary full execution");
        let mut never_cancel = |_: VmCancellationCheckpoint| false;
        let mut full_control = VmCancellationControl::new(7, &mut never_cancel)
            .expect("nonzero cancellation interval");
        let controlled = execute_full_with_control(
            &full_program,
            &full_haystack,
            CompileLimits::default(),
            VmLimits::default(),
            &mut full_control,
        )
        .expect("controlled full execution");
        assert_eq!(controlled, ordinary);
        assert_eq!(
            full_control.observed_work_units(),
            controlled.resources.work_units
        );
        assert!(full_control.checkpoints() > 0);
        assert_eq!(full_control.cancelled_at(), None);

        let capture_program = lower_default("(a+)");
        let private_haystack = "private-cancel-canary-aaaa";
        let mut capture_receipts = Vec::new();
        let mut cancel_capture = |checkpoint: VmCancellationCheckpoint| {
            capture_receipts.push(checkpoint);
            checkpoint.sequence == 3
        };
        let mut capture_control = VmCancellationControl::new(5, &mut cancel_capture)
            .expect("nonzero cancellation interval");
        let capture_error = execute_search_with_control(
            &capture_program,
            private_haystack,
            CompileLimits::default(),
            CaptureVmLimits::default(),
            &mut capture_control,
        )
        .expect_err("third checkpoint cancels capture search");
        assert_eq!(capture_error.kind, VmErrorKind::Cancelled);
        assert_eq!(
            capture_control.cancelled_at(),
            Some(VmCancellationCheckpoint {
                sequence: 3,
                work_units: 15,
                offset: capture_error.offset.expect("cancel offset"),
                state: capture_error.state,
            })
        );
        assert!(!capture_error.to_string().contains(private_haystack));
        assert_ne!(
            capture_control.checkpoint_fingerprint(),
            FINGERPRINT_OFFSET_BASIS
        );
        assert_eq!(capture_receipts.len(), 3);
        assert!(
            execute_search(
                &capture_program,
                private_haystack,
                CompileLimits::default(),
                CaptureVmLimits::default(),
            )
            .expect("program is reusable after cancellation")
            .is_match()
        );

        let iteration_program = lower_default("a");
        let mut first_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 4;
        let mut first_control =
            VmCancellationControl::new(3, &mut first_probe).expect("valid first control");
        let first_error = execute_find_iter_with_control(
            &iteration_program,
            "a a a a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
            &mut first_control,
        )
        .expect_err("fourth aggregate checkpoint cancels iteration");
        let first_receipt = (
            first_error,
            first_control.cancelled_at(),
            first_control.checkpoint_fingerprint(),
        );

        let mut second_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 4;
        let mut second_control =
            VmCancellationControl::new(3, &mut second_probe).expect("valid second control");
        let second_error = execute_find_iter_with_control(
            &iteration_program,
            "a a a a",
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
            &mut second_control,
        )
        .expect_err("replayed aggregate cancellation");
        assert_eq!(
            first_receipt,
            (
                second_error,
                second_control.cancelled_at(),
                second_control.checkpoint_fingerprint(),
            )
        );
        assert_eq!(first_receipt.0.kind, VmErrorKind::Cancelled);
        assert_eq!(
            iterate("a", "a a a a", IterationPolicy::NonOverlapping)
                .matches
                .len(),
            4
        );
    }

    #[test]
    fn empty_literals_classes_assertions_and_utf8_byte_chains_are_exact() {
        for (pattern, haystack, expected) in [
            ("", "", true),
            ("", "a", false),
            ("a", "a", true),
            ("a", "", false),
            ("é", "é", true),
            ("[a-c]+", "abc", true),
            ("[a-c]+", "abd", false),
            ("^a$", "a", true),
            ("^a$", "aa", false),
            (r"\bword\b", "word", true),
            (r"\bword\b", "sword", false),
        ] {
            assert_eq!(
                execute(pattern, haystack).is_full_match,
                expected,
                "{pattern:?} on {haystack:?}"
            );
        }

        // The R3.3 compiler only emits its validated exact-byte chain for this
        // retained case-folding path. Non-folded byte-mode escape lowering is
        // outside this VM bead and remains a compiler-terminal defer case.
        let byte_program = lower_default("(?i-u:é)");
        let exact_bytes = byte_program
            .classes
            .iter()
            .filter_map(|class| match &class.ranges {
                CanonicalRanges::Bytes(ranges) if ranges.len() == 1 => {
                    let range = ranges.first()?;
                    (range.start == range.end).then_some(range.start)
                }
                CanonicalRanges::Unicode(_) | CanonicalRanges::Bytes(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(exact_bytes, "é".as_bytes());
        let byte_outcome = execute_full(
            &byte_program,
            "é",
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("validated exact-byte chain executes");
        assert!(
            byte_outcome.is_full_match,
            "exact byte trace: {:?}",
            byte_outcome.trace
        );
    }

    #[test]
    fn epsilon_cycle_terminates_and_ordered_split_keeps_first_arrival() {
        let program = Program::checked(
            StateId::new(0),
            StateId::new(3),
            vec![
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(1),
                        fallback: StateId::new(2),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Jump {
                        target: StateId::new(3),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(0),
                        fallback: StateId::new(3),
                    },
                    source: span(),
                },
                State {
                    instruction: Instruction::Accept,
                    source: span(),
                },
            ],
            vec![],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("cycle with reachable accept is valid IR");
        let outcome = execute_full(&program, "", CompileLimits::default(), VmLimits::default())
            .expect("epsilon closure terminates");
        assert!(outcome.is_full_match);
        let enqueued = outcome
            .trace
            .iter()
            .filter(|event| event.action == VmTraceAction::Enqueue)
            .map(|event| event.state.index())
            .collect::<Vec<_>>();
        assert_eq!(enqueued, vec![0, 1, 2, 3]);
        assert!(outcome.resources.deduplicated_threads >= 1);
    }

    #[test]
    fn mixed_unicode_and_byte_paths_share_a_bounded_offset_ring() {
        let program = lower_default(r"(?:é|(?i-u:é))");
        let outcome = execute_full(&program, "é", CompileLimits::default(), VmLimits::default())
            .expect("mixed path executes");
        assert!(outcome.is_full_match);
        assert!(outcome.resources.peak_threads_per_offset <= program.states.len());
        assert!(outcome.resources.accounted_memory_bytes <= DEFAULT_MAX_VM_MEMORY_BYTES);
    }

    #[test]
    fn every_vm_ceiling_fails_closed_before_partial_outcome() {
        let program = lower_default("(?:a|b|c)");
        let invalid = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 0,
                ..VmLimits::default()
            },
        )
        .expect_err("invalid limits");
        assert_eq!(invalid.kind, VmErrorKind::InvalidLimits);

        let input = execute_full(
            &program,
            "aa",
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("input ceiling");
        assert_eq!(input.kind, VmErrorKind::InputLimit);

        let threads = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_threads_per_offset: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("thread ceiling");
        assert_eq!(threads.kind, VmErrorKind::ThreadLimit);

        let memory = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_memory_bytes: ACCOUNTED_VM_BASE_BYTES,
                ..VmLimits::default()
            },
        )
        .expect_err("memory ceiling");
        assert_eq!(memory.kind, VmErrorKind::MemoryLimit);

        let work = execute_full(
            &program,
            "a",
            CompileLimits::default(),
            VmLimits {
                max_work_units: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("work ceiling");
        assert_eq!(work.kind, VmErrorKind::WorkLimit);
    }

    #[test]
    fn malformed_ir_is_rejected_by_r3_3_before_vm_allocation() {
        let mut program = lower_default("a");
        program.states[0].instruction = Instruction::Jump {
            target: StateId::new(usize::MAX),
        };
        let error = execute_full(&program, "a", CompileLimits::default(), VmLimits::default())
            .expect_err("invalid target must fail validation");
        assert_eq!(
            error.kind,
            VmErrorKind::Compile(CompileErrorKind::InvalidTarget)
        );
    }

    #[test]
    fn long_input_is_linear_deterministic_and_trace_bounded() {
        let program = lower_default("a*");
        let haystack = "a".repeat(10_000);
        let first = execute_full(
            &program,
            &haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("long input");
        let second = execute_full(
            &program,
            &haystack,
            CompileLimits::default(),
            VmLimits::default(),
        )
        .expect("deterministic replay");
        assert!(first.is_full_match);
        assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
        assert_eq!(first.resources, second.resources);
        assert!(first.trace_truncated);
        assert_eq!(first.trace.len(), DEFAULT_MAX_TRACE_EVENTS);
        let state_bound = u64::try_from(program.states.len()).expect("state count fits u64");
        let input_bound = u64::try_from(haystack.len() + 1).expect("input fits u64");
        assert!(first.resources.state_visits <= state_bound * input_bound);
    }

    #[test]
    fn error_display_is_pattern_and_haystack_free() {
        let private = "private-vm-canary";
        let program = lower_default("a");
        let error = execute_full(
            &program,
            private,
            CompileLimits::default(),
            VmLimits {
                max_input_bytes: 1,
                ..VmLimits::default()
            },
        )
        .expect_err("input ceiling");
        let rendered = error.to_string();
        assert!(rendered.starts_with("[RGX-VM-E002]"));
        assert!(!rendered.contains(private));
        assert_eq!(program.schema_version, IR_SCHEMA_VERSION);
    }
