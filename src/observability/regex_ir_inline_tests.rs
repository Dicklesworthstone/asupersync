    use super::*;
    use crate::observability::regex_semantics::{ByteRange, ScalarRange};

    const EMPTY_SPAN: SourceSpan = SourceSpan {
        byte_start: 0,
        byte_end: 0,
        scalar_start: 0,
        scalar_end: 0,
    };
    const ONE_SPAN: SourceSpan = SourceSpan {
        byte_start: 0,
        byte_end: 1,
        scalar_start: 0,
        scalar_end: 1,
    };

    fn literal_program() -> Program {
        Program::checked(
            StateId::new(0),
            StateId::new(1),
            vec![
                State {
                    instruction: Instruction::Consume {
                        class: ClassId::new(0),
                        target: StateId::new(1),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Accept,
                    source: EMPTY_SPAN,
                },
            ],
            vec![IrClass {
                ranges: CanonicalRanges::Unicode(vec![ScalarRange::new('a', 'a')]),
                source: ONE_SPAN,
            }],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("literal program must be valid")
    }

    fn capture_split_program() -> Program {
        Program::checked(
            StateId::new(0),
            StateId::new(6),
            vec![
                State {
                    instruction: Instruction::Save {
                        slot: CaptureSlot::new(0),
                        target: StateId::new(1),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Split {
                        preferred: StateId::new(2),
                        fallback: StateId::new(4),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Consume {
                        class: ClassId::new(0),
                        target: StateId::new(3),
                    },
                    source: ONE_SPAN,
                },
                State {
                    instruction: Instruction::Jump {
                        target: StateId::new(5),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Assert {
                        kind: BoundaryKind::InputStart,
                        target: StateId::new(5),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Save {
                        slot: CaptureSlot::new(1),
                        target: StateId::new(6),
                    },
                    source: EMPTY_SPAN,
                },
                State {
                    instruction: Instruction::Accept,
                    source: EMPTY_SPAN,
                },
            ],
            vec![IrClass {
                ranges: CanonicalRanges::Bytes(vec![ByteRange::new(b'a', b'z')]),
                source: ONE_SPAN,
            }],
            2,
            0,
            CompileLimits::default(),
        )
        .expect("capture/split program must be valid")
    }

    #[test]
    fn checked_accepts_empty_literal_and_full_instruction_surface() {
        let empty = Program::checked(
            StateId::new(0),
            StateId::new(0),
            vec![State {
                instruction: Instruction::Accept,
                source: EMPTY_SPAN,
            }],
            vec![],
            0,
            0,
            CompileLimits::default(),
        )
        .expect("empty expression program");
        empty
            .validate(CompileLimits::default())
            .expect("empty expression validates");
        literal_program()
            .validate(CompileLimits::default())
            .expect("literal validates");
        let full = capture_split_program();
        full.validate(CompileLimits::default())
            .expect("all instruction variants validate");
        assert_eq!(full.resources.states, 7);
        assert_eq!(full.resources.transitions, 7);
        assert_eq!(full.resources.capture_slots, 2);
    }

    #[test]
    fn accounting_is_target_independent_and_checked() {
        let program = literal_program();
        assert_eq!(
            program.resources,
            CompileResources {
                states: 2,
                transitions: 1,
                classes: 1,
                class_ranges: 1,
                capture_slots: 0,
                repetition_expansion: 0,
                accounted_memory_bytes: 200,
                work_units: 6,
            }
        );
        let mut tampered = program;
        tampered.resources.work_units += 1;
        assert_eq!(
            tampered
                .validate(CompileLimits::default())
                .expect_err("tampered accounting must fail")
                .kind,
            CompileErrorKind::ResourceAccountingMismatch
        );
    }

    #[test]
    fn diagnostic_golden_is_versioned_pattern_free_and_nonpersistent() {
        let diagnostic = literal_program().diagnostic_json();
        assert_eq!(
            diagnostic,
            json!({
                "schema_id": "asupersync-regex-thompson-ir-diagnostic-v1",
                "schema_version": 1,
                "ir_id": "ASUP-REGEX-THOMPSON-IR-V1",
                "persistence_policy": "diagnostic-only-no-deserialization-contract",
                "entry": 0,
                "accept": 1,
                "capture_slots": 0,
                "repetition_expansion": 0,
                "resources": {
                    "states": 2,
                    "transitions": 1,
                    "classes": 1,
                    "class_ranges": 1,
                    "capture_slots": 0,
                    "repetition_expansion": 0,
                    "accounted_memory_bytes": 200,
                    "work_units": 6,
                },
                "classes": [{
                    "alphabet": "unicode-scalar",
                    "source": {
                        "byte_start": 0,
                        "byte_end": 1,
                        "scalar_start": 0,
                        "scalar_end": 1,
                    },
                    "ranges": [{"start": 97, "end": 97}],
                }],
                "states": [
                    {
                        "source": {
                            "byte_start": 0,
                            "byte_end": 1,
                            "scalar_start": 0,
                            "scalar_end": 1,
                        },
                        "instruction": {"op": "consume", "class": 0, "target": 1},
                    },
                    {
                        "source": {
                            "byte_start": 0,
                            "byte_end": 0,
                            "scalar_start": 0,
                            "scalar_end": 0,
                        },
                        "instruction": {"op": "accept"},
                    },
                ],
            })
        );
        let text = diagnostic.to_string();
        assert!(!text.contains("pattern"));
        assert!(text.contains(PERSISTENCE_POLICY));
    }

    #[test]
    fn malformed_graph_targets_classes_slots_and_accepts_are_rejected() {
        let mut invalid_target = literal_program();
        invalid_target.states[0].instruction = Instruction::Jump {
            target: StateId::new(99),
        };
        assert_eq!(
            invalid_target
                .validate(CompileLimits::default())
                .expect_err("invalid target")
                .kind,
            CompileErrorKind::InvalidTarget
        );

        let mut invalid_class = literal_program();
        invalid_class.states[0].instruction = Instruction::Consume {
            class: ClassId::new(9),
            target: StateId::new(1),
        };
        assert_eq!(
            invalid_class
                .validate(CompileLimits::default())
                .expect_err("invalid class")
                .kind,
            CompileErrorKind::InvalidClassReference
        );

        let mut invalid_slot = capture_split_program();
        invalid_slot.states[0].instruction = Instruction::Save {
            slot: CaptureSlot::new(9),
            target: StateId::new(1),
        };
        assert_eq!(
            invalid_slot
                .validate(CompileLimits::default())
                .expect_err("invalid slot")
                .kind,
            CompileErrorKind::InvalidCaptureSlot
        );

        let mut invalid_accept = literal_program();
        invalid_accept.states[1].instruction = Instruction::Jump {
            target: StateId::new(1),
        };
        invalid_accept.resources =
            CompileResources::checked(&invalid_accept.states, &invalid_accept.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            invalid_accept
                .validate(CompileLimits::default())
                .expect_err("accept must be terminal")
                .kind,
            CompileErrorKind::AcceptNotTerminal
        );
    }

    #[test]
    fn malformed_spans_classes_reachability_and_references_are_rejected() {
        let mut bad_span = literal_program();
        bad_span.states[0].source.byte_end = 0;
        assert_eq!(
            bad_span
                .validate(CompileLimits::default())
                .expect_err("scalar width cannot exceed byte width")
                .kind,
            CompileErrorKind::InvalidSpan
        );

        let mut bad_class = literal_program();
        bad_class.classes[0].ranges = CanonicalRanges::Unicode(vec![ScalarRange::new('z', 'a')]);
        assert_eq!(
            bad_class
                .validate(CompileLimits::default())
                .expect_err("descending class range")
                .kind,
            CompileErrorKind::NonCanonicalClass
        );

        let mut unreachable = literal_program();
        unreachable.states.insert(
            1,
            State {
                instruction: Instruction::Jump {
                    target: StateId::new(2),
                },
                source: EMPTY_SPAN,
            },
        );
        unreachable.accept = StateId::new(2);
        unreachable.states[0].instruction = Instruction::Consume {
            class: ClassId::new(0),
            target: StateId::new(2),
        };
        unreachable.resources =
            CompileResources::checked(&unreachable.states, &unreachable.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            unreachable
                .validate(CompileLimits::default())
                .expect_err("state 1 is unreachable")
                .kind,
            CompileErrorKind::UnreachableState
        );

        let mut unreferenced = literal_program();
        unreferenced.classes.push(IrClass {
            ranges: CanonicalRanges::Bytes(vec![ByteRange::new(b'0', b'9')]),
            source: ONE_SPAN,
        });
        unreferenced.resources =
            CompileResources::checked(&unreferenced.states, &unreferenced.classes, 0, 0)
                .expect("accounting");
        assert_eq!(
            unreferenced
                .validate(CompileLimits::default())
                .expect_err("unused class")
                .kind,
            CompileErrorKind::UnreferencedClass
        );
    }

    #[test]
    fn every_resource_ceiling_fails_closed() {
        let program = capture_split_program();
        let cases = [
            (
                CompileLimits {
                    max_states: program.resources.states - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::StateLimit,
            ),
            (
                CompileLimits {
                    max_transitions: program.resources.transitions - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::TransitionLimit,
            ),
            (
                CompileLimits {
                    max_classes: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_ranges_per_class: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_total_class_ranges: 0,
                    ..CompileLimits::default()
                },
                CompileErrorKind::InvalidLimits,
            ),
            (
                CompileLimits {
                    max_capture_slots: 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::CaptureSlotLimit,
            ),
            (
                CompileLimits {
                    max_memory_bytes: program.resources.accounted_memory_bytes - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::MemoryLimit,
            ),
            (
                CompileLimits {
                    max_work_units: program.resources.work_units - 1,
                    ..CompileLimits::default()
                },
                CompileErrorKind::WorkLimit,
            ),
        ];
        for (limits, expected) in cases {
            assert_eq!(
                program
                    .validate(limits)
                    .expect_err("ceiling must reject")
                    .kind,
                expected
            );
        }

        let repetition = Program::checked(
            StateId::new(0),
            StateId::new(0),
            vec![State {
                instruction: Instruction::Accept,
                source: EMPTY_SPAN,
            }],
            vec![],
            0,
            2,
            CompileLimits::default(),
        )
        .expect("repetition accounting program");
        assert_eq!(
            repetition
                .validate(CompileLimits {
                    max_repetition_expansion: 1,
                    ..CompileLimits::default()
                })
                .expect_err("repetition ceiling")
                .kind,
            CompileErrorKind::RepetitionLimit
        );
    }

    #[test]
    fn malformed_input_validation_is_panic_free() {
        let mut malformed = capture_split_program();
        malformed.entry = StateId::new(usize::MAX);
        let result = std::panic::catch_unwind(|| malformed.validate(CompileLimits::default()));
        assert!(result.is_ok(), "validator must contain malformed input");
        assert_eq!(
            result
                .expect("panic containment")
                .expect_err("invalid entry must fail")
                .kind,
            CompileErrorKind::InvalidEntry
        );
    }

    #[test]
    fn error_codes_are_unique_and_diagnostics_do_not_echo_patterns() {
        let kinds = [
            CompileErrorKind::InvalidLimits,
            CompileErrorKind::InvalidSchema,
            CompileErrorKind::ArithmeticOverflow,
            CompileErrorKind::EmptyProgram,
            CompileErrorKind::StateLimit,
            CompileErrorKind::TransitionLimit,
            CompileErrorKind::ClassLimit,
            CompileErrorKind::ClassRangeLimit,
            CompileErrorKind::TotalClassRangeLimit,
            CompileErrorKind::CaptureSlotLimit,
            CompileErrorKind::OddCaptureSlots,
            CompileErrorKind::RepetitionLimit,
            CompileErrorKind::MemoryLimit,
            CompileErrorKind::WorkLimit,
            CompileErrorKind::ResourceAccountingMismatch,
            CompileErrorKind::InvalidEntry,
            CompileErrorKind::InvalidAccept,
            CompileErrorKind::AcceptNotTerminal,
            CompileErrorKind::ExtraAcceptState,
            CompileErrorKind::InvalidTarget,
            CompileErrorKind::InvalidClassReference,
            CompileErrorKind::InvalidCaptureSlot,
            CompileErrorKind::InvalidSpan,
            CompileErrorKind::NonCanonicalClass,
            CompileErrorKind::UnreferencedClass,
            CompileErrorKind::UnreferencedCaptureSlot,
            CompileErrorKind::AcceptUnreachable,
            CompileErrorKind::UnreachableState,
        ];
        let mut codes = kinds.map(CompileErrorKind::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));

        let error = CompileError::new(CompileErrorKind::InvalidTarget)
            .with_state(StateId::new(3))
            .with_span(ONE_SPAN);
        let display = error.to_string();
        assert!(display.starts_with("[RGX-IR-E020]"));
        assert!(!display.contains("secret-pattern"));
    }
