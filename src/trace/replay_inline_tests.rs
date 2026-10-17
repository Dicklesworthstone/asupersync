    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn metadata_creation() {
        let meta = TraceMetadata::new(42);
        assert_eq!(meta.version, REPLAY_SCHEMA_VERSION);
        assert_eq!(meta.seed, 42);
        assert_eq!(meta.recorded_at, 0);
        assert!(meta.is_compatible());
    }

    #[test]
    fn metadata_creation_is_deterministic_for_same_seed() {
        let first = TraceMetadata::new(42);
        let second = TraceMetadata::new(42);

        assert_eq!(first, second);
        assert_eq!(first.recorded_at, 0);
    }

    #[test]
    fn metadata_builder() {
        let meta = TraceMetadata::new(42)
            .with_config_hash(0xDEAD_BEEF)
            .with_description("test trace");
        assert_eq!(meta.config_hash, 0xDEAD_BEEF);
        assert_eq!(meta.description, Some("test trace".to_string()));
    }

    #[test]
    fn compact_task_id_roundtrip() {
        let task = TaskId::new_for_test(123, 456);
        let compact = CompactTaskId::from(task);
        let (index, generation) = compact.unpack();
        assert_eq!(index, 123);
        assert_eq!(generation, 456);
        assert_eq!(compact.to_task_id(), task);
    }

    #[test]
    fn replay_event_sizes() {
        // Verify events are compact
        let events = [
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(0),
                at_tick: 0,
            },
            ReplayEvent::TaskYielded {
                task: CompactTaskId(0),
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(0),
                outcome: 0,
            },
            ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 0,
            },
            ReplayEvent::TimerFired { timer_id: 0 },
            ReplayEvent::IoReady {
                token: 0,
                readiness: 0,
            },
            ReplayEvent::RngSeed { seed: 0 },
            ReplayEvent::WakerWake {
                task: CompactTaskId(0),
            },
        ];

        for event in &events {
            let size = event.estimated_size();
            assert!(size < 64, "Event {event:?} exceeds 64 bytes: {size} bytes");
        }
    }

    #[test]
    fn trace_serialization_roundtrip() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });
        trace.push(ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        });
        trace.push(ReplayEvent::TimeAdvanced {
            from_nanos: 0,
            to_nanos: 1_000_000,
        });
        trace.push(ReplayEvent::TaskCompleted {
            task: CompactTaskId(1),
            outcome: 0,
        });

        let bytes = trace.to_bytes().expect("serialize");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");

        assert_eq!(loaded.metadata.seed, 42);
        assert_eq!(loaded.events.len(), 4);
        assert_eq!(loaded.events[0], ReplayEvent::RngSeed { seed: 42 });
    }

    #[test]
    fn trace_actual_serialized_size() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));

        // Add typical events
        for i in 0..100 {
            trace.push(ReplayEvent::TaskScheduled {
                task: CompactTaskId(i),
                at_tick: i,
            });
        }

        let bytes = trace.to_bytes().expect("serialize");
        let avg_size = bytes.len() / 100;

        // Verify average event size is reasonable (should be well under 64 bytes)
        assert!(
            avg_size < 32,
            "Average serialized event size {avg_size} bytes exceeds expected"
        );
    }

    #[test]
    fn error_kind_roundtrip() {
        use io::ErrorKind::*;
        let kinds = [
            NotFound,
            PermissionDenied,
            ConnectionRefused,
            ConnectionReset,
            BrokenPipe,
            WouldBlock,
            TimedOut,
        ];

        for kind in kinds {
            let encoded = error_kind_to_u8(kind);
            let decoded = u8_to_error_kind(encoded);
            assert_eq!(kind, decoded, "Failed roundtrip for {kind:?}");
        }
    }

    #[test]
    fn version_compatibility_check() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });

        // Serialize
        let bytes = trace.to_bytes().expect("serialize");

        // Modify version in raw bytes would require manual byte manipulation
        // Just verify normal case works
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");
        assert!(loaded.metadata.is_compatible());
    }

    #[test]
    fn io_ready_flags() {
        let event = ReplayEvent::io_ready(123, true, false, false, false);
        if let ReplayEvent::IoReady { token, readiness } = event {
            assert_eq!(token, 123);
            assert_eq!(readiness & 1, 1); // readable
            assert_eq!(readiness & 2, 0); // not writable
        } else {
            panic!("Expected IoReady");
        }

        let event = ReplayEvent::io_ready(456, true, true, true, true);
        if let ReplayEvent::IoReady { readiness, .. } = event {
            assert_eq!(readiness, 0b1111); // all flags set
        } else {
            panic!("Expected IoReady");
        }
    }

    #[test]
    fn chaos_injection_variants() {
        let event_no_task = ReplayEvent::ChaosInjection {
            kind: 1, // delay
            task: None,
            data: 1_000_000, // 1ms in nanos
        };
        assert!(event_no_task.estimated_size() < 64);

        let event_with_task = ReplayEvent::ChaosInjection {
            kind: 0, // cancel
            task: Some(CompactTaskId(42)),
            data: 0,
        };
        assert!(event_with_task.estimated_size() < 64);
    }

    #[test]
    fn region_created_event() {
        let event = ReplayEvent::region_created(CompactRegionId(1), Some(CompactRegionId(0)), 100);

        if let ReplayEvent::RegionCreated {
            region,
            parent,
            at_tick,
        } = event
        {
            assert_eq!(region.0, 1);
            assert_eq!(parent.map(|p| p.0), Some(0));
            assert_eq!(at_tick, 100);
        } else {
            panic!("Expected RegionCreated");
        }

        // Test without parent (root region)
        let root = ReplayEvent::region_created(CompactRegionId(0), None::<CompactRegionId>, 0);
        if let ReplayEvent::RegionCreated { parent, .. } = root {
            assert!(parent.is_none());
        } else {
            panic!("Expected RegionCreated");
        }
    }

    #[test]
    fn region_closed_event() {
        let event = ReplayEvent::region_closed(CompactRegionId(5), Severity::Ok);

        if let ReplayEvent::RegionClosed { region, outcome } = event {
            assert_eq!(region.0, 5);
            assert_eq!(outcome, Severity::Ok.as_u8());
        } else {
            panic!("Expected RegionClosed");
        }
    }

    #[test]
    fn region_cancelled_event() {
        let event = ReplayEvent::region_cancelled(CompactRegionId(3), 1);

        if let ReplayEvent::RegionCancelled {
            region,
            cancel_kind,
        } = event
        {
            assert_eq!(region.0, 3);
            assert_eq!(cancel_kind, 1);
        } else {
            panic!("Expected RegionCancelled");
        }
    }

    #[test]
    fn checkpoint_event() {
        let event = ReplayEvent::checkpoint(42, 1_000_000_000, 5, 2);

        if let ReplayEvent::Checkpoint {
            sequence,
            time_nanos,
            active_tasks,
            active_regions,
        } = event
        {
            assert_eq!(sequence, 42);
            assert_eq!(time_nanos, 1_000_000_000);
            assert_eq!(active_tasks, 5);
            assert_eq!(active_regions, 2);
        } else {
            panic!("Expected Checkpoint");
        }
    }

    #[test]
    fn region_events_size() {
        // Verify all region events stay compact (< 64 bytes)
        let events = [
            ReplayEvent::RegionCreated {
                region: CompactRegionId(0),
                parent: None,
                at_tick: 0,
            },
            ReplayEvent::RegionCreated {
                region: CompactRegionId(0),
                parent: Some(CompactRegionId(1)),
                at_tick: 0,
            },
            ReplayEvent::RegionClosed {
                region: CompactRegionId(0),
                outcome: 0,
            },
            ReplayEvent::RegionCancelled {
                region: CompactRegionId(0),
                cancel_kind: 0,
            },
            ReplayEvent::Checkpoint {
                sequence: 0,
                time_nanos: 0,
                active_tasks: 0,
                active_regions: 0,
            },
        ];

        for event in &events {
            let size = event.estimated_size();
            assert!(size < 64, "Event {event:?} exceeds 64 bytes: {size} bytes");
        }
    }

    #[test]
    fn empty_trace_serialization_roundtrip() {
        let trace = ReplayTrace::new(TraceMetadata::new(0));
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);

        let bytes = trace.to_bytes().expect("serialize empty");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize empty");

        assert_eq!(loaded.metadata.seed, 0);
        assert!(loaded.is_empty());
    }

    #[test]
    fn incompatible_version_rejected() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 42 });

        let _bytes = trace.to_bytes().expect("serialize");

        // Manually tamper with the version in the serialized bytes
        // TraceMetadata is serialized via msgpack, version is the first field
        // Instead, create a trace with wrong version directly
        let meta = TraceMetadata {
            version: 999,
            seed: 42,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        };
        let bad_trace = ReplayTrace {
            metadata: meta,
            events: vec![ReplayEvent::RngSeed { seed: 42 }],
            cursor: 0,
        };
        let bad_bytes = bad_trace.to_bytes().expect("serialize bad version");
        let err = ReplayTrace::from_bytes(&bad_bytes).unwrap_err();
        assert!(matches!(
            err,
            ReplayTraceError::IncompatibleVersion {
                expected: REPLAY_SCHEMA_VERSION,
                found: 999
            }
        ));
    }

    #[test]
    fn trace_with_capacity_preallocates() {
        let trace = ReplayTrace::with_capacity(TraceMetadata::new(1), 100);
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);
    }

    #[test]
    fn estimated_size_increases_with_events() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        let base_size = trace.estimated_size();

        trace.push(ReplayEvent::RngSeed { seed: 42 });
        let one_event_size = trace.estimated_size();
        assert!(one_event_size > base_size);

        trace.push(ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 0,
        });
        let two_event_size = trace.estimated_size();
        assert!(two_event_size > one_event_size);
    }

    #[test]
    fn compact_region_id_roundtrip() {
        let region = RegionId::new_for_test(456, 789);
        let compact = CompactRegionId::from(region);
        let (index, generation) = compact.unpack();
        assert_eq!(index, 456);
        assert_eq!(generation, 789);
        assert_eq!(compact.to_region_id(), region);
    }

    #[test]
    fn metadata_compatibility_flag() {
        let meta = TraceMetadata::new(42);
        assert!(meta.is_compatible());

        let old_meta = TraceMetadata {
            version: 0,
            seed: 42,
            recorded_at: 0,
            config_hash: 0,
            description: None,
        };
        assert!(!old_meta.is_compatible());
    }

    #[test]
    fn io_error_roundtrip_all_known_kinds() {
        use io::ErrorKind::*;
        let all_known = [
            NotFound,
            PermissionDenied,
            ConnectionRefused,
            ConnectionReset,
            ConnectionAborted,
            NotConnected,
            AddrInUse,
            AddrNotAvailable,
            BrokenPipe,
            AlreadyExists,
            WouldBlock,
            InvalidInput,
            InvalidData,
            TimedOut,
            WriteZero,
            Interrupted,
            UnexpectedEof,
            OutOfMemory,
        ];

        for kind in all_known {
            let encoded = error_kind_to_u8(kind);
            let decoded = u8_to_error_kind(encoded);
            assert_eq!(kind, decoded, "Roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn unknown_error_kind_maps_to_other() {
        let decoded = u8_to_error_kind(255);
        assert_eq!(decoded, io::ErrorKind::Other);
        let decoded = u8_to_error_kind(200);
        assert_eq!(decoded, io::ErrorKind::Other);
    }

    #[test]
    fn trace_iter_yields_all_events() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        trace.push(ReplayEvent::RngSeed { seed: 1 });
        trace.push(ReplayEvent::RngSeed { seed: 2 });
        trace.push(ReplayEvent::RngSeed { seed: 3 });

        assert_eq!(trace.iter().count(), 3);
    }

    #[test]
    fn region_events_serialization_roundtrip() {
        let mut trace = ReplayTrace::new(TraceMetadata::new(123));

        // Add region lifecycle events
        trace.push(ReplayEvent::RegionCreated {
            region: CompactRegionId(0),
            parent: None,
            at_tick: 0,
        });
        trace.push(ReplayEvent::RegionCreated {
            region: CompactRegionId(1),
            parent: Some(CompactRegionId(0)),
            at_tick: 10,
        });
        trace.push(ReplayEvent::RegionCancelled {
            region: CompactRegionId(1),
            cancel_kind: 2,
        });
        trace.push(ReplayEvent::RegionClosed {
            region: CompactRegionId(1),
            outcome: 2, // Cancelled
        });
        trace.push(ReplayEvent::RegionClosed {
            region: CompactRegionId(0),
            outcome: 0, // Ok
        });
        trace.push(ReplayEvent::Checkpoint {
            sequence: 1,
            time_nanos: 1_000_000,
            active_tasks: 0,
            active_regions: 0,
        });

        let bytes = trace.to_bytes().expect("serialize");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");

        assert_eq!(loaded.events.len(), 6);

        // Verify first event (root region created)
        match &loaded.events[0] {
            ReplayEvent::RegionCreated {
                region,
                parent,
                at_tick,
            } => {
                assert_eq!(region.0, 0);
                assert!(parent.is_none());
                assert_eq!(*at_tick, 0);
            }
            _ => panic!("Expected RegionCreated"),
        }

        // Verify checkpoint event
        match &loaded.events[5] {
            ReplayEvent::Checkpoint {
                sequence,
                time_nanos,
                active_tasks,
                active_regions,
            } => {
                assert_eq!(*sequence, 1);
                assert_eq!(*time_nanos, 1_000_000);
                assert_eq!(*active_tasks, 0);
                assert_eq!(*active_regions, 0);
            }
            _ => panic!("Expected Checkpoint"),
        }
    }

    // --- wave 77 trait coverage ---

    #[test]
    fn trace_metadata_debug_clone_eq() {
        let m = TraceMetadata {
            version: REPLAY_SCHEMA_VERSION,
            seed: 42,
            recorded_at: 0,
            config_hash: 0xABC,
            description: Some("test".into()),
        };
        let m2 = m.clone();
        assert_eq!(m, m2);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("TraceMetadata"));
    }

    #[test]
    fn compact_task_id_debug_clone_copy_eq() {
        let id = CompactTaskId(42);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, CompactTaskId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"));
    }

    #[test]
    fn compact_region_id_debug_clone_copy_eq() {
        let id = CompactRegionId(7);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, CompactRegionId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains('7'));
    }

    #[test]
    fn replay_event_debug_clone_eq() {
        let e = ReplayEvent::TaskScheduled {
            task: CompactTaskId(1),
            at_tick: 100,
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
        assert_ne!(
            e,
            ReplayEvent::TaskYielded {
                task: CompactTaskId(1),
            }
        );
        let dbg = format!("{e:?}");
        assert!(dbg.contains("TaskScheduled"));
    }
