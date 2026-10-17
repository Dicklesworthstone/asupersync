    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::{CancelKind, CancelReason, PanicPayload, RegionId, Time};

    fn close_handle_for_release(table: &mut WasmHandleTable, handle: &WasmHandleRef) {
        match table.get(handle).unwrap().state {
            WasmBoundaryState::Unbound => {
                table.transition(handle, WasmBoundaryState::Bound).unwrap();
                table.transition(handle, WasmBoundaryState::Closed).unwrap();
            }
            WasmBoundaryState::Bound
            | WasmBoundaryState::Active
            | WasmBoundaryState::Cancelling
            | WasmBoundaryState::Draining => {
                table.transition(handle, WasmBoundaryState::Closed).unwrap();
            }
            WasmBoundaryState::Closed => {}
        }
    }

    fn register_example_fetch_authority(
        dispatcher: &mut WasmExportDispatcher,
        runtime: &WasmHandleRef,
    ) {
        dispatcher
            .register_runtime_fetch_authority(
                runtime,
                FetchAuthority::deny_all()
                    .grant_origin("https://example.com")
                    .grant_method(FetchMethod::Get),
            )
            .unwrap();
    }

    #[test]
    fn abi_compatibility_rules_enforced() {
        let exact = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 2 },
            WasmAbiVersion { major: 1, minor: 2 },
        );
        assert_eq!(exact, WasmAbiCompatibilityDecision::Exact);
        assert!(exact.is_compatible());

        let backward = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 2 },
            WasmAbiVersion { major: 1, minor: 5 },
        );
        assert!(matches!(
            backward,
            WasmAbiCompatibilityDecision::BackwardCompatible {
                producer_minor: 2,
                consumer_minor: 5
            }
        ));
        assert!(backward.is_compatible());

        let old_consumer = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 3 },
            WasmAbiVersion { major: 1, minor: 2 },
        );
        assert!(matches!(
            old_consumer,
            WasmAbiCompatibilityDecision::ConsumerTooOld {
                producer_minor: 3,
                consumer_minor: 2
            }
        ));
        assert!(!old_consumer.is_compatible());

        let major_mismatch = classify_wasm_abi_compatibility(
            WasmAbiVersion { major: 1, minor: 0 },
            WasmAbiVersion { major: 2, minor: 0 },
        );
        assert!(matches!(
            major_mismatch,
            WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2
            }
        ));
        assert!(!major_mismatch.is_compatible());
    }

    #[test]
    fn change_class_maps_to_required_version_bump() {
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::AdditiveField),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::AdditiveSymbol),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::BehavioralRelaxation),
            WasmAbiVersionBump::Minor
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::BehavioralTightening),
            WasmAbiVersionBump::Major
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::SymbolRemoval),
            WasmAbiVersionBump::Major
        );
        assert_eq!(
            required_wasm_abi_bump(WasmAbiChangeClass::ValueEncodingChange),
            WasmAbiVersionBump::Major
        );
    }

    #[test]
    fn signature_fingerprint_matches_expected_v1() {
        let fingerprint = wasm_abi_signature_fingerprint(&WASM_ABI_SIGNATURES_V1);
        assert_eq!(
            fingerprint, WASM_ABI_SIGNATURE_FINGERPRINT_V1,
            "ABI signature drift detected; update version policy and migration notes first"
        );
    }

    #[test]
    fn cancellation_payload_maps_core_reason_fields() {
        let reason = CancelReason::with_origin(
            CancelKind::Timeout,
            RegionId::new_for_test(3, 7),
            Time::from_nanos(42),
        )
        .with_task(crate::types::TaskId::new_for_test(4, 1))
        .with_message("deadline exceeded");

        let encoded = WasmAbiCancellation::from_reason(&reason, CancelPhase::Cancelling);

        assert_eq!(encoded.kind, "timeout");
        assert_eq!(encoded.phase, "cancelling");
        assert_eq!(encoded.timestamp_nanos, 42);
        assert_eq!(encoded.message.as_deref(), Some("deadline exceeded"));
        assert_eq!(encoded.origin_region, "R3");
        assert_eq!(encoded.origin_task.as_deref(), Some("T4"));
    }

    #[test]
    fn abort_signal_event_propagates_to_runtime_when_configured() {
        let snapshot = WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::AbortSignalToRuntime,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: false,
        };

        let update = apply_abort_signal_event(snapshot);
        assert_eq!(update.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(update.abort_signal_aborted);
        assert!(update.propagated_to_runtime);
        assert!(!update.propagated_to_abort_signal);

        let repeated = apply_abort_signal_event(WasmAbortInteropSnapshot {
            mode: snapshot.mode,
            boundary_state: update.next_boundary_state,
            abort_signal_aborted: update.abort_signal_aborted,
        });
        assert_eq!(repeated.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(repeated.abort_signal_aborted);
        assert!(!repeated.propagated_to_runtime);
        assert!(!repeated.propagated_to_abort_signal);
    }

    #[test]
    fn runtime_cancel_phase_event_maps_to_abort_signal_and_state() {
        let requested = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: WasmBoundaryState::Active,
                abort_signal_aborted: false,
            },
            CancelPhase::Requested,
        );
        assert_eq!(requested.next_boundary_state, WasmBoundaryState::Cancelling);
        assert!(requested.abort_signal_aborted);
        assert!(requested.propagated_to_abort_signal);
        assert!(!requested.propagated_to_runtime);

        let finalizing = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: requested.next_boundary_state,
                abort_signal_aborted: requested.abort_signal_aborted,
            },
            CancelPhase::Finalizing,
        );
        assert_eq!(finalizing.next_boundary_state, WasmBoundaryState::Draining);
        assert!(finalizing.abort_signal_aborted);
        assert!(!finalizing.propagated_to_abort_signal);

        let completed = apply_runtime_cancel_phase_event(
            WasmAbortInteropSnapshot {
                mode: WasmAbortPropagationMode::RuntimeToAbortSignal,
                boundary_state: finalizing.next_boundary_state,
                abort_signal_aborted: finalizing.abort_signal_aborted,
            },
            CancelPhase::Completed,
        );
        assert_eq!(completed.next_boundary_state, WasmBoundaryState::Closed);
        assert!(completed.abort_signal_aborted);
    }

    #[test]
    fn bidirectional_mode_keeps_already_aborted_signal_idempotent() {
        let update = apply_abort_signal_event(WasmAbortInteropSnapshot {
            mode: WasmAbortPropagationMode::Bidirectional,
            boundary_state: WasmBoundaryState::Active,
            abort_signal_aborted: true,
        });
        assert_eq!(update.next_boundary_state, WasmBoundaryState::Active);
        assert!(update.abort_signal_aborted);
        assert!(!update.propagated_to_runtime);
    }

    #[test]
    fn outcome_envelope_serialization_round_trip() {
        let handle = WasmHandleRef {
            kind: WasmHandleKind::Task,
            slot: 11,
            generation: 2,
            owner_token: 0,
        };
        let ok = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::Handle(handle),
        };
        let ok_json = serde_json::to_string(&ok).expect("serialize ok");
        let ok_back: WasmAbiOutcomeEnvelope =
            serde_json::from_str(&ok_json).expect("deserialize ok");
        assert_eq!(ok, ok_back);

        let err = WasmAbiOutcomeEnvelope::Err {
            failure: WasmAbiFailure {
                code: WasmAbiErrorCode::CapabilityDenied,
                recoverability: WasmAbiRecoverability::Permanent,
                message: "missing fetch capability".to_string(),
            },
        };
        let err_json = serde_json::to_string(&err).expect("serialize err");
        let err_back: WasmAbiOutcomeEnvelope =
            serde_json::from_str(&err_json).expect("deserialize err");
        assert_eq!(err, err_back);
    }

    #[test]
    fn from_outcome_maps_cancel_and_panic_variants() {
        let cancel_reason = CancelReason::with_origin(
            CancelKind::ParentCancelled,
            RegionId::new_for_test(9, 1),
            Time::from_nanos(9_000),
        );
        let cancelled = WasmAbiOutcomeEnvelope::from_outcome(Outcome::cancelled(cancel_reason));
        assert!(matches!(
            cancelled,
            WasmAbiOutcomeEnvelope::Cancelled {
                cancellation: WasmAbiCancellation {
                    kind,
                    phase,
                    ..
                }
            } if kind == "parentcancelled" && phase == "completed"
        ));

        let panicked = WasmAbiOutcomeEnvelope::from_outcome(Outcome::Panicked(PanicPayload::new(
            "boundary panic",
        )));
        assert_eq!(
            panicked,
            WasmAbiOutcomeEnvelope::Panicked {
                message: "boundary panic".to_string(),
            }
        );
    }

    #[test]
    fn boundary_transition_validator_accepts_and_rejects_expected_paths() {
        assert!(
            validate_wasm_boundary_transition(WasmBoundaryState::Unbound, WasmBoundaryState::Bound)
                .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(WasmBoundaryState::Bound, WasmBoundaryState::Active)
                .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Active,
                WasmBoundaryState::Cancelling
            )
            .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Cancelling,
                WasmBoundaryState::Draining
            )
            .is_ok()
        );
        assert!(
            validate_wasm_boundary_transition(
                WasmBoundaryState::Draining,
                WasmBoundaryState::Closed
            )
            .is_ok()
        );

        let invalid =
            validate_wasm_boundary_transition(WasmBoundaryState::Closed, WasmBoundaryState::Active);
        assert!(matches!(
            invalid,
            Err(WasmBoundaryTransitionError::Invalid {
                from: WasmBoundaryState::Closed,
                to: WasmBoundaryState::Active
            })
        ));
    }

    #[test]
    fn boundary_event_log_fields_include_contract_keys() {
        let event = WasmAbiBoundaryEvent {
            abi_version: WasmAbiVersion::CURRENT,
            symbol: WasmAbiSymbol::FetchRequest,
            payload_shape: WasmAbiPayloadShape::FetchRequestV1,
            state_from: WasmBoundaryState::Active,
            state_to: WasmBoundaryState::Cancelling,
            compatibility: WasmAbiCompatibilityDecision::Exact,
        };

        let fields = event.as_log_fields();
        assert_eq!(fields.get("abi_version"), Some(&"1.0".to_string()));
        assert_eq!(fields.get("symbol"), Some(&"fetch_request".to_string()));
        assert!(fields.contains_key("payload_shape"));
        assert!(fields.contains_key("state_from"));
        assert!(fields.contains_key("state_to"));
        assert!(fields.contains_key("compatibility"));
        assert_eq!(fields.get("compatibility"), Some(&"exact".to_string()));
        assert_eq!(
            fields.get("compatibility_decision"),
            Some(&"exact".to_string())
        );
        assert_eq!(
            fields.get("compatibility_compatible"),
            Some(&"true".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_minor"),
            Some(&"0".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_minor"),
            Some(&"0".to_string())
        );
        assert_eq!(
            fields.get("payload_shape"),
            Some(&"fetch_request_v1".to_string())
        );
        assert_eq!(fields.get("state_from"), Some(&"active".to_string()));
        assert_eq!(fields.get("state_to"), Some(&"cancelling".to_string()));
    }

    #[test]
    fn major_mismatch_log_fields_include_major_only_details() {
        let event = WasmAbiBoundaryEvent {
            abi_version: WasmAbiVersion::CURRENT,
            symbol: WasmAbiSymbol::RuntimeCreate,
            payload_shape: WasmAbiPayloadShape::Empty,
            state_from: WasmBoundaryState::Unbound,
            state_to: WasmBoundaryState::Bound,
            compatibility: WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2,
            },
        };

        let fields = event.as_log_fields();
        assert_eq!(
            fields.get("compatibility_decision"),
            Some(&"major_mismatch".to_string())
        );
        assert_eq!(
            fields.get("compatibility_compatible"),
            Some(&"false".to_string())
        );
        assert_eq!(
            fields.get("compatibility_producer_major"),
            Some(&"1".to_string())
        );
        assert_eq!(
            fields.get("compatibility_consumer_major"),
            Some(&"2".to_string())
        );
        assert!(!fields.contains_key("compatibility_producer_minor"));
        assert!(!fields.contains_key("compatibility_consumer_minor"));
    }

    // -----------------------------------------------------------------------
    // Memory Ownership Protocol Tests
    // -----------------------------------------------------------------------

    #[test]
    fn handle_table_allocate_and_get() {
        let mut table = WasmHandleTable::new();
        assert_eq!(table.live_count(), 0);

        let h1 = table.allocate(WasmHandleKind::Runtime);
        assert_eq!(h1.slot, 0);
        assert_eq!(h1.generation, 0);
        assert_eq!(h1.kind, WasmHandleKind::Runtime);
        assert_eq!(table.live_count(), 1);

        let entry = table.get(&h1).unwrap();
        assert_eq!(entry.state, WasmBoundaryState::Unbound);
        assert_eq!(entry.ownership, WasmHandleOwnership::WasmOwned);
        assert!(!entry.pinned);

        let h2 = table.allocate(WasmHandleKind::Task);
        assert_eq!(h2.slot, 1);
        assert_eq!(table.live_count(), 2);
    }

    #[test]
    fn handle_table_full_lifecycle() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Region);

        // Unbound -> Bound -> Active -> Cancelling -> Draining -> Closed
        table.transition(&h, WasmBoundaryState::Bound).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Bound);

        table.transition(&h, WasmBoundaryState::Active).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Active);

        table.transition(&h, WasmBoundaryState::Cancelling).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Cancelling);

        table.transition(&h, WasmBoundaryState::Draining).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Draining);

        table.transition(&h, WasmBoundaryState::Closed).unwrap();
        assert_eq!(table.get(&h).unwrap().state, WasmBoundaryState::Closed);

        // Release the closed handle
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn handle_table_slot_recycling_with_generation_bump() {
        let mut table = WasmHandleTable::new();
        let h1 = table.allocate(WasmHandleKind::Task);
        assert_eq!(h1.slot, 0);
        assert_eq!(h1.generation, 0);

        // Release h1
        close_handle_for_release(&mut table, &h1);
        table.release(&h1).unwrap();

        // Allocate again — should reuse slot 0 with bumped generation
        let h2 = table.allocate(WasmHandleKind::Region);
        assert_eq!(h2.slot, 0);
        assert_eq!(h2.generation, 1);

        // h1 is now stale
        let err = table.get(&h1).unwrap_err();
        assert!(matches!(
            err,
            WasmHandleError::StaleGeneration {
                slot: 0,
                expected: 1,
                actual: 0,
            }
        ));

        // h2 is valid
        assert!(table.get(&h2).is_ok());
    }

    #[test]
    fn handle_table_stale_handle_rejected() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::CancelToken);
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();

        // Try to use released handle
        let err = table.get(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
    }

    #[test]
    fn handle_table_out_of_range() {
        let table = WasmHandleTable::new();
        let out_of_range = WasmHandleRef {
            kind: WasmHandleKind::Runtime,
            slot: 999,
            generation: 0,
            owner_token: 0,
        };
        let err = table.get(&out_of_range).unwrap_err();
        assert!(matches!(
            err,
            WasmHandleError::SlotOutOfRange {
                slot: 999,
                table_size: 0,
            }
        ));
    }

    #[test]
    fn handle_table_pin_unpin() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);

        // Pin
        table.pin(&h).unwrap();
        assert!(table.get(&h).unwrap().pinned);

        // Pinning again is idempotent
        table.pin(&h).unwrap();
        assert!(table.get(&h).unwrap().pinned);

        // Cannot release while pinned
        let err = table.release(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::ReleasePinned { slot: 0 }));

        // Unpin
        table.unpin(&h).unwrap();
        assert!(!table.get(&h).unwrap().pinned);

        // Can release after unpin
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn handle_table_unpin_not_pinned_is_error() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Runtime);

        let err = table.unpin(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::NotPinned { slot: 0 }));
    }

    #[test]
    fn handle_table_transfer_to_js() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::FetchRequest);

        table.transfer_to_js(&h).unwrap();
        assert_eq!(
            table.get(&h).unwrap().ownership,
            WasmHandleOwnership::TransferredToJs
        );

        // Cannot transfer again
        let err = table.transfer_to_js(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::InvalidTransfer { .. }));
    }

    #[test]
    fn handle_table_detect_leaks() {
        let mut table = WasmHandleTable::new();
        let h1 = table.allocate(WasmHandleKind::Task);
        let h2 = table.allocate(WasmHandleKind::Region);
        let h3 = table.allocate(WasmHandleKind::Runtime);

        // h1: close but don't release (leaked)
        table.transition(&h1, WasmBoundaryState::Bound).unwrap();
        table.transition(&h1, WasmBoundaryState::Closed).unwrap();

        // h2: still active (not leaked yet)
        table.transition(&h2, WasmBoundaryState::Bound).unwrap();
        table.transition(&h2, WasmBoundaryState::Active).unwrap();

        // h3: properly released
        close_handle_for_release(&mut table, &h3);
        table.release(&h3).unwrap();

        let leaks = table.detect_leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0], h1);
    }

    #[test]
    fn handle_table_memory_report() {
        let mut table = WasmHandleTable::with_capacity(8);
        let h1 = table.allocate(WasmHandleKind::Runtime);
        let h2 = table.allocate(WasmHandleKind::Task);
        let _h3 = table.allocate(WasmHandleKind::Task);

        table.transition(&h1, WasmBoundaryState::Bound).unwrap();
        table.transition(&h1, WasmBoundaryState::Active).unwrap();
        table.pin(&h2).unwrap();

        let report = table.memory_report();
        assert_eq!(report.live_handles, 3);
        assert_eq!(report.pinned_count, 1);
        assert_eq!(report.by_kind.get("task"), Some(&2));
        assert_eq!(report.by_kind.get("runtime"), Some(&1));

        // _h3 is still unbound
        assert_eq!(report.by_state.get("unbound"), Some(&2));
        assert_eq!(report.by_state.get("active"), Some(&1));
    }

    #[test]
    fn handle_table_release_already_released() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);
        close_handle_for_release(&mut table, &h);
        table.release(&h).unwrap();

        // Stale generation
        let err = table.release(&h).unwrap_err();
        assert!(matches!(err, WasmHandleError::StaleGeneration { .. }));
    }

    #[test]
    fn handle_table_release_requires_closed_and_quiescent_state() {
        let mut table = WasmHandleTable::new();
        let root = table.allocate(WasmHandleKind::Runtime);
        let child = table.allocate_with_parent(WasmHandleKind::Task, Some(root));

        let err = table.release(&root).unwrap_err();
        assert_eq!(
            err,
            WasmHandleError::ReleaseBeforeClosed {
                slot: root.slot,
                state: WasmBoundaryState::Unbound,
            }
        );
        assert_eq!(table.live_count(), 2);

        close_handle_for_release(&mut table, &root);
        let err = table.release(&root).unwrap_err();
        assert_eq!(
            err,
            WasmHandleError::ReleaseWithLiveDescendants {
                slot: root.slot,
                live_descendants: 1,
            }
        );
        assert_eq!(table.live_count(), 2);

        close_handle_for_release(&mut table, &child);
        table.release(&child).unwrap();
        table.release(&root).unwrap();
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn handle_table_descendants_postorder_rejects_parent_cycles() {
        let mut table = WasmHandleTable::new();
        let root = table.allocate(WasmHandleKind::Runtime);
        let child = table.allocate_with_parent(WasmHandleKind::Region, Some(root));

        table.get_mut(&root).unwrap().parent = Some(child);

        let err = table.descendants_postorder(&root).unwrap_err();
        assert_eq!(
            err,
            WasmHandleError::OwnershipCycle {
                slot: root.slot,
                parent_slot: child.slot,
            }
        );
    }

    #[test]
    fn buffer_transfer_mode_copy_is_default() {
        assert!(WasmBufferTransferMode::Copy.is_copy());
        assert!(!WasmBufferTransferMode::Transfer.is_copy());
    }

    #[test]
    fn buffer_transfer_serialization_round_trip() {
        let transfer = WasmBufferTransfer {
            source_handle: WasmHandleRef {
                kind: WasmHandleKind::FetchRequest,
                slot: 5,
                generation: 2,
                owner_token: 0,
            },
            byte_length: 1024,
            mode: WasmBufferTransferMode::Transfer,
        };
        let json = serde_json::to_string(&transfer).unwrap();
        let back: WasmBufferTransfer = serde_json::from_str(&json).unwrap();
        assert_eq!(transfer, back);
    }

    #[test]
    fn handle_ownership_serialization_round_trip() {
        for ownership in [
            WasmHandleOwnership::WasmOwned,
            WasmHandleOwnership::TransferredToJs,
            WasmHandleOwnership::Released,
        ] {
            let json = serde_json::to_string(&ownership).unwrap();
            let back: WasmHandleOwnership = serde_json::from_str(&json).unwrap();
            assert_eq!(ownership, back);
        }
    }

    #[test]
    fn handle_lifecycle_event_captures_transitions() {
        let event = WasmHandleLifecycleEvent {
            handle: WasmHandleRef {
                kind: WasmHandleKind::Task,
                slot: 3,
                generation: 0,
                owner_token: 0,
            },
            event: WasmHandleEventKind::StateTransition,
            ownership_before: WasmHandleOwnership::WasmOwned,
            ownership_after: WasmHandleOwnership::WasmOwned,
            state_before: WasmBoundaryState::Active,
            state_after: WasmBoundaryState::Cancelling,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: WasmHandleLifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn handle_table_cancellation_and_release_flow() {
        // Simulates a typical task lifecycle: create → activate → cancel → drain → close → release
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);

        table.transition(&h, WasmBoundaryState::Bound).unwrap();
        table.transition(&h, WasmBoundaryState::Active).unwrap();

        // Pin during active work
        table.pin(&h).unwrap();

        // Cancel arrives
        table.transition(&h, WasmBoundaryState::Cancelling).unwrap();
        table.transition(&h, WasmBoundaryState::Draining).unwrap();
        table.transition(&h, WasmBoundaryState::Closed).unwrap();

        // Still pinned — cannot release
        assert!(table.release(&h).is_err());

        // Unpin and release
        table.unpin(&h).unwrap();
        table.release(&h).unwrap();
        assert_eq!(table.live_count(), 0);
        assert!(table.detect_leaks().is_empty());
    }

    #[test]
    fn handle_table_with_capacity_preallocates() {
        let table = WasmHandleTable::with_capacity(16);
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.capacity(), 0); // No actual slots until allocated
    }

    // -----------------------------------------------------------------------
    // Export Dispatcher Conformance Tests
    // -----------------------------------------------------------------------

    #[test]
    fn dispatcher_runtime_create_and_close_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        assert_eq!(d.dispatch_count(), 0);

        let rt = d.runtime_create(None).unwrap();
        assert_eq!(rt.kind, WasmHandleKind::Runtime);
        assert_eq!(d.dispatch_count(), 1);
        assert_eq!(d.handles().live_count(), 1);

        let outcome = d.runtime_close(&rt, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.dispatch_count(), 2);
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_scope_enter_and_close() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("test-scope".to_string()),
                },
                None,
            )
            .unwrap();
        assert_eq!(scope.kind, WasmHandleKind::Region);
        assert_eq!(d.handles().live_count(), 2);

        let outcome = d.scope_close(&scope, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.handles().live_count(), 1); // runtime still alive

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_runtime_close_releases_descendants() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        register_example_fetch_authority(&mut d, &rt);
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("runtime-close".to_string()),
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("worker".to_string()),
                    cancel_kind: Some("user".to_string()),
                },
                None,
            )
            .unwrap();
        let fetch = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://example.com/data".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap();

        let outcome = d.runtime_close(&rt, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert_eq!(d.handles().live_count(), 0);
        assert!(d.handles().get(&scope).is_err());
        assert!(d.handles().get(&task).is_err());
        assert!(d.handles().get(&fetch).is_err());
        assert!(d.handles().detect_leaks().is_empty());
    }

    #[test]
    fn dispatcher_scope_close_releases_nested_descendants() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let outer = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("outer".to_string()),
                },
                None,
            )
            .unwrap();
        let inner = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: outer,
                    label: Some("inner".to_string()),
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: inner,
                    label: Some("nested".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let outcome = d.scope_close(&outer, None).unwrap();
        assert!(matches!(outcome, WasmAbiOutcomeEnvelope::Ok { .. }));
        assert!(d.handles().get(&inner).is_err());
        assert!(d.handles().get(&task).is_err());
        assert_eq!(d.handles().live_count(), 1);

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_scope_close_rejects_ownership_cycles_in_handle_graph() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let outer = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("outer".to_string()),
                },
                None,
            )
            .unwrap();
        let inner = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: outer,
                    label: Some("inner".to_string()),
                },
                None,
            )
            .unwrap();

        d.handles_mut().get_mut(&outer).unwrap().parent = Some(inner);

        let err = d.scope_close(&outer, None).unwrap_err();
        assert_eq!(
            err,
            WasmDispatchError::Handle(WasmHandleError::OwnershipCycle {
                slot: outer.slot,
                parent_slot: inner.slot,
            })
        );
        assert_eq!(d.handles().live_count(), 3);
    }

    #[test]
    fn dispatcher_task_spawn_join_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("worker".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(task.kind, WasmHandleKind::Task);
        assert!(d.handles().get(&task).unwrap().pinned); // tasks are auto-pinned

        let result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
                None,
            )
            .unwrap();
        assert!(matches!(
            result,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::I64(42)
            }
        ));

        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_task_cancel_flow() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Cancel the active task
        let cancel_result = d
            .task_cancel(
                &WasmTaskCancelRequest {
                    task,
                    kind: "user".to_string(),
                    message: Some("user requested".to_string()),
                },
                None,
            )
            .unwrap();
        assert!(matches!(cancel_result, WasmAbiOutcomeEnvelope::Ok { .. }));

        // Task is now Cancelling
        assert_eq!(
            d.handles().get(&task).unwrap().state,
            WasmBoundaryState::Cancelling
        );

        // Join with cancelled outcome
        let join_result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Cancelled {
                    cancellation: WasmAbiCancellation {
                        kind: "user".to_string(),
                        phase: "completed".to_string(),
                        origin_region: "R0".to_string(),
                        origin_task: None,
                        timestamp_nanos: 0,
                        message: Some("user requested".to_string()),
                        truncated: false,
                    },
                },
                None,
            )
            .unwrap();
        assert!(matches!(
            join_result,
            WasmAbiOutcomeEnvelope::Cancelled { .. }
        ));
        assert_eq!(d.handles().live_count(), 1); // only runtime left

        d.runtime_close(&rt, None).unwrap();
    }

    #[test]
    fn dispatcher_abi_incompatible_rejected() {
        let mut d = WasmExportDispatcher::new();
        let bad_version = WasmAbiVersion {
            major: 99,
            minor: 0,
        };

        let err = d.runtime_create(Some(bad_version)).unwrap_err();
        assert!(matches!(err, WasmDispatchError::Incompatible { .. }));

        // Error converts to proper failure envelope
        let failure = err.to_failure();
        assert_eq!(failure.code, WasmAbiErrorCode::CompatibilityRejected);
        assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
    }

    #[test]
    fn dispatcher_stale_handle_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        // Try to close again — handle is stale
        let err = d.runtime_close(&rt, None).unwrap_err();
        assert!(matches!(err, WasmDispatchError::Handle(_)));
    }

    #[test]
    fn dispatcher_scope_enter_requires_active_parent() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        // Try to enter scope on closed runtime — stale handle
        let err = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::Handle(_)));
    }

    #[test]
    fn dispatcher_task_spawn_wrong_handle_kind_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        // Spawn a task
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Try to spawn under a Task handle (not Region/Runtime)
        let err = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: task,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_scope_enter_wrong_parent_kind_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: Some("worker".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let err = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: task,
                    label: Some("illegal-child".to_string()),
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_fetch_request_wrong_scope_kind_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: Some("worker".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let err = d
            .fetch_request(
                &WasmFetchRequest {
                    scope: task,
                    url: "https://example.com/data".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_cancel_non_active_task_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Cancel once (should succeed)
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "user".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();

        // Cancel again — task is now Cancelling, not Active
        let err = d
            .task_cancel(
                &WasmTaskCancelRequest {
                    task,
                    kind: "user".to_string(),
                    message: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidState { .. }));
    }

    #[test]
    fn dispatcher_fetch_request_and_complete() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        register_example_fetch_authority(&mut d, &rt);
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();

        let fetch = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://example.com/api".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(fetch.kind, WasmHandleKind::FetchRequest);
        assert!(d.handles().get(&fetch).unwrap().pinned);

        let result = d
            .fetch_complete(
                &fetch,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::String("response body".to_string()),
                },
            )
            .unwrap();
        assert!(matches!(result, WasmAbiOutcomeEnvelope::Ok { .. }));
        // Fetch handle released after completion
        assert!(d.handles().get(&fetch).is_err());
    }

    #[test]
    fn dispatcher_fetch_defaults_to_deny_without_allocating_a_handle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("default-deny".to_string()),
                },
                None,
            )
            .unwrap();
        let live_before = d.handles().live_count();

        let err = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://example.com/denied".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap_err();

        assert!(matches!(err, WasmDispatchError::CapabilityDenied { .. }));
        assert_eq!(err.to_failure().code, WasmAbiErrorCode::CapabilityDenied);
        assert_eq!(d.handles().live_count(), live_before);
    }

    #[test]
    fn dispatcher_fetch_authority_is_one_shot_and_inherited_by_regions() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let authority = FetchAuthority::deny_all()
            .grant_origin("https://api.example.com")
            .grant_method(FetchMethod::Get);
        d.register_runtime_fetch_authority(&rt, authority.clone())
            .unwrap();
        let duplicate = d
            .register_runtime_fetch_authority(&rt, authority)
            .unwrap_err();
        assert!(matches!(
            duplicate,
            WasmDispatchError::InvalidRequest { .. }
        ));

        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("inherits-fetch-authority".to_string()),
                },
                None,
            )
            .unwrap();
        let live_before = d.handles().live_count();

        let denied = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://evil.example/collect".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(denied, WasmDispatchError::CapabilityDenied { .. }));
        assert_eq!(d.handles().live_count(), live_before);

        let allowed = d
            .fetch_request(
                &WasmFetchRequest {
                    scope,
                    url: "https://api.example.com/data".to_string(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(allowed.kind, WasmHandleKind::FetchRequest);
        assert_eq!(d.handles().live_count(), live_before + 1);
    }

    #[test]
    fn dispatcher_fetch_credentials_require_an_explicit_grant() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        register_example_fetch_authority(&mut d, &rt);

        let err = d
            .fetch_request(
                &WasmFetchRequest {
                    scope: rt,
                    url: "https://example.com/private".to_string(),
                    method: "GET".to_string(),
                    credentials: true,
                    body: None,
                },
                None,
            )
            .unwrap_err();

        assert!(matches!(err, WasmDispatchError::CapabilityDenied { .. }));
        assert!(err.to_string().contains("credentialed fetch denied"));
    }

    #[test]
    fn dispatcher_fetch_empty_url_rejected() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let err = d
            .fetch_request(
                &WasmFetchRequest {
                    scope: rt,
                    url: String::new(),
                    method: "GET".to_string(),
                    credentials: false,
                    body: None,
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::InvalidRequest { .. }));
    }

    #[test]
    fn dispatcher_event_log_records_all_symbol_calls() {
        let mut d = WasmExportDispatcher::new();

        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: None,
                },
                None,
            )
            .unwrap();
        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "timeout".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();

        let events = d.event_log().events();
        assert_eq!(events.len(), 7);
        assert_eq!(events[0].symbol, WasmAbiSymbol::RuntimeCreate);
        assert_eq!(events[1].symbol, WasmAbiSymbol::ScopeEnter);
        assert_eq!(events[2].symbol, WasmAbiSymbol::TaskSpawn);
        assert_eq!(events[3].symbol, WasmAbiSymbol::TaskCancel);
        assert_eq!(events[4].symbol, WasmAbiSymbol::TaskJoin);
        assert_eq!(events[5].symbol, WasmAbiSymbol::ScopeClose);
        assert_eq!(events[6].symbol, WasmAbiSymbol::RuntimeClose);
    }

    #[test]
    fn dispatcher_event_log_drain_clears() {
        let mut d = WasmExportDispatcher::new();
        d.runtime_create(None).unwrap();

        assert_eq!(d.event_log().len(), 1);
        let drained = d.event_log_mut().drain();
        assert_eq!(drained.len(), 1);
        assert!(d.event_log().is_empty());
    }

    #[test]
    fn dispatcher_dispatch_count_increments_on_errors() {
        let mut d = WasmExportDispatcher::new();

        // Failing call still increments dispatch count
        let _ = d.runtime_create(Some(WasmAbiVersion {
            major: 99,
            minor: 0,
        }));
        assert_eq!(d.dispatch_count(), 1);
    }

    #[test]
    fn dispatcher_abort_signal_propagation() {
        let mut d =
            WasmExportDispatcher::new().with_abort_mode(WasmAbortPropagationMode::Bidirectional);
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        // Apply abort signal
        let update = d.apply_abort(&task).unwrap();
        assert!(update.propagated_to_runtime);
        assert_eq!(
            d.handles().get(&task).unwrap().state,
            WasmBoundaryState::Cancelling
        );
    }

    #[test]
    fn dispatcher_full_multi_task_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let scope = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("multi-task".to_string()),
                },
                None,
            )
            .unwrap();

        // Spawn multiple tasks
        let t1 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t1".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        let t2 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t2".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();
        let t3 = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope,
                    label: Some("t3".to_string()),
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        assert_eq!(d.handles().live_count(), 5); // rt + scope + 3 tasks

        // Complete t1, cancel t2, join t3
        d.task_join(
            &t1,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::I64(1),
            },
            None,
        )
        .unwrap();
        d.task_cancel(
            &WasmTaskCancelRequest {
                task: t2,
                kind: "race_lost".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &t2,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.task_join(
            &t3,
            WasmAbiOutcomeEnvelope::Err {
                failure: WasmAbiFailure {
                    code: WasmAbiErrorCode::InternalFailure,
                    recoverability: WasmAbiRecoverability::Transient,
                    message: "transient failure".to_string(),
                },
            },
            None,
        )
        .unwrap();

        assert_eq!(d.handles().live_count(), 2); // rt + scope

        d.scope_close(&scope, None).unwrap();
        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
        assert!(d.handles().detect_leaks().is_empty());
    }

    #[test]
    fn dispatcher_high_frequency_invocation_stress() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        // Rapid-fire 100 task spawn/join cycles
        for i in 0u64..100 {
            let task = d
                .task_spawn(
                    &WasmTaskSpawnRequest {
                        scope: rt,
                        label: Some(format!("task-{i}")),
                        cancel_kind: None,
                    },
                    None,
                )
                .unwrap();
            d.task_join(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::U64(i),
                },
                None,
            )
            .unwrap();
        }

        assert_eq!(d.dispatch_count(), 201); // 1 create + 100 spawns + 100 joins
        assert_eq!(d.handles().live_count(), 1); // only runtime
        assert!(d.handles().detect_leaks().is_empty());

        // Verify slot recycling worked — capacity should be much less than 100
        let report = d.handles().memory_report();
        assert!(report.capacity <= 100);

        d.runtime_close(&rt, None).unwrap();
    }

    #[test]
    fn dispatcher_error_to_outcome_envelope_conversion() {
        let errors = [
            WasmDispatchError::Incompatible {
                decision: WasmAbiCompatibilityDecision::MajorMismatch {
                    producer_major: 1,
                    consumer_major: 2,
                },
            },
            WasmDispatchError::Handle(WasmHandleError::SlotOutOfRange {
                slot: 5,
                table_size: 3,
            }),
            WasmDispatchError::InvalidState {
                state: WasmBoundaryState::Closed,
                symbol: WasmAbiSymbol::TaskSpawn,
            },
            WasmDispatchError::InvalidRequest {
                reason: "bad payload".to_string(),
            },
        ];

        let expected_codes = [
            WasmAbiErrorCode::CompatibilityRejected,
            WasmAbiErrorCode::InvalidHandle,
            WasmAbiErrorCode::InvalidHandle,
            WasmAbiErrorCode::DecodeFailure,
        ];

        for (err, expected_code) in errors.iter().zip(expected_codes.iter()) {
            let outcome = err.to_outcome();
            match outcome {
                WasmAbiOutcomeEnvelope::Err { failure } => {
                    assert_eq!(failure.code, *expected_code);
                    assert_eq!(failure.recoverability, WasmAbiRecoverability::Permanent);
                    assert!(!failure.message.is_empty());
                }
                _ => panic!("expected Err outcome"),
            }
        }
    }

    #[test]
    fn dispatcher_backward_compatible_version_accepted() {
        let mut d = WasmExportDispatcher::new();
        // Consumer with higher minor version (backward compatible)
        let compat_version = WasmAbiVersion {
            major: WASM_ABI_MAJOR_VERSION,
            minor: WASM_ABI_MINOR_VERSION + 5,
        };

        let rt = d.runtime_create(Some(compat_version)).unwrap();
        assert_eq!(rt.kind, WasmHandleKind::Runtime);

        // Check that the event recorded the compatibility decision
        let event = &d.event_log().events()[0];
        assert!(matches!(
            event.compatibility,
            WasmAbiCompatibilityDecision::BackwardCompatible { .. }
        ));
    }

    #[test]
    fn dispatcher_request_payload_serialization_round_trip() {
        let scope_req = WasmScopeEnterRequest {
            parent: WasmHandleRef {
                kind: WasmHandleKind::Runtime,
                slot: 0,
                generation: 0,
                owner_token: 0,
            },
            label: Some("test".to_string()),
        };
        let json = serde_json::to_string(&scope_req).unwrap();
        let back: WasmScopeEnterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(scope_req, back);

        let spawn_req = WasmTaskSpawnRequest {
            scope: WasmHandleRef {
                kind: WasmHandleKind::Region,
                slot: 1,
                generation: 0,
                owner_token: 0,
            },
            label: Some("worker".to_string()),
            cancel_kind: Some("timeout".to_string()),
        };
        let json = serde_json::to_string(&spawn_req).unwrap();
        let back: WasmTaskSpawnRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(spawn_req, back);

        let cancel_req = WasmTaskCancelRequest {
            task: WasmHandleRef {
                kind: WasmHandleKind::Task,
                slot: 2,
                generation: 0,
                owner_token: 0,
            },
            kind: "user".to_string(),
            message: Some("cancelled by operator".to_string()),
        };
        let json = serde_json::to_string(&cancel_req).unwrap();
        let back: WasmTaskCancelRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(cancel_req, back);

        let fetch_req = WasmFetchRequest {
            scope: WasmHandleRef {
                kind: WasmHandleKind::Region,
                slot: 1,
                generation: 0,
                owner_token: 0,
            },
            url: "https://example.com".to_string(),
            method: "POST".to_string(),
            credentials: false,
            body: Some(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&fetch_req).unwrap();
        let back: WasmFetchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(fetch_req, back);
    }

    #[test]
    fn dispatcher_nested_scopes_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let s1 = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: rt,
                    label: Some("outer".to_string()),
                },
                None,
            )
            .unwrap();
        let s2 = d
            .scope_enter(
                &WasmScopeEnterRequest {
                    parent: s1,
                    label: Some("inner".to_string()),
                },
                None,
            )
            .unwrap();

        assert_eq!(d.handles().live_count(), 3); // rt + s1 + s2

        // Close inner first, then outer (structured concurrency order)
        d.scope_close(&s2, None).unwrap();
        assert_eq!(d.handles().live_count(), 2);

        d.scope_close(&s1, None).unwrap();
        assert_eq!(d.handles().live_count(), 1);

        d.runtime_close(&rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn dispatcher_panicked_outcome_passes_through() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();

        let task = d
            .task_spawn(
                &WasmTaskSpawnRequest {
                    scope: rt,
                    label: None,
                    cancel_kind: None,
                },
                None,
            )
            .unwrap();

        let result = d
            .task_join(
                &task,
                WasmAbiOutcomeEnvelope::Panicked {
                    message: "boundary panic in task".to_string(),
                },
                None,
            )
            .unwrap();
        assert_eq!(
            result,
            WasmAbiOutcomeEnvelope::Panicked {
                message: "boundary panic in task".to_string(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Ergonomic API Facade Tests
    // -----------------------------------------------------------------------

    #[test]
    fn scope_enter_builder_produces_correct_request() {
        let parent = WasmHandleRef {
            kind: WasmHandleKind::Runtime,
            slot: 0,
            generation: 0,
            owner_token: 0,
        };

        // With label
        let req = WasmScopeEnterBuilder::new(parent).label("test").build();
        assert_eq!(req.parent, parent);
        assert_eq!(req.label, Some("test".to_string()));

        // Without label
        let req = WasmScopeEnterBuilder::new(parent).build();
        assert_eq!(req.label, None);
    }

    #[test]
    fn task_spawn_builder_produces_correct_request() {
        let scope = WasmHandleRef {
            kind: WasmHandleKind::Region,
            slot: 1,
            generation: 0,
            owner_token: 0,
        };

        let req = WasmTaskSpawnBuilder::new(scope)
            .label("worker")
            .cancel_kind("timeout")
            .build();
        assert_eq!(req.scope, scope);
        assert_eq!(req.label, Some("worker".to_string()));
        assert_eq!(req.cancel_kind, Some("timeout".to_string()));
    }

    #[test]
    fn fetch_builder_defaults_to_get() {
        let scope = WasmHandleRef {
            kind: WasmHandleKind::Region,
            slot: 1,
            generation: 0,
            owner_token: 0,
        };

        let req = WasmFetchBuilder::new(scope, "https://example.com").build();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://example.com");
        assert!(req.body.is_none());

        let req = WasmFetchBuilder::new(scope, "https://example.com")
            .method("POST")
            .body(vec![1, 2, 3])
            .build();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, Some(vec![1, 2, 3]));
    }

    #[test]
    fn outcome_ext_trait_inspectors() {
        let ok = WasmAbiOutcomeEnvelope::Ok {
            value: WasmAbiValue::I64(42),
        };
        assert!(ok.is_ok());
        assert!(!ok.is_err());
        assert!(!ok.is_cancelled());
        assert!(!ok.is_panicked());
        assert_eq!(ok.ok_value(), Some(&WasmAbiValue::I64(42)));
        assert!(ok.err_failure().is_none());
        assert_eq!(ok.outcome_kind(), "ok");

        let err = WasmAbiOutcomeEnvelope::Err {
            failure: WasmAbiFailure {
                code: WasmAbiErrorCode::InternalFailure,
                recoverability: WasmAbiRecoverability::Transient,
                message: "boom".to_string(),
            },
        };
        assert!(err.is_err());
        assert!(!err.is_ok());
        assert_eq!(
            err.err_failure().unwrap().code,
            WasmAbiErrorCode::InternalFailure
        );
        assert_eq!(err.outcome_kind(), "err");

        let cancelled = WasmAbiOutcomeEnvelope::Cancelled {
            cancellation: WasmAbiCancellation {
                kind: "user".to_string(),
                phase: "completed".to_string(),
                origin_region: "R0".to_string(),
                origin_task: None,
                timestamp_nanos: 0,
                message: None,
                truncated: false,
            },
        };
        assert!(cancelled.is_cancelled());
        assert!(cancelled.cancellation().is_some());
        assert_eq!(cancelled.outcome_kind(), "cancelled");

        let panicked = WasmAbiOutcomeEnvelope::Panicked {
            message: "oom".to_string(),
        };
        assert!(panicked.is_panicked());
        assert_eq!(panicked.outcome_kind(), "panicked");
    }

    #[test]
    fn create_scoped_runtime_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("test"), None).unwrap();

        assert_eq!(rt.kind, WasmHandleKind::Runtime);
        assert_eq!(scope.kind, WasmHandleKind::Region);
        assert_eq!(d.handles().live_count(), 2);

        d.close_scoped_runtime(&scope, &rt, None).unwrap();
        assert_eq!(d.handles().live_count(), 0);
    }

    #[test]
    fn spawn_with_builder_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(None, None).unwrap();

        let task = d
            .spawn(WasmTaskSpawnBuilder::new(scope).label("worker"), None)
            .unwrap();
        assert_eq!(task.kind, WasmHandleKind::Task);

        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.close_scoped_runtime(&scope, &rt, None).unwrap();
    }

    #[test]
    fn spawn_and_join_convenience() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(None, None).unwrap();

        let result = d
            .spawn_and_join(
                scope,
                Some("inline-task"),
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::String("done".to_string()),
                },
                None,
            )
            .unwrap();
        assert!(result.is_ok());
        assert_eq!(
            result.ok_value(),
            Some(&WasmAbiValue::String("done".to_string()))
        );

        d.close_scoped_runtime(&scope, &rt, None).unwrap();
    }

    #[test]
    fn diagnostic_snapshot_clean_after_full_lifecycle() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("diag-test"), None).unwrap();

        let task = d
            .spawn(WasmTaskSpawnBuilder::new(scope).label("t1"), None)
            .unwrap();
        d.task_join(
            &task,
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::Unit,
            },
            None,
        )
        .unwrap();
        d.close_scoped_runtime(&scope, &rt, None).unwrap();

        let diag = d.diagnostic_snapshot();
        assert!(diag.is_clean());
        assert!(diag.leaks.is_empty());
        assert_eq!(diag.memory_report.live_handles, 0);
        assert!(diag.dispatch_count > 0);
    }

    #[test]
    fn diagnostic_snapshot_detects_leaks() {
        let mut d = WasmExportDispatcher::new();
        let rt = d.runtime_create(None).unwrap();
        let task = d
            .task_spawn(&WasmTaskSpawnBuilder::new(rt).label("leaked").build(), None)
            .unwrap();

        // Cancel and close but don't join (handle transitions to Closed via
        // dispatcher internals when we force-close)
        d.task_cancel(
            &WasmTaskCancelRequest {
                task,
                kind: "user".to_string(),
                message: None,
            },
            None,
        )
        .unwrap();

        // Task is still live (Cancelling, pinned) — not leaked yet
        let diag = d.diagnostic_snapshot();
        assert!(!diag.is_clean());
        assert_eq!(diag.memory_report.live_handles, 2); // rt + task
    }

    #[test]
    fn diagnostic_log_fields_include_expected_keys() {
        let mut d = WasmExportDispatcher::new();
        d.runtime_create(None).unwrap();

        let diag = d.diagnostic_snapshot();
        let fields = diag.as_log_fields();

        assert!(fields.contains_key("dispatch_count"));
        assert!(fields.contains_key("live_handles"));
        assert!(fields.contains_key("pinned_count"));
        assert!(fields.contains_key("event_count"));
        assert!(fields.contains_key("leak_count"));
        assert!(fields.contains_key("abi_version"));
        assert!(fields.contains_key("clean"));
        assert_eq!(fields.get("abi_version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn ergonomic_api_full_lifecycle_with_mixed_outcomes() {
        let mut d = WasmExportDispatcher::new();
        let (rt, scope) = d.create_scoped_runtime(Some("mixed"), None).unwrap();

        // Spawn-and-join with Ok
        let r1 = d
            .spawn_and_join(
                scope,
                Some("ok-task"),
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(1),
                },
                None,
            )
            .unwrap();
        assert!(r1.is_ok());

        // Spawn-and-join with Err
        let r2 = d
            .spawn_and_join(
                scope,
                Some("err-task"),
                WasmAbiOutcomeEnvelope::Err {
                    failure: WasmAbiFailure {
                        code: WasmAbiErrorCode::InternalFailure,
                        recoverability: WasmAbiRecoverability::Transient,
                        message: "retriable".to_string(),
                    },
                },
                None,
            )
            .unwrap();
        assert!(r2.is_err());
        assert_eq!(
            r2.err_failure().unwrap().recoverability,
            WasmAbiRecoverability::Transient
        );

        // Spawn-and-join with Cancelled
        let r3 = d
            .spawn_and_join(
                scope,
                Some("cancelled-task"),
                WasmAbiOutcomeEnvelope::Cancelled {
                    cancellation: WasmAbiCancellation {
                        kind: "timeout".to_string(),
                        phase: "completed".to_string(),
                        origin_region: "R0".to_string(),
                        origin_task: None,
                        timestamp_nanos: 100,
                        message: Some("deadline".to_string()),
                        truncated: false,
                    },
                },
                None,
            )
            .unwrap();
        assert!(r3.is_cancelled());
        assert_eq!(r3.cancellation().unwrap().kind, "timeout");

        d.close_scoped_runtime(&scope, &rt, None).unwrap();

        let diag = d.diagnostic_snapshot();
        assert!(diag.is_clean());
    }

    // -----------------------------------------------------------------------
    // React Provider Lifecycle Tests
    // -----------------------------------------------------------------------

    #[test]
    fn provider_phase_transitions_valid() {
        use ReactProviderPhase::*;
        // Valid forward transitions
        assert!(is_valid_provider_transition(Pending, Initializing));
        assert!(is_valid_provider_transition(Initializing, Ready));
        assert!(is_valid_provider_transition(Initializing, Failed));
        assert!(is_valid_provider_transition(Ready, Disposing));
        assert!(is_valid_provider_transition(Disposing, Disposed));
        assert!(is_valid_provider_transition(Disposing, Failed));
        // StrictMode remount
        assert!(is_valid_provider_transition(Disposed, Initializing));
        // Identity
        assert!(is_valid_provider_transition(Ready, Ready));
    }

    #[test]
    fn provider_phase_transitions_invalid() {
        use ReactProviderPhase::*;
        assert!(!is_valid_provider_transition(Pending, Ready));
        assert!(!is_valid_provider_transition(Pending, Disposing));
        assert!(!is_valid_provider_transition(Ready, Initializing));
        assert!(!is_valid_provider_transition(Disposed, Ready));
        assert!(!is_valid_provider_transition(Failed, Ready));
        assert!(validate_provider_transition(Pending, Ready).is_err());
    }

    #[test]
    fn provider_mount_unmount_lifecycle() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        assert_eq!(provider.phase(), ReactProviderPhase::Pending);

        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        assert!(provider.runtime_handle().is_some());
        assert!(provider.root_scope_handle().is_some());

        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);

        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 0);
        assert_eq!(snap.active_task_count, 0);
        assert_eq!(
            snap.transition_history,
            vec![
                ReactProviderPhase::Pending,
                ReactProviderPhase::Initializing,
                ReactProviderPhase::Ready,
                ReactProviderPhase::Disposing,
                ReactProviderPhase::Disposed,
            ]
        );
    }

    #[test]
    fn provider_strict_mode_remount() {
        let mut provider = ReactProviderState::new(ReactProviderConfig {
            strict_mode_resilient: true,
            ..Default::default()
        });

        // First mount
        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        let first_rt = provider.runtime_handle().unwrap();

        // StrictMode unmount
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);

        // StrictMode remount — new handles, clean state
        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        let second_rt = provider.runtime_handle().unwrap();
        assert_ne!(first_rt, second_rt);

        // Final cleanup
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);
    }

    #[test]
    fn provider_clean_remount_remains_valid_without_strict_mode_resilience() {
        let mut provider = ReactProviderState::new(ReactProviderConfig {
            strict_mode_resilient: false,
            ..Default::default()
        });

        provider.mount().unwrap();
        let first_rt = provider.runtime_handle().unwrap();
        provider.unmount().unwrap();

        provider.mount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Ready);
        assert_ne!(provider.runtime_handle().unwrap(), first_rt);
    }

    #[test]
    fn provider_child_scopes_tracked() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();

        let s1 = provider.create_child_scope(Some("panel-a")).unwrap();
        let s2 = provider.create_child_scope(Some("panel-b")).unwrap();
        assert_ne!(s1, s2);

        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 2);

        // Unmount cleans up child scopes
        provider.unmount().unwrap();
        let snap = provider.snapshot();
        assert_eq!(snap.child_scope_count, 0);
    }

    #[test]
    fn provider_task_spawn_and_complete() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();

        let task = provider.spawn_task(root_scope, Some("fetch-user")).unwrap();
        assert_eq!(provider.snapshot().active_task_count, 1);

        let outcome = provider
            .complete_task(
                &task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
            )
            .unwrap();
        assert!(outcome.is_ok());
        assert_eq!(provider.snapshot().active_task_count, 0);

        provider.unmount().unwrap();
    }

    #[test]
    fn provider_complete_task_error_keeps_task_tracked_for_cleanup() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();

        let task = provider.spawn_task(root_scope, Some("fetch-user")).unwrap();
        assert_eq!(provider.snapshot().active_task_count, 1);

        let bogus = WasmHandleRef {
            generation: task.generation.wrapping_add(1),
            ..task
        };

        let err = provider
            .complete_task(
                &bogus,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
            )
            .unwrap_err();
        assert!(matches!(err, WasmDispatchError::Handle(_)));
        assert_eq!(provider.snapshot().active_task_count, 1);

        provider.unmount().unwrap();
    }

    #[test]
    fn provider_rejects_spawning_into_foreign_scope() {
        let mut owner = ReactProviderState::new(ReactProviderConfig::default());
        let mut intruder = ReactProviderState::new(ReactProviderConfig {
            label: "intruder".to_string(),
            ..Default::default()
        });
        owner.mount().unwrap();
        intruder.mount().unwrap();

        let foreign_scope = owner.root_scope_handle().unwrap();
        let err = intruder
            .spawn_task(foreign_scope, Some("cross-provider-task"))
            .unwrap_err();
        assert!(matches!(
            err,
            WasmDispatchError::InvalidRequest { ref reason }
                if reason == "scope not owned by provider"
        ));
        assert_eq!(intruder.snapshot().active_task_count, 0);
        assert_eq!(owner.snapshot().active_task_count, 0);

        intruder.unmount().unwrap();
        owner.unmount().unwrap();
    }

    #[test]
    fn provider_rejects_completing_foreign_task() {
        let mut owner = ReactProviderState::new(ReactProviderConfig::default());
        let mut intruder = ReactProviderState::new(ReactProviderConfig {
            label: "intruder".to_string(),
            ..Default::default()
        });
        owner.mount().unwrap();
        intruder.mount().unwrap();

        let owner_root = owner.root_scope_handle().unwrap();
        let foreign_task = owner.spawn_task(owner_root, Some("owner-task")).unwrap();

        let err = intruder
            .complete_task(
                &foreign_task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(42),
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            WasmDispatchError::InvalidRequest { ref reason }
                if reason == "task not tracked by provider"
        ));
        assert_eq!(owner.snapshot().active_task_count, 1);
        assert_eq!(intruder.snapshot().active_task_count, 0);

        let joined = owner
            .complete_task(
                &foreign_task,
                WasmAbiOutcomeEnvelope::Ok {
                    value: WasmAbiValue::I64(7),
                },
            )
            .unwrap();
        assert_eq!(joined.ok_value(), Some(&WasmAbiValue::I64(7)));

        intruder.unmount().unwrap();
        owner.unmount().unwrap();
    }

    #[test]
    fn provider_unmount_cancels_active_tasks() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();

        // Spawn tasks but don't complete them
        let _t1 = provider.spawn_task(root_scope, Some("task-a")).unwrap();
        let _t2 = provider.spawn_task(root_scope, Some("task-b")).unwrap();
        assert_eq!(provider.snapshot().active_task_count, 2);

        // Unmount should cancel tasks, not leak them
        provider.unmount().unwrap();
        assert_eq!(provider.phase(), ReactProviderPhase::Disposed);
    }

    #[test]
    fn provider_unmount_failure_preserves_live_handles_for_retry() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        provider.mount().unwrap();
        let runtime = provider.runtime_handle().unwrap();
        let root_scope = provider.root_scope_handle().unwrap();
        let child_scope = provider.create_child_scope(Some("child")).unwrap();
        let task = provider.spawn_task(root_scope, Some("fetch-user")).unwrap();

        provider.config.consumer_version = Some(WasmAbiVersion { major: 2, minor: 0 });
        let err = provider.unmount().unwrap_err();
        assert!(matches!(err, WasmDispatchError::Incompatible { .. }));
        assert_eq!(provider.phase(), ReactProviderPhase::Failed);

        let snapshot = provider.snapshot();
        assert_eq!(snapshot.active_task_count, 1);
        assert_eq!(snapshot.child_scope_count, 1);
        assert_eq!(snapshot.runtime_handle, Some(runtime));
        assert_eq!(snapshot.root_scope_handle, Some(root_scope));
        assert!(provider.dispatcher.handles().get(&task).is_ok());
        assert!(provider.dispatcher.handles().get(&child_scope).is_ok());
        assert!(provider.dispatcher.handles().get(&root_scope).is_ok());
        assert!(provider.dispatcher.handles().get(&runtime).is_ok());

        provider.config.consumer_version = None;
        provider.do_unmount().unwrap();
        let cleaned = provider.snapshot();
        assert_eq!(cleaned.active_task_count, 0);
        assert_eq!(cleaned.child_scope_count, 0);
        assert!(cleaned.runtime_handle.is_none());
        assert!(cleaned.root_scope_handle.is_none());
        assert!(
            provider.dispatcher.diagnostic_snapshot().is_clean(),
            "retry cleanup should release all retained handles"
        );
    }

    #[test]
    fn provider_operations_rejected_when_not_ready() {
        let mut provider = ReactProviderState::new(ReactProviderConfig::default());
        // Not mounted — should reject operations
        assert!(provider.create_child_scope(Some("x")).is_err());
        assert!(
            provider
                .spawn_task(
                    WasmHandleRef {
                        kind: WasmHandleKind::Runtime,
                        slot: 0,
                        generation: 0,
                        owner_token: 0,
                    },
                    Some("y"),
                )
                .is_err()
        );
    }

    #[test]
    fn provider_snapshot_diagnostics() {
        let mut provider = ReactProviderState::new(ReactProviderConfig {
            label: "test-provider".to_string(),
            devtools_diagnostics: true,
            ..Default::default()
        });
        provider.mount().unwrap();

        let snap = provider.snapshot();
        assert_eq!(snap.phase, ReactProviderPhase::Ready);
        assert_eq!(snap.config.label, "test-provider");
        assert!(snap.config.devtools_diagnostics);
        assert!(snap.dispatcher_diagnostics.is_some());
        assert!(snap.runtime_handle.is_some());
        assert!(snap.root_scope_handle.is_some());

        provider.unmount().unwrap();
    }

    #[test]
    fn provider_config_default_values() {
        let cfg = ReactProviderConfig::default();
        assert_eq!(cfg.label, "asupersync");
        assert_eq!(cfg.abort_mode, WasmAbortPropagationMode::Bidirectional);
        assert!(cfg.strict_mode_resilient);
        assert!(!cfg.devtools_diagnostics);
        assert!(cfg.consumer_version.is_none());
    }

    // -----------------------------------------------------------------------
    // React Hook Contract Tests
    // -----------------------------------------------------------------------

    #[test]
    fn hook_phase_transitions_valid() {
        use ReactHookPhase::*;
        assert!(is_valid_hook_transition(Idle, Active));
        assert!(is_valid_hook_transition(Idle, Error));
        assert!(is_valid_hook_transition(Active, Cleanup));
        assert!(is_valid_hook_transition(Cleanup, Unmounted));
        assert!(is_valid_hook_transition(Cleanup, Active)); // StrictMode remount
        assert!(is_valid_hook_transition(Cleanup, Error));
        assert!(is_valid_hook_transition(Unmounted, Active)); // StrictMode
        // Identity
        assert!(is_valid_hook_transition(Active, Active));
    }

    #[test]
    fn hook_phase_transitions_invalid() {
        use ReactHookPhase::*;
        assert!(!is_valid_hook_transition(Idle, Cleanup));
        assert!(!is_valid_hook_transition(Idle, Unmounted));
        assert!(!is_valid_hook_transition(Active, Idle));
        assert!(!is_valid_hook_transition(Active, Unmounted));
        assert!(!is_valid_hook_transition(Error, Active));
        assert!(validate_hook_transition(Idle, Cleanup).is_err());
    }

    #[test]
    fn use_scope_config_defaults() {
        let cfg = UseScopeConfig::default();
        assert_eq!(cfg.label, "scope");
        assert!(cfg.propagate_cancel);
    }

    #[test]
    fn use_scope_snapshot_round_trip() {
        let snap = UseScopeSnapshot {
            phase: ReactHookPhase::Active,
            config: UseScopeConfig::default(),
            scope_handle: None,
            task_count: 3,
            child_scope_count: 1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseScopeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_task_config_defaults() {
        let cfg = UseTaskConfig::default();
        assert_eq!(cfg.label, "task");
        assert_eq!(cfg.dep_change_policy, TaskDepChangePolicy::CancelAndRestart);
        assert!(cfg.memoize_result);
    }

    #[test]
    fn use_task_snapshot_round_trip() {
        let snap = UseTaskSnapshot {
            phase: ReactHookPhase::Active,
            status: UseTaskStatus::Running,
            config: UseTaskConfig::default(),
            task_handle: None,
            scope_handle: None,
            spawn_count: 2,
            dep_cancel_count: 1,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseTaskSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_race_config_defaults() {
        let cfg = UseRaceConfig::default();
        assert_eq!(cfg.label, "race");
        assert_eq!(cfg.max_racers, 8);
        assert!(cfg.drain_losers_before_resolve);
    }

    #[test]
    fn racer_snapshot_round_trip() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Task);
        let racer = RacerSnapshot {
            index: 0,
            state: RacerState::Won,
            task_handle: h,
            label: Some("fast-path".to_string()),
        };
        let json = serde_json::to_string(&racer).unwrap();
        let decoded: RacerSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(racer, decoded);
    }

    #[test]
    fn use_race_snapshot_round_trip() {
        let snap = UseRaceSnapshot {
            phase: ReactHookPhase::Active,
            config: UseRaceConfig::default(),
            scope_handle: None,
            racers: vec![],
            race_count: 1,
            has_winner: true,
            losers_drained: true,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseRaceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn use_cancellation_config_defaults() {
        let cfg = UseCancellationConfig::default();
        assert_eq!(cfg.label, "cancellation");
        assert!(!cfg.can_trigger);
    }

    #[test]
    fn use_cancellation_snapshot_round_trip() {
        let snap = UseCancellationSnapshot {
            phase: ReactHookPhase::Active,
            config: UseCancellationConfig {
                label: "cancel-observer".to_string(),
                can_trigger: true,
            },
            scope_handle: None,
            is_cancelled: true,
            cancellation: Some(WasmAbiCancellation {
                kind: "timeout".to_string(),
                phase: "completed".to_string(),
                origin_region: "R0".to_string(),
                origin_task: None,
                timestamp_nanos: 0,
                message: None,
                truncated: false,
            }),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: UseCancellationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn hook_diagnostic_event_round_trip() {
        let mut table = WasmHandleTable::new();
        let h = table.allocate(WasmHandleKind::Region);
        let evt = ReactHookDiagnosticEvent {
            hook_kind: ReactHookKind::Scope,
            label: "panel".to_string(),
            from_phase: ReactHookPhase::Idle,
            to_phase: ReactHookPhase::Active,
            handles: vec![h],
            detail: Some("mounted".to_string()),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let decoded: ReactHookDiagnosticEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, decoded);
    }

    #[test]
    fn task_dep_change_policy_serde() {
        for policy in [
            TaskDepChangePolicy::CancelAndRestart,
            TaskDepChangePolicy::DiscardAndRestart,
            TaskDepChangePolicy::KeepRunning,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let decoded: TaskDepChangePolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, decoded);
        }
    }

    #[test]
    fn hook_kind_serde() {
        for kind in [
            ReactHookKind::Scope,
            ReactHookKind::Task,
            ReactHookKind::Race,
            ReactHookKind::Cancellation,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: ReactHookKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // Next.js App Router Integration Tests
    // -----------------------------------------------------------------------

    #[test]
    fn render_environment_supports_wasm() {
        assert!(NextjsRenderEnvironment::ClientHydrated.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::ClientSsr.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::ServerComponent.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::EdgeRuntime.supports_wasm_runtime());
        assert!(!NextjsRenderEnvironment::NodeServer.supports_wasm_runtime());
    }

    #[test]
    fn render_environment_has_browser_apis() {
        assert!(NextjsRenderEnvironment::ClientHydrated.has_browser_apis());
        assert!(NextjsRenderEnvironment::ClientSsr.has_browser_apis());
        assert!(!NextjsRenderEnvironment::ServerComponent.has_browser_apis());
        assert!(!NextjsRenderEnvironment::EdgeRuntime.has_browser_apis());
        assert!(!NextjsRenderEnvironment::NodeServer.has_browser_apis());
    }

    #[test]
    fn render_environment_is_server_side() {
        assert!(NextjsRenderEnvironment::ServerComponent.is_server_side());
        assert!(NextjsRenderEnvironment::EdgeRuntime.is_server_side());
        assert!(NextjsRenderEnvironment::NodeServer.is_server_side());
        assert!(!NextjsRenderEnvironment::ClientSsr.is_server_side());
        assert!(!NextjsRenderEnvironment::ClientHydrated.is_server_side());
    }

    #[test]
    fn render_environment_boundary_mode_mapping() {
        assert_eq!(
            NextjsRenderEnvironment::ClientSsr.boundary_mode(),
            NextjsBoundaryMode::Client
        );
        assert_eq!(
            NextjsRenderEnvironment::ClientHydrated.boundary_mode(),
            NextjsBoundaryMode::Client
        );
        assert_eq!(
            NextjsRenderEnvironment::ServerComponent.boundary_mode(),
            NextjsBoundaryMode::Server
        );
        assert_eq!(
            NextjsRenderEnvironment::NodeServer.boundary_mode(),
            NextjsBoundaryMode::Server
        );
        assert_eq!(
            NextjsRenderEnvironment::EdgeRuntime.boundary_mode(),
            NextjsBoundaryMode::Edge
        );
    }

    #[test]
    fn render_environment_runtime_fallback_mapping() {
        assert_eq!(
            NextjsRenderEnvironment::ClientHydrated.runtime_fallback(),
            NextjsRuntimeFallback::NoneRequired
        );
        assert_eq!(
            NextjsRenderEnvironment::ClientSsr.runtime_fallback(),
            NextjsRuntimeFallback::DeferUntilHydrated
        );
        assert_eq!(
            NextjsRenderEnvironment::ServerComponent.runtime_fallback(),
            NextjsRuntimeFallback::UseServerBridge
        );
        assert_eq!(
            NextjsRenderEnvironment::NodeServer.runtime_fallback(),
            NextjsRuntimeFallback::UseServerBridge
        );
        assert_eq!(
            NextjsRenderEnvironment::EdgeRuntime.runtime_fallback(),
            NextjsRuntimeFallback::UseEdgeBridge
        );

        for env in [
            NextjsRenderEnvironment::ClientSsr,
            NextjsRenderEnvironment::ClientHydrated,
            NextjsRenderEnvironment::ServerComponent,
            NextjsRenderEnvironment::EdgeRuntime,
            NextjsRenderEnvironment::NodeServer,
        ] {
            assert!(
                !env.runtime_fallback_reason().is_empty(),
                "fallback reason should be present for {env:?}"
            );
        }
    }

    #[test]
    fn capability_matrix_wasm_runtime() {
        use NextjsCapability::WasmRuntime;
        assert!(is_capability_available(
            NextjsRenderEnvironment::ClientHydrated,
            WasmRuntime
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::ClientSsr,
            WasmRuntime
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::ServerComponent,
            WasmRuntime
        ));
    }

    #[test]
    fn capability_matrix_server_only() {
        use NextjsCapability::{NodeApis, RequestContext, ServerCookies};
        for cap in [ServerCookies, RequestContext] {
            assert!(is_capability_available(
                NextjsRenderEnvironment::ServerComponent,
                cap
            ));
            assert!(is_capability_available(
                NextjsRenderEnvironment::EdgeRuntime,
                cap
            ));
            assert!(is_capability_available(
                NextjsRenderEnvironment::NodeServer,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ClientHydrated,
                cap
            ));
        }
        assert!(is_capability_available(
            NextjsRenderEnvironment::NodeServer,
            NodeApis
        ));
        assert!(!is_capability_available(
            NextjsRenderEnvironment::EdgeRuntime,
            NodeApis
        ));
    }

    #[test]
    fn capability_matrix_client_only() {
        use NextjsCapability::{BrowserStorage, DomAccess, WebWorkers};
        for cap in [DomAccess, WebWorkers, BrowserStorage] {
            assert!(is_capability_available(
                NextjsRenderEnvironment::ClientHydrated,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ClientSsr,
                cap
            ));
            assert!(!is_capability_available(
                NextjsRenderEnvironment::ServerComponent,
                cap
            ));
        }
    }

    #[test]
    fn anti_pattern_explanations_non_empty() {
        let patterns = [
            NextjsAntiPattern::WasmImportInServerComponent,
            NextjsAntiPattern::RuntimeCallDuringSsr,
            NextjsAntiPattern::RuntimeInitInRender,
            NextjsAntiPattern::HandlesSharingAcrossRoutes,
            NextjsAntiPattern::RuntimeInEdgeMiddleware,
            NextjsAntiPattern::BlockingHydration,
            NextjsAntiPattern::HandlesInServerActions,
        ];
        for ap in patterns {
            assert!(
                !ap.explanation().is_empty(),
                "anti-pattern {ap:?} has empty explanation"
            );
        }
    }

    #[test]
    fn navigation_type_runtime_survives() {
        assert!(NextjsNavigationType::SoftNavigation.runtime_survives());
        assert!(!NextjsNavigationType::HardNavigation.runtime_survives());
        assert!(!NextjsNavigationType::PopState.runtime_survives());
    }

    #[test]
    fn bootstrap_transitions_valid() {
        use NextjsBootstrapPhase::*;
        assert!(is_valid_bootstrap_transition(ServerRendered, Hydrating));
        assert!(is_valid_bootstrap_transition(Hydrating, Hydrated));
        assert!(is_valid_bootstrap_transition(Hydrating, RuntimeFailed));
        assert!(is_valid_bootstrap_transition(Hydrated, RuntimeReady));
        assert!(is_valid_bootstrap_transition(Hydrated, RuntimeFailed));
        assert!(is_valid_bootstrap_transition(RuntimeReady, Hydrating));
        assert!(is_valid_bootstrap_transition(RuntimeReady, ServerRendered));
        assert!(is_valid_bootstrap_transition(RuntimeFailed, Hydrating));
        assert!(is_valid_bootstrap_transition(RuntimeFailed, ServerRendered));
        // Identity
        assert!(is_valid_bootstrap_transition(Hydrated, Hydrated));
    }

    #[test]
    fn bootstrap_transitions_invalid() {
        use NextjsBootstrapPhase::*;
        assert!(!is_valid_bootstrap_transition(ServerRendered, Hydrated));
        assert!(!is_valid_bootstrap_transition(ServerRendered, RuntimeReady));
        assert!(!is_valid_bootstrap_transition(Hydrating, RuntimeReady)); // must pass through Hydrated
        assert!(!is_valid_bootstrap_transition(RuntimeFailed, RuntimeReady)); // must retry hydration first
        assert!(validate_bootstrap_transition(ServerRendered, RuntimeReady).is_err());
    }

    #[test]
    fn bootstrap_state_idempotent_hydration_reentry() {
        let mut state = NextjsBootstrapState::new();
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);

        let changed = state.start_hydration().expect("start hydration");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 1);

        let changed = state.start_hydration().expect("idempotent hydration start");
        assert!(!changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 1);
    }

    #[test]
    fn bootstrap_state_cancelled_then_retry_flow() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");

        state
            .mark_runtime_cancelled("navigation interrupted")
            .expect("mark cancelled");
        assert_eq!(state.phase(), NextjsBootstrapPhase::RuntimeFailed);
        assert_eq!(state.last_failure(), Some("navigation interrupted"));

        let changed = state.retry_after_failure().expect("retry after failure");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hydration_cycle_count(), 2);
        assert_eq!(state.last_failure(), None);
    }

    #[test]
    fn bootstrap_retry_requires_runtime_failed_phase() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let before_log = state.transition_log().to_vec();
        let err = state.retry_after_failure().unwrap_err();
        assert_eq!(
            err,
            NextjsBootstrapTransitionError {
                from: NextjsBootstrapPhase::RuntimeReady,
                to: NextjsBootstrapPhase::Hydrating,
            }
        );
        assert_eq!(state.phase(), NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(state.hydration_cycle_count(), 1);
        assert_eq!(state.runtime_generation(), 1);
        assert_eq!(state.transition_log(), before_log.as_slice());
    }

    #[test]
    fn bootstrap_retry_does_not_relabel_normal_rehydration_paths() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        state.on_hot_reload().expect("hot reload");
        let last = state.transition_log().last().expect("transition record");
        assert_eq!(last.trigger, NextjsBootstrapTrigger::HotReload);
        assert_eq!(last.from, NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(last.to, NextjsBootstrapPhase::Hydrating);
    }

    #[test]
    fn bootstrap_state_soft_navigation_is_non_destructive() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state
            .on_navigation(NextjsNavigationType::SoftNavigation)
            .expect("soft navigation");
        assert!(!changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::RuntimeReady);
        assert_eq!(state.runtime_generation(), 1);
        assert_eq!(state.navigation_count(), 1);
    }

    #[test]
    fn bootstrap_state_hard_navigation_resets_phase() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state
            .on_navigation(NextjsNavigationType::HardNavigation)
            .expect("hard navigation");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);
        assert_eq!(state.navigation_count(), 1);
        assert_eq!(state.last_failure(), None);
    }

    #[test]
    fn bootstrap_state_hard_navigation_during_hydration_resets_cleanly() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");

        let changed = state
            .on_navigation(NextjsNavigationType::HardNavigation)
            .expect("hard navigation during hydration");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);
        assert_eq!(state.navigation_count(), 1);
        assert_eq!(state.hydration_cycle_count(), 1);
        assert_eq!(state.last_failure(), None);
    }

    #[test]
    fn bootstrap_state_hard_navigation_clears_previous_failure() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state
            .mark_runtime_failed("module fetch failed")
            .expect("mark failed");
        assert_eq!(state.last_failure(), Some("module fetch failed"));

        let changed = state
            .on_navigation(NextjsNavigationType::HardNavigation)
            .expect("hard navigation after failure");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::ServerRendered);
        assert_eq!(state.last_failure(), None);
    }

    #[test]
    fn bootstrap_state_hot_reload_forces_rehydration() {
        let mut state = NextjsBootstrapState::new();
        state.start_hydration().expect("start hydration");
        state.complete_hydration().expect("complete hydration");
        state.mark_runtime_ready().expect("runtime ready");

        let changed = state.on_hot_reload().expect("hot reload");
        assert!(changed);
        assert_eq!(state.phase(), NextjsBootstrapPhase::Hydrating);
        assert_eq!(state.hot_reload_count(), 1);
        assert_eq!(state.hydration_cycle_count(), 2);
    }

    #[test]
    fn component_placement_round_trip() {
        let placement = NextjsComponentPlacement {
            environment: NextjsRenderEnvironment::ClientHydrated,
            route_segment: "/dashboard/settings".to_string(),
            inside_suspense: true,
            inside_error_boundary: false,
            layout_depth: 2,
        };
        let json = serde_json::to_string(&placement).unwrap();
        let decoded: NextjsComponentPlacement = serde_json::from_str(&json).unwrap();
        assert_eq!(placement, decoded);
    }

    #[test]
    fn integration_snapshot_round_trip() {
        let snap = NextjsIntegrationSnapshot {
            bootstrap_phase: NextjsBootstrapPhase::RuntimeReady,
            environment: NextjsRenderEnvironment::ClientHydrated,
            route_segment: "/app".to_string(),
            active_provider_count: 1,
            wasm_module_loaded: true,
            navigation_count: 3,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: NextjsIntegrationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, decoded);
    }

    #[test]
    fn anti_pattern_serde() {
        for ap in [
            NextjsAntiPattern::WasmImportInServerComponent,
            NextjsAntiPattern::RuntimeCallDuringSsr,
            NextjsAntiPattern::RuntimeInitInRender,
            NextjsAntiPattern::HandlesSharingAcrossRoutes,
            NextjsAntiPattern::RuntimeInEdgeMiddleware,
            NextjsAntiPattern::BlockingHydration,
            NextjsAntiPattern::HandlesInServerActions,
        ] {
            let json = serde_json::to_string(&ap).unwrap();
            let decoded: NextjsAntiPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(ap, decoded);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // br-asupersync-3iuhhg — WASM ABI serialization stability goldens.
    //
    // The wasm_abi.rs surface is the wire contract between the Rust
    // runtime and the JS package. Any layout change (field add/rename,
    // tag scheme, snake_case discipline) silently breaks compiled wasm
    // artifacts that depend on the prior shape. The fingerprint at
    // signature_fingerprint_matches_expected_v1 catches symbol/payload
    // tuple drift, but it does NOT catch:
    //   * new fields added to a struct (e.g. WasmAbiCancellation),
    //   * a serde tag/rename change (e.g. dropping rename_all="snake_case"),
    //   * an envelope variant tag rename (e.g. "ok" -> "Ok"),
    //   * a value-arm encoding change (e.g. WasmAbiValue::Bytes layout).
    //
    // The insta goldens below freeze the JSON shape of every public ABI
    // type. Any drift requires an explicit `cargo insta review` and a
    // deliberate version bump in WASM_ABI_MAJOR/MINOR — the same hard
    // gate the fingerprint already provides for symbol tuples.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn wasm_abi_v1_signature_set_serde_snapshot() {
        // Freezes the eight-symbol v1 contract: any reorder, payload
        // shape change, or symbol rename must reviewer-approve here.
        insta::assert_json_snapshot!("wasm_abi_v1_signature_set", WASM_ABI_SIGNATURES_V1.to_vec());
    }

    #[test]
    fn wasm_abi_compatibility_decision_variants_snapshot() {
        // All four decision variants — Exact, BackwardCompatible,
        // MajorMismatch, ConsumerTooOld — encoded with the
        // tag = "decision" / snake_case discipline.
        let variants = vec![
            WasmAbiCompatibilityDecision::Exact,
            WasmAbiCompatibilityDecision::BackwardCompatible {
                producer_minor: 2,
                consumer_minor: 5,
            },
            WasmAbiCompatibilityDecision::MajorMismatch {
                producer_major: 1,
                consumer_major: 2,
            },
            WasmAbiCompatibilityDecision::ConsumerTooOld {
                producer_minor: 7,
                consumer_minor: 3,
            },
        ];
        insta::assert_json_snapshot!("wasm_abi_compatibility_decision_variants", variants);
    }

    #[test]
    fn wasm_abi_atomic_enums_snapshot() {
        // Single snapshot covering every snake_case-discipline enum that
        // has no payload. A rename or reorder of any variant breaks
        // a wire contract; this golden is the gate.
        let payload = serde_json::json!({
            "symbol": [
                WasmAbiSymbol::RuntimeCreate,
                WasmAbiSymbol::RuntimeClose,
                WasmAbiSymbol::ScopeEnter,
                WasmAbiSymbol::ScopeClose,
                WasmAbiSymbol::TaskSpawn,
                WasmAbiSymbol::TaskJoin,
                WasmAbiSymbol::TaskCancel,
                WasmAbiSymbol::FetchRequest,
            ],
            "payload_shape": [
                WasmAbiPayloadShape::Empty,
                WasmAbiPayloadShape::HandleRefV1,
                WasmAbiPayloadShape::ScopeEnterRequestV1,
                WasmAbiPayloadShape::SpawnRequestV1,
                WasmAbiPayloadShape::CancelRequestV1,
                WasmAbiPayloadShape::FetchRequestV1,
                WasmAbiPayloadShape::OutcomeEnvelopeV1,
            ],
            "handle_kind": [
                WasmHandleKind::Runtime,
                WasmHandleKind::Region,
                WasmHandleKind::Task,
                WasmHandleKind::CancelToken,
                WasmHandleKind::FetchRequest,
            ],
            "boundary_state": [
                WasmBoundaryState::Unbound,
                WasmBoundaryState::Bound,
                WasmBoundaryState::Active,
                WasmBoundaryState::Cancelling,
                WasmBoundaryState::Draining,
                WasmBoundaryState::Closed,
            ],
            "error_code": [
                WasmAbiErrorCode::CapabilityDenied,
                WasmAbiErrorCode::InvalidHandle,
                WasmAbiErrorCode::DecodeFailure,
                WasmAbiErrorCode::CompatibilityRejected,
                WasmAbiErrorCode::InternalFailure,
            ],
            "recoverability": [
                WasmAbiRecoverability::Transient,
                WasmAbiRecoverability::Permanent,
                WasmAbiRecoverability::Unknown,
            ],
            "change_class": [
                WasmAbiChangeClass::AdditiveField,
                WasmAbiChangeClass::AdditiveSymbol,
                WasmAbiChangeClass::BehavioralTightening,
                WasmAbiChangeClass::BehavioralRelaxation,
                WasmAbiChangeClass::SymbolRemoval,
                WasmAbiChangeClass::ValueEncodingChange,
                WasmAbiChangeClass::OutcomeSemanticChange,
                WasmAbiChangeClass::CancellationSemanticChange,
            ],
        });
        insta::assert_json_snapshot!("wasm_abi_atomic_enums", payload);
    }

    #[test]
    fn wasm_abi_value_variants_snapshot() {
        // tag="kind", content="value" envelope — every WasmAbiValue arm.
        // Bytes is fixed so the snapshot is byte-stable across runs.
        let variants = vec![
            WasmAbiValue::Unit,
            WasmAbiValue::Bool(true),
            WasmAbiValue::I64(-42),
            WasmAbiValue::U64(7),
            WasmAbiValue::String("hello".to_string()),
            WasmAbiValue::Bytes(vec![0x00, 0x01, 0x02, 0xff]),
            WasmAbiValue::Handle(WasmHandleRef {
                kind: WasmHandleKind::Region,
                slot: 11,
                generation: 3,
                owner_token: 0xDEAD_BEEF_FEED_FACE,
            }),
        ];
        insta::assert_json_snapshot!("wasm_abi_value_variants", variants);
    }

    #[test]
    fn wasm_abi_outcome_envelope_variants_snapshot() {
        // tag="outcome" envelope — Ok / Err / Cancelled / Panicked
        // shapes, including nested WasmAbiFailure and WasmAbiCancellation.
        let envelopes = vec![
            WasmAbiOutcomeEnvelope::Ok {
                value: WasmAbiValue::U64(7),
            },
            WasmAbiOutcomeEnvelope::Err {
                failure: WasmAbiFailure {
                    code: WasmAbiErrorCode::CapabilityDenied,
                    recoverability: WasmAbiRecoverability::Permanent,
                    message: "scope closed".to_string(),
                },
            },
            WasmAbiOutcomeEnvelope::Cancelled {
                cancellation: WasmAbiCancellation {
                    kind: "user".to_string(),
                    phase: "completed".to_string(),
                    origin_region: "R(3,7)".to_string(),
                    origin_task: Some("T(4,1)".to_string()),
                    timestamp_nanos: 42,
                    message: Some("deadline exceeded".to_string()),
                    truncated: false,
                },
            },
            WasmAbiOutcomeEnvelope::Panicked {
                message: "boom".to_string(),
            },
        ];
        insta::assert_json_snapshot!("wasm_abi_outcome_envelope_variants", envelopes);
    }

    #[test]
    fn wasm_abi_boundary_event_snapshot() {
        // Full WasmAbiBoundaryEvent — the structured-log shape consumed
        // by JS observability. Every field is part of the wire contract.
        let event = WasmAbiBoundaryEvent {
            abi_version: WasmAbiVersion { major: 1, minor: 2 },
            symbol: WasmAbiSymbol::TaskSpawn,
            payload_shape: WasmAbiPayloadShape::SpawnRequestV1,
            state_from: WasmBoundaryState::Bound,
            state_to: WasmBoundaryState::Active,
            compatibility: WasmAbiCompatibilityDecision::BackwardCompatible {
                producer_minor: 1,
                consumer_minor: 2,
            },
        };
        insta::assert_json_snapshot!("wasm_abi_boundary_event", event);
    }

    #[test]
    fn wasm_abi_handle_ref_snapshot() {
        // Handle reference: kind/slot/generation/owner_token. The
        // owner_token field was added by br-asupersync-axbme3 and is
        // serde(default)'d for backward read compatibility — this
        // snapshot freezes the post-token JSON layout so removing it
        // would require explicit reviewer approval.
        let handle = WasmHandleRef {
            kind: WasmHandleKind::Task,
            slot: 5,
            generation: 1,
            owner_token: 0x1234_5678_9ABC_DEF0,
        };
        insta::assert_json_snapshot!("wasm_abi_handle_ref", handle);
    }
