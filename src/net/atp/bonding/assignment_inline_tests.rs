    use super::super::descriptor::{BondEntry, BondTransferDescriptor};
    use super::*;
    use crate::security::SecurityContext;
    use crate::types::{SymbolId, SymbolKind};

    fn endpoint() -> SocketAddr {
        "127.0.0.1:8472".parse().expect("test endpoint")
    }

    fn symbol() -> Symbol {
        Symbol::new(
            SymbolId::new_for_test(7, 0, 4),
            b"bonded-symbol".to_vec(),
            SymbolKind::Repair,
        )
    }

    fn descriptor() -> BondTransferDescriptor {
        BondTransferDescriptor {
            transfer_id: "bond-schedule-transfer".to_string(),
            root_name: "root".to_string(),
            is_directory: false,
            total_bytes: 13,
            merkle_root_hex: "schedule-root".to_string(),
            metadata: None,
            entries: vec![BondEntry {
                index: 0,
                rel_path: "payload.bin".to_string(),
                size: 13,
                sha256_hex: "00".repeat(32),
            }],
            symbol_size: 4,
            max_block_size: 8,
            auth_key_id: Some("key-1".to_string()),
        }
    }

    #[test]
    fn static_assignment_uses_a2_residue_partition() {
        let assignment = DonorAssignment::new_static(
            1,
            3,
            vec![endpoint()],
            Some(BondAuthKeyRef::ControlPlane("bond-key-1".to_string())),
        );
        assignment.validate().expect("valid assignment");

        assert!(assignment.owns_esi(1));
        assert!(assignment.owns_esi(4));
        assert!(!assignment.owns_esi(2));
        assert!(assignment.requires_symbol_auth());
    }

    #[test]
    fn explicit_windows_override_static_residue() {
        let assignment = DonorAssignment::new_windowed(
            1,
            3,
            vec![EsiWindow::new(10, 12)],
            vec![endpoint()],
            None,
        );
        assignment.validate().expect("valid windowed assignment");

        assert!(
            !assignment.owns_esi(1),
            "windowed assignments override residue"
        );
        assert!(assignment.owns_esi(10));
        assert!(assignment.owns_esi(11));
        assert!(!assignment.owns_esi(12));
    }

    #[test]
    fn donor_spray_schedule_partitions_source_and_repair_esis() {
        let descriptor = descriptor();
        let donor0 = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let donor1 = DonorAssignment::new_static(1, 2, vec![endpoint()], None);

        let schedule0 =
            schedule_bonded_donor_spray(&descriptor, &donor0, 4).expect("donor 0 schedule");
        let schedule1 =
            schedule_bonded_donor_spray(&descriptor, &donor1, 4).expect("donor 1 schedule");

        assert_eq!(schedule0.blocks.len(), 2);
        assert_eq!(schedule1.blocks.len(), 2);
        assert!(schedule0.covers_every_block());
        assert!(schedule1.covers_every_block());
        assert_eq!(
            schedule0.total_symbol_count() + schedule1.total_symbol_count(),
            12
        );

        for (left, right) in schedule0.blocks.iter().zip(&schedule1.blocks) {
            assert_eq!(left.geometry, right.geometry);
            let left_esis = left.ordered_esis();
            let right_esis = right.ordered_esis();
            let mut combined = left_esis.clone();
            combined.extend_from_slice(&right_esis);
            combined.sort_unstable();
            combined.dedup();
            assert_eq!(
                combined,
                vec![0, 1, 2, 3, 4, 5],
                "two donors cover source ESIs 0..K and four repair ESIs"
            );

            for esi in left_esis {
                assert!(!right_esis.contains(&esi));
                assert_eq!(esi % 2, 0);
            }
            for esi in right_esis {
                assert_eq!(esi % 2, 1);
            }
        }
    }

    #[test]
    fn single_donor_spray_schedule_matches_single_source_esi_order() {
        let descriptor = descriptor();
        let donor = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let schedule =
            schedule_bonded_donor_spray(&descriptor, &donor, 4).expect("single donor schedule");

        assert_eq!(schedule.donor_index, 0);
        assert_eq!(schedule.donor_count, 1);
        assert_eq!(schedule.blocks.len(), 2);
        assert!(schedule.covers_every_block());
        assert_eq!(schedule.source_symbol_count(), 4);
        assert_eq!(schedule.repair_symbol_count(), 8);
        assert_eq!(schedule.total_symbol_count(), 12);

        for block in &schedule.blocks {
            assert_eq!(block.source_esis, vec![0, 1]);
            assert_eq!(block.repair_esis, vec![2, 3, 4, 5]);
            assert_eq!(block.ordered_esis(), vec![0, 1, 2, 3, 4, 5]);
            assert_eq!(block.next_repair_esi, 6);
            assert_eq!(block.stagger_delay_slots, 0);
        }

        let emissions = schedule.symbol_emissions();
        assert_eq!(emissions.len(), schedule.total_symbol_count());
        assert!(emissions.iter().all(|emission| emission.donor_index == 0));
        assert_eq!(emissions[0].kind, BondedDonorSymbolKind::Source);
        assert_eq!(emissions[2].kind, BondedDonorSymbolKind::Repair);
    }

    #[test]
    fn windowed_donor_spray_schedule_uses_explicit_esi_windows() {
        let descriptor = descriptor();
        let donor =
            DonorAssignment::new_windowed(0, 1, vec![EsiWindow::new(1, 3)], vec![endpoint()], None);

        let schedule =
            schedule_bonded_donor_spray(&descriptor, &donor, 4).expect("windowed schedule");

        for block in &schedule.blocks {
            assert_eq!(
                block.ordered_esis(),
                vec![1, 2],
                "explicit windows override static residue and remain half-open"
            );
            assert_eq!(block.source_esis, vec![1]);
            assert_eq!(block.repair_esis, vec![2]);
            assert_eq!(block.next_repair_esi, 6);
        }
    }

    #[test]
    fn source_first_coverage_proves_static_donors_cover_k_exactly_once() {
        let descriptor = descriptor();
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 2, vec![endpoint()], None),
        ];

        let coverage =
            schedule_bonded_source_first_coverage(&descriptor, &assignments).expect("coverage");

        assert_eq!(coverage.assignment_count, 2);
        assert_eq!(coverage.blocks.len(), 2);
        assert!(coverage.is_source_complete_exactly_once());

        for block in &coverage.blocks {
            assert!(block.is_source_complete_exactly_once());
            assert_eq!(
                block.scheduled_source_symbol_count(),
                usize::from(block.geometry.source_symbols)
            );
            assert_eq!(block.missing_source_esis, Vec::<u32>::new());
            assert_eq!(block.duplicate_source_esis, Vec::<u32>::new());
            assert_eq!(block.donors[0].donor_index, 0);
            assert_eq!(block.donors[0].source_esis, vec![0]);
            assert_eq!(block.donors[0].first_repair_esi, Some(2));
            assert_eq!(block.donors[0].stagger_delay_slots, 0);
            assert_eq!(block.donors[1].donor_index, 1);
            assert_eq!(block.donors[1].source_esis, vec![1]);
            assert_eq!(block.donors[1].first_repair_esi, Some(3));
            assert_eq!(block.donors[1].stagger_delay_slots, 1);
        }
    }

    #[test]
    fn source_first_coverage_reports_windowed_missing_and_duplicate_source_esis() {
        let descriptor = descriptor();
        let assignments = vec![
            DonorAssignment::new_windowed(0, 2, vec![EsiWindow::new(0, 1)], vec![endpoint()], None),
            DonorAssignment::new_windowed(1, 2, vec![EsiWindow::new(0, 1)], vec![endpoint()], None),
        ];

        let coverage =
            schedule_bonded_source_first_coverage(&descriptor, &assignments).expect("coverage");

        assert!(!coverage.is_source_complete_exactly_once());
        for block in &coverage.blocks {
            assert_eq!(block.missing_source_esis, vec![1]);
            assert_eq!(block.duplicate_source_esis, vec![0]);
            assert_eq!(block.scheduled_source_symbol_count(), 2);
            assert_eq!(block.donors[0].source_esis, vec![0]);
            assert_eq!(block.donors[0].first_repair_esi, None);
            assert_eq!(block.donors[1].source_esis, vec![0]);
            assert_eq!(block.donors[1].first_repair_esi, None);
        }
    }

    #[test]
    fn source_first_coverage_fails_closed_for_invalid_collective_assignments() {
        let descriptor = descriptor();

        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &[]),
            Err(BondScheduleError::NoDonorAssignments)
        );

        let duplicate = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
        ];
        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &duplicate),
            Err(BondScheduleError::DuplicateDonorAssignment { donor_index: 0 })
        );

        let mismatched_count = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 3, vec![endpoint()], None),
        ];
        assert_eq!(
            schedule_bonded_source_first_coverage(&descriptor, &mismatched_count),
            Err(BondScheduleError::InconsistentDonorCount {
                expected: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn dynamic_repair_windows_are_disjoint_and_weighted_by_goodput() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 1,
                weight: 3,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 8, &weights).expect("window allocation");

        assert_eq!(plan.first_repair_esi, 2);
        assert_eq!(plan.next_repair_esi, 10);
        assert_eq!(plan.allocated_symbol_count(), 8);
        assert!(plan.windows_are_disjoint());
        assert_eq!(
            plan.windows,
            vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 4),
                    symbol_count: 2,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 10),
                    symbol_count: 6,
                    stagger_delay_slots: 1,
                },
            ]
        );
    }

    #[test]
    fn repair_window_plan_disjointness_rejects_malformed_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");

        let valid = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 6,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 6),
                symbol_count: 4,
                stagger_delay_slots: 0,
            }],
        };
        assert!(valid.windows_are_disjoint());

        let empty = BondedRepairWindowPlan {
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(6, 6),
                symbol_count: 0,
                stagger_delay_slots: 0,
            }],
            ..valid.clone()
        };
        assert!(
            !empty.windows_are_disjoint(),
            "empty windows do not allocate repair symbols"
        );

        let misreported_count = BondedRepairWindowPlan {
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 6),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
            ..valid.clone()
        };
        assert!(
            !misreported_count.windows_are_disjoint(),
            "symbol_count must match the half-open ESI range"
        );

        let overlapping = BondedRepairWindowPlan {
            windows: vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 5),
                    symbol_count: 3,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 6),
                    symbol_count: 2,
                    stagger_delay_slots: 1,
                },
            ],
            ..valid
        };
        assert!(!overlapping.windows_are_disjoint());
    }

    #[test]
    fn dynamic_repair_windows_distribute_remainders_deterministically() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 2,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 1,
                weight: 1,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 5, &weights).expect("window allocation");

        assert!(plan.windows_are_disjoint());
        assert_eq!(plan.allocated_symbol_count(), 5);
        assert_eq!(
            plan.windows,
            vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 4),
                    symbol_count: 2,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(4, 6),
                    symbol_count: 2,
                    stagger_delay_slots: 1,
                },
                BondedDonorRepairWindow {
                    donor_index: 2,
                    esi_window: EsiWindow::new(6, 7),
                    symbol_count: 1,
                    stagger_delay_slots: 2,
                },
            ]
        );
    }

    #[test]
    fn dynamic_repair_window_stagger_slots_are_compact() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let weights = vec![
            BondedDonorWindowWeight {
                donor_index: 2,
                weight: 0,
            },
            BondedDonorWindowWeight {
                donor_index: 7,
                weight: 1,
            },
            BondedDonorWindowWeight {
                donor_index: 42,
                weight: 1,
            },
        ];

        let plan =
            allocate_bonded_repair_windows(geometry, 2, 2, &weights).expect("window allocation");

        assert_eq!(plan.allocated_symbol_count(), 2);
        assert_eq!(
            plan.windows
                .iter()
                .map(|window| (window.donor_index, window.stagger_delay_slots))
                .collect::<Vec<_>>(),
            vec![(7, 0), (42, 1)]
        );
    }

    #[test]
    fn dynamic_repair_windows_fail_closed_for_invalid_allocation_inputs() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");

        assert_eq!(
            allocate_bonded_repair_windows(geometry, 2, 1, &[]),
            Err(BondScheduleError::NoDonorAssignments)
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                2,
                1,
                &[
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 1,
                    },
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 1,
                    },
                ],
            ),
            Err(BondScheduleError::DuplicateDonorAssignment { donor_index: 0 })
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                2,
                1,
                &[
                    BondedDonorWindowWeight {
                        donor_index: 0,
                        weight: 0,
                    },
                    BondedDonorWindowWeight {
                        donor_index: 1,
                        weight: 0,
                    },
                ],
            ),
            Err(BondScheduleError::ZeroWindowWeightSum)
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                1,
                1,
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::RepairStartBeforeSource {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                first_repair_esi: 1,
            })
        );
        assert_eq!(
            allocate_bonded_repair_windows(
                geometry,
                u32::MAX,
                1,
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::RepairWindowAllocationOverflow {
                entry_index: 0,
                source_block_number: 0,
                first_repair_esi: u32::MAX,
                requested_symbols: 1,
            })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_moves_budget_to_survivors() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let initial = allocate_bonded_repair_windows(
            geometry,
            2,
            8,
            &[
                BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                },
                BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 3,
                },
            ],
        )
        .expect("initial allocation");

        let replacement = reallocate_failed_bonded_repair_windows(
            geometry,
            initial.next_repair_esi,
            &initial.windows,
            &[1],
            &[BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            }],
        )
        .expect("reallocation");

        assert_eq!(replacement.first_repair_esi, 10);
        assert_eq!(replacement.next_repair_esi, 16);
        assert_eq!(replacement.allocated_symbol_count(), 6);
        assert!(replacement.windows_are_disjoint());
        assert_eq!(
            replacement.windows,
            vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(10, 16),
                symbol_count: 6,
                stagger_delay_slots: 0,
            }]
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_unknown_failed_donor() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let initial = allocate_bonded_repair_windows(
            geometry,
            2,
            4,
            &[BondedDonorWindowWeight {
                donor_index: 0,
                weight: 1,
            }],
        )
        .expect("initial allocation");

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                initial.next_repair_esi,
                &initial.windows,
                &[1],
                &[BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::MissingFailedDonorWindow { donor_index: 1 })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_overflowing_budget() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let outstanding_windows = vec![
            BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(0, u32::MAX),
                symbol_count: u32::MAX,
                stagger_delay_slots: 0,
            },
            BondedDonorRepairWindow {
                donor_index: 1,
                esi_window: EsiWindow::new(u32::MAX - 1, u32::MAX),
                symbol_count: 1,
                stagger_delay_slots: 1,
            },
        ];

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                u32::from(geometry.source_symbols),
                &outstanding_windows,
                &[0, 1],
                &[BondedDonorWindowWeight {
                    donor_index: 2,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::FailedDonorRepairBudgetOverflow {
                donor_index: 1,
                accumulated_symbols: u32::MAX,
                added_symbols: 1,
            })
        );
    }

    #[test]
    fn failed_donor_window_reallocation_rejects_malformed_failed_window() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let outstanding_windows = vec![BondedDonorRepairWindow {
            donor_index: 0,
            esi_window: EsiWindow::new(4, 6),
            symbol_count: 3,
            stagger_delay_slots: 0,
        }];

        assert_eq!(
            reallocate_failed_bonded_repair_windows(
                geometry,
                6,
                &outstanding_windows,
                &[0],
                &[BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 1,
                }],
            ),
            Err(BondScheduleError::InvalidRepairWindow {
                donor_index: 0,
                start_inclusive: 4,
                end_exclusive: 6,
                symbol_count: 3,
            })
        );
    }

    #[test]
    fn repair_window_assignments_preserve_control_metadata_and_override_residue() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let auth = BondAuthKeyRef::ControlPlane("bond-key-1".to_string());
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], Some(auth.clone())),
            DonorAssignment::new_static(1, 2, vec![endpoint()], Some(auth.clone())),
        ];
        let plan = allocate_bonded_repair_windows(
            geometry,
            2,
            8,
            &[
                BondedDonorWindowWeight {
                    donor_index: 0,
                    weight: 1,
                },
                BondedDonorWindowWeight {
                    donor_index: 1,
                    weight: 3,
                },
            ],
        )
        .expect("window allocation");

        let windowed = schedule_bonded_repair_window_assignments(&assignments, &plan)
            .expect("window assignments");

        assert_eq!(windowed.len(), 2);
        assert_eq!(windowed[0].donor_index, 0);
        assert_eq!(windowed[0].repair_window, plan.windows[0]);
        assert_eq!(
            windowed[0].assignment.esi_windows,
            vec![EsiWindow::new(2, 4)]
        );
        assert_eq!(
            windowed[0].assignment.receiver_udp_endpoints,
            vec![endpoint()]
        );
        assert_eq!(windowed[0].assignment.auth_key_ref, Some(auth.clone()));
        assert!(windowed[0].assignment.owns_esi(2));
        assert!(windowed[0].assignment.owns_esi(3));
        assert!(!windowed[0].assignment.owns_esi(4));

        assert_eq!(windowed[1].donor_index, 1);
        assert_eq!(windowed[1].repair_window, plan.windows[1]);
        assert_eq!(
            windowed[1].assignment.esi_windows,
            vec![EsiWindow::new(4, 10)]
        );
        assert_eq!(windowed[1].assignment.auth_key_ref, Some(auth));
        assert!(windowed[1].assignment.owns_esi(9));
        assert!(!windowed[1].assignment.owns_esi(3));
    }

    #[test]
    fn repair_window_assignments_fail_closed_for_unknown_or_malformed_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![DonorAssignment::new_static(0, 2, vec![endpoint()], None)];
        let missing_donor_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 4,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 1,
                esi_window: EsiWindow::new(2, 4),
                symbol_count: 2,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &missing_donor_plan),
            Err(BondScheduleError::MissingDonorAssignment { donor_index: 1 })
        );

        let malformed_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 4,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 4),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &malformed_plan),
            Err(BondScheduleError::InvalidRepairWindow {
                donor_index: 0,
                start_inclusive: 2,
                end_exclusive: 4,
                symbol_count: 3,
            })
        );
    }

    #[test]
    fn repair_window_assignments_reject_duplicate_donor_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![DonorAssignment::new_static(0, 1, vec![endpoint()], None)];
        let duplicate_donor_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 6,
            windows: vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 4),
                    symbol_count: 2,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(4, 6),
                    symbol_count: 2,
                    stagger_delay_slots: 1,
                },
            ],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &duplicate_donor_plan),
            Err(BondScheduleError::DuplicateDonorAssignment { donor_index: 0 })
        );
    }

    #[test]
    fn repair_window_assignments_reject_overlapping_windows() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![
            DonorAssignment::new_static(0, 2, vec![endpoint()], None),
            DonorAssignment::new_static(1, 2, vec![endpoint()], None),
        ];
        let overlapping_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 8,
            windows: vec![
                BondedDonorRepairWindow {
                    donor_index: 0,
                    esi_window: EsiWindow::new(2, 6),
                    symbol_count: 4,
                    stagger_delay_slots: 0,
                },
                BondedDonorRepairWindow {
                    donor_index: 1,
                    esi_window: EsiWindow::new(5, 8),
                    symbol_count: 3,
                    stagger_delay_slots: 1,
                },
            ],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &overlapping_plan),
            Err(BondScheduleError::OverlappingRepairWindows {
                previous_donor_index: 0,
                next_donor_index: 1,
                previous_end_exclusive: 6,
                next_start_inclusive: 5,
            })
        );
    }

    #[test]
    fn repair_window_assignments_reject_stale_window_cursor() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignments = vec![DonorAssignment::new_static(0, 1, vec![endpoint()], None)];
        let stale_cursor_plan = BondedRepairWindowPlan {
            geometry,
            first_repair_esi: 2,
            next_repair_esi: 3,
            windows: vec![BondedDonorRepairWindow {
                donor_index: 0,
                esi_window: EsiWindow::new(2, 5),
                symbol_count: 3,
                stagger_delay_slots: 0,
            }],
        };

        assert_eq!(
            schedule_bonded_repair_window_assignments(&assignments, &stale_cursor_plan),
            Err(BondScheduleError::RepairWindowCursorBeforeWindowEnd {
                next_repair_esi: 3,
                window_end_exclusive: 5,
            })
        );
    }

    #[test]
    fn donor_count_one_schedule_is_single_source_isomorphic() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 3).expect("schedule");

        assert_eq!(schedule.blocks.len(), 2);
        assert_eq!(schedule.blocks[0].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[0].repair_esis, vec![2, 3, 4]);
        assert_eq!(schedule.blocks[1].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[1].repair_esis, vec![2, 3, 4]);
        assert_eq!(schedule.total_symbol_count(), 10);
    }

    #[test]
    fn donor_count_one_emission_stream_matches_single_source_order() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 3).expect("schedule");
        let emissions = schedule
            .symbol_emissions()
            .into_iter()
            .map(|emission| {
                (
                    emission.geometry.entry_index,
                    emission.geometry.source_block_number,
                    emission.esi,
                    emission.kind,
                    emission.donor_index,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            emissions,
            vec![
                (0, 0, 0, BondedDonorSymbolKind::Source, 0),
                (0, 0, 1, BondedDonorSymbolKind::Source, 0),
                (0, 0, 2, BondedDonorSymbolKind::Repair, 0),
                (0, 0, 3, BondedDonorSymbolKind::Repair, 0),
                (0, 0, 4, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 0, BondedDonorSymbolKind::Source, 0),
                (0, 1, 1, BondedDonorSymbolKind::Source, 0),
                (0, 1, 2, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 3, BondedDonorSymbolKind::Repair, 0),
                (0, 1, 4, BondedDonorSymbolKind::Repair, 0),
            ],
            "donor_count=1 must preserve the single-source source-then-repair ESI stream"
        );
    }

    #[test]
    fn donor_symbol_emission_exposes_runtime_symbol_identity() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);
        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 1).expect("schedule");

        let source = schedule
            .symbol_emissions()
            .into_iter()
            .find(|emission| emission.kind == BondedDonorSymbolKind::Source)
            .expect("source emission");
        let repair = schedule
            .symbol_emissions()
            .into_iter()
            .find(|emission| emission.kind == BondedDonorSymbolKind::Repair)
            .expect("repair emission");

        assert_eq!(
            source.symbol_id(),
            SymbolId::new(
                source.geometry.object_id,
                source.geometry.source_block_number,
                0
            )
        );
        assert_eq!(source.symbol_kind(), SymbolKind::Source);
        assert!(
            source
                .symbol_id()
                .is_source(u32::from(source.geometry.source_symbols))
        );

        assert_eq!(
            repair.symbol_id(),
            SymbolId::new(
                repair.geometry.object_id,
                repair.geometry.source_block_number,
                2
            )
        );
        assert_eq!(repair.symbol_kind(), SymbolKind::Repair);
        assert!(
            repair
                .symbol_id()
                .is_repair(u32::from(repair.geometry.source_symbols))
        );
    }

    #[test]
    fn donor_symbol_emission_iterator_matches_materialized_stream() {
        let descriptor = descriptor();
        let donor = DonorAssignment::new_static(1, 3, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &donor, 8).expect("schedule");
        let streamed = schedule.iter_symbol_emissions().collect::<Vec<_>>();

        assert_eq!(streamed, schedule.symbol_emissions());
        for block in &schedule.blocks {
            assert_eq!(
                block
                    .iter_symbol_emissions(schedule.donor_index)
                    .collect::<Vec<_>>(),
                block.symbol_emissions(schedule.donor_index)
            );
        }
    }

    #[test]
    fn donor_symbol_emissions_are_residue_filtered_and_source_first() {
        let descriptor = descriptor();
        let donor = DonorAssignment::new_static(1, 3, vec![endpoint()], None);

        let schedule = schedule_bonded_donor_spray(&descriptor, &donor, 8).expect("schedule");
        let emissions = schedule.symbol_emissions();

        assert!(!emissions.is_empty());
        for emission in &emissions {
            assert_eq!(emission.donor_index, 1);
            assert!(donor.owns_esi(emission.esi));
            assert_eq!(emission.esi % 3, 1);
            assert_eq!(emission.stagger_delay_slots, 1);
            match emission.kind {
                BondedDonorSymbolKind::Source => {
                    assert!(emission.esi < u32::from(emission.geometry.source_symbols));
                }
                BondedDonorSymbolKind::Repair => {
                    assert!(emission.esi >= u32::from(emission.geometry.source_symbols));
                }
            }
        }

        for block in &schedule.blocks {
            let kinds = block
                .symbol_emissions(schedule.donor_index)
                .into_iter()
                .map(|emission| emission.kind)
                .collect::<Vec<_>>();
            let first_repair = kinds
                .iter()
                .position(|kind| *kind == BondedDonorSymbolKind::Repair);
            let last_source = kinds
                .iter()
                .rposition(|kind| *kind == BondedDonorSymbolKind::Source);
            if let (Some(first_repair), Some(last_source)) = (first_repair, last_source) {
                assert!(
                    last_source < first_repair,
                    "source symbols must precede repair symbols within each block"
                );
            }
        }
    }

    #[test]
    fn windowed_schedule_overrides_residue_and_keeps_source_first() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_windowed(
            1,
            3,
            vec![EsiWindow::new(0, 2), EsiWindow::new(4, 5)],
            vec![endpoint()],
            None,
        );

        let schedule = schedule_bonded_donor_spray(&descriptor, &assignment, 4).expect("schedule");

        assert_eq!(schedule.blocks[0].source_esis, vec![0, 1]);
        assert_eq!(schedule.blocks[0].repair_esis, vec![4]);
        assert_eq!(schedule.blocks[0].ordered_esis(), vec![0, 1, 4]);
        assert_eq!(schedule.blocks[0].stagger_delay_slots, 1);
    }

    #[test]
    fn repair_continuation_resumes_after_initial_window_without_duplicates() {
        let descriptor = descriptor();
        let donor0 = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let donor1 = DonorAssignment::new_static(1, 2, vec![endpoint()], None);
        let schedule0 =
            schedule_bonded_donor_spray(&descriptor, &donor0, 4).expect("donor 0 schedule");
        let schedule1 =
            schedule_bonded_donor_spray(&descriptor, &donor1, 4).expect("donor 1 schedule");

        assert_eq!(schedule0.blocks[0].repair_esis, vec![2, 4]);
        assert_eq!(schedule0.blocks[0].next_repair_esi, 6);
        assert_eq!(schedule1.blocks[0].repair_esis, vec![3, 5]);
        assert_eq!(schedule1.blocks[0].next_repair_esi, 6);

        let repair0 = schedule0.blocks[0]
            .repair_continuation(&donor0, 3)
            .expect("donor 0 continuation");
        let repair1 = schedule1.blocks[0]
            .repair_continuation(&donor1, 3)
            .expect("donor 1 continuation");

        assert_eq!(repair0.repair_esis, vec![6, 8, 10]);
        assert_eq!(repair0.next_repair_esi, 12);
        assert_eq!(repair1.repair_esis, vec![7, 9, 11]);
        assert_eq!(repair1.next_repair_esi, 13);

        for esi in &repair0.repair_esis {
            assert!(!schedule0.blocks[0].repair_esis.contains(esi));
            assert_eq!(esi % 2, 0);
        }
        for esi in &repair1.repair_esis {
            assert!(!schedule1.blocks[0].repair_esis.contains(esi));
            assert_eq!(esi % 2, 1);
        }
    }

    #[test]
    fn donor_control_loop_need_more_resumes_from_initial_spray_cursor() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let schedule =
            schedule_bonded_donor_spray(&descriptor, &assignment, 4).expect("initial schedule");
        let geometry = schedule.blocks[0].geometry;
        let mut control =
            BondedDonorControlLoop::from_spray_schedule(assignment.clone(), &schedule)
                .expect("control loop");

        let first = control
            .handle_event(BondedDonorControlEvent::NeedMore {
                geometry,
                requested_symbols: 3,
            })
            .expect("first need-more");
        let first_repair = first.repair_schedule.expect("repair schedule");

        assert_eq!(first_repair.repair_esis, vec![6, 8, 10]);
        assert_eq!(first_repair.next_repair_esi, 12);
        assert_eq!(first_repair.stagger_delay_slots, 0);
        assert_eq!(
            first.trace,
            BondedDonorControlTrace {
                event: BondedDonorControlTraceEvent::NeedMore,
                donor_index: 0,
                donor_count: 2,
                entry_index: Some(0),
                source_block_number: Some(0),
                requested_symbols: 3,
                emitted_symbols: 3,
                next_repair_esi: Some(12),
                closed: false,
            }
        );

        let second = control
            .handle_event(BondedDonorControlEvent::NeedMore {
                geometry,
                requested_symbols: 2,
            })
            .expect("second need-more");
        let second_repair = second.repair_schedule.expect("second repair schedule");

        assert_eq!(second_repair.repair_esis, vec![12, 14]);
        assert_eq!(second_repair.next_repair_esi, 16);
        assert_eq!(control.handled_events(), 2);
        assert!(!control.is_closed());
        assert_eq!(control.assignment(), &assignment);
    }

    #[test]
    fn donor_control_loop_close_latches_and_ignores_late_need_more() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(1, 2, vec![endpoint()], None);
        let schedule =
            schedule_bonded_donor_spray(&descriptor, &assignment, 4).expect("initial schedule");
        let geometry = schedule.blocks[0].geometry;
        let mut control =
            BondedDonorControlLoop::from_spray_schedule(assignment, &schedule).expect("control");

        let close = control
            .handle_event(BondedDonorControlEvent::Close)
            .expect("close");

        assert!(control.is_closed());
        assert_eq!(close.repair_schedule, None);
        assert_eq!(close.trace.event, BondedDonorControlTraceEvent::Close);
        assert!(close.trace.closed);

        let late = control
            .handle_event(BondedDonorControlEvent::NeedMore {
                geometry,
                requested_symbols: 3,
            })
            .expect("late need-more");

        assert_eq!(late.repair_schedule, None);
        assert_eq!(
            late.trace.event,
            BondedDonorControlTraceEvent::IgnoredAfterClose
        );
        assert_eq!(late.trace.requested_symbols, 3);
        assert_eq!(late.trace.emitted_symbols, 0);
        assert!(late.trace.closed);
        assert_eq!(control.handled_events(), 2);
    }

    #[test]
    fn donor_control_loop_rejects_schedule_for_another_donor() {
        let descriptor = descriptor();
        let donor0 = DonorAssignment::new_static(0, 2, vec![endpoint()], None);
        let donor1 = DonorAssignment::new_static(1, 2, vec![endpoint()], None);
        let schedule0 =
            schedule_bonded_donor_spray(&descriptor, &donor0, 4).expect("donor 0 schedule");

        assert_eq!(
            BondedDonorControlLoop::from_spray_schedule(donor1, &schedule0),
            Err(BondScheduleError::ControlScheduleDonorMismatch {
                assignment_donor_index: 1,
                schedule_donor_index: 0,
            })
        );
    }

    #[test]
    fn windowed_repair_continuation_requires_enough_receiver_window() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignment =
            DonorAssignment::new_windowed(0, 3, vec![EsiWindow::new(6, 8)], vec![endpoint()], None);

        let repair =
            schedule_bonded_repair_continuation(&assignment, geometry, 6, 2).expect("windowed");
        assert_eq!(repair.repair_esis, vec![6, 7]);
        assert_eq!(repair.next_repair_esi, 8);

        assert_eq!(
            schedule_bonded_repair_continuation(&assignment, geometry, 6, 3),
            Err(BondScheduleError::InsufficientRepairWindow {
                entry_index: 0,
                source_block_number: 0,
                requested_symbols: 3,
                scheduled_symbols: 2,
            })
        );
    }

    #[test]
    fn repair_continuation_rejects_source_esi_start() {
        let descriptor = descriptor();
        let geometry = descriptor
            .entry_block_geometry(0, 0)
            .expect("descriptor block geometry");
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        assert_eq!(
            schedule_bonded_repair_continuation(&assignment, geometry, 1, 1),
            Err(BondScheduleError::RepairStartBeforeSource {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                first_repair_esi: 1,
            })
        );
    }

    #[test]
    fn spray_schedule_fails_closed_for_invalid_inputs() {
        let valid_descriptor = descriptor();
        let invalid_assignment = DonorAssignment::new_static(2, 2, vec![endpoint()], None);
        assert!(matches!(
            schedule_bonded_donor_spray(&valid_descriptor, &invalid_assignment, 1),
            Err(BondScheduleError::InvalidAssignment(
                DonorAssignmentError::InvalidPartition(
                    EsiPartitionError::DonorIndexOutOfRange { .. }
                )
            ))
        ));

        let mut bad_descriptor = descriptor();
        bad_descriptor.total_bytes += 1;
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);
        assert!(matches!(
            schedule_bonded_donor_spray(&bad_descriptor, &assignment, 1),
            Err(BondScheduleError::InvalidDescriptor(
                BondProofError::TotalBytesMismatch { .. }
            ))
        ));
    }

    #[test]
    fn spray_schedule_rejects_repair_budget_overflow() {
        let descriptor = descriptor();
        let assignment = DonorAssignment::new_static(0, 1, vec![endpoint()], None);

        let err = schedule_bonded_donor_spray(&descriptor, &assignment, u32::MAX)
            .expect_err("overflowing repair ESI budget must fail closed");

        assert_eq!(
            err,
            BondScheduleError::RepairBudgetOverflow {
                entry_index: 0,
                source_block_number: 0,
                source_symbols: 2,
                repair_symbols: u32::MAX,
            }
        );
    }

    #[test]
    fn invalid_assignment_shapes_fail_closed() {
        let no_endpoint = DonorAssignment::new_static(0, 1, Vec::new(), None);
        assert!(matches!(
            no_endpoint.validate(),
            Err(DonorAssignmentError::NoReceiverEndpoints)
        ));

        let bad_index = DonorAssignment::new_static(3, 3, vec![endpoint()], None);
        assert!(matches!(
            bad_index.validate(),
            Err(DonorAssignmentError::InvalidPartition(
                EsiPartitionError::DonorIndexOutOfRange { .. }
            ))
        ));

        let overlapping = DonorAssignment::new_windowed(
            0,
            1,
            vec![EsiWindow::new(4, 9), EsiWindow::new(8, 10)],
            vec![endpoint()],
            None,
        );
        assert!(matches!(
            overlapping.validate(),
            Err(DonorAssignmentError::OverlappingEsiWindows { .. })
        ));

        let empty_key = DonorAssignment::new_static(
            0,
            1,
            vec![endpoint()],
            Some(BondAuthKeyRef::EnvVar(" ".to_string())),
        );
        assert!(matches!(
            empty_key.validate(),
            Err(DonorAssignmentError::EmptyAuthKeyRef)
        ));
    }

    #[test]
    fn bonded_symbol_auth_accepts_only_verified_tags() {
        let ctx = SecurityContext::for_testing(9);
        let other = SecurityContext::for_testing(10);
        let symbol = symbol();
        let good_tag = *ctx.sign_symbol(&symbol).tag();
        let bad_tag = *other.sign_symbol(&symbol).tag();

        assert!(matches!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(good_tag)),
            BondedSymbolAuthVerdict::Accepted(_)
        ));
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(bad_tag)),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::InvalidTag)
        );
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, Some(AuthenticationTag::zero())),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::ZeroTag)
        );
        assert_eq!(
            verify_bonded_symbol_tag(&ctx, &symbol, None),
            BondedSymbolAuthVerdict::Rejected(BondedSymbolRejectReason::MissingTag)
        );
    }
