    use super::*;

    #[test]
    fn checked_transfer_projection_advances_both_epochs_once() {
        for cross_region in [false, true] {
            for eager_terminal in [false, true] {
                let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x28_E0));
                let source_region = lab.state.create_root_region(Budget::INFINITE);
                let destination_region = if cross_region {
                    lab.state
                        .create_child_region(source_region, Budget::INFINITE)
                        .unwrap()
                } else {
                    source_region
                };
                let (source, _source_join) = lab
                    .state
                    .create_task(
                        source_region,
                        Budget::INFINITE,
                        std::future::pending::<()>(),
                    )
                    .unwrap();
                let (destination, _destination_join) = lab
                    .state
                    .create_task(
                        destination_region,
                        Budget::INFINITE,
                        std::future::pending::<()>(),
                    )
                    .unwrap();
                let source_cx = lab.state.task(source).unwrap().cx.clone().unwrap();
                let destination_cx = lab.state.task(destination).unwrap().cx.clone().unwrap();
                let token = source_cx
                    .try_register_obligation_checked(ObligationKind::Lease, source)
                    .unwrap()
                    .unwrap();
                assert_eq!(lab.state.drain_obligation_posts(1), 1);
                let id = lab.state.obligations.sorted_pending_ids_for_holder(source)[0];
                let before = (
                    lab.state.region_table_epoch,
                    lab.state.obligation_table_epoch,
                );
                let token = token.try_transfer(&destination_cx).unwrap();
                assert_eq!(
                    (
                        lab.state.region_table_epoch,
                        lab.state.obligation_table_epoch
                    ),
                    before
                );
                if eager_terminal {
                    lab.state.commit_obligation(id).unwrap();
                    assert!(!token.commit());
                    assert_eq!(lab.state.region_table_epoch, before.0.next());
                    assert_eq!(lab.state.obligation_table_epoch, before.1.next().next());
                } else {
                    assert_eq!(lab.state.drain_obligation_posts(1), 1);
                    assert_eq!(lab.state.region_table_epoch, before.0.next());
                    assert_eq!(lab.state.obligation_table_epoch, before.1.next());
                    assert_eq!(lab.state.obligation(id).unwrap().holder, destination);
                    assert!(token.commit());
                    assert_eq!(lab.state.drain_obligation_posts(1), 1);
                }
                let after = (
                    lab.state.region_table_epoch,
                    lab.state.obligation_table_epoch,
                );
                assert_eq!(
                    lab.state.drain_obligation_posts(64),
                    usize::from(eager_terminal)
                );
                assert_eq!(
                    (
                        lab.state.region_table_epoch,
                        lab.state.obligation_table_epoch
                    ),
                    after,
                    "late handoff receipt cannot advance either epoch again"
                );
                assert_eq!(lab.state.pending_obligation_count(), 0);
                assert_eq!(
                    lab.state
                        .obligation_gateway()
                        .unwrap()
                        .mailbox()
                        .stats()
                        .refused,
                    0
                );
                eprintln!(
                    "handoff epochs cross_region={cross_region} eager_terminal={eager_terminal} before={before:?} after={after:?} id={id:?}"
                );
            }
        }
    }

    /// The region, task and obligation tables each advance their own epoch
    /// counter once per mutation, so the counters are not comparable across
    /// tables. One task committing several obligations must not record
    /// cross-module "violations" (br-asupersync-0jroxu).
    #[test]
    fn independent_table_epochs_record_no_cross_module_violations() {
        let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x0_3E0));
        let region = lab.state.create_root_region(Budget::INFINITE);
        let (task, _join) = lab
            .state
            .create_task(region, Budget::INFINITE, std::future::pending::<()>())
            .unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        for _ in 0..8 {
            let token = cx
                .try_register_obligation_checked(ObligationKind::Lease, task)
                .unwrap()
                .unwrap();
            assert_eq!(lab.state.drain_obligation_posts(1), 1);
            let id = lab.state.obligations.sorted_pending_ids_for_holder(task)[0];
            lab.state.commit_obligation(id).unwrap();
            assert!(!token.commit());
        }
        assert!(
            lab.state
                .obligation_table_epoch
                .is_after(lab.state.task_table_epoch),
            "the workload must drive the obligation counter past the task counter"
        );
        assert_eq!(lab.state.epoch_tracker.violation_count(), 0);
    }
