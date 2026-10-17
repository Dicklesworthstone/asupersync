    use super::{
        CapacityTicketReceiptStatus, CapacityTicketRequest, CapacityTicketWorkKind,
        request_capacity_ticket, request_capacity_ticket_from_budget,
    };
    use crate::types::{
        Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetDimension,
        CapabilityBudgetRefusal, CapabilityBudgetRequirements, RegionId, TaskId,
    };
    use core::num::NonZeroU64;

    fn admission_sequence(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test admission sequences are non-zero")
    }

    #[test]
    fn cx_ticket_admission_uses_context_owner_and_fail_closed_requirements() {
        let cx = crate::cx::Cx::for_testing();
        let request = CapacityTicketRequest::agent_swarm_admission(
            CapabilityBudget::new()
                .with_memory_bytes(1024)
                .with_cpu_units(4)
                .with_artifact_bytes(256),
            "swarm admission",
        );

        let ticket =
            request_capacity_ticket(&cx, admission_sequence(1), request).expect("ticket admits");

        assert_eq!(ticket.owner_region(), cx.region_id());
        assert_eq!(ticket.owner_task(), cx.task_id());
        assert_eq!(ticket.id().lineage(), 0);
        assert_eq!(
            ticket.work_kind(),
            CapacityTicketWorkKind::AgentSwarmAdmission
        );
        let _ = ticket.release();

        let err = request_capacity_ticket(
            &cx,
            admission_sequence(2),
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_cpu_units(4)
                    .with_artifact_bytes(256),
                "missing memory",
            ),
        )
        .expect_err("missing required memory fails closed");
        assert_eq!(
            err.budget_refusal(),
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::MemoryBytes)
        );
    }

    #[test]
    fn split_and_lend_inherit_parent_budget_and_keep_explicit_owner() {
        let owner_region = RegionId::new_for_test(7, 1);
        let owner_task = TaskId::new_for_test(7, 0);
        let mut parent = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            admission_sequence(1),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(4096)
                    .with_cpu_units(8)
                    .with_artifact_bytes(512),
                "root",
            ),
        )
        .expect("parent admits");

        let split = parent
            .split(
                CapabilityBudget::new()
                    .with_memory_bytes(8192)
                    .with_cpu_units(2)
                    .with_artifact_bytes(128),
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_cpu_units()
                    .require_artifact_bytes(),
                "split child",
            )
            .expect("split tightens by meet");
        assert_eq!(split.granted().memory_bytes, Some(4096));
        assert_eq!(split.granted().cpu_units, Some(2));
        assert_eq!(split.granted().artifact_bytes, Some(128));
        assert_eq!(split.parent_id(), Some(parent.id()));
        assert_eq!(split.owner_region(), owner_region);

        let borrower_region = RegionId::new_for_test(8, 1);
        let borrower_task = TaskId::new_for_test(8, 0);
        let lent = parent
            .lend_to_for(
                borrower_region,
                borrower_task,
                CapacityTicketWorkKind::ProofArtifact,
                CapabilityBudget::new()
                    .with_memory_bytes(2048)
                    .with_cpu_units(1)
                    .with_artifact_bytes(256)
                    .with_cleanup_budget(Budget::MINIMAL),
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_cpu_units()
                    .require_artifact_bytes()
                    .require_cleanup(),
                "borrowed proof",
            )
            .expect("lend admits under parent");
        assert_eq!(lent.owner_region(), borrower_region);
        assert_eq!(lent.owner_task(), borrower_task);
        assert_eq!(lent.parent_id(), Some(parent.id()));
        assert_eq!(lent.work_kind(), CapacityTicketWorkKind::ProofArtifact);

        let _ = parent.unreleased_receipt();
        let _ = split.release();
        let _ = lent.revoke(CancelReason::new(CancelKind::User));
    }

    #[test]
    fn receipts_distinguish_release_revoke_and_unreleased_audit() {
        let mut release_ticket = request_capacity_ticket_from_budget(
            RegionId::new_for_test(9, 1),
            TaskId::new_for_test(9, 0),
            admission_sequence(1),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(1024)
                    .with_cpu_units(1)
                    .with_artifact_bytes(64),
                "receipt",
            ),
        )
        .expect("ticket admits");
        let revoke_ticket = request_capacity_ticket_from_budget(
            RegionId::new_for_test(9, 1),
            TaskId::new_for_test(9, 0),
            admission_sequence(2),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(1024)
                    .with_cpu_units(1)
                    .with_artifact_bytes(64),
                "receipt",
            ),
        )
        .expect("second ticket admits");

        let audit = release_ticket.unreleased_receipt();
        assert_eq!(audit.status, CapacityTicketReceiptStatus::Unreleased);
        assert!(!audit.obligation_leak_free);
        assert!(audit.no_ambient_authority);

        let released = release_ticket.release();
        assert_eq!(released.status, CapacityTicketReceiptStatus::Released);
        assert!(released.obligation_leak_free);
        assert!(released.cancel_reason.is_none());

        let revoked = revoke_ticket.revoke(CancelReason::new(CancelKind::User));
        assert_eq!(revoked.status, CapacityTicketReceiptStatus::Revoked);
        assert!(revoked.obligation_leak_free);
        assert_eq!(
            revoked.cancel_reason.as_ref().map(|reason| reason.kind),
            Some(CancelKind::User)
        );
    }

    #[test]
    fn sibling_and_cousin_children_get_distinct_ticket_ids() {
        // br-asupersync-audit-followups-2026-06-12-7tcipb item 1: two split()s
        // of the same parent previously minted identical CapacityTicketIds
        // (same owner + lineage depth). A receipt consumer matching releases by
        // ticket_id would then mis-close one sibling and silently mask the
        // other's unreleased-ticket obligation leak. Every derived ticket must
        // now carry a distinct id — for direct siblings AND for cousins at the
        // same depth (which share owner and lineage but descend from distinct
        // parents).
        let owner_region = RegionId::new_for_test(13, 1);
        let owner_task = TaskId::new_for_test(13, 0);
        let mut parent = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            admission_sequence(1),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(8192)
                    .with_cpu_units(8)
                    .with_artifact_bytes(1024),
                "parent",
            ),
        )
        .expect("parent admits");

        let budget = CapabilityBudget::new()
            .with_memory_bytes(1024)
            .with_cpu_units(1)
            .with_artifact_bytes(64);
        let reqs = CapabilityBudgetRequirements::new()
            .require_memory_bytes()
            .require_cpu_units()
            .require_artifact_bytes();

        let mut first = parent
            .split(budget, reqs, "first child")
            .expect("first split admits");
        let mut second = parent
            .split(budget, reqs, "second child")
            .expect("second split admits");

        // Same owner, same lineage depth, same request shape...
        assert_eq!(first.owner_region(), second.owner_region());
        assert_eq!(first.owner_task(), second.owner_task());
        assert_eq!(first.id().lineage(), 1);
        assert_eq!(second.id().lineage(), 1);
        // ...but the ids (and their sibling nonces) MUST differ.
        assert_ne!(
            first.id(),
            second.id(),
            "sibling splits must mint distinct capacity-ticket ids"
        );
        assert_ne!(first.id().nonce(), second.id().nonce());
        // Both still link back to the same parent.
        assert_eq!(first.parent_id(), Some(parent.id()));
        assert_eq!(second.parent_id(), Some(parent.id()));

        // Cousins: the first grandchild of each distinct parent shares owner and
        // lineage depth (2) but must still mint distinct ids, because the parent
        // nonce is folded into every child nonce.
        let mut g1 = first
            .split(budget, reqs, "grandchild of first")
            .expect("admits");
        let mut g2 = second
            .split(budget, reqs, "grandchild of second")
            .expect("admits");
        assert_eq!(g1.id().lineage(), 2);
        assert_eq!(g2.id().lineage(), 2);
        assert_ne!(
            g1.id(),
            g2.id(),
            "cousins at the same depth must mint distinct capacity-ticket ids"
        );

        // Determinism: re-running the identical split sequence reproduces the
        // same ids (the fix introduces no ambient clock / RNG / global counter).
        let mut parent_replay = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            admission_sequence(1),
            CapabilityBudget::UNSPECIFIED,
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(8192)
                    .with_cpu_units(8)
                    .with_artifact_bytes(1024),
                "parent",
            ),
        )
        .expect("parent admits");
        let first_replay = parent_replay
            .split(budget, reqs, "first child")
            .expect("first split admits");
        assert_eq!(first.id(), first_replay.id());

        let _ = parent.unreleased_receipt();
        let _ = parent_replay.unreleased_receipt();
        let _ = first_replay.release();
        let _ = g1.unreleased_receipt();
        let _ = g2.unreleased_receipt();
        let _ = first.release();
        let _ = second.unreleased_receipt();
    }

    #[test]
    fn root_tickets_use_admission_sequence_to_avoid_same_owner_collisions() {
        let owner_region = RegionId::new_for_test(14, 1);
        let owner_task = TaskId::new_for_test(14, 0);
        let request = || {
            CapacityTicketRequest::agent_swarm_admission(
                CapabilityBudget::new()
                    .with_memory_bytes(1024)
                    .with_cpu_units(1)
                    .with_artifact_bytes(64),
                "root",
            )
        };

        let first = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            admission_sequence(1),
            CapabilityBudget::UNSPECIFIED,
            request(),
        )
        .expect("first root admits");
        let second = request_capacity_ticket_from_budget(
            owner_region,
            owner_task,
            admission_sequence(2),
            CapabilityBudget::UNSPECIFIED,
            request(),
        )
        .expect("second root admits");

        assert_eq!(first.id().lineage(), 0);
        assert_eq!(second.id().lineage(), 0);
        assert_eq!(first.owner_region(), second.owner_region());
        assert_eq!(first.owner_task(), second.owner_task());
        assert_ne!(first.id(), second.id());
        assert_ne!(first.id().nonce(), second.id().nonce());

        let _ = first.release();
        let _ = second.release();
    }
