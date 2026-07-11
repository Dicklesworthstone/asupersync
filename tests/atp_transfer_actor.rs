#![allow(dead_code)]

use asupersync::atp::actor::{
    TransferActorId, TransferActorTopology, TransferChildRole, TransferObligationId,
    TransferRegionId,
};
use asupersync::atp::transfer::{
    IdempotencyKey, ObligationOutcome, PeerCapabilities, TransferActor, TransferCancelPhase,
    TransferCommand, TransferCommandKind, TransferFailureKind, TransferId, TransferManifestRef,
    TransferState,
};

fn command(key: u128, kind: TransferCommandKind) -> TransferCommand {
    TransferCommand::new(IdempotencyKey::new(key), kind)
}

fn build_actor() -> TransferActor {
    let topology = TransferActorTopology::new(TransferRegionId::new(10), TransferRegionId::new(20))
        .with_child(TransferRegionId::new(30), TransferChildRole::PathRace)
        .with_child(TransferRegionId::new(31), TransferChildRole::Writer)
        .with_child(TransferRegionId::new(32), TransferChildRole::Relay)
        .with_child(TransferRegionId::new(33), TransferChildRole::Mailbox)
        .with_child(TransferRegionId::new(34), TransferChildRole::Swarm)
        .with_child(TransferRegionId::new(35), TransferChildRole::Finalizer);

    TransferActor::new(
        TransferActorId::new(1),
        TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]),
        TransferManifestRef {
            schema_version: 1,
            merkle_root: [4; 32],
            object_count: 8,
        },
        PeerCapabilities {
            relay: true,
            mailbox: true,
            swarm: true,
            max_inflight_obligations: 4,
        },
        topology,
    )
    .expect("valid transfer actor topology")
}

#[test]
fn direct_transfer_actor_commits_without_obligation_leaks() {
    let mut actor = build_actor();
    actor.progress.verified_bytes = 8192;

    actor
        .apply(command(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(1),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            2,
            TransferCommandKind::Start {
                path_id: 42,
                obligation: TransferObligationId::new(2),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            3,
            TransferCommandKind::Commit {
                obligation: TransferObligationId::new(3),
            },
        ))
        .unwrap();

    assert_eq!(actor.state(), TransferState::Committed);
    assert_eq!(actor.progress.selected_path, Some(42));
    assert_eq!(actor.progress.committed_bytes, 8192);
    assert_eq!(actor.open_obligation_count(), 0);
    assert_eq!(
        actor.settled_obligations(),
        &[
            (TransferObligationId::new(1), ObligationOutcome::Committed),
            (TransferObligationId::new(2), ObligationOutcome::Committed),
            (TransferObligationId::new(3), ObligationOutcome::Committed),
        ]
    );
}

#[test]
fn relay_mailbox_swarm_topologies_are_explicit_states() {
    let mut actor = build_actor();

    actor
        .apply(command(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(10),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            2,
            TransferCommandKind::Start {
                path_id: 7,
                obligation: TransferObligationId::new(11),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            3,
            TransferCommandKind::ForwardRelay {
                obligation: TransferObligationId::new(12),
            },
        ))
        .unwrap();
    assert_eq!(actor.state(), TransferState::RelayForwarded);

    actor.apply(command(4, TransferCommandKind::Pause)).unwrap();
    actor
        .apply(command(
            5,
            TransferCommandKind::Resume {
                journal_seq: actor.journal().last().unwrap().seq,
                obligation: TransferObligationId::new(13),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            6,
            TransferCommandKind::StoreMailbox {
                obligation: TransferObligationId::new(14),
            },
        ))
        .unwrap();
    assert_eq!(actor.state(), TransferState::MailboxStored);

    actor
        .apply(command(
            7,
            TransferCommandKind::Resume {
                journal_seq: actor.journal().last().unwrap().seq,
                obligation: TransferObligationId::new(15),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            8,
            TransferCommandKind::JoinSwarm {
                obligation: TransferObligationId::new(16),
            },
        ))
        .unwrap();

    assert_eq!(actor.state(), TransferState::SwarmAssisted);
    assert_eq!(actor.open_obligation_count(), 0);
}

#[test]
fn public_topology_and_command_surface_is_exercised() {
    assert_eq!(TransferActorId::new(99).get(), 99);
    assert_eq!(TransferObligationId::new(44).get(), 44);
    assert_eq!(TransferChildRole::Repair.code(), "repair");

    let transfer_id = TransferId::new([9; 32]);
    assert_eq!(transfer_id.as_bytes(), [9; 32]);

    let mut actor = build_actor();
    actor
        .apply(command(
            1,
            TransferCommandKind::Accept {
                obligation: TransferObligationId::new(1),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            2,
            TransferCommandKind::Start {
                path_id: 11,
                obligation: TransferObligationId::new(2),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            3,
            TransferCommandKind::Commit {
                obligation: TransferObligationId::new(3),
            },
        ))
        .unwrap();
    actor
        .apply(command(
            4,
            TransferCommandKind::Seed {
                obligation: TransferObligationId::new(4),
            },
        ))
        .unwrap();
    assert_eq!(actor.state(), TransferState::Seeded);

    for phase in [
        TransferCancelPhase::Draining,
        TransferCancelPhase::Finalized,
    ] {
        let mut actor = build_actor();
        actor
            .apply(command(
                10 + u128::from(phase as u8),
                TransferCommandKind::Cancel { phase },
            ))
            .unwrap();
        assert_eq!(actor.state(), TransferState::Cancelling);
    }

    for failure in [
        TransferFailureKind::Verification,
        TransferFailureKind::ResourceBudget,
    ] {
        let mut actor = build_actor();
        actor
            .apply(command(
                20 + failure as u128,
                TransferCommandKind::Fail { kind: failure },
            ))
            .unwrap();
        assert_eq!(actor.state(), TransferState::Failed);
    }
}
