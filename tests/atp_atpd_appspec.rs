mod asupersync {
    pub use ::asupersync::*;
}

#[path = "../src/atp/atpd/mod.rs"]
mod atpd;
#[path = "../src/atp/supervision/mod.rs"]
mod supervision;

use atpd::{AtpdAppSpec, AtpdLifecycleAction, AtpdLifecyclePhase};
use supervision::{AtpdChildRole, AtpdRegionId, AtpdRestartPolicy, AtpdStopAction};

#[test]
fn default_atpd_appspec_has_deterministic_start_and_stop_order() {
    let compiled = AtpdAppSpec::default_daemon(AtpdRegionId::new(100))
        .compile()
        .unwrap();

    assert_eq!(compiled.name, "atpd");
    assert_eq!(compiled.lifecycle, AtpdLifecyclePhase::Compiled);
    assert_eq!(
        [
            AtpdLifecyclePhase::Constructed,
            AtpdLifecyclePhase::Starting,
            AtpdLifecyclePhase::Running,
            AtpdLifecyclePhase::Failed,
        ]
        .len(),
        4
    );
    assert_eq!(
        compiled.start_order,
        vec![
            AtpdChildRole::IdentityManager,
            AtpdChildRole::PeerDirectory,
            AtpdChildRole::PathManager,
            AtpdChildRole::ReceiveService,
            AtpdChildRole::TransferSupervisor,
            AtpdChildRole::CacheSeeder,
            AtpdChildRole::InboxMailbox,
            AtpdChildRole::DiagnosticsEndpoint,
        ]
    );

    let start_events = compiled.start_events();
    assert_eq!(start_events.len(), compiled.start_order.len());
    assert_eq!(start_events[0].action, AtpdLifecycleAction::StartChild);
    assert_eq!(start_events[0].phase, AtpdLifecyclePhase::Starting);

    let mut expected_stop = compiled.start_order.clone();
    expected_stop.reverse();
    assert_eq!(compiled.stop_order, expected_stop);
    assert!(compiled.topology.no_detached_children());
}

#[test]
fn restart_policy_matches_child_criticality() {
    let compiled = AtpdAppSpec::default_daemon(AtpdRegionId::new(1))
        .with_relay()
        .with_rendezvous()
        .compile()
        .unwrap();

    assert_eq!(
        compiled.restart_policy(AtpdChildRole::IdentityManager),
        Some(AtpdRestartPolicy::CriticalEscalate)
    );
    assert!(matches!(
        compiled.restart_policy(AtpdChildRole::TransferSupervisor),
        Some(AtpdRestartPolicy::Restart {
            max_restarts: 3,
            window_secs: 60,
        })
    ));
    assert_eq!(
        compiled.restart_policy(AtpdChildRole::RelayService),
        Some(AtpdRestartPolicy::DisableOptional)
    );
    assert_eq!(
        compiled.restart_policy(AtpdChildRole::RendezvousService),
        Some(AtpdRestartPolicy::DisableOptional)
    );
}

#[test]
fn shutdown_drains_transfers_and_joins_root() {
    let compiled = AtpdAppSpec::default_daemon(AtpdRegionId::new(7))
        .compile()
        .unwrap();
    let events = compiled.shutdown_events();

    let transfer_drain = events.iter().find(|event| {
        event.role == Some(AtpdChildRole::TransferSupervisor)
            && event.action == AtpdLifecycleAction::DrainTransfers
    });
    assert!(transfer_drain.is_some());
    assert_eq!(events.last().unwrap().action, AtpdLifecycleAction::JoinRoot);
    assert_eq!(events.last().unwrap().phase, AtpdLifecyclePhase::Stopped);
    assert!(compiled.shutdown_covers_every_child());
}

#[test]
fn all_children_have_root_scoped_name_leases() {
    let compiled = AtpdAppSpec::default_daemon(AtpdRegionId::new(7))
        .with_relay()
        .with_rendezvous()
        .compile()
        .unwrap();

    assert!(compiled.has_root_scoped_name_leases());
    for child in &compiled.topology.children {
        assert_eq!(child.lease.name, child.role.service_name());
    }
}

#[test]
fn topology_rejects_detached_worker_and_missing_transfer_drain() {
    let mut detached = AtpdAppSpec::default_daemon(AtpdRegionId::new(10));
    detached.children[0].parent_region = AtpdRegionId::new(999);
    assert!(detached.compile().is_err());

    let mut missing_drain = AtpdAppSpec::default_daemon(AtpdRegionId::new(10));
    let transfer = missing_drain
        .children
        .iter_mut()
        .find(|child| child.role == AtpdChildRole::TransferSupervisor)
        .unwrap();
    transfer
        .stop_actions
        .retain(|action| !matches!(action, AtpdStopAction::DrainTransfers { .. }));

    assert!(missing_drain.compile().is_err());
}

#[test]
fn optional_roles_are_added_after_core_dependencies() {
    let compiled = AtpdAppSpec::default_daemon(AtpdRegionId::new(50))
        .with_relay()
        .with_rendezvous()
        .compile()
        .unwrap();

    let identity_index = compiled
        .start_order
        .iter()
        .position(|role| *role == AtpdChildRole::IdentityManager)
        .unwrap();
    let relay_index = compiled
        .start_order
        .iter()
        .position(|role| *role == AtpdChildRole::RelayService)
        .unwrap();
    let rendezvous_index = compiled
        .start_order
        .iter()
        .position(|role| *role == AtpdChildRole::RendezvousService)
        .unwrap();

    assert!(identity_index < relay_index);
    assert!(identity_index < rendezvous_index);
    assert!(AtpdChildRole::RelayService.is_optional());
    assert!(AtpdChildRole::RendezvousService.is_optional());
}
