#![allow(missing_docs)]

use asupersync::channel::{mpsc, session};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::ObligationKind;
use asupersync::types::{Budget, CancelKind};
use std::sync::{Arc, Mutex};

#[test]
fn tracked_try_reserve_uses_explicit_production_context() {
    let mut lab = LabRuntime::new(LabConfig::default());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let child = lab
        .state
        .create_child_region(root, Budget::INFINITE)
        .expect("create non-root child region");
    let captured = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..2 {
        let captured = Arc::clone(&captured);
        let (task_id, _handle) = lab
            .state
            .create_task(child, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task installs a production context");
                captured.lock().expect("capture lock").push(cx);
            })
            .expect("create child task");
        lab.scheduler.lock().schedule(task_id, 0);
    }

    lab.run_until_quiescent();
    let (cancelled_cx, active_cx) = {
        let mut contexts = captured.lock().expect("capture lock");
        assert_eq!(contexts.len(), 2);
        (
            contexts.pop().expect("cancelled context"),
            contexts.pop().expect("active context"),
        )
    };
    assert_ne!(cancelled_cx.region_id().as_u64(), 0);
    assert_ne!(active_cx.region_id().as_u64(), 0);
    assert_ne!(cancelled_cx.task_id(), active_cx.task_id());
    assert!(
        Cx::current().is_none(),
        "lab context must be uninstalled outside task polling"
    );
    cancelled_cx.cancel_with(CancelKind::User, Some("cancel before nonblocking reserve"));

    let (tx, mut rx) = session::tracked_channel::<u8>(1);
    let before = tx.telemetry_snapshot(71);
    assert!(matches!(
        tx.try_reserve(&cancelled_cx),
        Err(mpsc::SendError::Cancelled(()))
    ));
    assert_eq!(rx.try_recv(), Err(mpsc::RecvError::Empty));
    assert_eq!(tx.telemetry_snapshot(71), before);

    let permit = tx
        .try_reserve(&active_cx)
        .expect("cancelled attempt must preserve the sole slot");
    let proof = permit
        .send(17)
        .expect("explicit production context must commit");
    assert_eq!(proof.kind(), ObligationKind::SendPermit);
    assert_eq!(rx.try_recv().expect("committed value is available"), 17);
}
