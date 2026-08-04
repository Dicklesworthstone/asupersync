//! Level 3: use two-phase effects and make the lab catch an obligation leak.

use asupersync::record::ObligationKind;
use asupersync::record::region::RegionState;
use asupersync::{LabConfig, LabRuntime, main, prelude::*};

#[main]
async fn main(cx: &Cx) {
    let (tx, mut rx) = mpsc::channel::<u8>(1);
    let permit = tx.reserve(cx).await.expect("reserve channel capacity");
    permit.send(7);
    assert_eq!(rx.recv(cx).await.expect("receive committed value"), 7);

    let mut lab = LabRuntime::new(LabConfig::new(7).panic_on_leak(false));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .expect("create lab task");
    lab.state
        .create_obligation(
            ObligationKind::SendPermit,
            task,
            region,
            Some("deliberate on-ramp leak".to_string()),
        )
        .expect("create lab obligation");
    lab.state
        .update_task(task, |record| record.complete(Outcome::Ok(())))
        .expect("complete holder without resolving its obligation");
    lab.state
        .region(region)
        .expect("lab region exists")
        .set_state(RegionState::Closed);

    let report = lab.report();
    let leak = report
        .oracle_report
        .entry("obligation_leak")
        .expect("obligation leak oracle is registered");
    assert!(!leak.passed, "the lab must catch the deliberate leak");
}
