//! Level 3: use two-phase effects and make the lab catch an obligation leak.

use asupersync::{LabConfig, LabRuntime, main, prelude::*};

#[main]
async fn main(cx: &Cx) {
    let (tx, mut rx) = mpsc::channel::<u8>(1);
    let permit = tx.reserve(cx).await.expect("reserve channel capacity");
    permit.send(7);
    assert_eq!(rx.recv(cx).await.expect("receive committed value"), 7);

    // The same reservation inside a deterministic lab task, except that this
    // permit escapes without `send` or `abort`. Stock permits are runtime
    // obligations, so the lab's obligation-leak oracle catches it by kind
    // without any hand-built obligation record.
    let mut lab = LabRuntime::new(LabConfig::new(7).panic_on_leak(false));
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {
            let cx = Cx::current().expect("lab task installs a current Cx");
            let (tx, _rx) = mpsc::channel::<u8>(1);
            let permit = tx.reserve(&cx).await.expect("reserve channel capacity");
            std::mem::forget(permit); // deliberate on-ramp leak
        })
        .expect("create lab task");
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_quiescent();

    let report = lab.report();
    let leak = report
        .oracle_report
        .entry("obligation_leak")
        .expect("obligation leak oracle is registered");
    assert!(!leak.passed, "the lab must catch the deliberate leak");
    let violation = leak.violation.as_deref().unwrap_or_default();
    assert!(
        violation.contains("SendPermit"),
        "the oracle names the leaked permit kind: {violation}"
    );
}
