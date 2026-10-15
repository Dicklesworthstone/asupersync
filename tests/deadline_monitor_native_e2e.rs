//! Behavioral proof that the production deadline monitor measures task
//! deadlines against runtime time.
//!
//! Task deadlines and creation times come from the runtime's timer driver.
//! The monitor thread used to read `RuntimeState::now` instead, which only the
//! lab runtime advances: in production it stayed at its initial 1 s forever.
//! Deadlines after that instant never looked closer, so no approaching-deadline
//! warning or deadline violation could fire, and deadlines before it looked
//! violated from the first scan.
//!
//! The test waits until runtime time is past 2 s, so a frozen 1 s clock sits
//! before the task's creation and the old monitor would report nothing. It
//! then runs a task with a 600 ms deadline and a 50% warning threshold, and
//! requires exactly one approaching-deadline warning for it, raised once at
//! most about 300 ms remain. The checkpoint timeout is an hour, so a
//! no-progress warning cannot stand in for it.
//!
//! No-claim: this does not prove warning latency bounds, the adaptive
//! threshold mode, or the violation metric.

use std::sync::mpsc;
use std::time::Duration;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::deadline_monitor::{DeadlineWarning, WarningReason};
use asupersync::time::sleep;
use asupersync::types::{Budget, Time};

const DEADLINE: Duration = Duration::from_millis(600);

#[test]
fn production_deadline_monitor_warns_as_runtime_time_approaches_a_deadline() {
    let (tx, rx) = mpsc::channel::<DeadlineWarning>();
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .deadline_monitoring(|monitor| {
            monitor
                .check_interval(Duration::from_millis(5))
                .warning_threshold_fraction(0.5)
                .checkpoint_timeout(Duration::from_secs(3600))
                .on_warning(move |warning| {
                    let _ = tx.send(warning);
                })
        })
        .build()
        .expect("runtime with deadline monitoring");

    let task_id = runtime.block_on(async {
        let root = Cx::current().expect("root cx");
        while root.now() < Time::from_secs(2) {
            sleep(root.now(), Duration::from_millis(20)).await;
        }
        let deadline = root.now() + DEADLINE;
        let request = runtime.request_cx_with_budget(Budget::new().with_deadline(deadline));
        let mut task = request
            .spawn(|task_cx| async move {
                // Outlive the warning point but finish before the deadline.
                sleep(task_cx.now(), Duration::from_millis(450)).await;
            })
            .expect("spawn task with a deadline");
        task.join(&root).await.expect("join task");
        task.task_id()
    });

    let warning = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the monitor must warn as the task's deadline approaches");
    assert_eq!(warning.task_id, task_id, "warning for the deadline task");
    assert_eq!(
        warning.reason,
        WarningReason::ApproachingDeadline,
        "the deadline, not missing progress, must raise the warning: {warning:?}"
    );
    assert!(
        warning.remaining <= DEADLINE / 2,
        "the warning fires only once half the deadline has elapsed in runtime time: {warning:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "one warning per task"
    );
}
