//! The `process` half of the gate check.
//!
//! The import below is unconditional on purpose: no `cfg`, no `required-features`. Three dependency graphs are built
//! from this one file:
//!
//! * bare (no fixture feature): the legacy selection keeps the module, so this must compile and run;
//! * `slim` only: the explicit slim runtime profile omits the module, so the compiler must reject the import as an
//!   unresolved import of `asupersync::process` (E0432);
//! * `slim` and `process`: the module is restored, so this must compile and run again.
//!
//! Do not gate this file to make a red row green.
//!
//! When it runs it uses the module for real, once and boundedly: it spawns one host child (`sh -c 'exit 7'`, no
//! hardware, no network, all three standard streams null), polls for its exit under a deadline, which also reaps it,
//! checks the exact exit status, and prints one marker line. It needs a Unix host with `sh`.

use asupersync::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long the child may take before it is killed and reaped. `exit 7` finishes at once; this only bounds a fault.
const CHILD_DEADLINE: Duration = Duration::from_secs(10);

fn main() {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("exit 7")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the bounded host child");

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the host child") {
            break status;
        }
        if started.elapsed() >= CHILD_DEADLINE {
            child.kill().expect("kill the overdue host child");
            let _ = child.wait();
            panic!("the host child did not exit within {CHILD_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    assert_eq!(status.code(), Some(7), "the child's exact exit code");
    assert!(!status.success(), "exit code 7 is not success");
    #[cfg(unix)]
    assert_eq!(
        status.signal(),
        None,
        "the child exited, it was not signalled"
    );
    println!("process-gate-consumer: spawned one host child and reaped it with exit code 7");
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_consumer_spawns_and_reaps_the_exact_child() {
        super::main();
    }
}
