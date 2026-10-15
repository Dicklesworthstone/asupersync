//! `race!` on the native runtime: the first branch to finish wins, and the
//! losing branch is cancelled and drained before `race!` returns.
//!
//! Each branch is a factory that receives its own child `Cx`. The slow branch
//! waits on a channel through that child context, so cancelling its task wakes
//! it, and its cleanup runs before the race completes. A branch that waited on
//! the caller's `cx` instead would never see the cancellation.
#![allow(missing_docs)]

#[cfg(feature = "proc-macros")]
fn main() {
    use asupersync::Cx;
    use asupersync::channel::mpsc;
    use asupersync::race;
    use asupersync::runtime::RuntimeBuilder;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records that the losing branch was torn down.
    struct CleanedUp(Arc<AtomicBool>);

    impl Drop for CleanedUp {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build a current-thread runtime");
    let loser_cleaned_up = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&loser_cleaned_up);
    let winner = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("a runtime task has a Cx");
        // Nothing is ever sent, so only cancellation ends the slow branch.
        let (_sender, mut receiver) = mpsc::channel::<()>(1);
        race!(cx, {
            move |_child| async move { "fast" },
            move |child| async move {
                let _cleanup = CleanedUp(observed);
                let _ = receiver.recv(&child).await;
                "slow"
            },
        })
    }));

    let winner = winner.expect("race! resolves to the winning branch");
    assert_eq!(winner, "fast");
    assert!(
        loser_cleaned_up.load(Ordering::SeqCst),
        "the losing branch was drained before race! returned"
    );
    println!(
        "race!: {winner:?} won; the slow branch was cancelled and drained before race! returned"
    );
}

#[cfg(not(feature = "proc-macros"))]
fn main() {}
