//! Native lifecycle quota regressions for br-asupersync-0fvvq9.
//!
//! Run with: rch exec -- env CARGO_TARGET_DIR=target/rch-gen-server-budget
//! cargo test --test gen_server_phase_budget -- --test-threads=1

#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::gen_server::{GenServer, Reply};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, yield_now};
use asupersync::types::{Budget, CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::{Pin, pin};
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    // A watchdog bounds a broken journey; readiness is established by an
    // actual Pending poll, never by sleeping for an assumed scheduling delay.
    let (send, receive) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                for sharded in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder.with_sharded_state(sharded).build().unwrap();
                    runtime.block_on(async {
                        let root = Cx::current().expect("runtime root context");
                        let mut owner = root.spawn(scenario).unwrap();
                        owner.join(&root).await.unwrap();
                    });
                    let drained = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
                    assert_eq!(drained.live_tasks, 0);
                    assert_eq!(drained.pending_spawns, 0);
                    assert_eq!(drained.pending_obligations, 0);
                }
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("GenServer phase and cleanup must finish");
    thread.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

#[derive(Clone, Copy)]
enum InitMode {
    Yield(usize),
    UntilQuota,
    UntilAbort,
}

struct BudgetProbe {
    mode: InitMode,
    init_budget: Budget,
    stop_budget: Budget,
    stop_yields: u32,
    ready: Option<oneshot::Sender<Cx>>,
    release: Option<oneshot::Receiver<()>>,
    cast_seen: Option<oneshot::Sender<()>>,
    init_quotas: Vec<u32>,
    init_reason: Option<CancelReason>,
    cleanup_before_restore: Option<Budget>,
    restored: Option<Budget>,
    stop_before: Option<Budget>,
    stop_after: Option<Budget>,
    stop_reason: Option<CancelReason>,
}

impl BudgetProbe {
    fn new(mode: InitMode, init_quota: u32, stop_budget: Budget, stop_yields: u32) -> Self {
        Self {
            mode,
            init_budget: Budget::INFINITE.with_poll_quota(init_quota),
            stop_budget,
            stop_yields,
            ready: None,
            release: None,
            cast_seen: None,
            init_quotas: Vec::new(),
            init_reason: None,
            cleanup_before_restore: None,
            restored: None,
            stop_before: None,
            stop_after: None,
            stop_reason: None,
        }
    }
}

impl GenServer for BudgetProbe {
    type Call = ();
    type Cast = ();
    type Info = ();
    type Reply = ();

    fn on_start_budget(&self) -> Budget {
        self.init_budget
    }

    fn on_stop_budget(&self) -> Budget {
        self.stop_budget
    }

    fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        let release = self.release.take();
        Box::pin(async move {
            let gate_cx = cx.clone();
            let mut gate = pin!(async move {
                if let Some(mut release) = release {
                    release.recv(&gate_cx).await.unwrap();
                }
            });
            let mut gate_open = false;
            let mut cancelled = pin!(cx.cancelled());
            let mut yields_left = match self.mode {
                InitMode::Yield(count) => count,
                _ => 0,
            };
            poll_fn(|task| {
                self.init_quotas.push(cx.budget().poll_quota);
                if !gate_open {
                    if gate.as_mut().poll(task).is_pending() {
                        if let Some(ready) = self.ready.take() {
                            ready.send_blocking(cx.clone()).unwrap();
                        }
                        return Poll::Pending;
                    }
                    gate_open = true;
                }
                match self.mode {
                    InitMode::Yield(_) if yields_left == 0 => Poll::Ready(()),
                    InitMode::Yield(_) => {
                        yields_left -= 1;
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                    InitMode::UntilQuota => {
                        // Do not checkpoint or consume quota here: this must
                        // exercise the native scheduler's exhaustion branch.
                        if cx.is_cancel_requested() {
                            return Poll::Ready(());
                        }
                        assert!(self.init_quotas.len() < 16, "finite init quota was ignored");
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                    InitMode::UntilAbort => match cancelled.as_mut().poll(task) {
                        Poll::Ready(()) => Poll::Ready(()),
                        Poll::Pending => {
                            if let Some(ready) = self.ready.take() {
                                ready.send_blocking(cx.clone()).unwrap();
                            }
                            Poll::Pending
                        }
                    },
                }
            })
            .await;
            if cx.is_cancel_requested() {
                self.init_reason = cx.cancel_reason();
                assert!(cx.checkpoint().is_err());
                // Cross a real Pending boundary so the runtime installs the
                // acknowledged cleanup budget before the phase guard drops.
                yield_now().await;
                self.cleanup_before_restore = Some(cx.budget());
            }
        })
    }

    fn handle_call(
        &mut self,
        _cx: &Cx,
        _request: (),
        reply: Reply<()>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let _ = reply.send(());
        Box::pin(async {})
    }

    fn handle_cast(&mut self, cx: &Cx, (): ()) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.restored = Some(cx.budget());
        if let Some(seen) = self.cast_seen.take() {
            seen.send_blocking(()).unwrap();
        }
        Box::pin(async {})
    }

    fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            self.stop_before = Some(cx.budget());
            for _ in 0..self.stop_yields {
                yield_now().await;
            }
            self.stop_after = Some(cx.budget());
            self.stop_reason = cx.cancel_reason();
        })
    }
}

#[test]
fn finite_init_quota_cancels_self_waking_native_server_and_preserves_cleanup() {
    native(|cx| async move {
        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let cleanup = CancelReason::poll_quota().cleanup_budget();
        let probe = BudgetProbe::new(
            InitMode::UntilQuota,
            4,
            Budget::INFINITE,
            cleanup.poll_quota + 5,
        );
        let mut server = region.cx().spawn_gen_server(probe, 2).unwrap();
        let probe = server.join(&cx).await.unwrap();
        assert_eq!(probe.init_quotas, [4, 3, 2, 1, 0, 0]);
        assert_eq!(probe.init_reason.as_ref().map(|reason| reason.kind), Some(CancelKind::PollQuota));
        assert_eq!(probe.cleanup_before_restore, Some(cleanup));
        assert_eq!(probe.stop_before, Some(cleanup), "phase restoration must retain cleanup");
        assert_eq!(probe.stop_after, Some(cleanup), "cleanup quota stays advisory");
        assert_eq!(probe.stop_reason.as_ref().map(|reason| reason.kind), Some(CancelKind::PollQuota));
        region.close().await.unwrap();
    });
}

async fn restored_budget(cx: Cx, parent_quota: u32, stop_budget: Budget, stop_yields: u32) {
    let region = cx
        .open_child_region(ChildRegionSpec::inherit().with_budget(
            Budget::INFINITE.with_poll_quota(parent_quota),
        ))
        .await
        .unwrap();
    let (ready_send, mut ready_recv) = oneshot::channel();
    let (release_send, release_recv) = oneshot::channel();
    let (seen_send, mut seen_recv) = oneshot::channel();
    let mut probe = BudgetProbe::new(InitMode::Yield(3), 20, stop_budget, stop_yields);
    probe.ready = Some(ready_send);
    probe.release = Some(release_recv);
    probe.cast_seen = Some(seen_send);
    let mut server = region.cx().spawn_gen_server(probe, 2).unwrap();
    let _admitted = ready_recv.recv(&cx).await.unwrap();
    // The source gate is already parked. Queue a cast before releasing it so
    // the restored budget is observed in the same poll that finishes init.
    server.cast(&cx, ()).await.unwrap();
    release_send.send_blocking(()).unwrap();
    seen_recv.recv(&cx).await.unwrap();
    server.stop();
    let probe = server.join(&cx).await.unwrap();
    assert_eq!(probe.init_quotas, [20, 19, 18, 17, 16]);
    let expected = if parent_quota == u32::MAX {
        u32::MAX
    } else {
        // One dispatch before phase entry, then exactly four phase polls.
        parent_quota - 5
    };
    assert_eq!(probe.restored.unwrap().poll_quota, expected);
    assert!(probe.init_reason.is_none());
    assert!(probe.stop_reason.is_none(), "graceful cleanup acquired a cancellation");
    assert_eq!(probe.stop_after, probe.stop_before, "stop must not consume advisory polls");
    region.close().await.unwrap();
}

#[test]
fn finite_init_phase_restores_unlimited_parent_without_leaving_a_finite_cache() {
    native(|cx| restored_budget(cx, u32::MAX, Budget::INFINITE, 150));
}

#[test]
fn finite_parent_keeps_each_init_poll_charge_exactly_once() {
    native(|cx| restored_budget(cx, 1_000, Budget::INFINITE, 0));
}

#[test]
fn graceful_stop_can_yield_beyond_its_advisory_minimal_poll_quota() {
    native(|cx| restored_budget(cx, u32::MAX, Budget::MINIMAL, Budget::MINIMAL.poll_quota + 5));
}

#[test]
fn cancellation_during_init_keeps_user_reason_and_its_cleanup_envelope() {
    native(|cx| async move {
        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let (ready_send, mut ready_recv) = oneshot::channel();
        let cleanup = CancelReason::user("server aborted").cleanup_budget();
        let mut probe = BudgetProbe::new(
            InitMode::UntilAbort,
            4,
            Budget::INFINITE,
            cleanup.poll_quota + 5,
        );
        probe.ready = Some(ready_send);
        let mut server = region.cx().spawn_gen_server(probe, 2).unwrap();
        let _admitted = ready_recv.recv(&cx).await.unwrap();
        server.abort();
        let probe = server.join(&cx).await.unwrap();
        assert_eq!(probe.init_reason.as_ref().map(|reason| reason.kind), Some(CancelKind::User));
        assert_eq!(probe.cleanup_before_restore, Some(cleanup));
        assert_eq!(probe.stop_before, Some(cleanup));
        assert_eq!(probe.stop_after, Some(cleanup));
        assert_eq!(probe.stop_reason.as_ref().map(|reason| reason.kind), Some(CancelKind::User));
        region.close().await.unwrap();
    });
}

#[test]
fn unlimited_init_phase_stays_unlimited_across_real_pending_polls() {
    native(|cx| async move {
        let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let (seen_send, mut seen_recv) = oneshot::channel();
        let mut probe = BudgetProbe::new(InitMode::Yield(3), u32::MAX, Budget::INFINITE, 0);
        probe.cast_seen = Some(seen_send);
        let mut server = region.cx().spawn_gen_server(probe, 2).unwrap();
        server.cast(&cx, ()).await.unwrap();
        seen_recv.recv(&cx).await.unwrap();
        server.stop();
        let probe = server.join(&cx).await.unwrap();
        assert_eq!(probe.init_quotas, [u32::MAX; 4]);
        assert_eq!(probe.restored.unwrap().poll_quota, u32::MAX);
        assert!(probe.init_reason.is_none());
        assert!(probe.stop_reason.is_none());
        region.close().await.unwrap();
    });
}
