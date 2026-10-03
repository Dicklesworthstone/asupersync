//! GenServers and actors spawned with `Cx::spawn_gen_server`,
//! `Cx::spawn_actor` and `Cx::spawn_supervised_actor` run on the native
//! runtime (br-asupersync-yvs9cx, br-asupersync-issue65-criticisms-kpmoy5.6.1).
//!
//! Every case runs on the current-thread and multi-thread runtimes through the
//! public API. Callers run in a child region, because a GenServer call from
//! the root region is refused ([ASUP-E103]).

#![allow(missing_docs)]

use asupersync::Cx;
use asupersync::actor::Actor;
use asupersync::cx::ChildRegionSpec;
use asupersync::gen_server::{CallError, GenServer, GenServerHandle, Reply, SystemMsg};
use asupersync::monitor::{DownNotification, DownReason, WatchError};
use asupersync::observability::Diagnostics;
use asupersync::runtime::{JoinError, Runtime, RuntimeBuilder, yield_now};
use asupersync::types::{CancelKind, RegionId, TaskId};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn runtimes() -> Vec<(&'static str, Runtime)> {
    vec![
        (
            "current_thread",
            RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime"),
        ),
        (
            "multi_thread",
            RuntimeBuilder::new()
                .worker_threads(2)
                .build()
                .expect("multi-thread runtime"),
        ),
    ]
}

/// Runs `body` in a task inside a child region, and closes the region after.
fn in_child_region<F, Fut, T>(rt: &Runtime, body: F) -> T
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    rt.block_on(async move {
        let cx = Cx::current().expect("block_on installs a root Cx");
        let child = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("open a child region");
        let mut task = child.cx().spawn(body).expect("spawn in the child region");
        let out = task.join(&cx).await.expect("the test task finishes");
        child.close().await.expect("close the child region");
        out
    })
}

/// Bounds every wait, so a broken watch fails instead of hanging.
const WAIT: Duration = Duration::from_secs(30);

/// Yields until `probe` holds or `WAIT` passes; returns whether it held.
async fn yield_until(mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        yield_now().await;
    }
    probe()
}

/// Yields until `cx` is cancelled; the cancellation kind, or `None` after
/// `WAIT`.
async fn run_until_cancelled(cx: &Cx) -> Option<CancelKind> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if cx.checkpoint().is_err() {
            return cx.cancel_reason().map(|reason| reason.kind);
        }
        yield_now().await;
    }
    None
}

#[derive(Debug)]
enum Request {
    Total,
    /// How many DOWN and exit notices the server has handled.
    Notices,
    /// Parks in the handler until the server is cancelled.
    Park,
}

/// Calls until the server has handled `count` notices, or `WAIT` passes.
async fn wait_for_notices(cx: &Cx, server: &GenServerHandle<Probe>, count: u64) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if server.call(cx, Request::Notices).await.expect("call") >= count {
            return true;
        }
        yield_now().await;
    }
    false
}

/// Records its lifecycle and every system message it receives.
#[derive(Debug, Default)]
struct Probe {
    total: u64,
    started: bool,
    stopped: bool,
    /// The task id and region the server runs as, seen from inside.
    identity: Arc<Mutex<Option<(TaskId, RegionId)>>>,
    downs: Vec<DownNotification>,
    exits: Vec<(TaskId, DownReason)>,
    parked: Arc<AtomicBool>,
}

impl Probe {
    fn identity(&self) -> Option<(TaskId, RegionId)> {
        *self.identity.lock().expect("identity lock")
    }
}

impl GenServer for Probe {
    type Call = Request;
    type Reply = u64;
    type Cast = Option<u64>;
    type Info = SystemMsg;

    fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.started = true;
        *self.identity.lock().expect("identity lock") = Some((cx.task_id(), cx.region_id()));
        Box::pin(async {})
    }

    fn handle_call(
        &mut self,
        cx: &Cx,
        request: Request,
        reply: Reply<u64>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            match request {
                Request::Total => {
                    let _ = reply.send(self.total);
                }
                Request::Notices => {
                    let notices = self.downs.len() + self.exits.len();
                    let _ = reply.send(u64::try_from(notices).expect("small count"));
                }
                Request::Park => {
                    self.parked.store(true, Ordering::Release);
                    let deadline = Instant::now() + WAIT;
                    while cx.checkpoint().is_ok() && Instant::now() < deadline {
                        yield_now().await;
                    }
                    if cx.checkpoint().is_ok() {
                        // Never cancelled: answer, so a broken abort fails
                        // the test instead of hanging it.
                        let _ = reply.send(u64::MAX);
                    } else {
                        // Dropping the reply on cancellation aborts it.
                        drop(reply);
                    }
                }
            }
        })
    }

    /// `Some(n)` adds `n`; `None` panics.
    fn handle_cast(
        &mut self,
        _cx: &Cx,
        msg: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let Some(n) = msg else {
            panic!("the probe server was told to panic");
        };
        self.total += n;
        Box::pin(async {})
    }

    fn handle_info(
        &mut self,
        _cx: &Cx,
        msg: SystemMsg,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        match msg {
            SystemMsg::Down { notification, .. } => self.downs.push(notification),
            SystemMsg::Exit { from, reason, .. } => self.exits.push((from, reason)),
            SystemMsg::Timeout { .. } => {}
        }
        Box::pin(async {})
    }

    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.stopped = true;
        Box::pin(async {})
    }
}

#[test]
fn a_native_server_serves_calls_and_casts_and_returns_its_final_state() {
    for (flavor, rt) in runtimes() {
        let (final_state, region, reported_id, total, retired) =
            in_child_region(&rt, |cx| async move {
                let mut server = cx.spawn_gen_server(Probe::default(), 8).expect("spawn");
                server.cast(&cx, Some(5)).await.expect("cast 5");
                server.cast(&cx, Some(7)).await.expect("cast 7");
                let total = server.call(&cx, Request::Total).await.expect("call");
                server.stop();
                let final_state = server.join(&cx).await.expect("join");
                // The join waited for the task to retire.
                let retired = cx.monitor(server.task_id()).await.map(|m| m.monitor_ref());
                (
                    final_state,
                    cx.region_id(),
                    server.task_id(),
                    total,
                    retired,
                )
            });
        assert_eq!(total, 12, "{flavor}: calls see the casts before them");
        assert_eq!(final_state.total, 12, "{flavor}");
        assert!(
            final_state.started && final_state.stopped,
            "{flavor}: full lifecycle"
        );
        let (inside_id, inside_region) = final_state.identity().expect("on_start ran");
        assert_eq!(
            inside_region, region,
            "{flavor}: the server runs in the caller's region"
        );
        assert_eq!(
            reported_id, inside_id,
            "{flavor}: the handle reports the admitted task id"
        );
        assert_eq!(
            retired,
            Err(WatchError::NotFound),
            "{flavor}: a joined server's task is no longer live"
        );
    }
}

/// Live obligations held in `region`.
fn live_in(diagnostics: &Diagnostics, region: RegionId) -> usize {
    diagnostics
        .find_leaked_obligations()
        .iter()
        .filter(|record| record.region_id == region)
        .count()
}

/// Runs in `block_on`, because the obligation diagnostics cannot move into a
/// spawned task; the server and its caller still run in a child region.
#[test]
fn aborting_a_native_server_mid_call_stops_it_and_aborts_the_reply() {
    for (flavor, rt) in runtimes() {
        let diagnostics = rt.diagnostics();
        rt.block_on(async {
            let cx = Cx::current().expect("block_on installs a root Cx");
            let child = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("open a child region");
            let region = child.region_id();
            let probe = Probe::default();
            let parked = Arc::clone(&probe.parked);
            let mut server = child.cx().spawn_gen_server(probe, 8).expect("spawn");
            let caller_server = server.server_ref();
            let mut caller = child
                .cx()
                .spawn(move |cx| async move { caller_server.call(&cx, Request::Park).await })
                .expect("spawn caller");
            assert!(
                yield_until(|| parked.load(Ordering::Acquire)).await,
                "{flavor}: the handler is parked in the call (state witness)"
            );
            assert!(
                yield_until(|| live_in(&diagnostics, region) > 0).await,
                "{flavor}: the call's reply obligation is live (state witness)"
            );
            server.abort();
            let final_state = server
                .join(&cx)
                .await
                .expect("an aborted server returns its state");
            let call = caller.join(&cx).await.expect("the caller finishes");
            assert!(
                matches!(call, Err(CallError::NoReply)),
                "{flavor}: the aborted handler's reply is aborted: {call:?}"
            );
            assert!(
                final_state.started && final_state.stopped,
                "{flavor}: abort still runs on_stop"
            );
            assert!(
                yield_until(|| live_in(&diagnostics, region) == 0).await,
                "{flavor}: no obligation stays live in the region"
            );
            child.close().await.expect("close the child region");
        });
        assert!(
            diagnostics.find_confirmed_obligation_leaks().is_empty(),
            "{flavor}: no leaks: {:?}",
            diagnostics.find_confirmed_obligation_leaks()
        );
    }
}

/// Dropping a pending join aborts the server, as dropping a `TaskHandle`
/// join does.
#[test]
fn dropping_a_pending_native_server_join_aborts_it() {
    for (flavor, rt) in runtimes() {
        let (call, final_state) = in_child_region(&rt, |cx| async move {
            let probe = Probe::default();
            let parked = Arc::clone(&probe.parked);
            let mut server = cx.spawn_gen_server(probe, 8).expect("spawn");
            let caller_server = server.server_ref();
            let mut caller = cx
                .spawn(move |cx| async move { caller_server.call(&cx, Request::Park).await })
                .expect("spawn caller");
            assert!(
                yield_until(|| parked.load(Ordering::Acquire)).await,
                "the handler is parked in the call (state witness)"
            );
            drop(server.join(&cx));
            let call = caller.join(&cx).await.expect("the caller finishes");
            let final_state = server
                .join(&cx)
                .await
                .expect("an aborted server returns its state");
            (call, final_state)
        });
        assert!(
            matches!(call, Err(CallError::NoReply)),
            "{flavor}: the dropped join aborted the handler: {call:?}"
        );
        assert!(final_state.stopped, "{flavor}: abort still runs on_stop");
    }
}

/// On the current-thread runtime the spawning task keeps the only thread, so
/// an abort right after the spawn lands before the server's first poll.
#[test]
fn aborting_a_native_server_before_its_first_poll_skips_on_start() {
    let rt = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    let final_state = in_child_region(&rt, |cx| async move {
        let mut server = cx.spawn_gen_server(Probe::default(), 8).expect("spawn");
        server.abort();
        server.join(&cx).await
    })
    .expect("an aborted server returns its state");
    assert!(!final_state.started, "on_start is skipped once cancelled");
    assert!(final_state.stopped, "on_stop still runs");
    assert!(final_state.identity().is_none());
}

#[test]
fn a_native_server_monitor_delivers_one_down_to_handle_info() {
    for (flavor, rt) in runtimes() {
        let (final_state, target_id) = in_child_region(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let target = cx
                .spawn(move |_| async move {
                    let _ = yield_until(|| g.load(Ordering::Acquire)).await;
                    panic!("the monitored task panics");
                })
                .expect("spawn target");
            // Ask right after the spawn, before the server's task can have
            // been admitted: the runtime holds the monitor once it is.
            let mut server = cx.spawn_gen_server(Probe::default(), 8).expect("spawn");
            server.monitor(&cx, &target).await.expect("monitor");
            gate.store(true, Ordering::Release);
            assert!(
                wait_for_notices(&cx, &server, 1).await,
                "the DOWN reaches handle_info"
            );
            server.stop();
            let final_state = server.join(&cx).await.expect("join");
            (final_state, target.task_id())
        });
        assert_eq!(
            final_state.downs.len(),
            1,
            "{flavor}: exactly one DOWN: {:?}",
            final_state.downs
        );
        let down = &final_state.downs[0];
        assert_eq!(down.monitored, target_id, "{flavor}");
        assert!(down.reason.is_panicked(), "{flavor}: {:?}", down.reason);
    }
}

#[test]
fn a_native_server_trapping_link_delivers_the_peer_exit() {
    for (flavor, rt) in runtimes() {
        let (final_state, peer_id, total_after) = in_child_region(&rt, |cx| async move {
            let gate = Arc::new(AtomicBool::new(false));
            let g = Arc::clone(&gate);
            let mut peer = cx
                .spawn(move |_| async move {
                    let _ = yield_until(|| g.load(Ordering::Acquire)).await;
                    panic!("the trapped peer panics");
                })
                .expect("spawn peer");
            let mut server = cx.spawn_gen_server(Probe::default(), 8).expect("spawn");
            server.link_trapping(&cx, &peer).await.expect("link");
            gate.store(true, Ordering::Release);
            assert!(matches!(peer.join(&cx).await, Err(JoinError::Panicked(_))));
            assert!(
                wait_for_notices(&cx, &server, 1).await,
                "the exit reaches handle_info"
            );
            // The server keeps serving after the trapped exit.
            server.cast(&cx, Some(3)).await.expect("cast");
            let total_after = server.call(&cx, Request::Total).await.expect("call");
            server.stop();
            let final_state = server.join(&cx).await.expect("join");
            (final_state, peer.task_id(), total_after)
        });
        assert_eq!(
            total_after, 3,
            "{flavor}: the trapping server keeps running"
        );
        assert_eq!(
            final_state.exits.len(),
            1,
            "{flavor}: {:?}",
            final_state.exits
        );
        let (from, reason) = &final_state.exits[0];
        assert_eq!(*from, peer_id, "{flavor}");
        assert!(reason.is_panicked(), "{flavor}: {reason:?}");
    }
}

/// A panicking server's task outcome is the panic: a monitor on its task sees
/// it, and the join reports it.
#[test]
fn a_native_server_panic_is_its_task_outcome() {
    for (flavor, rt) in runtimes() {
        let (down, joined) = in_child_region(&rt, |cx| async move {
            let probe = Probe::default();
            let identity = Arc::clone(&probe.identity);
            let mut server = cx.spawn_gen_server(probe, 8).expect("spawn");
            // After a call, the server task is admitted and running.
            server.call(&cx, Request::Total).await.expect("call");
            let seen = *identity.lock().expect("identity lock");
            let (task_id, _) = seen.expect("on_start ran");
            let monitor = cx.monitor(task_id).await.expect("monitor the server task");
            server.cast(&cx, None).await.expect("cast the panic");
            let joined = server.join(&cx).await.map(|state| state.total);
            let down = monitor.down(&cx).await.expect("DOWN");
            (down, joined)
        });
        assert!(down.reason.is_panicked(), "{flavor}: {:?}", down.reason);
        assert!(
            matches!(joined, Err(JoinError::Panicked(_))),
            "{flavor}: {joined:?}"
        );
    }
}

/// The server's panic cancels the peer it is linked with.
#[test]
fn a_native_server_panic_cancels_its_linked_peer() {
    for (flavor, rt) in runtimes() {
        let (peer_cancel, joined) = in_child_region(&rt, |cx| async move {
            let mut peer = cx
                .spawn(|cx| async move { run_until_cancelled(&cx).await })
                .expect("spawn peer");
            let mut server = cx.spawn_gen_server(Probe::default(), 8).expect("spawn");
            server.link(&cx, &peer).await.expect("link");
            server.cast(&cx, None).await.expect("cast the panic");
            let joined = server.join(&cx).await.map(|state| state.total);
            let peer_cancel = match peer.join(&cx).await {
                Ok(kind) => kind,
                Err(JoinError::Cancelled(reason)) => Some(reason.kind),
                Err(other) => panic!("peer failed: {other:?}"),
            };
            (peer_cancel, joined)
        });
        assert!(
            matches!(joined, Err(JoinError::Panicked(_))),
            "{flavor}: {joined:?}"
        );
        assert_eq!(peer_cancel, Some(CancelKind::LinkedExit), "{flavor}");
    }
}

// ---- Actors ----

#[derive(Debug)]
enum Note {
    Add(u64),
    /// Parks in the handler until the actor is cancelled.
    Park,
    Crash,
}

/// Sums what it is sent and records its lifecycle.
#[derive(Debug, Default)]
struct Tally {
    total: u64,
    started: bool,
    stopped: bool,
    identity: Arc<Mutex<Option<TaskId>>>,
    parked: Arc<AtomicBool>,
}

impl Actor for Tally {
    type Message = Note;

    fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.started = true;
        *self.identity.lock().expect("identity lock") = Some(cx.task_id());
        Box::pin(async {})
    }

    fn handle(&mut self, cx: &Cx, msg: Note) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            match msg {
                Note::Add(n) => self.total += n,
                Note::Park => {
                    self.parked.store(true, Ordering::Release);
                    let deadline = Instant::now() + WAIT;
                    while cx.checkpoint().is_ok() && Instant::now() < deadline {
                        yield_now().await;
                    }
                }
                Note::Crash => panic!("the tally actor was told to crash"),
            }
        })
    }

    fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.stopped = true;
        Box::pin(async {})
    }
}

#[test]
fn a_native_actor_handles_its_messages_and_returns_its_final_state() {
    for (flavor, rt) in runtimes() {
        let (final_state, reported_id) = in_child_region(&rt, |cx| async move {
            let mut actor = cx.spawn_actor(Tally::default(), 8).expect("spawn");
            for n in [4, 6] {
                actor
                    .send(&cx, Note::Add(n))
                    .await
                    .into_result()
                    .expect("send");
            }
            actor.stop();
            let final_state = actor.join(&cx).await.expect("join");
            (final_state, actor.task_id())
        });
        assert_eq!(final_state.total, 10, "{flavor}");
        assert!(
            final_state.started && final_state.stopped,
            "{flavor}: full lifecycle"
        );
        let inside = *final_state.identity.lock().expect("identity lock");
        assert_eq!(
            Some(reported_id),
            inside,
            "{flavor}: the handle reports the admitted task id"
        );
    }
}

#[test]
fn aborting_a_native_actor_mid_message_stops_it_with_its_state() {
    for (flavor, rt) in runtimes() {
        let (joined, waited) = in_child_region(&rt, |cx| async move {
            let tally = Tally::default();
            let parked = Arc::clone(&tally.parked);
            let mut actor = cx.spawn_actor(tally, 8).expect("spawn");
            actor
                .send(&cx, Note::Park)
                .await
                .into_result()
                .expect("send");
            assert!(
                yield_until(|| parked.load(Ordering::Acquire)).await,
                "the handler is parked (state witness)"
            );
            let aborted_at = Instant::now();
            actor.abort();
            let joined = actor.join(&cx).await;
            (joined, aborted_at.elapsed())
        });
        let final_state = joined.expect("an aborted actor returns its state");
        assert!(final_state.stopped, "{flavor}: abort still runs on_stop");
        assert!(
            waited < WAIT,
            "{flavor}: the abort reached the parked handler ({waited:?})"
        );
    }
}

/// Dropping a pending join aborts the actor, as dropping a `TaskHandle` join
/// does.
#[test]
fn dropping_a_pending_native_actor_join_aborts_it() {
    for (flavor, rt) in runtimes() {
        let (joined, waited) = in_child_region(&rt, |cx| async move {
            let tally = Tally::default();
            let parked = Arc::clone(&tally.parked);
            let mut actor = cx.spawn_actor(tally, 8).expect("spawn");
            actor
                .send(&cx, Note::Park)
                .await
                .into_result()
                .expect("send");
            assert!(
                yield_until(|| parked.load(Ordering::Acquire)).await,
                "the handler is parked (state witness)"
            );
            let aborted_at = Instant::now();
            drop(actor.join(&cx));
            let joined = actor.join(&cx).await;
            (joined, aborted_at.elapsed())
        });
        let final_state = joined.expect("an aborted actor returns its state");
        assert!(final_state.stopped, "{flavor}: abort still runs on_stop");
        assert!(
            waited < WAIT,
            "{flavor}: the dropped join reached the parked handler ({waited:?})"
        );
    }
}

/// A crashing actor's task outcome is the crash: a monitor on its task sees
/// it, and the join reports it.
#[test]
fn a_native_actor_crash_is_its_task_outcome() {
    for (flavor, rt) in runtimes() {
        let (down, joined) = in_child_region(&rt, |cx| async move {
            let tally = Tally::default();
            let identity = Arc::clone(&tally.identity);
            let mut actor = cx.spawn_actor(tally, 8).expect("spawn");
            assert!(
                yield_until(|| identity.lock().expect("identity lock").is_some()).await,
                "the actor started"
            );
            let task_id = identity.lock().expect("identity lock").expect("started");
            let monitor = cx.monitor(task_id).await.expect("monitor the actor task");
            actor
                .send(&cx, Note::Crash)
                .await
                .into_result()
                .expect("send");
            let joined = actor.join(&cx).await.map(|state| state.total);
            let down = monitor.down(&cx).await.expect("DOWN");
            (down, joined)
        });
        assert!(down.reason.is_panicked(), "{flavor}: {:?}", down.reason);
        assert!(
            matches!(joined, Err(JoinError::Panicked(_))),
            "{flavor}: {joined:?}"
        );
    }
}

#[test]
fn a_native_supervised_actor_restarts_after_a_crash() {
    use asupersync::supervision::{BackoffStrategy, RestartConfig, SupervisionStrategy};
    use std::sync::atomic::AtomicU32;
    for (flavor, rt) in runtimes() {
        let (final_state, instances) = in_child_region(&rt, |cx| async move {
            let instances = Arc::new(AtomicU32::new(0));
            let built = Arc::clone(&instances);
            let strategy = SupervisionStrategy::Restart(
                RestartConfig::new(3, Duration::from_secs(60)).with_backoff(BackoffStrategy::None),
            );
            let mut actor = cx
                .spawn_supervised_actor(
                    move || {
                        built.fetch_add(1, Ordering::Relaxed);
                        Tally::default()
                    },
                    strategy,
                    8,
                )
                .expect("spawn");
            for note in [Note::Add(1), Note::Crash, Note::Add(5)] {
                actor.send(&cx, note).await.into_result().expect("send");
            }
            let restarted = Arc::clone(&instances);
            assert!(
                yield_until(|| restarted.load(Ordering::Relaxed) == 2).await,
                "the crash restarted the actor"
            );
            actor.stop();
            let final_state = actor.join(&cx).await.expect("join");
            (final_state, instances.load(Ordering::Relaxed))
        });
        assert_eq!(instances, 2, "{flavor}: one restart");
        assert_eq!(
            final_state.total, 5,
            "{flavor}: the restarted instance handled the later message"
        );
    }
}
