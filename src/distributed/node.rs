//! One structured owner for prevalidated native distributed services.
//!
//! The caller constructs the authenticated computation listener (including any
//! registered symbol/membership services), the owned membership controller, and
//! optionally a trusted-network SWIM driver. This module gives those concrete
//! components one child-region lifetime. An opt-in outbound configuration adds
//! bounded node-owned named computations and explicit membership-bound route
//! publication. No authenticated authority or credential is derived from SWIM.
//!
//! Startup acknowledges task admission/body entry, not listener readiness: the
//! listener still opens its own connection region before accepting. A component
//! can fail immediately after admission. Its retirement stops sibling admission;
//! [`NativeDistributedNode::close`] collects the actual component outcomes and
//! waits for the entire child region, including listener connection work.

use crate::channel::oneshot;
use crate::cx::{ChildRegion, ChildRegionError, ChildRegionSpec, Cx};
use crate::distributed::membership::authority::MembershipStamp;
use crate::distributed::membership::driver::{SwimDriverReport, SwimObserver, UdpSwimDriver};
use crate::distributed::membership::owned::{OwnedMembershipController, OwnedMembershipError};
use crate::remote::{
    NodeId, RemoteComputationListenerError, RemoteComputationService,
    RemoteComputationServiceHandle, RemoteComputationServiceReport,
};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::sync::Notify;
use crate::types::RegionId;
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

mod outbound;
pub use outbound::{
    NativeDistributedClient, NativeDistributedOutboundConfig, NativeDistributedOutboundError,
    NativeDistributedOutboundReport, NativeDistributedRemoteError, NativeDistributedRemoteHandle,
    NativeDistributedRemoteResult,
};
use outbound::Outbound;

/// A concrete task owned by the node's child region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeDistributedComponent {
    /// Authenticated named computations and any registered symbol services.
    Listener,
    /// Expiry and terminal settlement of checked membership leases.
    Membership,
    /// Optional non-authoritative UDP failure detection.
    Swim,
}

/// The first event that sealed this node's admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeDistributedNodeStopCause {
    /// Explicit operator close.
    Close,
    /// Startup did not admit all requested components.
    StartupFailure,
    /// The owner/start/close future was dropped without collecting its receipt.
    OwnerDropped,
    /// A component returned, panicked, or was refused/dropped before execution.
    Component(NativeDistributedComponent),
}

/// A component's returned outcome and its independent task-retirement result.
///
/// The component publishes its actual outcome before its final checkpoint and
/// stop guard retire. Late cancellation or a subsequent stop-notification panic
/// can therefore coexist with a returned outcome. No outcome is fabricated for
/// a refused, never-polled, or panicking component that did not return one.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDistributedComponentResult<T> {
    /// Actual value returned by the component, if it reached that point.
    pub outcome: Option<T>,
    /// Unmodified runtime result after the task's retirement barrier opened.
    pub retirement: Result<(), JoinError>,
}

/// Authenticated listener outcome and its independent task retirement.
pub type NativeListenerResult = NativeDistributedComponentResult<
    Result<RemoteComputationServiceReport, RemoteComputationListenerError>,
>;

/// Membership expiry outcome and its independent task retirement.
pub type NativeMembershipResult =
    NativeDistributedComponentResult<Result<(), OwnedMembershipError>>;

/// Collected component results and the child-region quiescence receipt.
///
/// An absent slot was never submitted (or SWIM was not configured). An admitted
/// component that failed before body entry remains a `JoinError`, not a success.
/// A successful region close proves local retirement; it does not prove remote
/// execution quiescence, durable symbol storage, or consensus.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDistributedNodeReport {
    /// First observed reason admission was sealed.
    pub stop_cause: NativeDistributedNodeStopCause,
    /// Region identity, if startup obtained one.
    pub region_id: Option<RegionId>,
    /// Existing child-region close result, after all its descendants drained.
    pub region_close: Option<Result<(), ChildRegionError>>,
    /// Listener task and listener-level result, kept distinct.
    pub listener: Option<NativeListenerResult>,
    /// Membership task and controller-level result, kept distinct.
    pub membership: Option<NativeMembershipResult>,
    /// Optional SWIM task's actual protocol/runtime report.
    pub swim: Option<NativeDistributedComponentResult<SwimDriverReport>>,
    /// Optional outbound native driver drain, separate from local region close.
    pub outbound: Option<NativeDistributedOutboundReport>,
}

/// Admission failure. Already-started components are drained before return.
#[derive(Debug, thiserror::Error)]
#[error("native distributed node startup failed: {cause}")]
pub struct NativeDistributedNodeStartError {
    /// Original startup refusal; cleanup does not replace it.
    pub cause: NativeDistributedNodeStartFailure,
    /// Exact partial-start cleanup and task results.
    pub rollback: Box<NativeDistributedNodeReport>,
}

/// Why the requested node could not finish component admission.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedNodeStartFailure {
    /// No ambient timer or helper thread is created.
    #[error("node startup requires an explicit context timer")]
    MissingTimer,
    /// Native sockets require the caller's runtime I/O driver.
    #[error("node startup requires a native runtime I/O driver")]
    MissingIoDriver,
    /// Outbound configuration cannot override the caller's remote restriction.
    #[error("node outbound startup requires remote capability permission")]
    MissingRemote,
    /// The caller was cancelled before admission completed.
    #[error("node startup caller is cancelled")]
    Cancelled,
    /// The already-bound listener could not report its local address.
    #[error("node listener address: {0}")]
    Address(#[source] std::io::Error),
    /// Existing region admission refused the requested child specification.
    #[error("node child region: {0}")]
    Region(#[source] ChildRegionError),
    /// A component could not be submitted through the existing spawn gateway.
    #[error("node {component:?} spawn: {source}")]
    Spawn {
        /// Component whose submission failed.
        component: NativeDistributedComponent,
        /// Unmodified runtime refusal.
        #[source]
        source: SpawnError,
    },
    /// The runtime retired a submitted component before body entry.
    #[error("node {0:?} did not enter its task body")]
    Entry(NativeDistributedComponent),
    /// An already-submitted component stopped during remaining admission.
    #[error("node admission was sealed by {0:?}")]
    Stopped(NativeDistributedNodeStopCause),
}

struct StopPanics {
    unwinding: bool,
    first: Option<Box<dyn std::any::Any + Send>>,
}

impl StopPanics {
    fn new() -> Self {
        Self { unwinding: std::thread::panicking(), first: None }
    }

    fn run(&mut self, action: impl FnOnce()) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
            if self.unwinding || self.first.is_some() {
                std::mem::forget(payload);
            } else {
                self.first = Some(payload);
            }
        }
    }
}

impl Drop for StopPanics {
    fn drop(&mut self) {
        if let Some(payload) = self.first.take() {
            if std::thread::panicking() {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

struct Controls {
    stopped: AtomicU8,
    listener: RemoteComputationServiceHandle,
    membership: OwnedMembershipController,
    outbound: Option<Arc<Outbound>>,
    changed: Notify,
}

impl Controls {
    fn cause(&self) -> Option<NativeDistributedNodeStopCause> {
        use NativeDistributedComponent::{Listener, Membership, Swim};
        use NativeDistributedNodeStopCause::{Close, Component, OwnerDropped, StartupFailure};
        match self.stopped.load(Ordering::Acquire) {
            0 => None,
            1 => Some(Close),
            2 => Some(StartupFailure),
            3 => Some(OwnerDropped),
            4 => Some(Component(Listener)),
            5 => Some(Component(Membership)),
            6 => Some(Component(Swim)),
            _ => unreachable!("node stop causes are private and bounded"),
        }
    }

    fn stop(&self, cause: NativeDistributedNodeStopCause, panics: &mut StopPanics) {
        use NativeDistributedComponent::{Listener, Membership, Swim};
        use NativeDistributedNodeStopCause::{Close, Component, OwnerDropped, StartupFailure};
        let code = match cause {
            Close => 1,
            StartupFailure => 2,
            OwnerDropped => 3,
            Component(Listener) => 4,
            Component(Membership) => 5,
            Component(Swim) => 6,
        };
        if self.stopped.compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        // Publish the seal before any callback; independent stop actions must
        // all run even if a membership lease waiter panics while being woken.
        if let Some(outbound) = &self.outbound { outbound.begin_close(panics); }
        panics.run(|| { let _ = self.listener.begin_drain(); });
        panics.run(|| self.membership.close());
        panics.run(|| self.changed.notify_waiters());
    }
}

struct ComponentStop {
    controls: Arc<Controls>,
    component: NativeDistributedComponent,
}

// Fixed one-result retention per component. The native spawn classifier can
// suppress a returned value on pre-first-poll or late unacknowledged cancel;
// keeping the component outcome here preserves it without altering that policy.
struct Component<T> {
    task: Option<TaskHandle<()>>,
    outcome: Arc<Mutex<Option<T>>>,
}

impl<T> Component<T> {
    fn new() -> Self {
        Self { task: None, outcome: Arc::new(Mutex::new(None)) }
    }

    async fn join(&mut self, cx: &Cx) -> Option<Result<(), JoinError>> {
        let mut task = self.task.take()?;
        Some(task.join(cx).await)
    }

    fn collect(&self, retirement: Option<Result<(), JoinError>>) -> Option<NativeDistributedComponentResult<T>> {
        retirement.map(|retirement| NativeDistributedComponentResult {
            outcome: self.outcome.lock().take(),
            retirement,
        })
    }
}

impl Drop for ComponentStop {
    fn drop(&mut self) {
        let mut panics = StopPanics::new();
        self.controls.stop(NativeDistributedNodeStopCause::Component(self.component), &mut panics);
    }
}

// This guard is constructed synchronously by start(), before its returned
// future exists. A never-polled future still closes membership admission and
// retires the caller-supplied sockets; it has not minted any child region.
struct Unstarted {
    listener: Option<RemoteComputationService>,
    membership: Option<OwnedMembershipController>,
    swim: Option<UdpSwimDriver>,
    outbound: Option<NativeDistributedOutboundConfig>,
}

impl Drop for Unstarted {
    fn drop(&mut self) {
        let mut panics = StopPanics::new();
        if let Some(membership) = self.membership.take() {
            panics.run(|| membership.close());
            panics.run(move || drop(membership));
        }
        if let Some(listener) = self.listener.take() {
            panics.run(|| { let _ = listener.handle().begin_drain(); });
            panics.run(move || drop(listener));
        }
        if let Some(swim) = self.swim.take() {
            panics.run(move || drop(swim));
        }
    }
}

/// Opt-in ownership of an authenticated listener, membership expiry and SWIM.
///
/// Inputs retain their independently validated identities, capabilities,
/// routes, and resource policies. The owner adds at most three service tasks; connection,
/// frame, store and lease bounds remain those configured by the caller.
/// In particular, the listener's registry
/// must explicitly register the caller's symbol/membership handlers; this owner
/// cannot infer whether an arbitrary registered handler uses the supplied
/// controller. TCP and UDP may use the same numeric port, and SWIM is optional.
///
/// Dropping the owner seals admission and requests existing child-region close.
/// Only awaiting [`close`](Self::close) collects the quiescence receipt. No task
/// is detached, and no cleanup task, thread, or unbounded command queue is added.
#[must_use = "await close to collect component outcomes and child-region quiescence"]
pub struct NativeDistributedNode {
    controls: Arc<Controls>,
    region: Option<ChildRegion>,
    principal: Option<Cx>,
    region_id: Option<RegionId>,
    address: Option<SocketAddr>,
    observer: Option<SwimObserver>,
    unstarted_listener: Option<RemoteComputationService>,
    unstarted_swim: Option<UdpSwimDriver>,
    listener: Component<Result<RemoteComputationServiceReport, RemoteComputationListenerError>>,
    membership: Component<Result<(), OwnedMembershipError>>,
    swim: Component<SwimDriverReport>,
}

impl fmt::Debug for NativeDistributedNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedNode")
            .field("region_id", &self.region_id)
            .field("local_addr", &self.address)
            .field("stop_cause", &self.controls.cause())
            .field("swim", &self.observer.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeDistributedNode {
    /// Admit the concrete components into one existing-runtime child region.
    ///
    /// Ownership begins at this call, before the future is polled. A failed
    /// startup seals all supplied components, closes any admitted child region,
    /// and joins every submitted task before returning its rollback report.
    /// External future drop requests the same region cleanup through its owned
    /// guard; the parent runtime remains responsible for driving that cleanup.
    ///
    /// Success acknowledges task body entry only. Service-internal startup and
    /// later failures remain observable through `is_closed` and `close`.
    pub fn start(
        cx: &Cx,
        listener: RemoteComputationService,
        membership: OwnedMembershipController,
        swim: Option<UdpSwimDriver>,
        child: ChildRegionSpec,
    ) -> impl Future<Output = Result<Self, NativeDistributedNodeStartError>> {
        let unstarted = Unstarted {
            listener: Some(listener),
            membership: Some(membership),
            swim,
            outbound: None,
        };
        Self::start_inner(cx, unstarted, child)
    }

    /// Start the services and an explicit bounded outbound capability together.
    ///
    /// The outbound runtime starts with no routes. After admission, use
    /// [`client`](Self::client) to publish independently provisioned peer routes
    /// and submit membership-owned V3 computations. Closing the node seals that
    /// client, drains its native transport and closes every local owner task.
    /// The original [`start`](Self::start) keeps its service-only behavior.
    ///
    /// Ownership starts synchronously, including on a never-polled future.
    pub fn start_with_outbound(
        cx: &Cx,
        listener: RemoteComputationService,
        membership: OwnedMembershipController,
        swim: Option<UdpSwimDriver>,
        outbound: NativeDistributedOutboundConfig,
        child: ChildRegionSpec,
    ) -> impl Future<Output = Result<Self, NativeDistributedNodeStartError>> {
        let unstarted = Unstarted {
            listener: Some(listener), membership: Some(membership), swim,
            outbound: Some(outbound),
        };
        Self::start_inner(cx, unstarted, child)
    }

    async fn start_inner(
        cx: &Cx,
        mut unstarted: Unstarted,
        child: ChildRegionSpec,
    ) -> Result<Self, NativeDistributedNodeStartError> {
        let outbound = unstarted.outbound.take().map(|outbound| {
            outbound.bind(unstarted.membership.as_ref().expect("owned membership").clone())
        });
        let controls = Arc::new(Controls {
            stopped: AtomicU8::new(0),
            listener: unstarted.listener.as_ref().expect("owned listener").handle(),
            membership: unstarted.membership.as_ref().expect("owned membership").clone(),
            outbound,
            changed: Notify::new(),
        });
        let observer = unstarted.swim.as_ref().map(UdpSwimDriver::observer);
        let listener = Component::new();
        let membership = Component::new();
        let swim = Component::new();
        let mut node = Self {
            controls,
            region: None,
            principal: None,
            region_id: None,
            address: None,
            observer,
            unstarted_listener: unstarted.listener.take(),
            unstarted_swim: unstarted.swim.take(),
            listener,
            membership,
            swim,
        };
        // Node now owns the complete stop/rollback path. Retire only this extra
        // Arc, without running Unstarted's membership-close backstop.
        drop(unstarted.membership.take());
        if let Err(cause) = node.admit(cx, child).await {
            let rollback = node.finish(NativeDistributedNodeStopCause::StartupFailure).await;
            return Err(NativeDistributedNodeStartError { cause, rollback: Box::new(rollback) });
        }
        Ok(node)
    }

    async fn admit(&mut self, cx: &Cx, child: ChildRegionSpec) -> Result<(), NativeDistributedNodeStartFailure> {
        use NativeDistributedComponent::{Listener, Membership, Swim};
        use NativeDistributedNodeStartFailure as Failure;
        cx.checkpoint().map_err(|_| Failure::Cancelled)?;
        if cx.timer_driver().is_none() { return Err(Failure::MissingTimer); }
        if !cx.capabilities().io || cx.io_driver_handle().is_none() {
            return Err(Failure::MissingIoDriver);
        }
        if self.controls.outbound.is_some() && !cx.capabilities().remote {
            return Err(Failure::MissingRemote);
        }
        self.address = Some(self.unstarted_listener.as_ref().expect("unstarted listener")
            .local_addr().map_err(Failure::Address)?);
        let region = cx.open_child_region(child).await.map_err(Failure::Region)?;
        let principal = region.cx().clone();
        self.region_id = Some(region.region_id());
        self.principal = Some(principal.clone());
        self.region = Some(region);

        let (entered, receiver) = oneshot::channel();
        let stop = self.component_stop(Listener);
        let outcome = Arc::clone(&self.listener.outcome);
        let listener = self.unstarted_listener.take().expect("unstarted listener");
        self.listener.task = Some(principal.spawn(move |body| async move {
            let _stop = stop;
            let _ = entered.send_blocking(());
            let result = listener.run(&body).await;
            *outcome.lock() = Some(result);
            // Acknowledge observed cancellation, but preserve the component
            // outcome independently of the runtime's final classification.
            let _ = body.checkpoint();
        }).map_err(|source| Failure::Spawn { component: Listener, source })?);
        Self::entered(&self.controls, cx, Listener, receiver).await?;

        let (entered, receiver) = oneshot::channel();
        let stop = self.component_stop(Membership);
        let outcome = Arc::clone(&self.membership.outcome);
        let membership = self.controls.membership.clone();
        self.membership.task = Some(principal.spawn(move |body| async move {
            let _stop = stop;
            let _ = entered.send_blocking(());
            let result = membership.run(&body).await;
            *outcome.lock() = Some(result);
            let _ = body.checkpoint();
        }).map_err(|source| Failure::Spawn { component: Membership, source })?);
        Self::entered(&self.controls, cx, Membership, receiver).await?;

        if self.unstarted_swim.is_some() {
            let (entered, receiver) = oneshot::channel();
            let stop = self.component_stop(Swim);
            let controls = Arc::clone(&self.controls);
            let outcome = Arc::clone(&self.swim.outcome);
            let swim = self.unstarted_swim.take().expect("configured swim");
            self.swim.task = Some(principal.spawn(move |body| async move {
                let _stop = stop;
                let _ = entered.send_blocking(());
                let result = swim.run_until(&body, controls.changed.wait_until(|| {
                    controls.cause().is_some()
                })).await;
                *outcome.lock() = Some(result);
                let _ = body.checkpoint();
            }).map_err(|source| Failure::Spawn { component: Swim, source })?);
            Self::entered(&self.controls, cx, Swim, receiver).await?;
        }
        Ok(())
    }

    fn component_stop(&self, component: NativeDistributedComponent) -> ComponentStop {
        ComponentStop { controls: Arc::clone(&self.controls), component }
    }

    async fn entered(
        controls: &Controls,
        cx: &Cx,
        component: NativeDistributedComponent,
        mut receiver: oneshot::Receiver<()>,
    ) -> Result<(), NativeDistributedNodeStartFailure> {
        let entered = receiver.recv(cx).await;
        cx.checkpoint().map_err(|_| NativeDistributedNodeStartFailure::Cancelled)?;
        entered.map_err(|_| NativeDistributedNodeStartFailure::Entry(component))?;
        if let Some(cause) = controls.cause() {
            return Err(NativeDistributedNodeStartFailure::Stopped(cause));
        }
        Ok(())
    }

    /// The already-bound TCP listener address. This is not a readiness promise.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.address.expect("successfully admitted node address")
    }

    /// Child region that owns every component and listener descendant.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region_id.expect("successfully admitted node region")
    }

    /// Whether admission has been sealed; does not imply drain has completed.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.controls.cause().is_some() }

    /// Current authenticated membership stamp, without delegating update authority.
    #[must_use]
    pub fn membership_stamp(&self, node: &NodeId) -> Option<MembershipStamp> {
        self.controls.membership.stamp(node)
    }

    /// Checked membership leases currently retained by this controller.
    #[must_use]
    pub fn live_leases(&self) -> usize { self.controls.membership.live_leases() }

    /// Bounded, non-authoritative observation of the optional SWIM driver.
    #[must_use]
    pub fn swim_observer(&self) -> Option<SwimObserver> { self.observer.clone() }

    /// Bounded node-owned outbound work, when configured at startup.
    ///
    /// Clones retain the node's child authority and cannot reopen it after close.
    /// This does not expose the raw native runtime or permit replacing its
    /// membership controller, transport policy or capability after admission.
    #[must_use]
    pub fn client(&self) -> Option<NativeDistributedClient> {
        self.controls.outbound.as_ref().map(|_| NativeDistributedClient::new(
            Arc::clone(&self.controls), self.principal.as_ref().expect("admitted node principal").clone(),
        ))
    }

    /// Seal admission and ask every component to stop. Await `close` for drain.
    pub fn begin_close(&self) {
        let mut panics = StopPanics::new();
        self.controls.stop(NativeDistributedNodeStopCause::Close, &mut panics);
    }

    /// Seal admission, drain the whole child region, and collect every task.
    ///
    /// Existing region close and task joins are cancellation-independent. A
    /// cancelled caller therefore still receives the real cleanup results.
    /// A component may report cancellation while its region closes successfully.
    /// Dropping this future requests cleanup but forfeits the collected report.
    pub async fn close(mut self) -> NativeDistributedNodeReport {
        self.finish(NativeDistributedNodeStopCause::Close).await
    }

    async fn finish(&mut self, cause: NativeDistributedNodeStopCause) -> NativeDistributedNodeReport {
        let mut panics = StopPanics::new();
        self.controls.stop(cause, &mut panics);
        self.retire_unstarted(&mut panics);
        let outbound_graceful = if let Some(outbound) = &self.controls.outbound {
            Some(outbound.close(self.principal.as_ref()).await)
        } else { None };
        let region_close = if let Some(region) = self.region.take() {
            Some(region.close().await)
        } else {
            None
        };
        if matches!(&region_close, Some(Ok(()))) {
            if let Some(outbound) = &self.controls.outbound { outbound.region_retired(); }
        }
        let (mut listener, mut membership, mut swim) = (None, None, None);
        if let Some(principal) = self.principal.as_ref() {
            listener = self.listener.join(principal).await;
            membership = self.membership.join(principal).await;
            swim = self.swim.join(principal).await;
        }
        // Any stop callback panic resumes only after independent component
        // shutdown and the child-region receipt have been collected.
        NativeDistributedNodeReport {
            stop_cause: self.controls.cause().expect("finish sealed admission"),
            region_id: self.region_id,
            region_close,
            listener: self.listener.collect(listener),
            membership: self.membership.collect(membership),
            swim: self.swim.collect(swim),
            outbound: self.controls.outbound.as_ref().zip(outbound_graceful)
                .map(|(outbound, graceful)| outbound.report(graceful)),
        }
    }

    fn retire_unstarted(&mut self, panics: &mut StopPanics) {
        if let Some(listener) = self.unstarted_listener.take() { panics.run(move || drop(listener)); }
        if let Some(swim) = self.unstarted_swim.take() { panics.run(move || drop(swim)); }
    }
}

impl Drop for NativeDistributedNode {
    fn drop(&mut self) {
        let mut panics = StopPanics::new();
        self.controls.stop(NativeDistributedNodeStopCause::OwnerDropped, &mut panics);
        self.retire_unstarted(&mut panics);
        if let Some(region) = self.region.take() { panics.run(move || drop(region)); }
        if let Some(task) = self.listener.task.take() { panics.run(move || drop(task)); }
        if let Some(task) = self.membership.task.take() { panics.run(move || drop(task)); }
        if let Some(task) = self.swim.task.take() { panics.run(move || drop(task)); }
    }
}
