//! Runtime-accounted name ownership over the canonical [`NameRegistry`].
//!
//! Raw registry leases deliberately retain their legacy drop-bomb contract.
//! This opt-in API instead requires a runtime-wired [`Cx`], reserves checked
//! `Lease` quota before publishing a name, and couples registry removal with
//! obligation settlement. Dropping a guard aborts both resources. A forgotten
//! guard remains visible to the runtime's holder-completion leak audit; it is
//! not a promise that `mem::forget` can reclaim the registry entry.
//!
//! The backing registry is private: raw force-removal/replacement could bypass
//! the guard's ownership and create an ABA collision at the same virtual time.
//! Clones share one canonical registry, permanently bound to the first admitted
//! runtime. Keep guards within the lifetime of the admitting task. A Rust move
//! does not transfer the obligation to another task or region.

mod permit;
pub use permit::TrackedNamePermit;

use super::Cx;
use super::registry::{NameLease, NameLeaseError, NameRegistry, RegistryCap, RegistryHandle};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::runtime::obligation_mailbox::{
    ObligationAdmissionError, ObligationMailbox, ObligationToken,
};
use crate::types::{RegionId, TaskId, Time};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

/// Refusal of a runtime-accounted name operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrackedNameError {
    /// The context's cancellation checkpoint refused the operation.
    Cancelled,
    /// A stateless context cannot provide runtime accounting.
    RuntimeRequired,
    /// The sentinel region cannot own a graded name lease.
    UnscopedRegion,
    /// Authoritative runtime admission or pre-publication validation refused.
    Admission(ObligationAdmissionError),
    /// This registry already belongs to a different runtime's identity domain.
    DifferentRuntime,
    /// A deadline-bearing wait requires the admitting context's timer driver.
    TimerRequired,
    /// The canonical registry refused the operation.
    Registry(NameLeaseError),
    /// Cleanup freed the name, but the runtime did not accept settlement.
    /// The runtime may be gone or the original holder may already have leaked it.
    SettlementRejected,
}

impl std::fmt::Display for TrackedNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("name operation cancelled"),
            Self::RuntimeRequired => f.write_str("tracked names require a runtime-wired context"),
            Self::UnscopedRegion => f.write_str("a name lease requires a non-sentinel region"),
            Self::Admission(error) => write!(f, "name obligation admission: {error}"),
            Self::DifferentRuntime => f.write_str("name registry belongs to a different runtime"),
            Self::TimerRequired => f.write_str("name wait deadline requires an explicit timer driver"),
            Self::Registry(error) => std::fmt::Display::fmt(error, f),
            Self::SettlementRejected => f.write_str("name removed but runtime settlement refused"),
        }
    }
}

impl std::error::Error for TrackedNameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}

/// Shared registry whose name guards also own checked runtime obligations.
///
/// This wraps [`NameRegistry`], rather than maintaining a second name-resolution
/// algorithm. All write authority remains in the returned guards; lookup is
/// available through every clone. Raw leases and managed-supervisor registries
/// are unchanged and do not acquire accounting merely by existing elsewhere.
#[derive(Debug, Clone)]
pub struct TrackedNameRegistry {
    inner: Arc<Mutex<NameRegistry>>,
    // Preserve the identity allocation, not the runtime or its queued resources.
    // An expired binding is NOT vacant: rebinding would alias reused task IDs.
    runtime: Arc<Mutex<Option<Weak<ObligationMailbox>>>>,
    waiters: Arc<Mutex<BTreeMap<String, NameWaitEntry>>>,
}

impl Default for TrackedNameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryCap for TrackedNameRegistry {}

impl TrackedNameRegistry {
    /// Creates an empty registry, initially unbound to a runtime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NameRegistry::new())),
            runtime: Arc::new(Mutex::new(None)),
            waiters: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// An explicit capability handle sharing this registry's ownership.
    #[must_use]
    pub fn capability(&self) -> RegistryHandle {
        RegistryHandle::new(Arc::new(self.clone()))
    }

    /// Looks up an active name. No runtime or global registry is inferred.
    #[must_use]
    pub fn whereis(&self, name: &str) -> Option<TaskId> {
        self.inner.lock().whereis(name)
    }

    /// Publishes a name owned by `cx` and returns its runtime-accounted guard.
    ///
    /// Quota, holder liveness, and region admission are checked before registry
    /// mutation. Cancellation or holder retirement during an admission callback
    /// refuses publication. On collision the unused quota is returned synchronously.
    /// All admission and settlement notifications run outside the registry lock.
    /// The first live acquisition attempt binds every clone to that runtime; a later
    /// runtime cannot reuse this registry even after all names have been removed.
    pub fn register(
        &self,
        cx: &Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNameLease, TrackedNameError> {
        let name = name.into();
        let mut admission = Admission::new(cx)?;
        let now = cx.now();
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let token = admission.token.as_ref().expect("admitted name credit");
        validate_owner(cx, token)?;
        self.bind_runtime(cx)?;
        let result = {
            self.inner
                .lock()
                .register(name, token.holder(), token.region(), now)
        };
        let lease = result.map_err(TrackedNameError::Registry)?;
        Ok(TrackedNameLease {
            registry: self.clone(),
            lease: Some(lease),
            obligation: admission.token.take(),
        })
    }

    fn bind_runtime(&self, cx: &Cx) -> Result<(), TrackedNameError> {
        let (gateway, _) = cx
            .obligation_transfer_destination()
            .map_err(TrackedNameError::Admission)?;
        let identity = Arc::downgrade(gateway.mailbox());
        let mut binding = self.runtime.lock();
        match binding.as_ref() {
            Some(previous) if !Weak::ptr_eq(previous, &identity) => {
                Err(TrackedNameError::DifferentRuntime)
            }
            Some(_) => Ok(()),
            None => {
                *binding = Some(identity);
                Ok(())
            }
        }
    }

    /// Waits for a name, then publishes it with checked runtime accounting.
    ///
    /// This is [`Self::reserve_wait`] followed by [`TrackedNamePermit::commit`].
    /// Contenders compete on wake; this does not promise FIFO acquisition.
    pub async fn register_wait(
        &self,
        cx: &Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNameLease, TrackedNameError> {
        self.reserve_wait(cx, name).await?.commit()
    }

    fn subscribe<'a>(&'a self, name: &'a str) -> NameInterest<'a> {
        let mut waiters = self.waiters.lock();
        let entry = waiters.entry(name.to_owned()).or_insert_with(|| NameWaitEntry {
            users: 0,
            signal: Arc::new(NameAvailability::default()),
        });
        entry.users = entry.users.checked_add(1).expect("name waiter count overflow");
        NameInterest {
            waiters: &self.waiters,
            name,
            signal: Arc::clone(&entry.signal),
        }
    }

    // Call only AFTER removing ownership, with no registry lock held. The
    // returned guard signals after quota settlement, including notifier unwind.
    fn publish_availability(&self, name: &str) -> Option<NameChanged> {
        self.waiters.lock().get(name).map(|entry| NameChanged(Arc::clone(&entry.signal)))
    }
}

#[derive(Debug)]
struct NameWaitEntry {
    users: usize,
    signal: Arc<NameAvailability>,
}

#[derive(Debug, Default)]
struct NameAvailability {
    epoch: AtomicU64,
    notify: crate::sync::Notify,
}

// Subscription state is per NAME, not per release across the entire registry.
// Dropping the last interested future removes the entry, even if a detached
// notifier still holds a signal Arc. No cancelled-name tombstones accumulate.
struct NameInterest<'a> {
    waiters: &'a Mutex<BTreeMap<String, NameWaitEntry>>,
    name: &'a str,
    signal: Arc<NameAvailability>,
}

impl NameInterest<'_> {
    fn changed(&self, epoch: u64) -> impl std::future::Future<Output = ()> + '_ {
        self.signal.notify.wait_until(move || self.signal.epoch.load(Ordering::Acquire) != epoch)
    }
}

impl Drop for NameInterest<'_> {
    fn drop(&mut self) {
        let retired = {
            let mut waiters = self.waiters.lock();
            let remove = if let Some(entry) = waiters.get_mut(self.name) {
                if Arc::ptr_eq(&entry.signal, &self.signal) {
                    entry.users -= 1;
                    entry.users == 0
                } else {
                    false
                }
            } else {
                false
            };
            if remove { waiters.remove(self.name) } else { None }
        };
        drop(retired);
    }
}

struct NameChanged(Arc<NameAvailability>);

impl Drop for NameChanged {
    fn drop(&mut self) {
        self.0.epoch.fetch_add(1, Ordering::Release);
        let unwinding = std::thread::panicking();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.0.notify.notify_waiters();
        }));
        if let Err(payload) = result {
            if unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

/// Owns both discovery and its runtime `Lease` obligation.
///
/// `release` removes the name and commits the runtime obligation. `abort` and
/// drop remove the name and abort the obligation. Settlement returns quota
/// synchronously; the runtime projects its terminal record on mailbox drain.
/// Deliberately forgetting this guard is detectable but does not free the name.
#[derive(Debug)]
#[must_use = "dropping the guard unregisters the name and aborts its obligation"]
pub struct TrackedNameLease {
    registry: TrackedNameRegistry,
    lease: Option<NameLease>,
    obligation: Option<ObligationToken>,
}

impl TrackedNameLease {
    /// The registered name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.lease.as_ref().expect("live name guard").name()
    }

    /// The original holder; a Rust move does not change this identity.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.lease.as_ref().expect("live name guard").holder()
    }

    /// The runtime region accountable for this lease.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.lease.as_ref().expect("live name guard").region()
    }

    /// Acquisition time from the admitting context's clock.
    #[must_use]
    pub fn acquired_at(&self) -> Time {
        self.lease.as_ref().expect("live name guard").acquired_at()
    }

    /// Stable runtime mailbox ticket for diagnostics.
    #[must_use]
    pub fn obligation_ticket(&self) -> u64 {
        self.obligation.as_ref().expect("live name obligation").ticket()
    }

    /// Removes discovery and commits the obligation, returning quota immediately.
    pub fn release(mut self) -> Result<(), TrackedNameError> {
        self.resolve(None)
    }

    /// Removes discovery and explicitly aborts the obligation.
    pub fn abort(mut self) -> Result<(), TrackedNameError> {
        self.resolve(Some(ObligationAbortReason::Explicit))
    }

    fn resolve(&mut self, abort: Option<ObligationAbortReason>) -> Result<(), TrackedNameError> {
        let Some(mut lease) = self.lease.take() else {
            return Ok(());
        };
        // Defuse the legacy drop bomb before registry cleanup can unwind. This
        // does not settle runtime credit or change registry ownership identity.
        let grade = if abort.is_some() {
            lease.abort().map(|_| ())
        } else {
            lease.release().map(|_| ())
        };
        let removed = self
            .registry
            .inner
            .lock()
            .unregister_owned_and_grant(&lease, lease.acquired_at());
        // There are no raw waiters in this private registry, so removal needs
        // no fresh clock callback. Never run user/runtime callbacks under it.
        let result = grade.and(removed).map_err(TrackedNameError::Registry);
        let _changed = if result.is_ok() {
            self.registry.publish_availability(lease.name())
        } else {
            None
        };
        let token = self.obligation.take().expect("name guard owns runtime credit");
        let accepted = match (abort, result.is_ok()) {
            (None, true) => token.commit(),
            (Some(reason), true) => token.abort(reason),
            (_, false) => token.abort(ObligationAbortReason::Error),
        };
        result?;
        if accepted { Ok(()) } else { Err(TrackedNameError::SettlementRejected) }
    }
}

impl Drop for TrackedNameLease {
    fn drop(&mut self) {
        let _ = self.resolve(Some(ObligationAbortReason::Cancel));
    }
}

// Revalidate after arbitrary admission/clock/checkpoint callbacks and before
// publication. This is not a new admission: a permit at quota one can commit
// without taking a second credit. Holding a guard still does not extend the
// original task's lifetime or transfer liability to the thread using it.
fn validate_owner(cx: &Cx, token: &ObligationToken) -> Result<(), TrackedNameError> {
    let (gateway, holder) = cx
        .obligation_transfer_destination()
        .map_err(TrackedNameError::Admission)?;
    let refusal = if !gateway.is_runtime_available() {
        Some(ObligationAdmissionError::RuntimeUnavailable)
    } else if !holder.is_live() {
        Some(ObligationAdmissionError::HolderNotLive)
    } else if token.holder() != holder.holder()
        || token.region() != holder.region()
        || token.holder() != cx.task_id()
        || token.region() != cx.region_id()
    {
        Some(ObligationAdmissionError::HolderMismatch)
    } else {
        None
    };
    refusal.map_or(Ok(()), |error| Err(TrackedNameError::Admission(error)))
}

// A refused or panicking acquisition must abort an admitted credit, not report
// a leaked resource that the caller never received. Checked-token settlement
// suppresses arbitrary notification callbacks during an existing unwind.
struct Admission {
    token: Option<ObligationToken>,
}

impl Admission {
    fn new(cx: &Cx) -> Result<Self, TrackedNameError> {
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let token = cx
            .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
            .map_err(TrackedNameError::Admission)?
            .ok_or(TrackedNameError::RuntimeRequired)?;
        let unscoped = token.region().as_u64() == 0;
        let admission = Self { token: Some(token) };
        if unscoped {
            return Err(TrackedNameError::UnscopedRegion);
        }
        Ok(admission)
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = token.abort(ObligationAbortReason::Error);
        }
    }
}

#[cfg(test)]
#[path = "tracked_registry_tests.rs"]
mod tests;

#[cfg(test)]
mod authority_tests {
    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use super::tests::{finish, fixture, flush};
    use crate::runtime::obligation_mailbox::ObligationGateway;

    #[test]
    fn independent_runtime_ids_cannot_alias_shared_discovery() {
        let (first_lab, first, first_handle) = fixture(1);
        let (second_lab, second, second_handle) = fixture(1);
        assert_eq!(first.task_id(), second.task_id());
        assert_eq!(first.region_id(), second.region_id());
        let names = TrackedNameRegistry::new();
        names.register(&first, "worker").unwrap().release().unwrap();
        let clone = names.clone();
        assert!(matches!(clone.register(&second, "worker"), Err(TrackedNameError::DifferentRuntime)));
        assert!(matches!(clone.reserve(&second, "startup"), Err(TrackedNameError::DifferentRuntime)));
        assert_eq!(clone.whereis("worker"), None);
        assert_eq!(clone.whereis("startup"), None);
        // Failed cross-runtime attempts must not retain the second runtime's quota.
        TrackedNameRegistry::new().register(&second, "worker").unwrap().release().unwrap();
        names.register(&first, "worker").unwrap().release().unwrap();
        finish(first_lab, &first, first_handle, 2);
        finish(second_lab, &second, second_handle, 3);
    }

    #[test]
    fn dead_runtime_binding_is_not_reusable_or_a_strong_runtime_owner() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        names.register(&cx, "worker").unwrap().release().unwrap();
        let weak = Arc::downgrade(lab.state.obligation_gateway().unwrap().mailbox());
        finish(lab, &cx, handle, 1);
        drop(cx);
        assert!(weak.upgrade().is_none(), "registry retained runtime mailbox resources");
        let (lab, cx, handle) = fixture(1);
        assert!(matches!(names.register(&cx, "worker"), Err(TrackedNameError::DifferentRuntime)));
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn gateway_wrappers_in_one_runtime_share_the_identity_binding() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        names.register(&cx, "worker").unwrap().release().unwrap();
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(|| {}),
            Arc::downgrade(&liveness),
        ));
        let wrapped = cx.clone().with_obligation_gateway(Some(gateway), None);
        names.reserve(&wrapped, "worker").unwrap().commit().unwrap().release().unwrap();
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn admission_callback_cannot_publish_for_a_retired_holder() {
        let (mut lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let retired = cx.clone();
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || retired.revoke_obligation_admission()),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        assert!(matches!(names.register(&cx, "worker"),
            Err(TrackedNameError::Admission(ObligationAdmissionError::HolderNotLive))));
        assert!(!cx.is_cancel_requested());
        assert_eq!(names.whereis("worker"), None);
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        drop(handle);
    }

    #[test]
    fn retired_holder_cannot_commit_an_unpublished_name() {
        let (mut lab, cx, mut handle) = fixture(1);
        lab.state.set_obligation_leak_response(crate::runtime::config::ObligationLeakResponse::Silent);
        let names = TrackedNameRegistry::new();
        let permit = names.reserve(&cx, "worker").unwrap();
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 1);
        lab.scheduler.lock().schedule(cx.task_id(), 0);
        let _report = lab.run_until_quiescent_with_report();
        assert!(!matches!(handle.try_join(), Ok(None)));
        assert_eq!(lab.state.leak_count(), 1);
        assert!(matches!(permit.commit(),
            Err(TrackedNameError::Admission(ObligationAdmissionError::HolderNotLive))));
        assert_eq!(names.whereis("worker"), None);
        assert_eq!(lab.state.leak_count(), 1, "late cleanup changed the audit outcome");
    }

    #[test]
    fn runtime_teardown_cannot_be_followed_by_name_publication() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let permit = names.reserve(&cx, "worker").unwrap();
        drop(handle);
        drop(lab);
        assert!(matches!(permit.commit(),
            Err(TrackedNameError::Admission(ObligationAdmissionError::RuntimeUnavailable))));
        assert_eq!(names.whereis("worker"), None);
    }
}
