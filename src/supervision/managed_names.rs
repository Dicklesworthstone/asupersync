//! Generation-owned registration for the executing managed supervisor.
//!
//! These guards are private so a caller cannot separate a supervised name
//! from the controller that drains its generation. The legacy registry's raw
//! leases remain compatible and are not runtime-table obligations.

use super::{ManagedGeneration, NameCollisionPolicy, NameRegistrationPolicy};
use crate::cx::Cx;
use crate::cx::registry::{
    NameCollisionOutcome, NameCollisionPolicy as RegistryCollisionPolicy, NameLease,
    NameLeaseError, NameRegistry,
};
use crate::types::{CancelReason, Time};
use parking_lot::Mutex;
use std::sync::Arc;

/// The raw shared registry exposes no notification future. A waiting
/// registration therefore inspects only its own FIFO grant on a real timer,
/// at most once per millisecond, and also observes task cancellation. It
/// never steals another consumer's grant or repeatedly self-wakes.
const GRANT_CHECK_NANOS: u64 = 1_000_000;

#[derive(Debug)]
pub(super) enum RegistrationFailure {
    Name(NameLeaseError),
    Cancelled(CancelReason),
    RuntimeUnavailable,
}

#[derive(Default)]
struct Ownership {
    identity: Option<ManagedGeneration>,
    cx: Option<Cx>,
    lease: Option<NameLease>,
    waiting: bool,
    resolved: bool,
}

pub(super) struct GenerationName {
    registry: Arc<Mutex<NameRegistry>>,
    name: String,
    collision: NameCollisionPolicy,
    ownership: Mutex<Ownership>,
}

impl GenerationName {
    pub(super) fn for_policy(
        registry: &Arc<Mutex<NameRegistry>>,
        policy: &NameRegistrationPolicy,
    ) -> Option<Arc<Self>> {
        let NameRegistrationPolicy::Register { name, collision } = policy else {
            return None;
        };
        Some(Arc::new(Self {
            registry: Arc::clone(registry),
            name: name.clone(),
            collision: *collision,
            ownership: Mutex::new(Ownership::default()),
        }))
    }

    pub(super) async fn acquire(
        &self,
        cx: &Cx,
        identity: ManagedGeneration,
    ) -> Result<(), RegistrationFailure> {
        Self::check_cancel(cx)?;
        let deadline = cx.budget().deadline.unwrap_or(Time::from_nanos(u64::MAX));
        let displaced = {
            let mut ownership = self.ownership.lock();
            ownership.identity = Some(identity);
            ownership.cx = Some(cx.clone());
            let policy = match self.collision {
                NameCollisionPolicy::Fail => RegistryCollisionPolicy::Fail,
                NameCollisionPolicy::Replace => RegistryCollisionPolicy::Replace,
                NameCollisionPolicy::Wait => RegistryCollisionPolicy::Wait { deadline },
            };
            let result = self.registry.lock().register_with_policy(
                self.name.clone(),
                identity.task,
                identity.region,
                cx.now(),
                policy,
            );
            match result.map_err(RegistrationFailure::Name)? {
                NameCollisionOutcome::Registered { lease } => {
                    ownership.lease = Some(lease);
                    None
                }
                NameCollisionOutcome::Replaced {
                    lease,
                    displaced_holder,
                    ..
                } => {
                    ownership.lease = Some(lease);
                    Some(displaced_holder)
                }
                NameCollisionOutcome::Enqueued => {
                    ownership.waiting = true;
                    None
                }
            }
        };
        if let Some(task) = displaced {
            // Publish through the runtime gateway after both registry and
            // ownership locks are released. Replacement changes discovery;
            // it is not a receipt that the old task has already drained.
            let reason = CancelReason::user("managed supervisor name replaced");
            if !cx
                .spawn_gateway_handle()
                .is_some_and(|gateway| gateway.enqueue_handle_cancel(task, reason))
            {
                self.release();
                return Err(RegistrationFailure::RuntimeUnavailable);
            }
        }
        loop {
            Self::check_cancel(cx)?;
            {
                let mut ownership = self.ownership.lock();
                if let Some(lease) = &ownership.lease {
                    return if self.registry.lock().owns_lease(lease) {
                        Ok(())
                    } else {
                        Err(RegistrationFailure::Name(NameLeaseError::NotFound {
                            name: self.name.clone(),
                        }))
                    };
                }
                let now = cx.now();
                if now >= deadline {
                    return Err(RegistrationFailure::Name(
                        NameLeaseError::WaitBudgetExceeded {
                            name: self.name.clone(),
                        },
                    ));
                }
                let mut registry = self.registry.lock();
                if let Some(mut grant) =
                    registry.take_granted_for(&self.name, identity.task, identity.region)
                {
                    if registry.owns_lease(&grant.lease) {
                        ownership.waiting = false;
                        ownership.lease = Some(grant.lease);
                        return Ok(());
                    }
                    let _ = grant.lease.abort();
                    return Err(RegistrationFailure::Name(NameLeaseError::NotFound {
                        name: self.name.clone(),
                    }));
                }
            }
            let check_at = Time::from_nanos(
                cx.now()
                    .as_nanos()
                    .saturating_add(GRANT_CHECK_NANOS)
                    .min(deadline.as_nanos()),
            );
            let Some(timer) = cx.timer_driver() else {
                return Err(RegistrationFailure::RuntimeUnavailable);
            };
            crate::time::Sleep::with_timer_driver(check_at, timer).await;
        }
    }

    fn check_cancel(cx: &Cx) -> Result<(), RegistrationFailure> {
        if cx.checkpoint().is_err() {
            Err(RegistrationFailure::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("named child cancelled before start")),
            ))
        } else {
            Ok(())
        }
    }

    /// Called after the actual generation region drains, before a successor
    /// can start. A task/generation identity mismatch means an external
    /// replacement already won; settle our token without removing its entry.
    pub(super) fn release(&self) {
        let mut ownership = self.ownership.lock();
        if ownership.resolved {
            return;
        }
        ownership.resolved = true;
        let now = ownership.cx.as_ref().map_or(Time::ZERO, Cx::now);
        let mut registry = self.registry.lock();
        if let Some(mut lease) = ownership.lease.take() {
            if registry.unregister_owned_and_grant(&lease, now).is_ok() {
                let _ = lease.release();
            } else {
                let _ = lease.abort();
            }
        }
        if ownership.waiting {
            if let Some(identity) = ownership.identity {
                registry.cancel_wait_for(&self.name, identity.task, identity.region, now);
            }
            ownership.waiting = false;
        }
    }
}

impl Drop for GenerationName {
    fn drop(&mut self) {
        // A runtime-owned finalizer holds an Arc from before child admission.
        // If the controller future is abandoned, that finalizer retains the
        // lease through descendant drain and later-registered LIFO finalizers.
        // The final owner cannot erase an independently acquired successor.
        self.release();
    }
}
