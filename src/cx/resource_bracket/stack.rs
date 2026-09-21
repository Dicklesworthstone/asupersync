//! Bounded, typed ownership of heterogeneous resources and asynchronous LIFO release.
//!
//! Reserve a slot before starting an acquisition. A committed slot owns both the
//! resource and its release factory; typed keys only borrow the stored resource.
//! Closing seals registration and releases every entry in reverse registration
//! order, including after another release fails or panics. The current release
//! future and completed results live in the stack, not in its borrowing wait.
//!
//! A standalone stack's owner must establish user quiescence BEFORE `close`.
//! [`Cx::spawn_resource_scope`] instead retains the stack inside the existing
//! bracket controller and drains its work subtree before releasing any resource.
//! Its work callback receives [`ResourceScope`], which cannot close or replace
//! the stack. This is not general runtime finalizer registration. Dropping an
//! entire standalone stack performs ordinary destruction, not async release.
//! A blocked release blocks older entries deliberately: dependent resources must
//! not be torn down out of order.

use super::{
    BracketConfig, BracketHandle, BracketPhase, BracketReport, BracketUseFuture,
    Cx, Outcome, cancel_reason, evaluate,
};
use crate::runtime::{JoinError, SpawnError};
use crate::types::TaskId;
use parking_lot::Mutex;
use std::any::Any;
use std::fmt;
use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

// Bound immediately-ready callbacks per outer poll. This cannot bound time
// inside a user poll, factory, or destructor.
const RELEASES_PER_POLL: usize = 16;

type ReleaseFuture<C> = Pin<Box<dyn Future<Output = Outcome<(), C>> + Send>>;
type EvaluatedRelease<C> = Pin<Box<dyn Future<Output = BracketPhase<(), C>> + Send>>;

/// Refusal before a resource acquisition or registration is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceStackError {
    /// Closing has begun; registration never reopens.
    #[error("resource stack is closed for registration")]
    Closed,
    /// The caller-selected number of resource registrations was reached.
    #[error("resource stack capacity {limit} exhausted")]
    Capacity {
        /// Maximum registrations in this stack's lifetime.
        limit: usize,
    },
    /// Metadata for the resource and its eventual result could not be reserved.
    #[error("resource stack metadata allocation failed")]
    Allocation,
}

/// A refused insertion returns both owners, without invoking the release factory.
/// Dropping this error drops its fields normally; it does not run async cleanup.
pub struct ResourceInsertError<T, F> {
    /// Reason registration was not accepted.
    pub error: ResourceStackError,
    /// Original resource, still owned by the caller.
    pub resource: T,
    /// Original release factory, still owned by the caller.
    pub release: F,
}

impl<T, F> fmt::Debug for ResourceInsertError<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceInsertError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<T, F> fmt::Display for ResourceInsertError<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}
impl<T, F> std::error::Error for ResourceInsertError<T, F> {}

/// Typed, stack-specific identity. Cloning a key never clones or releases T.
/// Keys cannot extract ownership and remain invalid after closing begins.
pub struct ResourceKey<T> {
    owner: Arc<()>,
    index: usize,
    marker: PhantomData<fn(T) -> T>,
}
impl<T> Clone for ResourceKey<T> {
    fn clone(&self) -> Self {
        Self { owner: Arc::clone(&self.owner), index: self.index, marker: PhantomData }
    }
}
impl<T> fmt::Debug for ResourceKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceKey").field("index", &self.index).finish_non_exhaustive()
    }
}
impl<T> ResourceKey<T> {
    /// Zero-based registration index, also used by the cleanup report.
    /// This integer alone is not a key and is not globally unique.
    #[must_use]
    pub const fn index(&self) -> usize { self.index }
}

trait OwnedResource<C>: Send {
    fn resource(&self) -> &dyn Any;
    fn resource_mut(&mut self) -> &mut dyn Any;
    fn release(self: Box<Self>, cx: Cx) -> ReleaseFuture<C>;
}

struct Entry<T, F> { resource: T, release: F }
impl<T, C, F, Fut> OwnedResource<C> for Entry<T, F>
where
    T: Send + 'static,
    F: FnOnce(Cx, T) -> Fut + Send + 'static,
    Fut: Future<Output = Outcome<(), C>> + Send + 'static,
{
    fn resource(&self) -> &dyn Any { &self.resource }
    fn resource_mut(&mut self) -> &mut dyn Any { &mut self.resource }
    fn release(self: Box<Self>, cx: Cx) -> ReleaseFuture<C> {
        let Self { resource, release } = *self;
        Box::pin(release(cx, resource))
    }
}

/// The exact release result, including a separate future-retirement panic.
#[derive(Debug)]
pub struct ResourceCleanup<C> {
    /// Registration index of the resource being released.
    pub index: usize,
    /// Typed return, factory/poll panic, and independent destructor panic.
    pub phase: BracketPhase<(), C>,
}

/// Results in actual LIFO execution order. A successful entry cannot erase a
/// sibling error, cancellation, or panic. Partial reports do not imply completion.
#[derive(Debug)]
pub struct ResourceCleanupReport<C> {
    /// Completed releases, including failures, in execution order.
    pub entries: Vec<ResourceCleanup<C>>,
    /// Every registered resource has reached a terminal release result.
    pub complete: bool,
}
impl<C> ResourceCleanupReport<C> {
    /// Every registered release completed successfully, including retirement.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.complete && self.entries.iter().all(|entry| entry.phase.is_success())
    }
}

struct Active<C> { index: usize, future: EvaluatedRelease<C> }

/// Exclusive owner of heterogeneous `Send` resources; neither Clone nor Sync is
/// required on those resources or their cleanup errors. Registration metadata and
/// result slots are reserved BEFORE a slot is returned. Resource/future boxes and
/// caller payload memory are separate from the registration-count bound.
#[must_use = "close after quiescence; Drop does not perform asynchronous release"]
pub struct ResourceStack<C> {
    owner: Arc<()>,
    capacity: usize,
    entries: Vec<Option<Box<dyn OwnedResource<C>>>>,
    closing: bool,
    next: usize,
    active: Option<Active<C>>,
    report: ResourceCleanupReport<C>,
}
impl<C> fmt::Debug for ResourceStack<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceStack")
            .field("capacity", &self.capacity)
            .field("registered", &self.entries.len())
            .field("closing", &self.closing)
            .field("released", &self.report.entries.len())
            .field("complete", &self.report.complete)
            .finish_non_exhaustive()
    }
}

impl<C: Send + 'static> ResourceStack<C> {
    /// Create an empty stack. Zero capacity is valid and admits no resources.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            owner: Arc::new(()), capacity, entries: Vec::new(), closing: false,
            next: 0, active: None,
            report: ResourceCleanupReport { entries: Vec::new(), complete: false },
        }
    }

    /// Reserve registration/result metadata before performing acquisition effects.
    /// Dropping the reservation accepts no resource and spends no capacity.
    /// It borrows the stack exclusively, so another registration or close cannot
    /// invalidate the reserved position while acquisition is pending.
    pub fn reserve(&mut self) -> Result<ResourceReservation<'_, C>, ResourceStackError> {
        if self.closing { return Err(ResourceStackError::Closed); }
        if self.entries.len() >= self.capacity {
            return Err(ResourceStackError::Capacity { limit: self.capacity });
        }
        let count = self.entries.len() + 1; // strictly below the usize capacity
        self.entries.try_reserve(1).map_err(|_| ResourceStackError::Allocation)?;
        // No release runs while registration is open. Reserve enough eventual
        // result slots, not merely one extra slot relative to the still-empty Vec.
        self.report.entries.try_reserve(count).map_err(|_| ResourceStackError::Allocation)?;
        Ok(ResourceReservation { stack: self })
    }

    /// Register an already-acquired resource or return both unchanged owners.
    /// Prefer `reserve` before acquisition when registration failure would leave
    /// the caller with a resource requiring asynchronous release.
    pub fn try_insert<T, F, Fut>(&mut self, resource: T, release: F)
        -> Result<ResourceKey<T>, ResourceInsertError<T, F>>
    where
        T: Send + 'static,
        F: FnOnce(Cx, T) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        match self.reserve() {
            Ok(slot) => Ok(slot.insert(resource, release)),
            Err(error) => Err(ResourceInsertError { error, resource, release }),
        }
    }

    /// Borrow a live resource. Foreign keys and keys used after close return None.
    #[must_use]
    pub fn get<T: 'static>(&self, key: &ResourceKey<T>) -> Option<&T> {
        if self.closing || !Arc::ptr_eq(&self.owner, &key.owner) { return None; }
        self.entries.get(key.index)?.as_ref()?.resource().downcast_ref()
    }

    /// Mutably borrow a live resource. As with any `&mut T`, a caller can replace
    /// its value; release then receives the replacement. Interior ownership and
    /// any explicitly extracted/replaced values remain the caller's responsibility.
    pub fn get_mut<T: 'static>(&mut self, key: &ResourceKey<T>) -> Option<&mut T> {
        if self.closing || !Arc::ptr_eq(&self.owner, &key.owner) { return None; }
        self.entries.get_mut(key.index)?.as_mut()?.resource_mut().downcast_mut()
    }

    /// Observe completed cleanup entries without executing callbacks.
    #[must_use]
    pub fn report(&self) -> &ResourceCleanupReport<C> { &self.report }

    /// Seal and drive LIFO cleanup AFTER the caller establishes user quiescence.
    ///
    /// Dropping this borrowing wait retains the active future and earlier results.
    /// Resume on the same stack; a completed close is idempotent. This wait does
    /// not cancel itself or skip callbacks because the supplied Cx is cancelled:
    /// each release owns its cancellation policy. No mask is added here. A started
    /// release retains the Cx from that start, even across a later resumed close.
    /// At most 16 immediately-ready releases are polled per outer poll.
    pub async fn close<'a>(&'a mut self, cx: &Cx) -> &'a ResourceCleanupReport<C> {
        poll_fn(|task| self.poll_close(cx, task)).await;
        &self.report
    }

    fn poll_close(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<()> {
        if self.report.complete { return Poll::Ready(()); }
        if !self.closing { self.closing = true; self.next = self.entries.len(); }
        for _ in 0..RELEASES_PER_POLL {
            if self.active.is_none() {
                if self.next == 0 {
                    self.report.complete = true;
                    return Poll::Ready(());
                }
                self.next -= 1;
                let index = self.next;
                let entry = self.entries[index].take().expect("unreleased resource slot");
                let release_cx = cx.clone();
                // Reuse bracket's factory/poll/retirement isolation. No release
                // factory is invoked before this owned future is installed.
                let future = Box::pin(evaluate(move || entry.release(release_cx), None));
                self.active = Some(Active { index, future });
            }
            let active = self.active.as_mut().expect("installed release");
            let phase = std::task::ready!(active.future.as_mut().poll(task));
            let index = active.index;
            // Report capacity was reserved at registration. Publish before retiring
            // the outer bookkeeping future; no application error is dropped here.
            self.report.entries.push(ResourceCleanup { index, phase });
            drop(self.active.take());
        }
        if self.next == 0 && self.active.is_none() {
            self.report.complete = true;
            Poll::Ready(())
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Exclusively reserved stack slot. No resource is owned until insertion.
#[must_use = "insert an acquired resource, or drop the unused reservation"]
pub struct ResourceReservation<'a, C> { stack: &'a mut ResourceStack<C> }
impl<C> fmt::Debug for ResourceReservation<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceReservation").finish_non_exhaustive()
    }
}
impl<C: Send + 'static> ResourceReservation<'_, C> {
    /// Acquire into an already-reserved slot. On success the resource is installed
    /// before returning, even if cancellation arrived during acquisition or the
    /// acquisition future's destructor panicked. Inspect BOTH phase fields: an
    /// `Ok(key)` with a retirement panic preserves ownership, not successful setup.
    ///
    /// Cancellation before the first acquisition poll skips the factory. Factory
    /// and poll panics use the bracket's existing phase isolation. A failure that
    /// returns no resource owns its own partial-acquisition cleanup. Dropping this
    /// future while acquisition is pending drops that acquisition, not any older
    /// registered resources. Use a resource scope to retain controller ownership.
    pub async fn acquire<T, E, A, AF, F, FF>(
        self, cx: &Cx, acquire: A, release: F,
    ) -> BracketPhase<ResourceKey<T>, E>
    where
        T: Send + 'static,
        A: FnOnce(Cx) -> AF,
        AF: Future<Output = Outcome<T, E>>,
        F: FnOnce(Cx, T) -> FF + Send + 'static,
        FF: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        if cx.checkpoint().is_err() {
            return BracketPhase {
                outcome: Outcome::Cancelled(cancel_reason(cx)), retirement_panic: None,
            };
        }
        let BracketPhase { outcome, retirement_panic } =
            evaluate(|| acquire(cx.clone()), None).await;
        let outcome = match outcome {
            // No checkpoint or await may separate a returned resource from the
            // reserved release owner, including after an acquisition Drop panic.
            Outcome::Ok(resource) => Outcome::Ok(self.insert(resource, release)),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        };
        BracketPhase { outcome, retirement_panic }
    }

    /// Infallibly commit this slot; no cancellation checkpoint separates successful
    /// acquisition from installing its resource owner. Standard Box allocation can
    /// still abort on OOM. The factory is invoked only by a subsequent close.
    pub fn insert<T, F, Fut>(self, resource: T, release: F) -> ResourceKey<T>
    where
        T: Send + 'static,
        F: FnOnce(Cx, T) -> Fut + Send + 'static,
        Fut: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        let index = self.stack.entries.len();
        self.stack.entries.push(Some(Box::new(Entry { resource, release })));
        ResourceKey { owner: Arc::clone(&self.stack.owner), index, marker: PhantomData }
    }
}

/// Restricted work-phase access to a controller-owned resource stack.
///
/// This facade provides registration and borrowing, but NOT close, extraction,
/// or replacement of the stack. Dropping the facade does not drop its resources.
/// Returned keys carry identity only and do not keep resources alive after close.
pub struct ResourceScope<'a, C> { stack: &'a mut ResourceStack<C> }
impl<C> fmt::Debug for ResourceScope<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceScope").field("stack", &self.stack).finish()
    }
}
impl<C: Send + 'static> ResourceScope<'_, C> {
    /// Reserve capacity before starting acquisition. Refusal invokes no factory.
    pub fn reserve(&mut self) -> Result<ResourceReservation<'_, C>, ResourceStackError> {
        self.stack.reserve()
    }

    /// Register an existing resource or recover it and its release factory.
    pub fn try_insert<T, F, FF>(&mut self, resource: T, release: F)
        -> Result<ResourceKey<T>, ResourceInsertError<T, F>>
    where
        T: Send + 'static,
        F: FnOnce(Cx, T) -> FF + Send + 'static,
        FF: Future<Output = Outcome<(), C>> + Send + 'static,
    {
        self.stack.try_insert(resource, release)
    }

    /// Borrow a resource from this scope; foreign keys return None.
    #[must_use]
    pub fn get<T: 'static>(&self, key: &ResourceKey<T>) -> Option<&T> { self.stack.get(key) }

    /// Mutably borrow the registered value. Replacing the value changes what its
    /// release factory later owns, exactly as with a standalone stack's get_mut.
    pub fn get_mut<T: 'static>(&mut self, key: &ResourceKey<T>) -> Option<&mut T> {
        self.stack.get_mut(key)
    }
}

/// Work, runtime drain, and every release result, without requiring Clone errors.
#[derive(Debug)]
#[must_use = "inspect both runtime lifecycle and every resource cleanup result"]
pub struct ResourceScopeReport<T, E, C> {
    /// Existing bracket lifecycle. A release `Err(())` means at least one stack
    /// entry failed; the exact typed errors are in `cleanup`. A failed region
    /// close leaves the ENTIRE stack in `unreleased`; it must not be closed until
    /// user quiescence is independently established.
    pub lifecycle: BracketReport<ResourceStack<C>, T, E, ()>,
    /// Every terminal resource release in LIFO order, including successes. None
    /// when no stack was created or the runtime could not establish quiescence.
    pub cleanup: Option<ResourceCleanupReport<C>>,
}
impl<T, E, C> ResourceScopeReport<T, E, C> {
    /// Both work and every runtime/resource cleanup phase succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.lifecycle.is_success()
            && self.cleanup.as_ref().is_some_and(ResourceCleanupReport::is_success)
    }
}

/// Owns the existing bracket controller; no second worker or executor is created.
/// Dropping this handle requests cancellation; join it to observe resource release.
#[must_use = "retain and join to observe resource-scope cleanup"]
pub struct ResourceScopeHandle<T, E, C> {
    bracket: BracketHandle<ResourceStack<C>, T, E, ()>,
    cleanup: Arc<Mutex<Option<ResourceCleanupReport<C>>>>,
}
impl<T, E, C> fmt::Debug for ResourceScopeHandle<T, E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceScopeHandle").field("bracket", &self.bracket).finish_non_exhaustive()
    }
}
impl<T, E, C> ResourceScopeHandle<T, E, C> {
    /// Current identity of the bracket controller task.
    #[must_use]
    pub fn task_id(&self) -> TaskId { self.bracket.task_id() }

    /// Request stop; joining still waits for subtree drain and LIFO cleanup.
    pub fn abort(&self) { self.bracket.abort(); }

    /// Join once. Dropping a borrowing wait neither requests stop nor discards
    /// partial work/cleanup results. This wait is deliberately uninterruptible;
    /// use abort to request cooperative shutdown and then continue joining.
    pub async fn join(&mut self) -> Result<ResourceScopeReport<T, E, C>, JoinError> {
        let lifecycle = self.bracket.join().await?;
        let cleanup = self.cleanup.lock().take();
        Ok(ResourceScopeReport { lifecycle, cleanup })
    }
}

impl Cx {
    /// Run multi-step resource acquisition/use with runtime-owned LIFO release.
    ///
    /// The work callback may register different `Send` resource types, and all
    /// release callbacks share the caller's cleanup error type C. The existing
    /// bracket owns the stack BEFORE the work factory runs, joins its body, drains
    /// descendants/finalizers, then releases entries newest-first. Work errors,
    /// cancellation and panics do not bypass cleanup of earlier registrations.
    ///
    /// `config.release_masked_polls` applies to the ENTIRE stack release future,
    /// not a fresh allowance per entry. A pending release stays owned when this
    /// finite allowance ends; subsequent polls are unmasked. Callbacks must return
    /// and make progress, and must drain any work they themselves start. Captured
    /// external capabilities, hard runtime abort and process exit remain outside
    /// this contract. This is not registration on an arbitrary existing region.
    ///
    /// # Errors
    /// Returns the original SpawnError if controller submission is refused.
    /// Later admission/work/drain/cleanup failures remain in the joined report.
    pub fn spawn_resource_scope<T, E, C, U>(
        &self, config: BracketConfig, capacity: usize, work: U,
    ) -> Result<ResourceScopeHandle<T, E, C>, SpawnError>
    where
        T: Send + 'static, E: Send + 'static, C: Send + 'static,
        U: for<'a> FnOnce(Cx, ResourceScope<'a, C>) -> BracketUseFuture<'a, T, E>
            + Send + 'static,
    {
        let cleanup = Arc::new(Mutex::new(None));
        let publication = Arc::clone(&cleanup);
        let bracket = self.spawn_bracket(
            config,
            move |_| async move { Outcome::<_, E>::Ok(ResourceStack::<C>::new(capacity)) },
            move |cx, stack| work(cx, ResourceScope { stack }),
            move |cx, mut stack| async move {
                stack.close(&cx).await;
                let report = stack.report;
                let success = report.is_success();
                // Terminal publication is independent of cancelled Cx. No user
                // error/destructor is invoked while holding this private slot lock.
                let old = publication.lock().replace(report);
                debug_assert!(old.is_none(), "one cleanup report per resource scope");
                drop(old);
                if success { Outcome::Ok(()) } else { Outcome::Err(()) }
            },
        )?;
        Ok(ResourceScopeHandle { bracket, cleanup })
    }
}

#[cfg(test)]
mod tests;
