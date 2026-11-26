//! Typed actor instances behind managed AppSpec generations.

use super::managed_execution::ManagedAppWorkError;
use crate::actor::{Actor, ActorRef};
use crate::channel::watch;
use crate::cx::Cx;
use crate::runtime::JoinError;
use crate::supervision::{ManagedChildFuture, ManagedGeneration};
use crate::types::{CancelReason, Outcome};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;

/// One admitted mailbox belonging to an exact managed work generation.
///
/// Publication means the actor task was submitted, not that runtime admission
/// or `Actor::on_start` has completed. The actor runs as a child task of the
/// managed invocation, so its task ID differs from `generation.task`.
///
/// Cloning this snapshot requires no `Clone` implementation on the message.
/// Its actor reference always addresses this instance: it never forwards to a
/// replacement. A stopped or refused instance's mailbox becomes disconnected.
#[non_exhaustive]
pub struct ManagedAppActorGeneration<M> {
    /// Managed invocation identity, including its fresh region and task.
    pub generation: ManagedGeneration,
    /// Bounded mailbox of this actor instance.
    pub actor: ActorRef<M>,
}

impl<M> Clone for ManagedAppActorGeneration<M> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            actor: self.actor.clone(),
        }
    }
}

impl<M: Send + 'static> fmt::Debug for ManagedAppActorGeneration<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedAppActorGeneration")
            .field("generation", &self.generation)
            .field("actor_id", &self.actor.actor_id())
            .finish_non_exhaustive()
    }
}

pub(super) type ActorFactory<E> = dyn Fn(Cx, ManagedGeneration, usize) -> ManagedChildFuture<ManagedAppWorkError<E>>
    + Send
    + Sync;

struct Publication<M> {
    sender: Arc<watch::Sender<Option<ManagedAppActorGeneration<M>>>>,
    generation: ManagedGeneration,
}

impl<M> Drop for Publication<M> {
    fn drop(&mut self) {
        let already_panicking = std::thread::panicking();
        let cleared = catch_unwind(AssertUnwindSafe(|| {
            let mut retired = None;
            let _ = self.sender.send_modify(|current| {
                if current
                    .as_ref()
                    .is_some_and(|current| current.generation == self.generation)
                {
                    retired = current.take();
                }
            });
            // ActorRef destruction can wake mailbox waiters. Keep it outside
            // the watch writer's serialization lock.
            drop(retired);
        }));
        if let Err(payload) = cleared {
            if already_panicking {
                // Preserve the original failure and let the actor join guard
                // request cancellation. A hostile secondary payload may itself
                // panic in Drop, so it cannot safely be destroyed here.
                std::mem::forget(payload);
            } else {
                resume_unwind(payload);
            }
        }
    }
}

pub(super) fn factory<E, A, F>(
    create: F,
) -> (
    Arc<ActorFactory<E>>,
    watch::Receiver<Option<ManagedAppActorGeneration<A::Message>>>,
)
where
    E: Send + 'static,
    A: Actor,
    F: Fn(Cx, ManagedGeneration) -> A + Send + Sync + 'static,
{
    let (sender, receiver) = watch::channel(None);
    let sender = Arc::new(sender);
    let create = Arc::new(create);
    let factory = Arc::new(move |cx: Cx, generation, capacity| {
        let create = Arc::clone(&create);
        let sender = Arc::clone(&sender);
        Box::pin(async move {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("AppSpec actor cancelled")),
                );
            }
            let actor = create(cx.clone(), generation);
            let mut actor = match cx.spawn_actor(actor, capacity) {
                Ok(actor) => actor,
                Err(error) => return Outcome::Err(ManagedAppWorkError::Spawn(error)),
            };
            let snapshot = ManagedAppActorGeneration {
                generation,
                actor: actor.sender(),
            };
            // Establish drop-to-abort ownership before publishing to observers:
            // watch notification can run an arbitrary user waker and panic.
            let join = actor.join(&cx);
            let _publication = Publication {
                sender: Arc::clone(&sender),
                generation,
            };
            let _ = sender.send(Some(snapshot));
            match join.await {
                Ok(_) => Outcome::Ok(()),
                Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason),
                Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload),
                Err(error) => Outcome::Err(ManagedAppWorkError::Join(error)),
            }
        }) as ManagedChildFuture<ManagedAppWorkError<E>>
    });
    (factory, receiver)
}
