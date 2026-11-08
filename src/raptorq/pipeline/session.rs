//! Owner-bound waits shared by the resumable SDK sessions.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::channel::OwnedCancelRegistration;
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::time::Sleep;

// Bound symbol work, including ignored input, before giving the executor a
// scheduling opportunity. An individual encode/decode step remains synchronous.
pub(super) const SYMBOLS_PER_POLL: usize = 32;

pub(super) struct SessionState {
    pub(super) owner: Cx,
    error: Option<Error>,
    complete: bool,
    poisoned: bool,
}

impl SessionState {
    pub(super) fn new(owner: &Cx) -> Self {
        Self {
            owner: owner.clone(),
            error: None,
            complete: false,
            poisoned: false,
        }
    }

    pub(super) const fn is_finished(&self) -> bool {
        self.complete || self.error.is_some() || self.poisoned
    }

    fn previous_error(&self) -> Option<Error> {
        self.error.clone().or_else(|| {
            if self.poisoned {
                Some(invalid_state(
                    "RaptorQ session cannot resume after a provider or iterator panicked",
                ))
            } else if self.complete {
                Some(invalid_state("RaptorQ session has already completed"))
            } else {
                None
            }
        })
    }
}

pub(super) trait SessionOperation {
    type Output;

    fn state(&mut self) -> &mut SessionState;
    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::Output, Error>>;
}

pub(super) struct SessionWait<'a, O: SessionOperation> {
    operation: &'a mut O,
    cancellation: OwnedCancelRegistration,
    deadline: Option<Pin<Box<Sleep>>>,
    completed: bool,
}

impl<'a, O: SessionOperation> SessionWait<'a, O> {
    pub(super) fn new(operation: &'a mut O) -> Self {
        let owner = operation.state().owner.clone();
        let deadline = owner.budget_deadline_sleep().map(Box::pin);
        Self {
            operation,
            cancellation: OwnedCancelRegistration::new(owner),
            deadline,
            completed: false,
        }
    }
}

impl<O: SessionOperation> Future for SessionWait<'_, O> {
    type Output = Result<O::Output, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(invalid_state("RaptorQ session wait polled after completion")));
        }
        if let Some(error) = this.operation.state().previous_error() {
            this.completed = true;
            this.cancellation.clear();
            this.deadline = None;
            return Poll::Ready(Err(error));
        }

        // Leave the poison set if arbitrary Waker, iterator, transport, or
        // decoder code unwinds. Resuming then cannot replay unknown effects.
        this.operation.state().poisoned = true;
        let owner = this.cancellation.cx().clone();
        let _current = owner.clone().set_current_restricted();
        this.cancellation.refresh(cx.waker());
        if let Some(deadline) = &mut this.deadline {
            // The captured owner's absolute deadline wakes this wait even when
            // polled by a foreign task or with an attenuated time capability.
            // Only checkpoint decides cancellation acknowledgement/masking.
            if deadline.as_mut().poll_deadline(cx).is_ready() {
                // A cancellation mask may let the operation continue after its
                // deadline. A completed Sleep must never be polled again.
                this.deadline = None;
            }
        }
        let result = match owner.checkpoint() {
            Ok(()) => this.operation.poll_progress(cx),
            Err(error) => Poll::Ready(Err(error)),
        };
        let state = this.operation.state();
        state.poisoned = false;
        match &result {
            Poll::Ready(Ok(_)) => state.complete = true,
            Poll::Ready(Err(error)) => state.error = Some(error.clone()),
            Poll::Pending => {}
        }
        if result.is_ready() {
            this.completed = true;
            // This removes the registration but retains the last Waker owner
            // until the wait is dropped, after its Ready value is delivered.
            this.cancellation.clear();
            this.deadline = None;
        }
        result
    }
}

fn invalid_state(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidStateTransition).with_message(message)
}
