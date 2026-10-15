//! Cancellation enrollment for a listener's explicit owner and polling task.

use crate::cx::{CancelWakerToken, Cx};
use std::task::Context;

/// Each observer owns its registration even when both contexts are the same.
/// Register before checking so cancellation cannot race a quiet accept into
/// sleeping without a wake source. Observing cancellation acknowledges it;
/// the listener still drains its connections before returning its report.
pub(super) struct ListenerCancellation {
    cx: Option<Cx>,
    token: Option<CancelWakerToken>,
}

impl ListenerCancellation {
    pub(super) fn new(cx: Option<Cx>) -> Self {
        Self { cx, token: None }
    }

    pub(super) fn is_requested(&self) -> bool {
        self.cx.as_ref().is_some_and(|cx| {
            if cx.is_cancel_requested() {
                let _ = cx.checkpoint();
                true
            } else {
                false
            }
        })
    }

    pub(super) fn poll_cancelled(&mut self, task: &Context<'_>) -> bool {
        if let Some(cx) = &self.cx {
            self.token = Some(cx.refresh_cancel_waker(self.token.take(), task.waker()));
        }
        self.is_requested()
    }

    pub(super) fn stop_observing(&mut self) {
        if let Some(cx) = &self.cx
            && let Some(token) = self.token.take()
        {
            cx.clear_cancel_waker(token);
        }
    }
}

impl Drop for ListenerCancellation {
    fn drop(&mut self) {
        self.stop_observing();
    }
}
