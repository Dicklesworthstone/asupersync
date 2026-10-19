//! Scheduler-owned buffered HTTP/1 request execution.
//!
//! This opt-in executor shares the established parser and response path with
//! legacy serving. A response is published independently of task cancellation,
//! then withheld from the connection until the actual request subtree closes.

use super::{
    Http1Response, HttpError, IntoHttp1Response, Request, RequestExecutionConfig,
    ServerHopOutcome, ServerRequestRegion, ShutdownPhase,
};
use crate::cx::{ChildRegion, ChildRegionSpec, Cx};
use crate::http::listener_cancel::ListenerCancellation;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelKind, CancelReason};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub(in crate::http::h1) struct OwnedRequests {
    owner: Cx,
}

impl OwnedRequests {
    pub(in crate::http::h1) fn new(owner: Cx) -> Result<Self, HttpError> {
        if owner.timer_driver().is_none() {
            return Err(ownership_error("owned HTTP/1 serving requires a runtime timer"));
        }
        if owner.spawn_gateway_handle().is_none() {
            return Err(ownership_error("owned HTTP/1 serving requires a runtime gateway"));
        }
        Ok(Self { owner })
    }
}

impl OwnedRequests {
    pub(in crate::http::h1) async fn execute<F, Fut, R>(
        self,
        handler: Arc<F>,
        request: Request,
        config: RequestExecutionConfig,
    ) -> Result<Option<ServerHopOutcome<Http1Response>>, HttpError>
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoHttp1Response,
    {
        run_owned_request(&self.owner, config, move || async move {
            // Both factory invocation and response conversion are inside the
            // actual admitted task and its panic boundary.
            handler(request).await.into_h1_response()
        })
        .await
    }
}

fn ownership_error(error: impl std::fmt::Display) -> HttpError {
    HttpError::Io(std::io::Error::other(format!(
        "HTTP/1 request ownership: {error}"
    )))
}

struct OwnedRequest {
    region: Option<ChildRegion>,
    body: Option<TaskHandle<()>>,
}

impl OwnedRequest {
    fn cancel(&self, reason: CancelReason) -> Result<(), HttpError> {
        self.region
            .as_ref()
            .expect("admitted HTTP/1 request region")
            .cancel(reason)
            .map_err(ownership_error)
    }
}

impl Drop for OwnedRequest {
    fn drop(&mut self) {
        // ChildRegion's own backstop requests close, including descendants.
        // Abandonment does not manufacture a terminal/quiescent receipt.
        if let Some(body) = &self.body {
            body.abort();
        }
    }
}

fn request_cancel_reason(cx: &Cx, kind: CancelKind) -> CancelReason {
    let mut reason = CancelReason::with_origin(kind, cx.region_id(), cx.now());
    reason.origin_task = Some(cx.task_id());
    reason
}

fn force_closing(config: &RequestExecutionConfig) -> bool {
    config
        .shutdown
        .as_ref()
        .is_some_and(|signal| signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8)
}

async fn run_owned_request<F, Fut>(
    cx: &Cx,
    config: RequestExecutionConfig,
    factory: F,
) -> Result<Option<ServerHopOutcome<Http1Response>>, HttpError>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Http1Response> + Send + 'static,
{
    let polling_cx = Cx::current();
    let region = cx
        .open_child_region(ChildRegionSpec::inherit().with_budget(config.budget))
        .await
        .map_err(ownership_error)?;
    let mut owner = OwnedRequest {
        region: Some(region),
        body: None,
    };
    let mut owner_cancel = ListenerCancellation::new(Some(cx.clone()));
    let mut polling_cancel = ListenerCancellation::new(polling_cx);
    let owner_cancelled = owner_cancel.is_requested();
    let polling_cancelled = polling_cancel.is_requested();
    let cancelled = owner_cancelled || polling_cancelled;
    let deadline_passed = config.budget.is_past_deadline(cx.now());
    if cancelled || force_closing(&config) || deadline_passed {
        let reason = if cancelled {
            cx.cancel_reason()
                .unwrap_or_else(|| request_cancel_reason(cx, CancelKind::ParentCancelled))
        } else if deadline_passed {
            request_cancel_reason(cx, CancelKind::Deadline)
        } else {
            request_cancel_reason(cx, CancelKind::Shutdown)
        };
        let cancellation = owner.cancel(reason);
        let closed = owner
            .region
            .take()
            .expect("admitted HTTP/1 request region")
            .close()
            .await;
        cancellation?;
        closed.map_err(ownership_error)?;
        return Ok(if force_closing(&config) {
            None
        } else if cancelled {
            Some(ServerHopOutcome::ConnectionLost)
        } else {
            Some(ServerHopOutcome::DeadlineExceeded)
        });
    }

    let publication = Arc::new(parking_lot::Mutex::new(None));
    let body_publication = Arc::clone(&publication);
    let source = config.source;
    let started_at = config.started_at;
    let drain_grace = config.drain_grace;
    let signal = config.shutdown.clone();
    let region = owner.region.as_ref().expect("admitted HTTP/1 request region");
    let scope = region.cx().scope();
    let spawned = region.cx().spawn_in_cancellation_dominant(
        &scope,
        move |body_cx| async move {
            let region = ServerRequestRegion::from_body_cx("h1", body_cx.clone(), started_at);
            if signal
                .as_ref()
                .is_some_and(|signal| signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8)
            {
                region.finish("cancelled");
                *body_publication.lock() = Some(ServerHopOutcome::Cancelled);
                return;
            }
            let mut execution = Box::pin(CatchUnwind {
                inner: region.run_with_protocol_drain(
                    source,
                    Some(body_cx),
                    drain_grace,
                    async move { factory().await },
                ),
            });
            let returned = execution.as_mut().await;
            // A cancelled handler can panic when its future is retired. Catch
            // that boundary before making any success visible to the parent.
            let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(execution);
            }));
            let outcome = match (returned, retired) {
                (Err(payload), retirement) => {
                    if let Err(secondary) = retirement {
                        std::mem::forget(secondary);
                    }
                    ServerHopOutcome::Panicked(crate::cx::scope::payload_to_string(&payload))
                }
                (Ok(_), Err(payload)) => {
                    ServerHopOutcome::Panicked(crate::cx::scope::payload_to_string(&payload))
                }
                (Ok(outcome), Ok(())) => outcome,
            };
            *body_publication.lock() = Some(outcome);
        },
    );
    match spawned {
        Ok(body) => owner.body = Some(body),
        Err(error) => {
            owner
                .region
                .take()
                .expect("admitted HTTP/1 request region")
                .close()
                .await
                .map_err(ownership_error)?;
            return Err(ownership_error(error));
        }
    }

    let mut force = std::pin::pin!(async {
        match config.shutdown.as_ref() {
            Some(signal) => signal.wait_for_phase(ShutdownPhase::ForceClosing).await,
            None => std::future::pending().await,
        }
    });
    let mut cancellation_sent = false;
    let mut cancellation_failure = None;
    let task_outcome = poll_fn(|task| {
        if !cancellation_sent {
            let owner_cancelled = owner_cancel.poll_cancelled(task);
            let polling_cancelled = polling_cancel.poll_cancelled(task);
            let forced = force_closing(&config) || force.as_mut().poll(task).is_ready();
            if owner_cancelled || polling_cancelled || forced {
                let reason = if forced {
                    request_cancel_reason(cx, CancelKind::Shutdown)
                } else {
                    cx.cancel_reason()
                        .unwrap_or_else(|| request_cancel_reason(cx, CancelKind::ParentCancelled))
                };
                cancellation_failure = owner.cancel(reason).err();
                cancellation_sent = true;
                owner_cancel.stop_observing();
                polling_cancel.stop_observing();
            }
        }
        // poll_join waits for the real TaskRecord retirement barrier. Reading
        // the separate response slot is never a substitute for this wait.
        owner
            .body
            .as_mut()
            .expect("admitted HTTP/1 request task")
            .poll_join(task)
    })
    .await;
    owner.body = None;
    let closed = owner
        .region
        .take()
        .expect("admitted HTTP/1 request region")
        .close_with_outcome()
        .await
        .map_err(ownership_error)?;
    if let Some(error) = cancellation_failure {
        return Err(error);
    }
    let owner_cancelled = owner_cancel.is_requested();
    let polling_cancelled = polling_cancel.is_requested();
    let returned = publication.lock().take();

    if force_closing(&config) {
        return Ok(None);
    }
    if owner_cancelled || polling_cancelled {
        return Ok(Some(ServerHopOutcome::ConnectionLost));
    }
    if let Some(panic) = closed.descendant_panic {
        return Ok(Some(ServerHopOutcome::Panicked(panic.to_string())));
    }
    if let Some(cleanup) = closed.cleanup_outcome
        && !matches!(cleanup, crate::types::Outcome::Ok(()))
    {
        return Ok(Some(ServerHopOutcome::Panicked(format!(
            "HTTP/1 request cleanup failed: {cleanup:?}"
        ))));
    }
    let outcome = match (task_outcome, returned) {
        (Err(JoinError::Panicked(payload)), _) => {
            ServerHopOutcome::Panicked(payload.to_string())
        }
        (_, Some(outcome)) => outcome,
        (Err(JoinError::Cancelled(reason)), None)
            if matches!(reason.kind, CancelKind::Deadline | CancelKind::Timeout) =>
        {
            ServerHopOutcome::DeadlineExceeded
        }
        (Err(JoinError::Cancelled(_)), None) => ServerHopOutcome::Cancelled,
        _ => ServerHopOutcome::Panicked("HTTP/1 handler omitted terminal publication".to_owned()),
    };
    Ok(Some(outcome))
}

#[pin_project::pin_project]
struct CatchUnwind<F> {
    #[pin]
    inner: F,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        })) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}
