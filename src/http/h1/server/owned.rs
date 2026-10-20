//! Scheduler-owned HTTP/1 request execution.
//!
//! This opt-in executor shares the established parser and response path with
//! legacy serving. A response is published independently of task cancellation,
//! then withheld from the connection until the actual request subtree closes.

use super::{
    Http1Response, HttpError, IntoHttp1Response, ProducedHopOutcome, ProducedRequestExecution,
    Request, RequestExecutionConfig,
    ServerHopOutcome, ServerRequestRegion, ShutdownPhase, StreamingRequestExecution,
    StreamingRequestOutcome, drive_incoming_body, execute_produced_request_flow,
    join_streaming_handler_and_body,
};
use crate::bytes::BytesMut;
use crate::cx::{ChildRegion, ChildRegionSpec, Cx};
use crate::http::h1::stream::{
    Http1ProducedResponse, IncomingBodyAdmissionError, IncomingRequestBody, StreamingServerRequest,
};
use crate::http::h1::types::Response;
use crate::http::listener_cancel::ListenerCancellation;
use crate::io::{AsyncRead, AsyncWrite};
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
        let source = config.source;
        let drain_grace = config.drain_grace;
        run_owned_request(&self.owner, config, move |body_cx, region| async move {
            region
                .run_with_protocol_drain(
                    source,
                    Some(body_cx),
                    drain_grace,
                    async move {
                        // Factory invocation and response conversion stay
                        // inside the task's protocol drain/panic boundary.
                        handler(request).await.into_h1_response()
                    },
                )
                .await
        })
        .await
    }

    pub(super) async fn execute_streaming<F, Fut, T>(
        self,
        handler: Arc<F>,
        io: T,
        read_buffer: BytesMut,
        execution: StreamingRequestExecution,
    ) -> Result<(T, BytesMut, StreamingRequestOutcome), HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // The protocol-drain boundary encloses the handler, not the owned
        // transport. A timeout must retain I/O to deliver its 503 and keep
        // read-ahead bytes whenever the body reached synchronized EOF.
        // The guard also returns I/O on unwind, but it is never reclaimed
        // until the task and the complete subtree have actually retired.
        let transport = Arc::new(parking_lot::Mutex::new(Some((io, read_buffer))));
        let task_transport = Arc::clone(&transport);
        let source = execution.request.source;
        let drain_grace = execution.request.drain_grace;
        let signal = execution.request.shutdown.clone();
        let config = execution.config;
        let head = execution.head;
        let body_kind = execution.body_kind;
        let peer_addr = execution.peer_addr;
        let outcome = run_owned_request(
            &self.owner,
            execution.request,
            move |body_cx, region| async move {
                let mut transport = StreamingTransport::take(task_transport);
                let (io, read_buffer) = transport.parts();
                let (writer, body) = match IncomingRequestBody::channel_with_limits_checked(
                    &body_cx,
                    body_kind,
                    config.incoming_body_frame_capacity,
                    config.incoming_body_queued_bytes,
                    u64::try_from(config.max_body_size).unwrap_or(u64::MAX),
                ) {
                    Ok(channel) => channel,
                    Err(error) => {
                        let outcome = match error {
                            IncomingBodyAdmissionError::Policy(error) => {
                                StreamingRequestOutcome::BodyFailed(error)
                            }
                            IncomingBodyAdmissionError::Cancelled { kind } => {
                                let hop = if matches!(kind, CancelKind::Deadline | CancelKind::Timeout) {
                                    ServerHopOutcome::DeadlineExceeded
                                } else {
                                    ServerHopOutcome::Cancelled
                                };
                                StreamingRequestOutcome::Complete { hop, drain: None }
                            }
                            IncomingBodyAdmissionError::Runtime(_)
                            | IncomingBodyAdmissionError::RuntimeRequired => {
                                StreamingRequestOutcome::Complete {
                                    hop: ServerHopOutcome::Ok(super::hop_error_response(
                                        head.version, 503, "request body admission unavailable",
                                    )),
                                    drain: None,
                                }
                            }
                        };
                        return region
                            .run_with_protocol_drain(
                                source,
                                Some(body_cx.clone()),
                                drain_grace,
                                async move { outcome },
                            )
                            .await;
                    }
                };
                let request = StreamingServerRequest {
                    head,
                    peer_addr,
                    body,
                };
                let handler_cx = body_cx.clone();
                let handler = region.run_with_protocol_drain(
                    source,
                    Some(body_cx.clone()),
                    drain_grace,
                    async move { handler(handler_cx, request).await },
                );
                let handler = async move { Some(handler.await) };
                let body_driver = drive_incoming_body(
                    &body_cx,
                    io,
                    read_buffer,
                    writer.max_body_size(u64::try_from(config.max_body_size).unwrap_or(u64::MAX)),
                    &config,
                );
                let joined = join_streaming_handler_and_body(
                    &body_cx,
                    handler,
                    body_driver,
                    &config,
                    signal.as_ref(),
                )
                .await;
                // Retire the protocol writer in its admitted task too. Only
                // its observed drain progress crosses the retirement barrier.
                ServerHopOutcome::Ok(StreamingRequestOutcome::from_joined(joined))
            },
        )
        .await?;
        let (io, read_buffer) = transport
            .lock()
            .take()
            .ok_or_else(|| ownership_error("streaming request omitted its transport return"))?;
        let terminal = |hop| StreamingRequestOutcome::Complete { hop, drain: None };
        let outcome = match outcome {
            None => StreamingRequestOutcome::Closed,
            Some(ServerHopOutcome::Ok(outcome)) => outcome,
            Some(ServerHopOutcome::Cancelled) => terminal(ServerHopOutcome::Cancelled),
            Some(ServerHopOutcome::ConnectionLost) => terminal(ServerHopOutcome::ConnectionLost),
            Some(ServerHopOutcome::DeadlineExceeded) => terminal(ServerHopOutcome::DeadlineExceeded),
            Some(ServerHopOutcome::Panicked(message)) => terminal(ServerHopOutcome::Panicked(message)),
        };
        Ok((io, read_buffer, outcome))
    }

    pub(super) async fn execute_produced<F, Fut, T>(
        self,
        handler: Arc<F>,
        io: T,
        read_buffer: BytesMut,
        execution: ProducedRequestExecution,
    ) -> Result<(T, ProducedHopOutcome), HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http1ProducedResponse> + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let transport = Arc::new(parking_lot::Mutex::new(Some((io, read_buffer))));
        let task_transport = Arc::clone(&transport);
        let config = execution.streaming.request.clone();
        let source = config.source;
        let drain_grace = config.drain_grace;
        let outcome = run_owned_request(&self.owner, config, move |body_cx, region| async move {
            // Keep transport outside the protocol future: expiry may discard
            // the exchange but must retain I/O for an early 503 or a truncated
            // close. Reclaim it only after the whole request subtree retires.
            let mut transport = StreamingTransport::take(task_transport);
            let (io, read_buffer) = transport.parts();
            let flow = execute_produced_request_flow(
                &body_cx, io, read_buffer, handler, execution, true,
            );
            let outcome = region
                .run_with_protocol_drain(source, Some(body_cx.clone()), drain_grace, flow)
                .await;
            match outcome {
                ServerHopOutcome::Ok(Err(HttpError::Io(error))) => {
                    // An application error source may own a checked token.
                    // Retire that opaque source in the request task instead
                    // of carrying an obligation into the region-close wait.
                    let snapshot = error.raw_os_error().map_or_else(
                        || std::io::Error::new(error.kind(), error.to_string()),
                        std::io::Error::from_raw_os_error,
                    );
                    drop(error);
                    ServerHopOutcome::Ok(Err(HttpError::Io(snapshot)))
                }
                outcome => outcome,
            }
        })
        .await?;
        let (io, _read_buffer) = transport
            .lock()
            .take()
            .ok_or_else(|| ownership_error("produced request omitted its transport return"))?;
        Ok((io, outcome))
    }
}

/// Exclusive transport ownership while an admitted streaming task runs.
/// The shared slot carries ownership only at admission and retirement; no
/// socket poll, application code, or transport destructor runs under its lock.
struct StreamingTransport<T> {
    value: Option<(T, BytesMut)>,
    returned: Arc<parking_lot::Mutex<Option<(T, BytesMut)>>>,
}

impl<T> StreamingTransport<T> {
    fn take(returned: Arc<parking_lot::Mutex<Option<(T, BytesMut)>>>) -> Self {
        let value = returned.lock().take();
        Self { value, returned }
    }

    fn parts(&mut self) -> (&mut T, &mut BytesMut) {
        let (io, buffer) = self.value.as_mut().expect("admitted streaming transport");
        (io, buffer)
    }
}

impl<T> Drop for StreamingTransport<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            let previous = self.returned.lock().replace(value);
            // Retire any unexpected previous value after releasing the lock.
            debug_assert!(previous.is_none(), "streaming transport returned twice");
            drop(previous);
        }
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

async fn run_owned_request<F, Fut, R>(
    cx: &Cx,
    config: RequestExecutionConfig,
    factory: F,
) -> Result<Option<ServerHopOutcome<R>>, HttpError>
where
    F: FnOnce(Cx, ServerRequestRegion) -> Fut + Send + 'static,
    Fut: Future<Output = ServerHopOutcome<R>> + Send + 'static,
    R: Send + 'static,
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
    let started_at = config.started_at;
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
                // Each protocol keeps its own drain boundary. In particular,
                // streaming transport ownership must survive handler timeout.
                inner: async move { factory(body_cx, region).await },
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
