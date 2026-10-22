//! Checked body ownership through the native HTTP/2 fixture.

use super::*;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::RuntimeHandle;
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::ObligationId;

fn body_events<'a>(trace: &'a [TraceEvent], request: &Cx) -> Vec<(usize, &'a TraceEvent)> {
    trace
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(event.data,
                TraceData::Obligation { task, region, kind: ObligationKind::IoOp, .. }
                if task == request.task_id() && region == request.region_id()
            )
        })
        .collect()
}

pub async fn pending_credit(runtime: &RuntimeHandle, request: &Cx) -> ObligationId {
    loop {
        let trace = runtime.trace_snapshot().expect("live HTTP/2 runtime trace");
        let events = body_events(&trace, request);
        if let Some((_, reserve)) = events.first() {
            assert_eq!(events.len(), 1, "admitted body must retain one live credit");
            assert_eq!(reserve.kind, TraceEventKind::ObligationReserve);
            let TraceData::Obligation { obligation, .. } = reserve.data else {
                unreachable!("filtered body obligation");
            };
            assert!(!trace.iter().any(|event| {
                event.kind == TraceEventKind::Complete
                    && matches!(event.data, TraceData::Task { task, .. } if task == request.task_id())
            }));
            return obligation;
        }
        // Checked admission precedes its mailbox projection. Observe that
        // record; elapsed time is not a witness for an admitted live credit.
        asupersync::runtime::yield_now().await;
    }
}

async fn terminal_credit(
    runtime: &RuntimeHandle,
    request: &Cx,
    expected_abort: Option<ObligationAbortReason>,
) -> ObligationId {
    loop {
        let trace = runtime.trace_snapshot().expect("live HTTP/2 runtime trace");
        let events = body_events(&trace, request);
        if events.len() >= 2 {
            assert_eq!(events.len(), 2, "one reserve and exactly one settlement");
            assert_eq!(events[0].1.kind, TraceEventKind::ObligationReserve);
            assert_eq!(
                events[1].1.kind,
                if expected_abort.is_some() {
                    TraceEventKind::ObligationAbort
                } else {
                    TraceEventKind::ObligationCommit
                },
            );
            let TraceData::Obligation {
                obligation,
                abort_reason,
                ..
            } = events[1].1.data
            else {
                unreachable!("filtered body obligation");
            };
            assert_eq!(abort_reason, expected_abort);
            assert!(matches!(events[0].1.data,
                TraceData::Obligation { obligation: reserved, .. } if reserved == obligation
            ));
            return obligation;
        }
        asupersync::runtime::yield_now().await;
    }
}

pub async fn assert_retired(
    runtime: &RuntimeHandle,
    request: &Cx,
    expected_abort: Option<ObligationAbortReason>,
) -> ObligationId {
    let obligation = terminal_credit(runtime, request, expected_abort).await;
    let trace = runtime.trace_snapshot().expect("live HTTP/2 runtime trace");
    let events = body_events(&trace, request);
    let retirement = trace
        .iter()
        .position(|event| {
            event.kind == TraceEventKind::Complete
                && matches!(event.data, TraceData::Task { task, .. } if task == request.task_id())
        })
        .expect("actual request holder retired");
    assert!(
        events[1].0 < retirement,
        "body settlement precedes holder retirement"
    );
    obligation
}

#[test]
fn checked_upload_commits_at_eof_while_the_actual_handler_remains_live() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let runtime = Runtime::current_handle().unwrap();
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked_tx)));
            let (eof_tx, mut eof_rx) = oneshot::channel();
            let eof = Arc::new(Mutex::new(Some(eof_tx)));
            let (release_tx, release_rx) = oneshot::channel();
            let release = Arc::new(Mutex::new(Some(release_rx)));
            let router = with_survivor(Router::new().route(
                "/tracked",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, mut body: StreamingRawBody| {
                        let parked = parked.lock().unwrap().take().unwrap();
                        let eof = eof.lock().unwrap().take().unwrap();
                        let mut release = release.lock().unwrap().take().unwrap();
                        async move {
                            let first = next_after_pending(&mut body, &request_cx, parked).await;
                            let Some(Ok(BodyFrame::Data(first))) = first else {
                                panic!("parked upload must receive DATA");
                            };
                            let mut bytes = first.chunk().to_vec();
                            bytes.extend(collect(&mut body).await.unwrap());
                            assert_eq!(bytes, b"abc");
                            eof.send_blocking(()).unwrap();
                            release.recv(&request_cx).await.unwrap();
                            Response::new(StatusCode::OK, "read")
                        }
                    },
                )),
            ));
            exercise(router, move |mut client, _| async move {
                let stream = client.open("POST", "/tracked", Some(3), false).await;
                let request = parked_rx.recv(&cx).await.unwrap();
                assert_ne!(request.task_id(), cx.task_id());
                assert_ne!(request.region_id(), cx.region_id());
                let credit = pending_credit(&runtime, &request).await;
                client.survivor().await;
                client.data(stream, Bytes::from_static(b"abc"), true).await;
                eof_rx.recv(&cx).await.unwrap();
                assert_eq!(terminal_credit(&runtime, &request, None).await, credit);
                assert!(!runtime.trace_snapshot().unwrap().iter().any(|event| {
                    event.kind == TraceEventKind::Complete
                        && matches!(event.data, TraceData::Task { task, .. } if task == request.task_id())
                }), "EOF settles the body independently of handler completion");
                release_tx.send(&cx, ()).unwrap();
                client.response(stream, "200", b"read").await;
                wait_region_closed(&request).await;
                assert_eq!(assert_retired(&runtime, &request, None).await, credit);
                client.survivor().await;
                client
            }).await;
        });
    }
}

#[test]
fn immediate_handler_return_settles_before_driver_retirement_and_preserves_response() {
    for workers in [1, 2] {
        for ended in [false, true] {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let runtime = Runtime::current_handle().unwrap();
                let (entered_tx, mut entered_rx) = oneshot::channel();
                let entered = Arc::new(Mutex::new(Some(entered_tx)));
                let router = with_survivor(Router::new().route(
                    "/early-owned",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, body: StreamingRawBody| {
                            let entered = entered.lock().unwrap().take().unwrap();
                            async move {
                                // No suspension separates source publication,
                                // this early response and task-local retirement.
                                drop(body);
                                entered.send_blocking(request_cx).unwrap();
                                Response::new(StatusCode::OK, "early")
                            }
                        },
                    )),
                ));
                exercise(router, move |mut client, _| async move {
                    let stream = client
                        .open("POST", "/early-owned", ended.then_some(0), ended)
                        .await;
                    let request = entered_rx.recv(&cx).await.unwrap();
                    client.response(stream, "200", b"early").await;
                    if !ended {
                        client.reset(stream, ErrorCode::NoError).await;
                    }
                    wait_region_closed(&request).await;
                    assert_retired(
                        &runtime,
                        &request,
                        (!ended).then_some(ObligationAbortReason::Error),
                    )
                    .await;
                    client.survivor().await;
                    client
                })
                .await;
            });
        }
    }
}

#[test]
fn checked_parked_body_aborts_exactly_once_on_reset_or_request_cancellation() {
    for workers in [1, 2] {
        for peer_reset in [false, true] {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let runtime = Runtime::current_handle().unwrap();
                let (parked_tx, mut parked_rx) = oneshot::channel();
                let parked = Arc::new(Mutex::new(Some(parked_tx)));
                let router = with_survivor(Router::new().route(
                    "/cancel-owned",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let parked = parked.lock().unwrap().take().unwrap();
                            async move {
                                let _ = next_after_pending(&mut body, &request_cx, parked).await;
                                std::future::pending::<Response>().await
                            }
                        },
                    )),
                ));
                exercise(router, move |mut client, _| async move {
                    let stream = client.open("POST", "/cancel-owned", None, false).await;
                    let request = parked_rx.recv(&cx).await.unwrap();
                    let credit = pending_credit(&runtime, &request).await;
                    client.survivor().await;
                    if peer_reset {
                        client.connection.reset_stream(stream, ErrorCode::Cancel);
                        client.flush().await;
                    } else {
                        request.cancel_with(
                            CancelKind::User,
                            Some("native checked-body cancellation"),
                        );
                        client.reset(stream, ErrorCode::Cancel).await;
                    }
                    wait_region_closed(&request).await;
                    let expected = if peer_reset {
                        ObligationAbortReason::Error
                    } else {
                        ObligationAbortReason::Cancel
                    };
                    assert_eq!(
                        assert_retired(&runtime, &request, Some(expected)).await,
                        credit
                    );
                    client.survivor().await;
                    client
                })
                .await;
            });
        }
    }
}
