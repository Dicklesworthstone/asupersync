//! Typed codecs composed with native admission and checked child-region ownership.
use super::*;
use asupersync::distributed::remote_owned::RemoteRunError;
use asupersync::remote::{
    NativeRemoteAdmissionError, NativeRemoteOwnedError, TypedRemoteRunError, TypedRemoteRunHandle,
};

async fn wait_unread<C: TypedRemoteComputation>(cx: &Cx, call: &mut TypedRemoteRunHandle<C>) {
    asupersync::time::timeout(cx.now(), WAIT, async move {
        while !call.is_finished() {
            asupersync::runtime::yield_now().await;
        }
    })
    .await
    .expect("native owner retires without polling its typed result");
}

#[test]
fn typed_admitted_owned_success_retains_unread_credit_and_transfers_decoded_values() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        assert!(
            cx.remote().is_none(),
            "the reservation supplies the route authority"
        );
        let node = NodeId::new("worker");
        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let mut call = prepared
            .spawn_admitted_owned(&cx, reservation, LEASE, owned_config())
            .unwrap();
        wait_unread(&cx, &mut call).await;
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.admitted.usage().in_flight, 1);
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);

        // A completed but unread typed call still occupies real native quota.
        let mut waiting = Box::pin(fixture.admitted.reserve(&cx, &node, 0, WAIT));
        poll_fn(|task| {
            assert!(waiting.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(fixture.admitted.usage().waiters, 1);
        drop(waiting);
        assert_eq!(fixture.admitted.usage().waiters, 0);

        let report = call.try_join().unwrap().expect("unread terminal report");
        assert!(report.is_success(), "{report:?}");
        assert_ne!(report.close.as_ref().unwrap().region_id, cx.region_id());
        let reply = report.task.as_ref().unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
        assert!(matches!(
            &reply.outcome,
            Outcome::Ok(TypedRemoteOutcome::Success(42))
        ));
        assert!(matches!(
            call.try_join(),
            Err(RemoteRunHandleError::Join(JoinError::PolledAfterCompletion))
        ));

        // Keep the first decoded report alive while reacquiring the only slot:
        // caller-owned typed values must not keep runtime-owned bytes charged.
        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(6, 7), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let next = prepared
            .run_admitted_owned(&cx, reservation, LEASE, owned_config())
            .await
            .unwrap();
        assert!(next.is_success());
        assert!(matches!(
            next.task.unwrap().outcome,
            Outcome::Ok(TypedRemoteOutcome::Success(13))
        ));
        assert!(report.is_success());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_admitted_owned_codec_refusal_preserves_commit_close_and_reusable_capacity() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let node = NodeId::new("worker");
        let prepared =
            PreparedTypedRemoteCall::<Add>::encode(&(21, 21), TypedRemoteLimits::new(1024, 1))
                .unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let mut call = prepared
            .spawn_admitted_owned(&cx, reservation, LEASE, owned_config())
            .unwrap();
        wait_unread(&cx, &mut call).await;
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        let report = call.join(&cx).await.unwrap();
        assert!(!report.is_success());
        assert!(matches!(report.trigger, RemoteRunTrigger::Finished));
        assert!(report.cancel_error.is_none());
        let close = report.close.unwrap();
        assert!(matches!(close.outcome, Outcome::Ok(())));
        assert!(
            close
                .cleanup_outcome
                .as_ref()
                .is_none_or(|value| matches!(value, Outcome::Ok(())))
        );
        let reply = report.task.unwrap();
        assert_eq!(
            reply.settlement,
            RemoteLeaseSettlement::Committed,
            "typed decoding cannot rewrite acknowledged protocol execution"
        );
        assert!(reply.cancellation.is_none());
        assert!(matches!(
            reply.outcome,
            Outcome::Err(TypedRemoteError::LimitExceeded {
                stage: TypedRemoteStage::Response,
                limit: 1,
            })
        ));

        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(u64::MAX, 0), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let failed = prepared
            .run_admitted_owned(&cx, reservation, LEASE, owned_config())
            .await
            .unwrap();
        assert!(!failed.is_success());
        assert!(failed.close.is_ok());
        let reply = failed.task.unwrap();
        assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
        assert!(matches!(reply.outcome,
            Outcome::Ok(TypedRemoteOutcome::Failed(message)) if message == "declared application failure"));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_admitted_owned_refusals_release_reservations_without_dispatch() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let node = NodeId::new("worker");
        for inline in [false, true] {
            let prepared = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
            let reservation = fixture
                .admitted
                .reserve(&cx, &node, prepared.encoded_len() + 1, WAIT)
                .await
                .unwrap();
            let error = if inline {
                prepared
                    .run_admitted_owned(&cx, reservation, LEASE, owned_config())
                    .await
                    .unwrap_err()
            } else {
                prepared
                    .spawn_admitted_owned(&cx, reservation, LEASE, owned_config())
                    .unwrap_err()
            };
            assert!(matches!(
                error,
                TypedRemoteRunError::NativeOwned(NativeRemoteOwnedError::Admission(
                    NativeRemoteAdmissionError::InputLength
                ))
            ));
            assert_eq!(fixture.admitted.usage().buffer_bytes, 0);
        }

        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let mut expired = owned_config();
        expired.timeout = Duration::ZERO;
        assert!(matches!(
            prepared.spawn_admitted_owned(&cx, reservation, LEASE, expired),
            Err(TypedRemoteRunError::NativeOwned(
                NativeRemoteOwnedError::Ownership(RemoteRunError::Timeout)
            )),
        ));
        assert_eq!(fixture.admitted.usage().buffer_bytes, 0);

        let prepared = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        fixture.admitted.begin_drain();
        assert!(matches!(
            prepared
                .run_admitted_owned(&cx, reservation, LEASE, owned_config())
                .await,
            Err(TypedRemoteRunError::NativeOwned(
                NativeRemoteOwnedError::Admission(NativeRemoteAdmissionError::Closed)
            )),
        ));
        assert_eq!(fixture.admitted.usage().buffer_bytes, 0);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert!(!fixture.gate.parked.load(Ordering::Acquire));
        fixture.finish(&cx).await;
    });
}

#[test]
fn typed_admitted_owned_parent_close_and_handle_drop_keep_parked_driver_credit() {
    native(|cx, runtime| async move {
        for drop_handle in [false, true] {
            let mut fixture = Fixture::new(&cx, runtime.clone()).await;
            let node = NodeId::new("worker");
            let boundary = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            assert!(boundary.cx().remote().is_none());
            let prepared = PreparedTypedRemoteCall::<Wait>::encode(&(), limits()).unwrap();
            let reservation = fixture
                .admitted
                .reserve(&cx, &node, prepared.encoded_len(), WAIT)
                .await
                .unwrap();
            let mut call = Some(
                prepared
                    .spawn_admitted_owned(boundary.cx(), reservation, LEASE, owned_config())
                    .unwrap(),
            );
            fixture.gate.wait(&fixture.gate.parked).await;
            assert!(!call.as_ref().unwrap().is_finished());

            let mut waiting = Box::pin(fixture.admitted.reserve(&cx, &node, 0, WAIT));
            poll_fn(|task| {
                assert!(waiting.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(fixture.admitted.usage().waiters, 1);
            if drop_handle {
                drop(call.take());
            }
            let mut closing = Box::pin(boundary.close());
            {
                let mut cancelled = pin!(fixture.gate.wait(&fixture.gate.cancelled));
                poll_fn(|task| {
                    assert!(
                        closing.as_mut().poll(task).is_pending(),
                        "the parent must await the peer's withheld cleanup"
                    );
                    cancelled.as_mut().poll(task)
                })
                .await;
            }
            assert!(!fixture.gate.retired.load(Ordering::Acquire));
            assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
            assert_eq!(fixture.admitted.usage().in_flight, 1);
            assert_eq!(
                fixture.admitted.usage().waiters,
                1,
                "cancellation progresses despite full data and waiter capacity"
            );
            if let Some(call) = call.as_mut() {
                assert!(call.try_join().unwrap().is_none());
            }
            fixture.gate.release();
            closing.await.unwrap();
            assert!(fixture.gate.retired.load(Ordering::Acquire));
            if let Some(call) = call.as_mut() {
                assert_eq!(
                    fixture.admitted.usage().buffer_bytes,
                    CHARGE,
                    "parent close does not consume the typed result"
                );
                let report = call.join(&cx).await.unwrap();
                assert!(!report.is_success());
                assert!(report.close.is_ok());
                assert!(report.cancel_error.is_none());
                let reply = report.task.unwrap();
                assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
                assert!(reply.cancellation.is_some());
                assert!(matches!(
                    reply.outcome,
                    Outcome::Ok(TypedRemoteOutcome::Cancelled(_))
                ));
            }
            let reusable = waiting.await.unwrap();
            drop(reusable);
            assert_eq!(fixture.admitted.usage().buffer_bytes, 0);
            assert!(!cx.is_cancel_requested());
            fixture.finish(&cx).await;
        }
    });
}

#[test]
fn typed_admitted_owned_inline_abandonment_drains_and_unpolled_drop_never_dispatches() {
    native(|cx, runtime| async move {
        let mut fixture = Fixture::new(&cx, runtime).await;
        let node = NodeId::new("worker");
        let prepared = PreparedTypedRemoteCall::<Wait>::encode(&(), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let never_polled = prepared.run_admitted_owned(&cx, reservation, LEASE, owned_config());
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        drop(never_polled);
        assert_eq!(fixture.admitted.usage().buffer_bytes, 0);
        assert!(!fixture.gate.parked.load(Ordering::Acquire));

        let boundary = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let owner = boundary.cx().clone();
        let prepared = PreparedTypedRemoteCall::<Wait>::encode(&(), limits()).unwrap();
        let reservation = fixture
            .admitted
            .reserve(&cx, &node, prepared.encoded_len(), WAIT)
            .await
            .unwrap();
        let mut call =
            Box::pin(prepared.run_admitted_owned(&owner, reservation, LEASE, owned_config()));
        {
            let mut parked = pin!(fixture.gate.wait(&fixture.gate.parked));
            poll_fn(|task| {
                assert!(call.as_mut().poll(task).is_pending());
                parked.as_mut().poll(task)
            })
            .await;
        }
        drop(call);
        fixture.gate.wait(&fixture.gate.cancelled).await;
        assert_eq!(fixture.admitted.usage().buffer_bytes, CHARGE);
        assert!(!fixture.gate.retired.load(Ordering::Acquire));
        let mut closing = Box::pin(boundary.close());
        poll_fn(|task| {
            assert!(closing.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        fixture.gate.release();
        closing.await.unwrap();
        assert!(fixture.gate.retired.load(Ordering::Acquire));
        let reusable = fixture.admitted.reserve(&cx, &node, 0, WAIT).await.unwrap();
        drop(reusable);
        assert_eq!(fixture.admitted.usage().buffer_bytes, 0);
        fixture.finish(&cx).await;
    });
}
