//! Connection-owned request coordinators and admission accounting.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct H2RequestLimits {
    pub(super) connection: usize,
    pub(super) global: usize,
}

impl Default for H2RequestLimits {
    fn default() -> Self {
        Self {
            connection: 256,
            global: 4096,
        }
    }
}

pub(super) struct H2RequestOwners {
    region: Option<ChildRegion>,
    tasks: BTreeMap<u32, TaskHandle<()>>,
    completed: Option<(u32, Result<(), JoinError>)>,
}

impl H2RequestOwners {
    pub(super) async fn new(cx: &Cx) -> io::Result<Self> {
        let region = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            region: Some(region),
            tasks: BTreeMap::new(),
            completed: None,
        })
    }

    pub(super) fn cx(&self) -> &Cx {
        self.region.as_ref().expect("open request region").cx()
    }

    pub(super) fn len(&self) -> usize {
        self.tasks.len()
    }

    pub(super) fn insert(&mut self, stream_id: u32, task: TaskHandle<()>) {
        assert!(self.tasks.insert(stream_id, task).is_none());
    }

    pub(super) fn cancel(&self, stream_id: u32, reason: CancelReason) {
        if let Some(task) = self.tasks.get(&stream_id) {
            task.abort_with_reason(reason);
        }
    }

    fn poll_completed(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.completed.is_some() {
            return Poll::Ready(());
        }
        for (&stream_id, task) in &mut self.tasks {
            if let Poll::Ready(result) = task.poll_join(cx) {
                self.completed = Some((stream_id, result));
                return Poll::Ready(());
            }
        }
        Poll::Pending
    }

    pub(super) fn poll_event<F>(
        &mut self,
        mut response: Pin<&mut F>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<DriverEvent>
    where
        F: Future<Output = Result<FunnelItem, mpsc::RecvError>>,
    {
        let response_pending = match response.as_mut().poll(cx) {
            Poll::Ready(Ok(item)) => return Poll::Ready(DriverEvent::Response(item)),
            Poll::Ready(Err(_)) => false,
            Poll::Pending => true,
        };
        if self.poll_completed(cx).is_ready() {
            // Publication and coordinator completion can happen on another
            // worker between the first funnel probe and the terminal probe.
            // Recheck after observing terminal publication, and retain that
            // consumed terminal while an earlier response wins the event.
            if response_pending && let Poll::Ready(Ok(item)) = response.as_mut().poll(cx) {
                return Poll::Ready(DriverEvent::Response(item));
            }
            let (stream_id, result) = self.completed.take().expect("polled terminal coordinator");
            return Poll::Ready(DriverEvent::RequestRetired(stream_id, result));
        }
        Poll::Pending
    }

    pub(super) fn remove_completed(&mut self, stream_id: u32) {
        self.tasks.remove(&stream_id);
    }

    pub(super) fn cancel_all(&self, reason: CancelReason) {
        for task in self.tasks.values() {
            task.abort_with_reason(reason.clone());
        }
    }

    pub(super) async fn close(&mut self, reason: CancelReason) -> io::Result<()> {
        // Cancel every admitted and pending coordinator before awaiting any
        // one of them. A reset never frees this ownership slot early.
        self.cancel_all(reason.clone());
        let region = self.region.take().expect("open request region");
        let cancellation = region.cancel(reason);
        // A funnel item can win after a terminal handle was consumed. Its
        // cached terminal must never be polled for a second time at teardown.
        if let Some((stream_id, result)) = self.completed.take() {
            self.tasks.remove(&stream_id);
            if let Err(error) = result {
                if let Some(cx) = Cx::current() {
                    cx.trace(&format!("h2_request_coordinator_terminal: {error:?}"));
                }
            }
        }
        for task in self.tasks.values_mut() {
            if let Err(error) = std::future::poll_fn(|cx| task.poll_join(cx)).await {
                if let Some(cx) = Cx::current() {
                    cx.trace(&format!("h2_request_coordinator_terminal: {error:?}"));
                }
            }
        }
        self.tasks.clear();
        // Region close additionally waits for descendants and finalizers; a
        // coordinator join alone cannot certify that its subtree is retired.
        let closed = region.close().await;
        cancellation.map_err(io::Error::other)?;
        closed.map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_published_between_funnel_and_join_probes_precedes_retirement() {
        let cx = Cx::for_testing();
        let (terminal, receiver) = crate::channel::oneshot::channel();
        let task = TaskHandle::new(cx.task_id(), receiver, std::sync::Weak::new());
        let mut owners = H2RequestOwners {
            region: None,
            tasks: BTreeMap::from([(1, task)]),
            completed: None,
        };
        let (sender, mut receiver) = mpsc::channel(1);
        let mut terminal = Some(terminal);
        let mut received = std::pin::pin!(receiver.recv(&cx));
        let mut probes = 0;
        let mut response = std::pin::pin!(std::future::poll_fn(|task_cx| {
            probes += 1;
            let result = received.as_mut().poll(task_cx);
            if probes == 1 {
                assert!(result.is_pending(), "first funnel probe is genuinely empty");
                // Simulate the other worker publishing after our empty probe
                // and finishing before this poll reaches the join handle.
                assert!(
                    sender
                        .try_send(FunnelItem::Response {
                            stream_id: 1,
                            response: Response::new(200, "OK", Vec::new()).into_h2_response(),
                            guard: InFlightRequestGuard::acquire(None),
                            suppress_response_body: false,
                        })
                        .is_ok()
                );
                assert!(terminal.take().unwrap().send_blocking(Ok(())).is_ok());
            }
            result
        }));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            owners.poll_event(response.as_mut(), &mut task_cx),
            Poll::Ready(DriverEvent::Response(FunnelItem::Response {
                stream_id: 1,
                ..
            }))
        ));
        assert!(
            owners.completed.is_some(),
            "terminal handle is consumed once and retained"
        );
        let mut empty = std::pin::pin!(std::future::pending());
        assert!(matches!(
            owners.poll_event(empty.as_mut(), &mut task_cx),
            Poll::Ready(DriverEvent::RequestRetired(1, Ok(())))
        ));
        owners.remove_completed(1);
        assert_eq!(owners.len(), 0);
    }

    #[test]
    fn producer_local_rejection_and_owner_cancel_both_start_bounded_drain() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{RegionId, TaskId};
        use std::sync::atomic::AtomicBool;

        struct Retirement(Arc<AtomicBool>);
        impl Drop for Retirement {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        for owner_cancel in [false, true] {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let _ambient = Cx::set_current(Some(owner.clone()));
            let region = ServerRequestRegion::mint_from_connection(
                "h2-produced",
                Budget::INFINITE,
                Time::ZERO,
                &owner,
            );
            let producer_cx = region.cx().clone();
            let retired = Arc::new(AtomicBool::new(false));
            let retirement = Retirement(Arc::clone(&retired));
            let observed_cancel = Arc::new(AtomicBool::new(false));
            let observed_by_body = Arc::clone(&observed_cancel);
            // Deliberately never wakes itself and never finishes, even after
            // observing cancellation. The protocol drain must bound it.
            let producer = std::future::poll_fn(move |_| {
                let _retained = &retirement;
                if Cx::current().unwrap().is_cancel_requested() {
                    observed_by_body.store(true, Ordering::Release);
                }
                Poll::<()>::Pending
            });
            let run = region.run_with_protocol_drain(
                RequestBudgetSource::Inherited,
                Some(producer_cx.clone()),
                Duration::from_millis(10),
                producer,
            );
            let mut future = Box::pin(forward_h2_producer_cancellation(&owner, &producer_cx, run));
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            if owner_cancel {
                owner.cancel_with(CancelKind::User, Some("connection owner cancelled"));
            } else {
                ProducedCancellationGuard::new(producer_cx.clone())
                    .cancel("locally rejected produced response body");
                assert!(!owner.is_cancel_requested());
            }
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            assert!(observed_cancel.load(Ordering::Acquire));
            assert!(!retired.load(Ordering::Acquire));
            clock.advance_to(Time::from_millis(10));
            assert!(timer.process_timers() > 0);
            assert!(matches!(
                future.as_mut().poll(&mut task_cx),
                Poll::Ready(ServerHopOutcome::ConnectionLost)
            ));
            drop(future);
            assert!(retired.load(Ordering::Acquire));
            assert_eq!(timer.pending_count(), 0);
        }
    }
}
