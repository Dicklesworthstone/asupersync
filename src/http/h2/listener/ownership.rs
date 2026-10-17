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
#[path = "ownership_inline_tests.rs"]
mod tests;
