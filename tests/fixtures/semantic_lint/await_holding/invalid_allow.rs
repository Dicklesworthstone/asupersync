async fn invalid_allow_for_permit_crosses_await(semaphore: &Semaphore, cx: &Cx) {
    let permit = semaphore.acquire(cx).await;
    // asupersync-lint:allow await-while-holding-capability-resource reason=test-fixture
    flush_queue(cx).await;
    drop(permit);
}
