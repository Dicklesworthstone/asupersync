async fn permit_crosses_await(semaphore: &Semaphore, cx: &Cx) {
    let permit = semaphore.acquire(cx).await;
    flush_queue(cx).await;
    drop(permit);
}
