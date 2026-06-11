async fn guard_crosses_await(mutex: &Mutex, cx: &Cx) {
    let guard = mutex.lock(cx).await;
    send_work(cx).await;
    drop(guard);
}
