async fn guard_dropped_before_await(mutex: &Mutex, cx: &Cx) {
    let guard = mutex.lock(cx).await;
    update_state(&guard);
    drop(guard);
    send_work(cx).await;
}

async fn guard_scope_ends_before_await(mutex: &Mutex, cx: &Cx) {
    {
        let guard = mutex.lock(cx).await;
        update_state(&guard);
    }
    send_work(cx).await;
}
