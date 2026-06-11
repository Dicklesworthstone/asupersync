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

async fn permit_sent_before_await(sender: &Sender, receiver: &mut Receiver, cx: &Cx) {
    let permit = sender.reserve(cx).await;
    permit.send(42);
    receiver.recv(cx).await;
}

async fn generic_result_is_not_an_obvious_resource_binding(semaphore: &Semaphore, cx: &Cx) {
    let result = semaphore.acquire(cx).await;
    audit_path(cx).await;
    assert!(result.is_ok());
}
