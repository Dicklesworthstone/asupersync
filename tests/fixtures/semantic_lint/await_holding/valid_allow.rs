async fn allowed_guard_crosses_await(mutex: &Mutex, cx: &Cx) {
    let guard = mutex.lock(cx).await;
    // asupersync-lint:allow await-while-holding-capability-resource reason=test-fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
    send_work(cx).await;
    drop(guard);
}
