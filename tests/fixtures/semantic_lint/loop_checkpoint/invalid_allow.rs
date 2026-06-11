async fn invalidly_allowed_loop(cx: &Cx) {
    // asupersync-lint:allow loop-without-cx-checkpoint reason=test-fixture
    loop {
        poll_once(cx).await;
    }
}
