async fn allowed_uncheckpointed_loop(cx: &Cx) {
    // asupersync-lint:allow loop-without-cx-checkpoint reason=test-fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
    loop {
        poll_once(cx).await;
    }
}
