use asupersync::Budget;
use std::time::Duration;

async fn unbounded_cleanup(cx: &asupersync::Cx) {
    let _budget = Budget::INFINITE;
    cleanup(cx).await;
    drain(cx, Duration::from_secs(30)).await;
}

async fn cleanup(_cx: &asupersync::Cx) {}

async fn drain(_cx: &asupersync::Cx, _duration: Duration) {}
