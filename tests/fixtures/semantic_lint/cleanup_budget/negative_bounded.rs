use asupersync::{Budget, Time};

async fn bounded_cleanup(cx: &asupersync::Cx, parent_budget: Budget) {
    let cleanup_budget = parent_budget.meet(Budget::new().with_deadline(Time::from_secs(10)));
    cleanup_with_budget(cx, cleanup_budget).await;
    drain_with_budget(cx, cleanup_budget).await;
}

async fn cleanup_with_budget(_cx: &asupersync::Cx, _budget: Budget) {}

async fn drain_with_budget(_cx: &asupersync::Cx, _budget: Budget) {}
