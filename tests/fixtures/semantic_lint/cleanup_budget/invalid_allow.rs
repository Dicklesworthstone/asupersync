use asupersync::Budget;

async fn invalid_unbounded_cleanup() {
    // asupersync-lint:allow unbounded-cleanup-budget reason=test-fixture
    let _budget = Budget::INFINITE;
}
