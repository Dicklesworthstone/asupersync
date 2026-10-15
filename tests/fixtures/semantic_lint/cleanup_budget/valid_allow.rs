use asupersync::Budget;

async fn documented_unbounded_cleanup() {
    // asupersync-lint:allow unbounded-cleanup-budget reason=test-fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
    let _budget = Budget::INFINITE;
}
