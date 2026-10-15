fn invalidly_ignore_fixture_outcome() {
    // asupersync-lint:allow ignored-outcome-severity reason=test-fixture
    let _ = Outcome::Panicked(panic_payload());
}
