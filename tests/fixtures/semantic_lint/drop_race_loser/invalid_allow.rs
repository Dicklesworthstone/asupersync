fn invalid_allow_for_drop_loser() {
    let loser_handle = spawn_loser_task();
    // asupersync-lint:allow drop-based-race-loser-handling reason=test-fixture
    drop(loser_handle);
}
