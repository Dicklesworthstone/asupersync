fn allowed_drop_loser_fixture() {
    let loser_handle = spawn_loser_task();
    // asupersync-lint:allow drop-based-race-loser-handling reason=test-fixture owner=asupersync-idea-wizard-fifth-wave-3gaiun.3.2
    drop(loser_handle);
}
