fn drops_race_loser_without_drain() {
    let loser_handle = spawn_loser_task();
    drop(loser_handle);
}

fn defuses_drop_abort_without_proof() {
    defuse_drop_abort(loser_future);
}
