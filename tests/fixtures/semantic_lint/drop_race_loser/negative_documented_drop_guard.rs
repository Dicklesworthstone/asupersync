fn documented_drop_guard_drains_loser(loser_handle: TaskHandle) {
    let loser_drain_guard = DropGuard::new(loser_handle);
    drop(loser_drain_guard);
}

fn defuse_with_loser_drain_proof(loser_future: RaceFuture) {
    // loser_drain_proof: this defuse path has a paired explicit drain proof.
    defuse_drop_abort(loser_future);
}

fn defuse_internal_api_behavior_is_not_a_candidate(join_future: JoinFuture) {
    join_future.defuse_drop_abort();
}
