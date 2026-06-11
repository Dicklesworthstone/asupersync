async fn aborts_and_joins_race_loser(mut loser_handle: TaskHandle, cx: &Cx) {
    loser_handle.abort(CancelReason::race_loser());
    loser_handle.join(cx).await;
}
