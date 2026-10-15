async fn drive_bounded(cx: &Cx) {
    for _ in 0..3 {
        poll_once(cx).await;
    }
}
