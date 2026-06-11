async fn drive_with_checkpoint(cx: &Cx) {
    loop {
        cx.checkpoint().await;
        poll_once(cx).await;
    }
}
