async fn drive_forever(cx: &Cx) {
    loop {
        poll_once(cx).await;
    }
}
