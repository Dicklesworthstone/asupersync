#[tokio::main]
async fn main() {
    let handle = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    });
    let _ = handle.await;
    let _router = axum::Router::<()>::new();
    let _client = reqwest::Client::new();
}
