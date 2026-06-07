use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel::<String>(8);
    let handle = tokio::spawn(background_loop(rx));
    let _ = tx.send("work".to_string()).await;
    let _ = handle.await;
    let _router = build_router();
    let _stack = tower::ServiceBuilder::new();
    let _client = reqwest::Client::new();
    let _token = std::env::var("TOKEN").ok();
    let _config = std::fs::read_to_string("service.toml").ok();
    let _thread = std::thread::spawn(|| ());
}

async fn background_loop(mut rx: mpsc::Receiver<String>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
            value = rx.recv() => {
                if value.is_none() {
                    break;
                }
            }
        }
        break;
    }
}

fn build_router() -> axum::Router {
    axum::Router::<()>::new()
}
