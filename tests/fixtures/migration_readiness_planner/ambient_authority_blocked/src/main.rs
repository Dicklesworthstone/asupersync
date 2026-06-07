fn main() {
    let _token = std::env::var("TOKEN").ok();
    let _config = std::fs::read_to_string("service.toml").ok();
}

async fn ambient_worker() {
    async_std::task::yield_now().await;
}
