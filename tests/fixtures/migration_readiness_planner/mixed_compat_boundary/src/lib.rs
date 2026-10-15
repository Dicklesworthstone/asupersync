use asupersync::Cx;

pub async fn handle_request(cx: &Cx) {
    cx.trace("mixed compat boundary fixture");
}

pub fn router() -> axum::Router {
    axum::Router::<()>::new()
}

pub fn service_stack() {
    let _stack = tower::ServiceBuilder::new();
    let _http_version = hyper::Version::HTTP_11;
}
