//! External compile check for absent and explicitly restored service APIs.
//!
//! Compile this same target with `slim` (expected unresolved imports) and with
//! `slim,services` (expected success). Never cfg away the negative imports.

use asupersync::grpc::Status;
use asupersync::http::h1::HttpClient;
use asupersync::net::websocket::CloseCode;
use asupersync::server::shutdown::ShutdownSignal;
use asupersync::web::Router;

fn main() {
    // Name the concrete public types without network access or worker threads.
    // This is compiler/API evidence, not protocol execution evidence.
    let _ = std::any::type_name::<HttpClient>();
    let _ = std::any::type_name::<Router>();
    let _ = std::any::type_name::<Status>();
    let _ = std::any::type_name::<ShutdownSignal>();
    let _ = std::any::type_name::<CloseCode>();
}
