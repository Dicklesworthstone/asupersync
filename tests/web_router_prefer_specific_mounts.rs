//! `Router::prefer_specific_mounts` (br-asupersync-vftw38 item 4): by
//! default a router consults its mounts only when none of its own routes
//! matches, so a top-level `/*` or `/:page` route shadows `nest("/api", ..)`
//! and `nest("/admin", ..)`. With the option the more specific of the two
//! wins. Both orders are pinned here.

use asupersync::web::extract::Request;
use asupersync::web::handler::FnHandler;
use asupersync::web::response::StatusCode;
use asupersync::web::router::{Router, get};

fn ok_handler() -> &'static str {
    "ok"
}

fn created_handler() -> StatusCode {
    StatusCode::CREATED
}

#[test]
fn prefer_specific_mounts_keeps_a_param_or_wildcard_route_from_shadowing_a_mount() {
    // br-asupersync-vftw38 item 4: `/:page` captures `/admin` ahead of a
    // protected `nest("/admin", ..)` unless mounts compete by specificity.
    let admin = || {
        Router::new()
            .route("/", get(FnHandler::new(created_handler)))
            .route("/users", get(FnHandler::new(created_handler)))
    };
    let default_order = Router::new()
        .route("/:page", get(FnHandler::new(ok_handler)))
        .nest("/admin", admin());
    assert_eq!(
        default_order.handle(Request::new("GET", "/admin")).status,
        StatusCode::OK
    );
    assert_eq!(
        default_order
            .handle(Request::new("GET", "/admin/users"))
            .status,
        StatusCode::CREATED,
        "no route matches two segments, so the mount is consulted"
    );

    let app = Router::new()
        .route("/:page", get(FnHandler::new(ok_handler)))
        .nest("/admin", admin())
        .prefer_specific_mounts(true);
    assert_eq!(
        app.handle(Request::new("GET", "/admin")).status,
        StatusCode::CREATED
    );
    assert_eq!(
        app.handle(Request::new("GET", "/admin/users")).status,
        StatusCode::CREATED
    );
    assert_eq!(
        app.handle(Request::new("GET", "/about")).status,
        StatusCode::OK
    );

    // `.route("/*", spa).nest("/api", api)` sends every API path to spa
    // by default.
    let api = || Router::new().route("/users", get(FnHandler::new(created_handler)));
    let default_order = Router::new()
        .route("/*", get(FnHandler::new(ok_handler)))
        .nest("/api", api());
    assert_eq!(
        default_order
            .handle(Request::new("GET", "/api/users"))
            .status,
        StatusCode::OK
    );
    let app = Router::new()
        .route("/*", get(FnHandler::new(ok_handler)))
        .nest("/api", api())
        .prefer_specific_mounts(true);
    assert_eq!(
        app.handle(Request::new("GET", "/api/users")).status,
        StatusCode::CREATED
    );
    // A path the mount does not route gets the mount's 404, as a
    // `prefix/*` route would, not the less specific catch-all.
    assert_eq!(
        app.handle(Request::new("GET", "/api/missing")).status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.handle(Request::new("GET", "/index.html")).status,
        StatusCode::OK
    );

    // An equally specific top-level route still wins its tie with a mount.
    let users = Router::new().route("/:id", get(FnHandler::new(created_handler)));
    let app = Router::new()
        .route("/users/:id", get(FnHandler::new(ok_handler)))
        .nest("/users", users)
        .prefer_specific_mounts(true);
    assert_eq!(
        app.handle(Request::new("GET", "/users/7")).status,
        StatusCode::OK
    );
}
