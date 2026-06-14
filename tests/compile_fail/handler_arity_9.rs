//! Arity-9 web handlers must fail with an explicit arity-limit diagnostic.

use std::collections::HashMap;

use asupersync::web::{
    Accept, ContentType, FnHandler9, Header, JsonExtract, Path, Query, State, UserAgent,
};

#[derive(Clone)]
struct TenantConfig;

#[derive(Clone)]
struct FeatureFlags;

type QueryMap = Query<HashMap<String, String>>;
type HeaderMap = HashMap<String, String>;
type Payload = JsonExtract<HashMap<String, String>>;

#[allow(clippy::too_many_arguments)]
fn audit(
    Path(_id): Path<String>,
    Query(_query): QueryMap,
    Header(_agent): Header<UserAgent>,
    Header(_accept): Header<Accept>,
    State(_tenant): State<TenantConfig>,
    State(_flags): State<FeatureFlags>,
    Header(_content_type): Header<ContentType>,
    _headers: HeaderMap,
    JsonExtract(_payload): Payload,
) -> &'static str {
    "too many extractors"
}

fn main() {
    let _handler = FnHandler9::<
        _,
        Path<String>,
        QueryMap,
        Header<UserAgent>,
        Header<Accept>,
        State<TenantConfig>,
        State<FeatureFlags>,
        Header<ContentType>,
        HeaderMap,
        Payload,
    >::new(audit);
}
