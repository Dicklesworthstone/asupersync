use asupersync_macros::scope;

async fn example(cx: &asupersync::Cx) {
    // return is forbidden inside scope! body
    scope!(cx, { return 42; });
}

fn main() {}
