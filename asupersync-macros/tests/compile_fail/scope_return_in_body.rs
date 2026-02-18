use asupersync_macros::scope;

struct DummyCx;

async fn example(cx: &DummyCx) {
    // return is forbidden inside scope! body
    scope!(cx, { return 42; });
}

fn main() {}
