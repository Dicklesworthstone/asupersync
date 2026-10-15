use asupersync::{Cx, Outcome};

pub async fn handle(cx: &Cx) -> Outcome<(), ()> {
    cx.trace("native fixture");
    Outcome::ok(())
}
