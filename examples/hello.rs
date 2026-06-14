use asupersync::{Cx, main};
#[main]
async fn main(cx: &Cx) {
    cx.checkpoint().expect("checkpoint");
}
