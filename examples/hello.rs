use asupersync::main;
#[main]
async fn main(cx: &asupersync::Cx) {
    cx.checkpoint().expect("checkpoint");
}
