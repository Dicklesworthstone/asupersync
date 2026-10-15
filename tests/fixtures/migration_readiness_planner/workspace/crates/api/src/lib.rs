use asupersync::Cx;

pub async fn worker(cx: &Cx) {
    cx.trace("workspace fixture");
}
