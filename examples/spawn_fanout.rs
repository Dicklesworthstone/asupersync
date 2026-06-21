use asupersync::{main, prelude::*};
#[main]
async fn main(cx: &Cx) {
    let mut set = JoinSet::in_cx(cx);
    for i in 0..10_u32 {
        set.spawn(cx, move |_| async move { Ok::<_, ()>(i) })
            .expect("spawn");
    }
    let total = set
        .join_all(cx)
        .await
        .into_iter()
        .fold(0, |sum, outcome| sum + outcome.expect("member ok"));
    assert_eq!(total, 45);
}
