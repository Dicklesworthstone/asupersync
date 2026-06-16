use asupersync::{main, prelude::*};

#[main]
async fn main(cx: &Cx) {
    let scope = cx.scope();
    let mut set = JoinSet::new(&scope);
    for i in 0..10_u32 {
        set.spawn(cx, move |_| async move { Ok::<_, ()>(i) })
            .expect("spawn");
    }
    let total: u32 = set.join_all(cx).await.into_iter().map(expect_ok).sum();
    assert_eq!(total, 45);
}

fn expect_ok(outcome: Outcome<u32, ()>) -> u32 {
    match outcome {
        Outcome::Ok(value) => value,
        other => panic!("unexpected outcome: {other:?}"),
    }
}
