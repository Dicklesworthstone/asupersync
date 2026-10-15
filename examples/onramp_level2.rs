//! Level 2: own dynamic fan-out through a scope and its policy.

use asupersync::{main, prelude::*};

#[main]
async fn main(cx: &Cx) {
    let scope = cx.scope_with_budget(Budget::new().with_poll_quota(64));
    let mut tasks = JoinSet::new(&scope);

    for value in 1..=3_u32 {
        tasks
            .spawn(cx, move |_| async move { Ok::<_, Error>(value) })
            .expect("spawn region-owned task");
    }

    let sum = tasks
        .join_all(cx)
        .await
        .into_iter()
        .map(|outcome| outcome.expect("child succeeds"))
        .sum::<u32>();
    assert_eq!(sum, 6);
}
