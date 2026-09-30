//! `join!` and `scope!` on the native runtime.
//!
//! `join!` polls its branches inline and completes once every branch has.
//! `scope!` binds the current region's `Scope` as `scope` for its body. A task
//! spawned there with `Cx::spawn` receives its own child `Cx`, belongs to the
//! same region, and is joined through the parent `Cx`.
//!
//! `spawn!` expands to `Scope::spawn_registered`, which needs `&mut
//! RuntimeState`; only a lab or test harness holds that, so runtime tasks use
//! `Cx::spawn` as below.
#![allow(missing_docs)]

#[cfg(feature = "proc-macros")]
fn main() {
    use asupersync::Cx;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::{join, scope};

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build a current-thread runtime");
    let (joined, spawned, same_region) = runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("a runtime task has a Cx");
        let joined = join!(async { 1 }, async { 2 });
        let (spawned, same_region) = scope!(cx, {
            let mut handle = cx
                .spawn(move |child| async move { (40 + 2, child.region_id()) })
                .expect("the runtime admits the task");
            let (value, child_region) = handle.join(&cx).await.expect("the task completes");
            (value, child_region == scope.region_id())
        });
        (joined, spawned, same_region)
    }));

    assert_eq!(joined, (1, 2));
    assert_eq!(spawned, 42);
    assert!(
        same_region,
        "the spawned task belongs to the scope's region"
    );
    println!(
        "join!: {joined:?}; the task spawned in scope! returned {spawned} from the same region"
    );
}

#[cfg(not(feature = "proc-macros"))]
fn main() {}
