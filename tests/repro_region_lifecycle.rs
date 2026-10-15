//! Regression coverage for runtime task region inheritance.

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;

#[test]
fn runtime_task_scope_inherits_current_cx_region_id() {
    let runtime = RuntimeBuilder::new().build().expect("runtime build");

    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task should install ambient Cx");
        let scope = cx.scope();
        assert_eq!(scope.region_id(), cx.region_id());
    });

    runtime.block_on(handle);
}
