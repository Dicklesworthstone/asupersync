#![allow(missing_docs)]

use asupersync::runtime::RuntimeBuilder;
use asupersync::Cx;

#[test]
fn test_scope_inherits_region_id_in_phase0() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build");

    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("cx");
        let scope = cx.scope();
        assert_eq!(scope.region_id(), cx.region_id());
    });

    runtime.block_on(handle);
}
