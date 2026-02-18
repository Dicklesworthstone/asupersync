#![allow(missing_docs)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;

#[test]
fn test_scope_inherits_region_id_in_phase0() {
    let runtime = RuntimeBuilder::new().build().expect("runtime build");

    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().unwrap_or_else(Cx::for_testing);
        let scope = cx.scope();
        assert_eq!(scope.region_id(), cx.region_id());
    });

    runtime.block_on(handle);
}
