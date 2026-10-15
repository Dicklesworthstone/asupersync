#![doc = "Integration tests for asupersync production-runtime entry macros."]

#[asupersync_macros::test]
async fn entry_asupersync_test_without_cx_runs() {
    assert_eq!(2 + 2, 4);
}

#[asupersync_macros::test(flavor = "current_thread", workers = 1, budget = 64)]
async fn entry_asupersync_test_with_cx_runs(cx: &asupersync::Cx) -> Result<(), asupersync::Error> {
    let _task_id = cx.task_id();
    assert!(asupersync::Cx::current().is_some());
    Ok(())
}
