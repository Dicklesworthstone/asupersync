import re
import sys

def main():
    with open('src/sync/pool_metamorphic_tests.rs', 'r') as f:
        content = f.read()

    # Replace #[tokio::test]\n    async fn xxx() { ... }
    # with #[test]\n    fn xxx() { futures_lite::future::block_on(async { ... }); }
    
    # We'll do it manually:
    content = content.replace("#[tokio::test]\n    async fn mr_pool_accounting_invariant() {\n", "#[test]\n    fn mr_pool_accounting_invariant() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_pool_accounting_invariant\");\n    }", "        crate::test_complete!(\"mr_pool_accounting_invariant\");\n        });\n    }")

    content = content.replace("#[tokio::test]\n    async fn mr_cancel_safety_invariance() {\n", "#[test]\n    fn mr_cancel_safety_invariance() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_cancel_safety_invariance\");\n    }", "        crate::test_complete!(\"mr_cancel_safety_invariance\");\n        });\n    }")

    content = content.replace("#[tokio::test]\n    async fn mr_return_vs_drop_equivalence() {\n", "#[test]\n    fn mr_return_vs_drop_equivalence() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_return_vs_drop_equivalence\");\n    }", "        crate::test_complete!(\"mr_return_vs_drop_equivalence\");\n        });\n    }")

    content = content.replace("#[tokio::test]\n    async fn mr_discard_vs_return_counting() {\n", "#[test]\n    fn mr_discard_vs_return_counting() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_discard_vs_return_counting\");\n    }", "        crate::test_complete!(\"mr_discard_vs_return_counting\");\n        });\n    }")

    content = content.replace("#[tokio::test]\n    async fn mr_hold_duration_invariance() {\n", "#[test]\n    fn mr_hold_duration_invariance() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_hold_duration_invariance\");\n    }", "        crate::test_complete!(\"mr_hold_duration_invariance\");\n        });\n    }")

    content = content.replace("#[tokio::test]\n    async fn mr_composite_operation_sequence() {\n", "#[test]\n    fn mr_composite_operation_sequence() {\n        futures_lite::future::block_on(async {\n")
    content = content.replace("        crate::test_complete!(\"mr_composite_operation_sequence\");\n    }", "        crate::test_complete!(\"mr_composite_operation_sequence\");\n        });\n    }")

    # Replace tokio::select! instances
    tokio_select_1 = """                tokio::select! {
                    result = acquire_future => {
                        if let Ok(resource) = result {
                            acquired_count += 1;

                            // Hold the resource briefly
                            crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(*hold_ms)).await;

                            resource.return_to_pool();
                            returned_count += 1;
                        }
                    }
                    _ = cancel_future => {
                        cancel_count += 1;
                    }
                }"""
    replacement_1 = """                futures_lite::future::race(
                    async {
                        if let Ok(resource) = acquire_future.await {
                            acquired_count += 1;

                            // Hold the resource briefly
                            crate::time::sleep(Time::ZERO,Time::ZERO,Duration::from_millis(*hold_ms)).await;

                            resource.return_to_pool();
                            returned_count += 1;
                        }
                    },
                    async {
                        cancel_future.await;
                        cancel_count += 1;
                    }
                ).await;"""
    content = content.replace(tokio_select_1, replacement_1)

    tokio_select_2 = """        tokio::select! {
            result = acquire_future => {
                // If acquire succeeded before cancel, return the resource
                if let Ok(resource) = result {
                    resource.return_to_pool();
                }
            }
            _ = cancel_future => {
                // Cancellation occurred
            }
        }"""
    replacement_2 = """        futures_lite::future::race(
            async {
                if let Ok(resource) = acquire_future.await {
                    resource.return_to_pool();
                }
            },
            async {
                cancel_future.await;
            }
        ).await;"""
    content = content.replace(tokio_select_2, replacement_2)

    with open('src/sync/pool_metamorphic_tests.rs', 'w') as f:
        f.write(content)

if __name__ == "__main__":
    main()