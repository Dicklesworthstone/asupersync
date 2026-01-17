#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn masked_panic_safety() {
        let cx = Cx::for_testing();
        
        // Initial state: not masked
        assert!(cx.checkpoint().is_ok());
        cx.set_cancel_requested(true);
        assert!(cx.checkpoint().is_err());

        // Run a masked block that panics
        let cx_clone = cx.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            cx_clone.masked(|| {
                panic!("oops");
            });
        }));

        // After panic, mask depth should have been restored
        // If the bug exists, this will FAIL because mask_depth is still 1
        assert!(
            cx.checkpoint().is_err(), 
            "Cx remains masked after panic! mask_depth leaked."
        );
    }
}
