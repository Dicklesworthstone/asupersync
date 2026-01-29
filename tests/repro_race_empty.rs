use asupersync::cx::Cx;
use asupersync::runtime::task_handle::JoinError;
use asupersync::test_utils::init_test_logging;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[tokio::test]
async fn test_race_empty_is_never() {
    init_test_logging();
    
    let cx = Cx::for_testing();
    
    // An empty race should be "never" (pending forever).
    // Currently, it returns Err(Cancelled).
    let futures: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
    let result = cx.race(futures).await;
    
    // If this assertion fails, it confirms the bug (it returned Err instead of hanging or behaving like never)
    // Note: In a real test we can't easily test "hangs forever" without a timeout.
    // But here we just check that it DOES NOT return the error immediately.
    
    // We expect it to NOT return Err(Cancelled).
    // Ideally it should timeout if we wrapped it in a timeout, but since we didn't,
    // if it returns ready immediately, that's wrong.
    
    assert!(result.is_err(), "Current implementation returns Err(Cancelled)");
    
    if let Err(JoinError::Cancelled(reason)) = &result {
        assert_eq!(reason.kind, asupersync::types::CancelKind::RaceLost);
        println!("Confirmed: race([]) returns Cancelled(RaceLost)");
    } else {
        panic!("Expected Cancelled error, got {:?}", result);
    }
}

#[tokio::test]
async fn test_race_identity_law_violation() {
    init_test_logging();
    let cx = Cx::for_testing();

    // Law: race(a, never) ≃ a
    // If race([]) is never, then race(async { 42 }, race([])) should be 42.
    
    let f1 = Box::pin(async { 
        tokio::time::sleep(Duration::from_millis(10)).await;
        42 
    }) as Pin<Box<dyn Future<Output = i32> + Send>>;
    
    let f2 = Box::pin(async {
        // race([]) currently returns Err immediately
        let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
        cx.race(empty).await.unwrap_or(-1)
    }) as Pin<Box<dyn Future<Output = i32> + Send>>;
    
    let combined = cx.race(vec![f1, f2]).await;
    
    // If bug exists, f2 wins immediately with -1 (or Err if we didn't unwrap).
    // If fixed, f2 hangs, so f1 wins with 42.
    
    assert_eq!(combined.unwrap(), -1, "Confirmed: race(a, race([])) fails because race([]) is not never");
}
