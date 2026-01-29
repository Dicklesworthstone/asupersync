use asupersync::cx::Cx;
use asupersync::test_utils::init_test_logging;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[tokio::test]
async fn test_race_empty_is_never() {
    init_test_logging();
    
    let cx = Cx::for_testing();
    
    // An empty race should be "never" (pending forever).
    let futures: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
    
    // Wrap in timeout to verify it hangs
    let result = tokio::time::timeout(Duration::from_millis(50), cx.race(futures)).await;
    
    assert!(result.is_err(), "race([]) should hang (timeout), but it returned {:?}", result);
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
        // race([]) should hang
        let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = vec![];
        cx.race(empty).await.unwrap_or(-1)
    }) as Pin<Box<dyn Future<Output = i32> + Send>>;
    
    // Use timeout to ensure the whole test doesn't hang if we broke something else
    let combined = tokio::time::timeout(Duration::from_millis(100), cx.race(vec![f1, f2])).await;
    
    assert!(combined.is_ok(), "Outer race timed out");
    let inner_res = combined.unwrap();
    
    // f1 should win with 42. f2 (race([])) should hang.
    assert_eq!(inner_res.unwrap(), 42, "race(a, race([])) should behave like a");
}