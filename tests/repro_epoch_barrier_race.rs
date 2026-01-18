use asupersync::epoch::{EpochBarrier, EpochId};
use asupersync::types::Time;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_epoch_barrier_overflow_race() {
    // 10 expected, but 20 arrive
    let expected = 10;
    let actual = 20;
    let barrier = Arc::new(EpochBarrier::new(EpochId(1), expected, Time::ZERO));
    
    let start_gate = Arc::new(Barrier::new(actual as usize));
    
    let mut handles = Vec::new();
    
    for i in 0..actual {
        let b = barrier.clone();
        let g = start_gate.clone();
        let id = format!("p-{}", i);
        
        handles.push(thread::spawn(move || {
            g.wait(); 
            // We ignore error "Participant already arrived" (IDs are unique so won't happen)
            // We ignore "Barrier already triggered" - wait, checking this might stop latecomers?
            // arrive() checks is_triggered() at the start!
            
            // If checking is_triggered() is racey (read lock), multiple might pass it.
            match b.arrive(&id, Time::ZERO) {
                Ok(res) => res.is_some(),
                Err(_) => false, // Already triggered error counts as "did not trigger"
            }
        }));
    }
    
    let mut trigger_count = 0;
    for h in handles {
        if h.join().unwrap() {
            trigger_count += 1;
        }
    }
    
    // Even with overflow, exactly ONE should trigger
    assert_eq!(trigger_count, 1, "Expected exactly 1 trigger, got {}", trigger_count);
}