#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic regression tests for pool acquire/drop behavior.

use asupersync::cx::Cx;
use asupersync::sync::{GenericPool, Pool, PoolConfig};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, PartialEq, Eq)]
struct AcquireDropTranscript {
    acquired: Vec<u32>,
    reacquired: Vec<u32>,
    projections: Vec<(usize, usize, usize, u64)>,
}

fn run_acquire_drop_transcript(release_by_drop: bool) -> AcquireDropTranscript {
    let counter = AtomicU32::new(0);
    let factory = move || {
        let id = counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(id) })
            as Pin<Box<dyn Future<Output = _> + Send>>
    };
    let pool = GenericPool::new(factory, PoolConfig::with_max_size(2));
    let cx: Cx = Cx::for_testing();
    let mut transcript = AcquireDropTranscript {
        acquired: Vec::new(),
        reacquired: Vec::new(),
        projections: Vec::new(),
    };

    for _ in 0..8 {
        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("initial acquire should succeed");
        transcript.acquired.push(*resource);
        if release_by_drop {
            drop(resource);
        } else {
            resource.return_to_pool();
        }

        let after_release = pool.stats();
        transcript.projections.push((
            after_release.active,
            after_release.idle,
            after_release.total,
            after_release.total_acquisitions,
        ));

        let resource = futures_lite::future::block_on(pool.acquire(&cx))
            .expect("reacquire after release should succeed");
        transcript.reacquired.push(*resource);
        if release_by_drop {
            drop(resource);
        } else {
            resource.return_to_pool();
        }

        let after_reacquire_release = pool.stats();
        transcript.projections.push((
            after_reacquire_release.active,
            after_reacquire_release.idle,
            after_reacquire_release.total,
            after_reacquire_release.total_acquisitions,
        ));
    }

    transcript
}

#[test]
fn metamorphic_pool_acquire_drop_matches_explicit_return() {
    let dropped = run_acquire_drop_transcript(true);
    let explicitly_returned = run_acquire_drop_transcript(false);

    assert_eq!(
        dropped, explicitly_returned,
        "dropping PooledResource must preserve return_to_pool reuse and accounting"
    );
    assert!(
        dropped
            .acquired
            .iter()
            .zip(dropped.reacquired.iter())
            .all(|(first, second)| first == second),
        "released resources should be reused before replacements are created"
    );
}
