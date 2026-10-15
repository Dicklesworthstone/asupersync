//! Fibers: concurrent child futures that borrow the caller's data.
//!
//! `fiber::scope` runs its fibers inside the calling task, so they need no
//! `'static` bound and no runtime task record, and the scope returns only
//! after every fiber has finished. Run with
//! `cargo run --example fibers_borrowing`.

use asupersync::cx::fiber;
use asupersync::main;

#[main]
async fn main() {
    let words = vec!["structured", "concurrency", "over", "borrowed", "data"];
    let words = &words;
    let letters = fiber::scope(|scope| async move {
        let handles: Vec<_> = words
            .iter()
            .map(|word| scope.spawn(async move { word.len() }))
            .collect();
        let mut letters = 0;
        for handle in handles {
            letters += handle.await.expect("fiber finished");
        }
        letters
    })
    .await;
    assert_eq!(letters, words.iter().map(|word| word.len()).sum::<usize>());
    println!("{letters} letters counted by {} fibers", words.len());
}
