//! Fan out tasks through the v2 spawn surface and join them — no
//! `&mut RuntimeState` anywhere (br-asupersync-69ftra, parent AC4).

use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let total: u32 = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs an ambient Cx");
        let handles: Vec<_> = (0..8)
            .map(|i| cx.spawn(move |_cx| async move { i }).expect("spawn"))
            .collect();
        let mut sum = 0;
        for mut handle in handles {
            sum += handle.join(&cx).await.expect("join");
        }
        sum
    });
    assert_eq!(total, 28);
    Ok(())
}
