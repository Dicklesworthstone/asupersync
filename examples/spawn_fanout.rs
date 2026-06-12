use asupersync::{cx::Cx, runtime::RuntimeBuilder};

fn main() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let total = runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("runtime task Cx");
        let mut sum = 0;
        for i in 0..10 {
            let mut handle = cx.spawn(move |_cx| async move { i }).expect("spawn");
            sum += handle.join(&cx).await.expect("join");
        }
        sum
    }));
    assert_eq!(total, 45);
}
