#![allow(missing_docs)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]

use asupersync_macros::{scope, spawn};
use std::future::Future;
use std::marker::PhantomData;

#[derive(Clone, Copy)]
struct MiniCx;

struct MiniScope;
struct MiniState;

#[derive(Debug)]
struct MiniError;

struct MiniHandle<T>(PhantomData<T>);

impl MiniCx {
    fn scope(&self) -> MiniScope {
        MiniScope
    }
}

impl MiniScope {
    fn spawn_registered<F, Fut>(
        &self,
        _state: &mut MiniState,
        _cx: &MiniCx,
        f: F,
    ) -> Result<MiniHandle<Fut::Output>, MiniError>
    where
        F: FnOnce(MiniCx) -> Fut,
        Fut: Future,
    {
        std::mem::drop(f(MiniCx));
        Ok(MiniHandle(PhantomData))
    }
}

#[test]
fn scope_state_binding_supports_spawn_macro() {
    let future = async {
        let cx = MiniCx;
        let mut state = MiniState;

        let value = scope!(cx, state: &mut state, {
            let _handle = spawn!(async { 42 });
            7
        });

        assert_eq!(value, 7);
    };

    std::mem::drop(future);
}
