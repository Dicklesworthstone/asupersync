//! Layering primitives for services.

/// A layer decorates an inner service to produce a new service.
pub trait Layer<S> {
    /// The service produced by this layer.
    type Service;

    /// Wraps an inner service with this layer.
    fn layer(&self, inner: S) -> Self::Service;
}

/// Identity layer that returns the inner service unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity;

impl<S> Layer<S> for Identity {
    type Service = S;

    fn layer(&self, inner: S) -> Self::Service {
        inner
    }
}

/// Stack two layers, applying `inner` first and then `outer`.
#[derive(Debug, Clone)]
pub struct Stack<Inner, Outer> {
    inner: Inner,
    outer: Outer,
}

impl<Inner, Outer> Stack<Inner, Outer> {
    /// Creates a new stacked layer.
    pub fn new(inner: Inner, outer: Outer) -> Self {
        Self { inner, outer }
    }

    /// Returns a reference to the inner layer.
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    /// Returns a reference to the outer layer.
    pub fn outer(&self) -> &Outer {
        &self.outer
    }
}

impl<S, Inner, Outer> Layer<S> for Stack<Inner, Outer>
where
    Inner: Layer<S>,
    Outer: Layer<Inner::Service>,
{
    type Service = Outer::Service;

    fn layer(&self, service: S) -> Self::Service {
        self.outer.layer(self.inner.layer(service))
    }
}
