//! Builder for composing service layers.

use super::{Identity, Layer, Stack};

/// Builder for stacking layers around a service.
#[derive(Debug, Clone)]
pub struct ServiceBuilder<L> {
    layer: L,
}

impl ServiceBuilder<Identity> {
    /// Creates a new builder with the identity layer.
    #[must_use]
    pub fn new() -> Self {
        Self { layer: Identity }
    }
}

impl<L> ServiceBuilder<L> {
    /// Adds a new layer to the builder.
    #[must_use]
    pub fn layer<T>(self, layer: T) -> ServiceBuilder<Stack<L, T>> {
        ServiceBuilder {
            layer: Stack::new(self.layer, layer),
        }
    }

    /// Wraps the given service with the configured layers.
    #[must_use]
    pub fn service<S>(self, service: S) -> L::Service
    where
        L: Layer<S>,
    {
        self.layer.layer(service)
    }

    /// Returns a reference to the composed layer stack.
    #[must_use]
    pub fn layer_ref(&self) -> &L {
        &self.layer
    }
}
