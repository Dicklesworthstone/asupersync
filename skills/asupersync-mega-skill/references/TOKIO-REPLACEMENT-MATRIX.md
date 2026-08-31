# Tokio Replacement Matrix

The maintained replacement matrix is `TOKIO-MAPPING.md`. Use
`STACK-SURFACES.md` for support classes and feature gates, and
`COMPAT-BOUNDARY.md` before proposing interop.

This file intentionally does not duplicate the matrix. In particular, do not
infer that the compatibility crate hosts reqwest, axum, tonic, SQLx, or any
other Tokio runtime consumer. It implements specific trait/context adapters,
not a Tokio runtime; the exact downstream path needs compile and runtime proof.
