# Vite Vanilla Consumer Fixture

Fixture for bead `asupersync-3qv04.6.1`.

Purpose:
- validate a real Vite vanilla consumer build against packaged Browser Edition outputs.
- exercise package import resolution from `@asupersync/browser`.

This fixture is executed through:
- `scripts/validate_vite_vanilla_consumer.sh`

The validation script copies this fixture into a temporary workspace and installs local package copies to keep runs deterministic and side-effect free.
