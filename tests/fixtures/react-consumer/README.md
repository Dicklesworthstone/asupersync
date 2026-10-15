# React Consumer Fixture

Fixture for bead `asupersync-3qv04.9.3.2`.

Purpose:
- publish a maintained React example that exercises the supported
  `@asupersync/react` provider/hook path.
- validate package import resolution and production bundling against local
  packaged Browser Edition artifacts.

This fixture is executed through:
- `scripts/validate_react_consumer.sh`

The validation script copies this fixture into a temporary workspace and
installs local package copies to keep runs deterministic and side-effect free.
