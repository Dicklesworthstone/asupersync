# Conformance Test Fixture Maintenance Procedures

## Overview

This document outlines the live procedures for maintaining the RFC 6330
conformance fixture surfaces that ship in this repository.

## Routine Maintenance Tasks

### Monthly Review
1. **Check fixture age**: Review fixtures older than 30 days
2. **Version tracking**: Verify tracked fixture directories, age, and workflow support
3. **Coverage analysis**: Ensure test coverage remains comprehensive

### Quarterly Updates
1. **Golden workflow updates**: Refresh the real in-repo golden fixture suite
2. **Fixture regeneration**: Regenerate only the references that have an in-repo generator
3. **Validation**: Verify regenerated fixtures with the live validator paths

## Automated Workflows

### Fixture Generation
```bash
# Check what needs updating
rch exec -- cargo run -p asupersync-conformance --bin maintain_fixtures -- --check-versions --dry-run

# Regenerate the real golden-fixture workflow
rch exec -- cargo run -p asupersync-conformance --bin maintain_fixtures -- --regenerate golden --dry-run

# Combined regenerate + validate cycle for the golden fixture lane
rch exec -- cargo run -p asupersync-conformance --bin maintain_fixtures -- --regenerate golden --validate
```

### Validation
```bash
# Validate fixtures after regeneration
rch exec -- cargo run -p asupersync-conformance --bin maintain_fixtures -- --validate

# Check for regressions
rch exec -- cargo run -p asupersync-conformance --bin check_conformance_regression -- --input <result.json>
```

## Reference Implementation Tracking

### Supported References
- **golden**: Real in-repo golden fixture generation plus round-trip / format validation via `tests/conformance/raptorq_rfc6330/golden/`
- **differential**: Provenance-only differential fixture catalog under `tests/conformance/raptorq_rfc6330/differential/fixtures/`; validation currently checks the catalog/provenance presence, not a generator
- Additional references may be layered in through `maintenance_config.json` overrides once they have real generation / validation commands

### Version Management
Each tracked reference records:
- Fixture directory and newest-file age
- Whether regeneration is supported in-repo or remains manual-only
- The exact generation and validation commands when those workflows exist
- Optional override metadata from `maintenance_config.json`

## Troubleshooting

### Common Issues
1. **Fixture validation failures**: Re-run the advertised validation command and inspect the referenced fixture directory first
2. **Generation command failures**: Verify the golden helper crates under `tests/conformance/raptorq_rfc6330/golden/` still build and that the command is being invoked through `rch exec`
3. **Manual-only references**: If `maintain_fixtures` reports a reference as manual-only, do not treat `--regenerate` failure as a bug in the CLI; add a real generator first

### Resolution Steps
1. Inspect the live support matrix with `--check-versions`
2. Regenerate only the references that advertise in-repo regeneration support
3. Run `--validate` after regeneration
4. Review fixture / provenance diffs and regression output
5. Update this document if the support matrix changes

---

**Last Updated**: Automatically maintained by fixture management pipeline
