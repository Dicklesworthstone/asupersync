# Conformance Test Fixture Maintenance Procedures

## Overview

This document outlines the procedures for maintaining RFC 6330 conformance test fixtures, ensuring they remain current with reference implementations and continue to provide accurate validation.

## Routine Maintenance Tasks

### Monthly Review
1. **Check fixture age**: Review fixtures older than 30 days
2. **Version tracking**: Verify reference implementation versions
3. **Coverage analysis**: Ensure test coverage remains comprehensive

### Quarterly Updates
1. **Reference implementation updates**: Check for new versions
2. **Fixture regeneration**: Update fixtures with latest reference outputs
3. **Validation**: Verify regenerated fixtures maintain test validity

## Automated Workflows

### Fixture Generation
```bash
# Check what needs updating
cargo run --bin maintain_fixtures -- --check-versions --dry-run

# Regenerate specific reference implementation
cargo run --bin maintain_fixtures -- --regenerate raptorq-go

# Full maintenance cycle
cargo run --bin maintain_fixtures -- --check-versions
```

### Validation
```bash
# Validate fixtures after regeneration
cargo run --bin maintain_fixtures -- --validate

# Check for regressions
cargo run --bin check_conformance_regression
```

## Reference Implementation Tracking

### Supported References
- **raptorq-go**: Go reference implementation
- **raptorq-c**: C reference implementation  
- **rfc6330-python**: Python reference implementation

### Version Management
Each reference implementation is tracked with:
- Version tags/commit hashes
- Last update timestamp
- Fixture generation commands
- Validation procedures

## Troubleshooting

### Common Issues
1. **Fixture validation failures**: Check reference implementation changes
2. **Generation command failures**: Verify dependencies and paths
3. **Version tracking errors**: Update git references

### Resolution Steps
1. Backup current fixtures
2. Update reference implementation
3. Regenerate fixtures with validation
4. Review changes for regressions
5. Update documentation

---

**Last Updated**: Automatically maintained by fixture management pipeline