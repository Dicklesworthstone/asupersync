# gRPC Health Service Golden Snapshot Provenance

## How Golden Snapshots Are Generated

### Environment Requirements
- **Platform**: Any (health service is platform-independent)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **Dependencies**: Uses insta crate for snapshot testing

### Generation Commands
```bash
# Generate all snapshot files
cargo test --test golden_grpc_health

# Review snapshots
cargo insta review

# Accept snapshots if correct
cargo insta accept
```

### Golden Snapshot Format
- **Format**: Debug representation of HealthResponseCapture structs
- **Content**: Health check requests, responses, service state, metadata
- **Normalization**: Service names sorted, deterministic request/response pairs
- **Metadata**: Test scenario, async/sync method, descriptions

### Validation Workflow
1. Run tests to generate/compare snapshots
2. Review snapshot changes via `cargo insta review`
3. Accept correct changes with `cargo insta accept`
4. Commit snapshot files with descriptive commit message

### Regeneration Triggers
- Changes to HealthCheckResponse format
- Updates to ServingStatus enum values
- Changes to health service API
- Modifications to request/response serialization

### Last Generated
- **Date**: 2026-04-21
- **Test Suite**: golden_grpc_health.rs
- **gRPC Version**: grpc.health.v1 protocol
- **Scenarios**: empty, unknown, serving, not_serving, mixed, async, overall, transitions

### Test Scenarios

#### empty_service
- Completely empty health service with no registered services
- Tests default behavior and error handling

#### unknown_service
- Request for service not registered in health service
- Tests NOT_FOUND vs UNKNOWN status distinction

#### serving_service
- Service explicitly set to Serving status
- Tests positive health response

#### not_serving_service
- Service explicitly set to NotServing status
- Tests negative health response

#### mixed_services
- Multiple services in different states
- Tests service isolation and state management

#### async_method
- Health check using async method path
- Tests async/sync response format consistency

#### overall_health
- Health check for overall server health (empty service name)
- Tests server-level health reporting

#### status_transitions
- Health check after multiple status changes
- Tests final state capture after transitions

## Stability Considerations

The gRPC health checking protocol response format is critical for client compatibility:

1. **Status Values**: ServingStatus enum values must remain stable
2. **Response Structure**: HealthCheckResponse fields and format
3. **Error Handling**: Status error codes and messages
4. **Protocol Compliance**: Must match grpc.health.v1.Health protocol

## Usage Guidelines

When modifying health service responses:
1. Run test suite to establish baseline
2. Make implementation changes
3. Re-run tests and review snapshot diffs carefully
4. Accept snapshots only if changes are intentional and protocol-compliant
5. Document breaking changes that affect gRPC client compatibility

This ensures the health service maintains protocol compliance for production gRPC clients.