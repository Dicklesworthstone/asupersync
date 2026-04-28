# PostgreSQL ParameterDescription/ParameterStatus Message Fuzzing

This fuzz target tests the parsing robustness of PostgreSQL protocol parameter messages:

## Target Functions

- **ParameterDescription** (`parse_parameter_description` in `src/database/postgres.rs`)
  - Format: `i16` parameter count + array of `i32` OID values
  - Tests: negative counts, oversized arrays, invalid OIDs

- **ParameterStatus** (`handle_parameter_status` in `src/database/postgres.rs`)  
  - Format: null-terminated parameter name + null-terminated value
  - Tests: embedded nulls, encoding corruption, oversized strings

## Structure-Aware Generation

The fuzzer generates PostgreSQL-aware test cases including:

- **Standard PostgreSQL types**: TEXT(25), INT4(23), BOOL(16), UUID(2950), etc.
- **Common runtime parameters**: `application_name`, `client_encoding`, `TimeZone`
- **Edge cases**: zero parameters, maximum counts, invalid UTF-8
- **Corruption patterns**: truncated messages, missing nulls, negative lengths

## Usage

```bash
# Build and run the fuzzer
cargo fuzz run postgres_parameter_messages

# Run with custom timeout  
cargo fuzz run postgres_parameter_messages -- -max_total_time=300

# Minimize a crash case
cargo fuzz tmin postgres_parameter_messages artifacts/postgres_parameter_messages/crash-xyz
```

## Seed Corpus

The corpus includes minimal valid examples:
- Empty ParameterDescription (0 parameters)
- Single TEXT parameter  
- Multiple parameters with different OIDs
- Common ParameterStatus messages

## Expected Behavior

The parsers should:
- Never panic on invalid input
- Return appropriate errors for malformed data
- Handle edge cases gracefully (negative counts → error)
- Preserve invariants (parameter count matches array length)

## Security Properties Tested

- **Input validation**: negative parameter counts rejected
- **Buffer safety**: no out-of-bounds reads on truncated messages  
- **Encoding safety**: graceful handling of invalid UTF-8
- **Resource limits**: prevent excessive memory allocation