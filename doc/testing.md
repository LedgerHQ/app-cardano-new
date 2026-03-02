# Testing Overview

This is the main entry point for test documentation in the Cardano Ledger app.

## Test Suites

- Unit tests: `../unit-tests/README.md`
- Standalone functional tests (ragger): `../tests/standalone/README.md`
- Swap/library-mode tests: `../tests/swap/README.md`
- Fuzzing: `../fuzzing/FUZZING.md`

## Workflow

- When C code is modified, run unit tests.
- After unit tests pass, run a fuzzing build as a compile-health gate.
- Regenerate unit-test fixtures when `tests/standalone/input_files/` or
  `tests/application_client/` changes via:
  `../unit-tests/generators/generate_unit_tests_from_ragger.py`.
- Run ragger and swap tests only when explicitly requested.

## Debugging & Tracing

Excessive tracing strings in the debug version of the app can lead to the binary exceeding the available flash memory on the device. To mitigate this, the app uses **conditional tracing guards** for verbose or repetitive debug output.

### Implementation Guide

To use a guard in your module:
1. Define the guard at the top of your `.c` file:
   ```c
   #ifdef TRACE_MY_MODULE
   #define TRACE_MODULE(...) TRACE("[module] " __VA_ARGS__)
   #else
   #define TRACE_MODULE(...) (void)0
   #endif
   ```
2. Use `TRACE_MODULE()` for state tracking, loops, or field-level parsing.
3. Keep standard `TRACE()` for critical errors and security-relevant information.

### Available Tracing Guards

| Guard Name | Target Modules | Purpose |
|------------|----------------|---------|
| `TRACE_TX_PARSE` | `src/transaction/tx_parse*.c`, `src/parsers/cardano_parsers.c` | Transaction component and core parsing |
| `TRACE_TX_HASH_BUILDER` | `src/transaction/tx_hash_builder.c` | Core transaction hashing |
| `TRACE_HANDLERS` | `src/handler/*.c` | APDU command handler flow |
| `TRACE_UI_DISPLAY` | `src/ui/ui_display*.c` | UI rendering and state |
| `TRACE_CVOTE` | `src/cvote/cvote_parser.c` | Catalyst voting data parsing |
| `TRACE_AUX_DATA_HASH_BUILDER` | `src/cvote/aux_data_hash_builder.c` | Voting aux data hashing |
| `TRACE_VOTECAST_HASH_BUILDER` | `src/cvote/vote_cast_hash_builder.c` | Vote cast hashing |
| `TRACE_NATIVE_SCRIPT_HASH_BUILDER` | `src/deriveNativeScriptHash/derive_native_script_hash_builder.c` | Native script hashing |

### How to Build & Verify

To enable specific tracing, add the guard(s) to your build command:
```bash
make DEBUG=1 -DTRACE_TX_PARSE -DTRACE_HANDLERS -j8
```

To verify that strings are correctly removed from the compiled binary:
```bash
# Build with guard disabled, then check count
make clean_target && make DEBUG=1 -j8
strings build/app-cardano/bin/app.elf | grep "your-string" | wc -l
```

### Impact on Release Builds
**None.** In release builds (where `HAVE_PRINTF` is not defined), the `TRACE` macro is defined as `do {} while(0)` in `utils/utils.h`. This means all strings are removed by the preprocessor regardless of guards. These guards specifically target the **debug binary** size constraints.

## Additional Index
