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

## Additional Index
