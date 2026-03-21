# Unit tests

## Prerequisite

See **[doc/testing.md](../../doc/testing.md)** for system dependencies and environment setup.

## Overview

In `tests/unit` folder, compile with

```shell
cmake -Bbuild -H. && make -C build -j4
```

and run tests with

```shell
CTEST_OUTPUT_ON_FAILURE=1 make -C build -j4 test
```

To run a specific test binary (e.g., `test_ui_formatters`), use:

```shell
cd tests/unit
cmake -Bbuild -H. && make -C build -j4
CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir build -R test_ui_formatters
```

## Generate code coverage

Just execute in `tests/unit` folder

```shell
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).

## Structure

- Test files are placed directly in `tests/unit/` directory with `test_*.c` naming pattern
- `mock_includes/` contains SDK header mocks for native compilation
- `libs/` contains mock implementations (crypto, etc.)
- Each test file tests a specific module from `../src/`

## Fixture Workflow

Use this short checklist when adding or updating fixtures:

1. Edit the source of truth:
   - Standalone ragger inputs: `tests/standalone/input_files/`
   - Generated unit fixtures: the relevant generator under `tests/unit/generators/`
   - Handwritten unit tests: `tests/unit/test_*.c`
2. Regenerate generated unit artifacts when needed (from repository root):
   - `source tests/venv/bin/activate`
   - `PYTHONPATH=. python3 -m tests.unit.generators.generate_unit_tests_from_ragger all`
3. Rebuild unit tests (from `tests/unit`):
   - `cmake -Bbuild -H. && make -C build -j8`
4. Run the relevant unit target:
   - `CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir build -R <test_name>`

Notes:

- Generated headers and runners under `tests/unit/generated/` should not be edited by hand.
- Handwritten `test_*.c` files usually need an explicit `tests/unit/CMakeLists.txt` entry.
- If you are changing a sign-tx fixture, the generator also updates the deny fixtures and mock crypto data when needed.

## Test Fixture Generation

Some unit tests consume generated C headers. Do not hand-edit these generated files; update the generator scripts and re-run them.

For the shared Python environment used by generators, see `../../doc/testing.md`.

### Transaction Signing Fixtures

Fixtures for sign-tx tests are generated from ragger fixtures and serialized through the shared Python command builder.

Generators (run from repository root):

```bash
source tests/venv/bin/activate
PYTHONPATH=. python3 -m tests.unit.generators.generate_unit_tests_from_ragger all
# or individual steps:
PYTHONPATH=. python3 -m tests.unit.generators.generate_unit_tests_from_ragger fixtures
PYTHONPATH=. python3 -m tests.unit.generators.generate_unit_tests_from_ragger generate-test-runners
```

The default command runs all generators in order (fixtures, generate-test-runners, rejects, mock-data).
**Ed25519 signatures for new fixtures are derived automatically** by the generator from the standard
test mnemonic — no manual crypto work is required when adding a fixture.

Notes:
- `tests/unit/generators/generate_unit_tests_from_ragger.py` produces `tests/unit/generated/sign_tx/test_sign_tx_fixtures_*.h` from
  `tests/standalone/input_files/signTx.py`, rewrites each test runner,
  and emits deny fixture headers.
- APDU fixtures use the app's binary schema (presence flags + length-prefixed ASCII for relays/metadata);
  they are not CBOR byte dumps. CBOR fixtures remain the source of truth for tx body/hash validation.
- `expected_warnings` values in `SignTxTestCase` come from the `WarningBit` enum in
  `tests/application_client/security_warnings.py`.

### Computing txBody for a new fixture

`txBody` is the canonical CBOR encoding of the transaction body map. When adding a fixture that
is a small variation of an existing one (e.g. different metadata URL, different cert field), derive
it by mutating the closest existing fixture rather than building from scratch:

```python
import cbor2, hashlib

base = bytes.fromhex("<existing_fixture_txBody_hex>")
decoded = cbor2.loads(base)

# mutate decoded as needed, e.g.:
# decoded[4][0][-1][0] = ""   # set pool metadata URL to empty string

new_body = cbor2.dumps(decoded, canonical=True)
print("txBody:", new_body.hex())
print("hash:  ", hashlib.new('blake2b', data=new_body, digest_size=32).hexdigest())
```

The printed hash matches `expected_hash_hex` in the generated C fixture.
Run this snippet with `source tests/venv/bin/activate && python3 -c "..."` (cbor2 is available in the venv).

### Mock Crypto Fixtures

Mock key material lives in `tests/unit/mock_crypto/crypto_mock_data.h`. For details on how these fixtures are verified and regenerated, see **[MOCK_DATA.md](MOCK_DATA.md)**.

You can add new mock paths or signatures by extending `MOCK_PATHS` / `MOCK_SIGNATURES` in that header. After updating the data, rerun the mock-data generator to refresh the derived key material and signatures.

Brief regeneration command (from repository root):

```bash
source tests/venv/bin/activate
python3 -m tests.unit.generators.generate_unit_tests_from_ragger mock-data
```
