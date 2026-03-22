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

`txBody` is the canonical CBOR encoding of the transaction body map. It must match **exactly** what
the app will compute from the `tx=Transaction(...)` parameters — any mismatch causes the unit test
to fail with a hash comparison error.

**Option A: derive from an existing fixture** (preferred for small variations):

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

Run with `source tests/venv/bin/activate && python3 -c "..."` (cbor2 is available in the venv).

**Option B: capture from a unit test run** (most reliable for complex transactions):

Add the fixture with a placeholder `txBody` (any valid hex), build and run the unit test, then
read the exact body from the trace log:

```
[txHashBuilder_finalize:NNNN] tx_body (NNN bytes)
[txHashBuilder_finalize:NNNN] <hex bytes of CBOR body>
```

Copy that hex as the `txBody` value. The printed hash matches `expected_hash_hex` in the C fixture.

### Step-by-step guide for adding or modifying a sign-tx fixture

1. **Edit `tests/standalone/input_files/signTx.py`** — add or update the `SignTxTestCase`. Do not
   remove existing test cases. Ensure `txBody` matches the transaction structure (see above).

2. **Update `MOCK_TX_HASH_*` in `tests/unit/mock_crypto/crypto_mock_data.h`** — if the txBody
   changed or is new, update the corresponding `static const uint8_t MOCK_TX_HASH_FOO[]` constant
   to the blake2b-256 of the new txBody hex:
   ```python
   import hashlib
   hashlib.blake2b(bytes.fromhex("<txbody_hex>"), digest_size=32).hexdigest()
   ```

3. **Update `MOCK_SIGNATURES[]` in `crypto_mock_data.h`** — for each PATH-type witness the test
   will request, add an entry pointing to the updated hash constant. Use zero bytes for `.signature`;
   the generator will fill them in. Path encoding example:
   `m/1852'/1815'/0'/0/0` → `{0x8000073c, 0x80000717, 0x80000000, 0x00000000, 0x00000000}`.

4. **Regenerate mock data first**, then the full generator (from repository root):
   ```bash
   source tests/venv/bin/activate
   python3 -m tests.unit.generators.generate_unit_tests_from_ragger mock-data
   python3 -m tests.unit.generators.generate_unit_tests_from_ragger
   ```
   The `mock-data` pass must run before the `fixtures` pass so that real signatures are available
   when the C fixture headers are written.

5. **Build and run** (from `tests/unit`):
   ```bash
   cmake -Bbuild -H. && make -C build -j4
   CTEST_OUTPUT_ON_FAILURE=1 make -C build -j4 test
   ```

### Diagnosing fixture failures

| Symptom | Cause | Fix |
|---|---|---|
| `crypto_mock: missing signature path … message_hex=<hash>` | A PATH witness was requested but no `MOCK_SIGNATURES[]` entry exists for that path+hash pair. | Add the missing entry to `MOCK_SIGNATURES[]` and rerun `mock-data`. |
| `difference at offset 0 …` / hash mismatch at `test_sign_tx_common.h:180` | The `txBody` in `signTx.py` doesn't match what the app computed from the transaction structure. | Capture the correct body from the `txHashBuilder_finalize` trace line and update `txBody`. Also update the `MOCK_TX_HASH_*` constant and rerun steps 4–5. |
| `0x6982` (`SWO_SECURITY_CONDITION_NOT_SATISFIED`) during a witness | A PATH in `requiredSigners` is denied by the witness security policy (e.g. `PATH_MULTISIG_ACCOUNT` falls through to `DENY` in `_plutusWitnessPolicy`). | Remove that path from the PLUTUS_TRANSACTION fixture, or use a MULTISIG_TRANSACTION fixture where it is not added as a witness. |

### Mock Crypto Fixtures

Mock key material lives in `tests/unit/mock_crypto/crypto_mock_data.h`. For details on how these fixtures are verified and regenerated, see **[MOCK_DATA.md](MOCK_DATA.md)**.

You can add new mock paths or signatures by extending `MOCK_PATHS` / `MOCK_SIGNATURES` in that header. After updating the data, rerun the mock-data generator to refresh the derived key material and signatures.

Brief regeneration command (from repository root):

```bash
source tests/venv/bin/activate
python3 -m tests.unit.generators.generate_unit_tests_from_ragger mock-data
```
