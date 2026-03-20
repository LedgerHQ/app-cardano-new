# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

On Ubuntu, the following command will install the required dependencies:

```shell
sudo apt install cmake libcmocka-dev lcov
```

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
2. Regenerate generated unit artifacts when needed:
   - `source ../venv/bin/activate`
   - `PYTHONPATH=../.. python3 generators/generate_unit_tests_from_ragger.py`
3. Rebuild unit tests:
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

Generators (run from `tests/unit/`):

```bash
cd tests/unit && source ../venv/bin/activate
PYTHONPATH=../.. python3 generators/generate_unit_tests_from_ragger.py
# or individual steps:
PYTHONPATH=../.. python3 generators/generate_unit_tests_from_ragger.py fixtures
PYTHONPATH=../.. python3 generators/generate_unit_tests_from_ragger.py generate-test-runners
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

Mock key material lives in `tests/unit/mock_crypto/crypto_mock_data.h` and is regenerated with:

```bash
source tests/venv/bin/activate
pushd tests/unit
python3 generators/generate_unit_tests_from_ragger.py mock-data
popd
```

This updates public keys, chain codes, and key hashes while preserving signature vectors.
The file is rewritten in place.

# Mock Data Verification Tests

This document describes the verification system for mock cryptographic data used in unit tests.

## Overview

The mock data in `mock_crypto/crypto_mock_data.h` contains hardcoded key material (public keys, chain codes) and test signatures. These tests ensure that:

1. **All key material is correctly derived** from the standard test mnemonic
2. **Key hashes are correctly computed** as Blake2b-224 hashes of public keys
3. **Opcert messages** are properly constructed for signing

## Standard Test Mnemonic

All mock data is derived from this standard mnemonic:

```
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

This is the standard test mnemonic used across all Cardano Ledger application tests for consistency.

## Test Coverage

### 1. Key Derivation Verification (`tests/unit/test_mock_key_derivation.c`)

**What it does:**
- Parses `crypto_mock_data.h` to extract all mock path entries (currently 49)
- For each entry, derives keys from the standard mnemonic using ragger
- Verifies that public key, chain code, and key hash match

**How to run:**
```bash
cd tests/unit
cmake -Bbuild -H. && make -C build -j4 test
# or specifically:
CTEST_OUTPUT_ON_FAILURE=1 make -C build -j4 test 2>&1 | grep test_mock_key_derivation
```

**Expected result:** ✓ All entries verified successfully

### 2. Ragger Test for Mock Key Derivation (`tests/standalone/test_mock_key_derivation.py`)

**What it does:**
- Python version of key derivation verification
- Dynamically parses the C header file
- Derives keys from the standard mnemonic using ragger's `calculate_public_key_and_chaincode`
- Verifies public key, chain code, and Blake2b-224 key hash

**How to run:**
```bash
cd tests/standalone
pytest -xvs --device stax test_mock_key_derivation.py::test_all_mock_key_derivation
```

**Key paths verified:**
- Governance paths (DRep, Committee hot keys)
- Pool cold keys
- Account keys
- All standard Cardano BIP-44 paths

### 3. Opcert Message Construction (`tests/unit/test_opcert.c`)

**What it does:**
- Verifies that opcert messages are constructed correctly
- Tests message structure: KES public key (32 bytes) || Issue counter (8 bytes) || KES period (8 bytes)
- Tests with actual values from ragger opcert tests

**Test vectors from ragger tests:**
- Path: `m/1853'/1815'/0'/0'` (pool cold key)
- KES public key: `3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822`
- KES period: 47
- Issue counter: 42

### 4. Ragger Opcert Test (`tests/standalone/test_opcert.py`)

**What it does:**
- Actually signs operational certificates using the Ledger app
- Verifies the signature against the constructed message
- Tests with actual Ed25519 signature verification

**How to run:**
```bash
cd tests/standalone
pytest -xvs --device stax test_opcert.py::test_opCert
```

## Mock Signature Data

The `MOCK_SIGNATURES` array in `mock_crypto/crypto_mock_data.h` contains pre-computed Ed25519 signatures for testing. These signatures are used by unit tests that call the mock `crypto_eddsa_sign` function.

**Note**: These signatures are derived from the standard test mnemonic and the message buffers stored in `mock_crypto/crypto_mock_data.h`. If you update a message buffer (for example, CVote payload hashes), rerun the regeneration script to keep signatures consistent.

## Regenerating Mock Data

If mock data (public keys, chain codes, key hashes) becomes outdated or incorrect:

```bash
cd tests/unit
source ../venv/bin/activate
python3 generators/generate_unit_tests_from_ragger.py mock-data
```

This script:
- Derives all public keys and chain codes from the standard test mnemonic
- Calculates Blake2b-224 key hashes
- Regenerates Ed25519 signatures using the standard mnemonic and the message buffers
- Updates `mock_crypto/crypto_mock_data.h` with correct key material

## Key Governance Paths

The implementation uses these standardCIP-1852 paths for governance:

- **DRep Key**: `m/1852'/1815'/0'/3/0` - For governance delegation
- **Committee Hot Key**: `m/1852'/1815'/0'/5/0` - For committee authorization
- **Pool Cold Key**: `m/1853'/1815'/0'/0'` - For operational certificates
- **Standard Address Keys**: `m/1852'/1815'/0'/0/x` - Standard account keys

All these paths are verified in the mock data tests.

## Adding New Mock Entries

To add a new mock path entry:

1. Add the path to `mock_crypto/crypto_mock_data.h` MOCK_PATHS array
2. Run `python3 generators/generate_unit_tests_from_ragger.py mock-data` to compute key material
3. The key derivation test will automatically verify the new entry
4. If the test fails, check that the path is correct

## Test Maintenance

These tests should be run:
- **Before commits** to ensure mock data is valid
- **After updating the test mnemonic** to regenerate all data
- **After adding new paths** to governance implementations
- **As part of CI/CD pipeline** to catch regressions

## References

- [CIP-0003: Ledger Nano S HD Wallet Derivation](https://cips.cardano.org/cips/cip3/)
- [CIP-1852: HD Wallets for Plutus](https://cips.cardano.org/cips/cip1852/)
- Ragger Library: `calculate_public_key_and_chaincode` with Ed25519Kholaw curve
- Cardano Address Standards: Blake2b-224 key hashing
