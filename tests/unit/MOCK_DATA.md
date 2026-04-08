# Mock Data Verification Tests

This document describes the verification system for mock cryptographic data used in unit tests.

## Overview

The mock data in `tests/unit/mock_crypto/crypto_mock_data.h` contains hardcoded key material (public keys, chain codes)
and test signatures. These tests ensure that:

1. **All key material is correctly derived** from the standard test mnemonic
2. **Key hashes are correctly computed** as Blake2b-224 hashes of public keys
3. **Opcert messages** are properly constructed for signing

## Standard Test Mnemonic

All mock data is derived from this standard mnemonic:

```text
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

The `MOCK_SIGNATURES` array in `mock_crypto/crypto_mock_data.h` contains pre-computed Ed25519 signatures for testing.
These signatures are used by unit tests that call the mock `crypto_eddsa_sign` function.

**Note**: These signatures are derived from the standard test mnemonic and the message buffers stored in `mock_crypto/crypto_mock_data.h`.
If you update a message buffer (for example, CVote payload hashes), rerun the regeneration script to keep signatures consistent.

## Regenerating Mock Data

If mock data (public keys, chain codes, key hashes) becomes outdated or incorrect:

```bash
# From repository root
source tests/venv/bin/activate
python3 -m tests.unit.generators.generate_unit_tests_from_ragger mock-data
```

This script:
- Derives all public keys and chain codes from the standard test mnemonic
- Calculates Blake2b-224 key hashes
- Regenerates Ed25519 signatures using the standard mnemonic and the message buffers
- Updates `mock_crypto/crypto_mock_data.h` with correct key material

If you need a new mock entry, add the path or signature to `mock_crypto/crypto_mock_data.h` first,
then rerun the generator so the derived values stay in sync.

## Key Governance Paths

The implementation uses these standard CIP-1852 paths for governance:

- **DRep Key**: `m/1852'/1815'/0'/3/0` - For governance delegation
- **Committee Hot Key**: `m/1852'/1815'/0'/5/0` - For committee authorization
- **Pool Cold Key**: `m/1853'/1815'/0'/0'` - For operational certificates
- **Standard Address Keys**: `m/1852'/1815'/0'/0/x` - Standard account keys

All these paths are verified in the mock data tests.

## Adding New Mock Entries

To add a new mock path entry or signature:

1. Add the path or signature to the relevant `mock_crypto/crypto_mock_data.h` array
2. Run the regeneration script above to recompute derived key material and signatures
3. The key derivation and signature tests will automatically verify the new entry
4. If the test fails, check that the path, message, or expected signature is correct

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
