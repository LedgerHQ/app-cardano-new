# Cardano Ledger App Architecture Overview

This document provides a high-level overview of the Cardano Ledger application architecture, data flow, and testing infrastructure.

## 1. C Application Architecture (`src/`)

The application is written in C and runs on Ledger devices (Stax, Flex, Nano X, Nano S+).
*Note: Nano S is no longer supported.*

### Core Components
- **`app_main.c`**: Entry point. Contains the main loop that initializes the device, shows the main menu, and waits for APDU commands.
- **`apdu/dispatcher.c`**: Maps APDU instructions (`INS_*`) to their respective handlers. It also protects against instruction interleaving attacks.
- **`handler/`**: Contains logic for specific commands.
    - `get_public_key.c`: Exports public keys.
    - `sign_tx.c`: Coordinates the multi-stage transaction signing process.
    - `sign_tx_aux_data.c`: Handles auxiliary data signing (metadata).
    - `sign_opcert.c`: Handles operational certificate signing.
    - `sign_msg.c`: CIP8 message signing.
    - `sign_cvote.c`: Catalyst voting (ballot signing).
    - `derive_address.c`: Address derivation and display.
    - `derive_native_script_hash.c`: Native script hash derivation.
    - Other utility handlers: `get_version.c`, `get_app_name.c`, `get_serial.c`, `debug_settings.c` (debug builds only).
- **`transaction/`**: Core transaction processing logic using a 2-phase architecture:
    - **Phase 1** (`tx_validate.c` with `tx_hash_builder.c`): Validates transaction structure, enforces security policies, computes the Blake2b-256 transaction hash, and counts required UI display pairs.
    - **Phase 2** (`tx_ui_format.c` with `tx_ui_helpers.c`): Formats validated transaction data into human-readable strings for NBGL UI display.
    - Also includes parsing (`tx_parse.c`, `tx_parse_outputs.c`, `tx_parse_certificates.c`) and utility functions (`tx_utils.c`).
    - Detailed documentation can be found in [tx.md](tx.md).
- **`ui/`**: User interface components using NBGL framework.
    - `tx_ui_format.c`: Formats transaction data into UI key-value pairs (Phase 2 of transaction processing).
    - `tx_ui_helpers.c`: Helper functions for transaction UI formatting.
    - `ui_formatters.c`: Low-level formatting functions for addresses, amounts, tokens.
    - Display modules for different operations: `ui_display_tx.c`, `ui_display_pubkey.c`, `ui_display_opcert.c`, `ui_display_cvote_aux_data.c`, `ui_display_native_script_hash.c`, `ui_display_address_derivation.c`, `ui_sign_msg.c`.
    - `ui_warnings.c`: Warning display logic.
    - `menu.c`: Main menu UI.
    - **UI callback convention**: Review callbacks should follow `cleanup -> finalize -> status`.
      - Cleanup must always call both `ui_free_pairs()` and `ui_free_warnings()` to keep handlers robust if warnings are added later.
      - Finalization should be delegated to handler-level `finalize_*()` functions rather than performing APDU response/state reset inline in UI modules.
- **`securityPolicy/`**: Enforces security rules for every operation, especially validating BIP44 paths and ensuring that transaction components are safe to sign.
- **`addressUtils/`**: Utilities for Cardano address manipulation (Shelley, Byron, Bech32).
- **`cvote/`**: Catalyst voting infrastructure.
    - `cvote_parser.c`, `cvote_hash.c`: Voting data parsing and hashing.
    - `vote_cast_hash_builder.c`, `aux_data_hash_builder.c`: Hash builders for voting structures.
- **`messageSigning/`**: CIP8 message signing implementation (`messageSigning.c`).
- **`deriveNativeScriptHash/`**: Native script hash derivation logic (`derive_native_script_hash_builder.c`).
- **`opcert/`**: Operational certificate parsing (`opcert_parse.c`).
- **`crypto/`**: Cryptographic operations and key derivation.
- **`keyDerivation/`**: BIP32/BIP44 key derivation logic.
- **`cardano_tokens/`**: Token registry for native token metadata.
- **`memory/`**: Custom memory management.
    - `mem.c`: Simple allocator (`app_mem_alloc`) used during transaction processing.
- **`parsers/`**: Generic parsing utilities for CBOR and other formats.
- **`utils/`**: Helper utilities (`textUtils`, `cbor`, `buffer_write`, `ipUtils`, `assert`).

## 2. Security Policy System

**Critical Component:** The `securityPolicy/` module is the cornerstone of the app's security model. Every operation that uses cryptographic keys or displays transaction data must pass through security policy validation.

**Key Functions:**
- **BIP44 Path Validation**: `policyForPrivateKey()` validates every BIP44 path before key derivation. Ensures paths follow allowed patterns and enforces the single-account constraint.
- **Transaction Element Policies**: During transaction validation, each element (output, certificate, withdrawal, etc.) is checked via `policyFor*()` functions (e.g., `policyForOutput()`, `policyForCertificate()`).
- **Policy Decisions**:
  - `POLICY_DENY`: Reject immediately (security risk).
  - `POLICY_SHOW`: Display to user (increment UI pair count).
  - `POLICY_HIDE`: Don't display (only allowed when safe, e.g., change outputs).

**Enforced Constraints:**
- Single-account: All witness paths in a transaction must use the same BIP44 account.
- Credential restrictions: Script hashes forbidden in ordinary signing mode (prevents deception attacks).
- Signing mode restrictions: Certificate types allowed depend on signing mode (ordinary/pool owner/pool operator/multisig/Plutus).
- Address ownership: Change outputs and collateral returns must use device-owned addresses.

Security policies are the gatekeeper that prevents the device from signing transactions that could deceive the user or result in loss of funds. See `doc/spec_*.md` for detailed rationale behind specific policy decisions.

## 3. Transaction Signing Data Flow

Detailed data flow and transaction-specific logic are documented in [tx.md](tx.md).

## 4. Testing Infrastructure

The app uses three complementary testing approaches for comprehensive validation:

### 4.1. Functional Tests (`tests/standalone/`)

Interactive tests using the `ragger` framework that simulate the device UI and verify end-to-end behavior. These test actual transactions, user interactions, and device responses.

- **`application_client/`**:
    - **`command_builder.py`**: Serializes transaction objects into APDU commands.
    - **`command_sender.py`**: Sends APDUs to the device and handles responses.
- **Constant synchronization checks**:
    - `tests/standalone/client_constants_check.py` verifies Python client constants against C headers.
    - Covered mappings currently include:
      - `CLA`, `INS_*`, `P1_*`, `P2_*` from `src/apdu/dispatcher.h`
      - `MAX_SIGN_TX_CHUNK_SIZE` from `src/handler/sign_tx.h`
      - `CVOTE_CREDENTIAL_*` from `src/cvote/cvote_types.h` (mapped to `application_client.command_builder.CVoteCredentialType`)
    - These checks are executed by:
      - `tests/standalone/test_client_constants.py`
      - `tests/standalone/conftest.py` session fixture (`enforce_client_constants`)
    - If any of these C constants change, update Python constants and extend the checks in `client_constants_check.py` in the same PR.
- **`standalone/`**:
    - Contains actual test cases (e.g., `test_sign_tx.py`).
    - **`conftest.py`**: Configures the ragger environment.
    - **`input_files/`**: Contains transaction objects and test vectors.

**Common Command Examples:**

```bash
# Run all transaction signing tests for Stax
pytest tests/standalone/test_sign_tx.py --device stax

# Run a specific test case by name
pytest tests/standalone/test_sign_tx.py --device stax -k "Sign_tx_with_script_data_hash"

# Run with verbose output and short tracebacks
pytest -v --tb=short tests/standalone/test_sign_tx.py --device stax
```

**Useful Ragger/Speculos Flags:**
- `--display`: Enables the Speculos graphical window to see the device screen during the test. By default, tests run in headless mode.
- `--no-nav`: Disables automatic navigation. This is useful when you want to manually interact with the device via Speculos or debug a specific UI state.

See [../tests/TESTS.md](../tests/TESTS.md) for more details.

### 4.2. Unit Tests (`unit-tests/`)

C unit tests using the `cmocka` framework that test individual modules in isolation on the host machine. These test core logic like transaction parsing, hashing, validation, and UI formatting without device simulation.

- **Structure**: Individual files test specific modules (e.g., `test_cbor.c`, `test_tx_hash_builder.c`, `test_ui_formatters.c`).
- **Fixtures**: `test_sign_tx_fixtures_*.h` contain large test vectors for different transaction eras. These fixtures are managed and regenerated using scripts.
- **Mocking**: `test_sign_tx_common.h` and other mock files provide mocks for IO and UI, allowing logic to be tested in isolation.

See [../unit-tests/UNIT-TESTS.md](../unit-tests/UNIT-TESTS.md) for setup, usage, and fixture management.

### 4.3. Fuzzing (`fuzzing/`)

Security-focused testing that feeds random or malformed data to critical components (APDU handlers, transaction parsers, key derivation). Uses the Ledger SDK fuzzing framework with libFuzzer.

Available harnesses:
- `fuzz_all_handlers`: Tests APDU dispatcher and command routing.
- `fuzz_signTx`: Transaction signing fuzzing.
- `fuzz_getPublicKeys`: BIP44 path parsing and key derivation.
- `fuzz_signOpCert`: Operational certificate signing.
- `fuzz_deriveAddress`, `fuzz_deriveNativeScriptHash`, and others.

See [../fuzzing/FUZZING.md](../fuzzing/FUZZING.md) for harnesses and execution instructions.

Together, these approaches ensure correctness (unit tests), real-world behavior (functional tests), and robustness against malformed input (fuzzing).

## 5. Generic Helpers

- **`LEDGER_ASSERT`** (`ledger_assert.h` / `utils/assert.h`): Assertion macros for parameter validation and invariant checking. Use liberally for all non-trivial functions that perform actual work on objects (not in simple pass-through helpers). Assertions document preconditions and catch logic errors early.

- **`buffer_t`** (SDK's `buffer.h`): Read-only buffer structure with const pointer. Used for safe APDU parsing and reading data. Provides bounds-checked operations like `buffer_read_u8()`, `buffer_read_u32()`, etc.

- **`write_buffer_t`** (`utils/buffer_write.h`): Write buffer structure with mutable pointer. Used for serializing data and building responses. Provides bounds-checked write operations.

- **Linked lists**: Transaction components (inputs, outputs, certificates, etc.) are stored in linked lists using `flist_node_t` from the Ledger SDK's `lists.h`.

- **`mem.h`**: Dynamic memory allocator optimized for Ledger device constraints (`app_mem_alloc`).

# Security

Apart from avoiding memory leaks and bugs in general, the security of the app has two main pillars:

1. Users must be shown everything important that is included in the transaction. There are very few exceptions where something is hidden, typically when the data cannot be verified by a human (inline datum) and are too long (in which case the error rate of human verification on a small screen mostly defeats the purpose of showing it), or when it is safe to hide data because user will not lose control of his assets (e.g. change outputs).

2. Data being displayed should not allow "attacks by deception", e.g. including several elements in the transaction that are signed by the same key, and tricking the user into overlooking some of them (most users are not aware of most security implications, so a compromised software wallet has a good chance of deceiving them). This means some combinations of elements are forbidden (e.g. key hash certificates in ordinary transaction signing mode because the user cannot easily determine if the key hash in the certificate comes from some of his keys).

There is an ["expert mode"](expert_mode.xlsx) setting that allows the user to somewhat control the amount of data being displayed. It is mostly relevant for Plutus transactions.

## Security Policy Documentation (`doc/spec_*.md`)

The reasoning behind specific security restrictions is the result of years of discussion among stakeholders (IOG, Intersect, Vacuumlabs, stake pool operators, wallet developers, power users, etc.). This historical context and decision rationale is documented in era/feature-specific files:

- **`spec_shelley.md`**: Base Shelley era rules (addresses, stake keys, delegation, certificates, withdrawals).
- **`spec_alonzo.md`**: Script support (Plutus v1, native scripts, script data hash).
- **`spec_babbage.md`**: Plutus v2, inline datums, reference scripts, reference inputs.
- **`spec_conway.md`**: Conway era features (DReps, constitutional committee, voting procedures, treasury, donation).
- **`spec_pool_registration.md`**: Stake pool operator signing mode and pool registration certificates.
- **`spec_multisig.md`**: Multisig/multi-account transaction validation rules.
- **`spec_single_account.md`**: Single account constraint explanation.
- **`spec_msg_signing.md`**: CIP8 message signing rules and restrictions.
- **`spec_cvote.md`**: Catalyst voting (cvote) restrictions and ballot signing.

These documents explain *why* certain combinations are forbidden, when data is hidden vs. shown, and how each era extended the app's capabilities. They serve as the authoritative source for understanding security policy decisions.

## Cryptographic Error Handling

Cryptographic operations in this app use **CX_ASSERT** rather than error checking. Crypto errors are unrecoverable:
broken device hardware, buggy crypto implementation, wrong usage of crypto API (app bug) etc.
**CX_CHECK** is appropriate if we need to wipe out some memory buffers before exiting (so that no attacker can read them).
