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
    - `sign_opcert.c`: Handles operational certificate signing.
- **`transaction/`**: Core transaction processing logic. Includes parsing (`tx_parse.c`), validation with security policies and hash computation (`tx_validate.c` with `tx_hash_builder.c`), and UI preparation (`tx_prepare.c`). Detailed documentation can be found in [tx.md](tx.md).
- **`securityPolicy/`**: Enforces security rules for every operation, especially validating BIP44 paths and ensuring that transaction components are safe to sign.
- **`addressUtils/`**: Utilities for Cardano address manipulation (Shelley, Byron, Bech32).
- **`memory/`**: Custom memory management.
    - `mem.c`: Simple allocator (`app_mem_alloc`) used during transaction processing.
    - `flist.c`: Simple linked list implementation for storing transaction components (inputs, outputs, etc.).

## 2. Transaction Signing Data Flow

Detailed data flow and transaction-specific logic are documented in [tx.md](tx.md).

## 3. Python Client and Functional Tests (`tests/`)

The functional tests use the `ragger` framework to simulate a Ledger device and a Python client to communicate with it.

- **`application_client/`**:
    - **`command_builder.py`**: Serializes transaction objects into APDU commands.
    - **`command_sender.py`**: Sends APDUs to the device and handles responses.
- **`standalone/`**:
    - Contains actual test cases (e.g., `test_sign_tx.py`).
    - **`conftest.py`**: Configures the ragger environment.
    - **`input_files/`**: Contains transaction objects and test vectors.

### Running Functional Tests

Functional tests are executed using `pytest`. You can filter tests, specify the target device, and control the simulation environment using various flags.

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

## 4. Unit Tests (`unit-tests/`)

Unit tests are written in C using the `cmocka` framework and run on the host machine. Detailed setup and usage instructions are in [../unit-tests/UNIT-TESTS.md](../unit-tests/UNIT-TESTS.md).

- **Structure**: Individual files test specific modules (e.g., `test_cbor.c`, `test_tx_hash_builder.c`).
- **Fixtures**: `test_sign_tx_fixtures_*.h` contain large test vectors for different transaction eras. These fixtures are managed and regenerated using scripts described in [../unit-tests/UNIT-TESTS.md](../unit-tests/UNIT-TESTS.md#regenerating-mock-data).
- **Mocking**: `test_sign_tx_common.h` provides mocks for IO and UI, allowing the transaction signing logic to be tested in isolation.

## 5. Generic Helpers

- **`buffer.h`**: Utilities for safe reading and writing of byte buffers. Used extensively in APDU parsing.
- **`ledger_assert.h` / `utils/assert.h`**: Assertion macros for runtime and static checks.
- **`utils/textUtils.h`**: Helpers for formatting numbers and addresses for UI display.
- **`flist.h`**: Generic linked list used to store transaction items during parsing.
- **`mem.h`**: Dynamic memory allocator optimized for Ledger device constraints.

# Security

Apart from avoiding memory leaks and bugs in general, the security of the app has two main pillars:

1. Users must be shown everything important that is included in the transaction. There are very few exceptions where something is hidden, typically when the data cannot be verified by a human (inline datum) and are too long (in which case the error rate of human verification on a small screen mostly defeats the purpose of showing it), or when it is safe to hide data because user will not lose control of his assets (e.g. change outputs).

2. Data being displayed should not allow "attacks by deception", e.g. including several elements in the transaction that are signed by the same key, and tricking the user into overlooking some of them (most users are not aware of most security implications, so a compromised software wallet has a good chance of deceiving them). This means some combinations of elements are forbidden (e.g. key hash certificates in ordinary transaction signing mode because the user cannot easily determine if the key hash in the certificate comes from some of his keys).

There is an ["expert mode"](expert_mode.xlsx) setting that allows the user to somewhat control the amount of data being displayed. It is mostly relevant for Plutus transactions.

The reasoning behind specific restrictions is the result of years of discussion among all the stakeholders (IOG, Intersect, Vacuumlabs, stake pool operators, wallet developers, power users etc.). You can find the historical documentation in `doc/spec_*.md`. It is organized by Cardano eras or specific features as they were added over time.

## Cryptographic Error Handling

Cryptographic operations in this app use **CX_ASSERT** rather than error checking. Crypto errors are unrecoverable:
broken device hardware, buggy crypto implementation, wrong usage of crypto API (app bug) etc.
**CX_CHECK** is appropriate if we need to wipe out some memory buffers before exiting (so that no attacker can read them).
