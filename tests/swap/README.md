# Cardano App Swap Tests

Local test suite for validating the Cardano app's swap functionality when called as a library by the Exchange app.

In this repository workflow, swap tests are run only on explicit request.

## Quick Start

```bash
# 1. Build app with swap support
make ENABLE_SWAP=1

# 2. Set up virtual environment (first time only)
cd tests/swap
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install GitPython

# 3. Clone and build test dependencies (first time only)
python helper_tool_clone_dependencies.py
docker run --user "$(id -u)":"$(id -g)" --rm -ti \
  -v "$(realpath ../../):/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest \
  bash -c "cd /app/tests/swap && python3 helper_tool_build_dependencies.py"

# 4. Run tests (activate venv first each time)
source venv/bin/activate
pytest . --device stax
```

## Prerequisites

### 1. Build the Cardano App with Swap Enabled

From the repository root:

```bash
make ENABLE_SWAP=1
```

### 2. Set Up Python Virtual Environment

Create and activate a virtual environment in `tests/swap/`:

```bash
cd tests/swap
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
# Make sure venv is activated
pip install -r requirements.txt
```

This installs all required dependencies including:
- Ragger (testing framework)
- pytest (test runner)
- ledger_app_clients (Exchange and Ethereum clients)
- Cardano-specific libraries (base58, bech32, cbor, etc.)
- GitPython (for cloning repositories)

### 4. Clone and Build Test Dependencies

The swap tests require the Exchange app and Ethereum app binaries.

**Clone dependencies:**

```bash
# Make sure you're in tests/swap/ with venv activated
python3 helper_tool_clone_dependencies.py
```

This creates `tests/swap/.test_dependencies/` and clones:
- `app-exchange` (main orchestrator)
- `app-ethereum` (secondary blockchain for testing)

**Build dependencies (inside Ledger Docker):**

```bash
docker run --user "$(id -u)":"$(id -g)" --rm -ti \
  -v "$(realpath ../../):/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest \
  bash -c "cd /app/tests/swap && python3 helper_tool_build_dependencies.py"
```

This builds Exchange and Ethereum apps for all devices (stax, flex, nanox, nanos+).

## Running Tests

**Important:** Always activate the virtual environment before running tests:

```bash
cd tests/swap
source venv/bin/activate
```

### List Available Tests

```bash
pytest . --device all --collect-only
```

### Run All Swap Tests

```bash
# Run on all devices
pytest . --device all

# Run on specific device
pytest . --device stax
pytest . --device flex
pytest . --device nanox
pytest . --device nanos+
```

### Run Specific Test Scenarios

The test suite includes multiple scenarios via parametrization:

```bash
# List all test scenarios
pytest . --device stax --collect-only

# Run specific scenario
pytest . -k "test_swap" --device stax -v
pytest . -k "test_swap_wrong_destination" --device stax -v
pytest . -k "test_swap_wrong_amount" --device stax -v
```

### Update UI Snapshots

After making UI changes, update the golden snapshots:

```bash
pytest . --device stax --golden_run
```

### Deactivate Virtual Environment

When done testing:

```bash
deactivate
```

## Test Structure

- `test_cardano_swap.py` - Main test file using ExchangeTestRunner
- `conftest.py` - Pytest configuration and fixtures
- `cal_helper.py` - Currency configuration (ADA)
- `helper_tool_*.py` - Scripts to clone and build dependencies
- `requirements.txt` - Python dependencies
- `snapshots/` - Expected UI screenshots per device

## How Swap Tests Work

1. **ExchangeTestRunner** orchestrates the test flow
2. **Exchange app** validates the swap proposal with the user
3. **Exchange app** calls the Cardano app as a library
4. **Cardano app** validates and signs the transaction
5. Test verifies the transaction matches swap parameters

## Test Scenarios

The test suite validates:
- ✅ Valid swaps with different amounts
- ✅ Invalid destination addresses (should reject)
- ✅ Invalid amounts (should reject)
- ✅ Invalid fees (should reject)
- ✅ Invalid refund addresses (should reject)
- ✅ UI flow and snapshots

## Troubleshooting

**Virtual environment not activated**
- Always run `source venv/bin/activate` before running tests
- Your prompt should show `(venv)` prefix when activated

**"No such file or directory: app-exchange"**
- Run `python helper_tool_clone_dependencies.py` and `python helper_tool_build_dependencies.py`
- Make sure you're in the `tests/swap/` directory

**"ImportError: ledger_app_clients.exchange"**
- Activate venv: `source venv/bin/activate`
- Install requirements: `pip install -r requirements.txt`

**"command not found: pytest"**
- Activate venv: `source venv/bin/activate`
- If still failing, reinstall: `pip install -r requirements.txt`

**"SWO_SWAP_CHECKING_FAIL" errors**
- Ensure the Cardano app is built with `ENABLE_SWAP=1`
- Check that swap validation logic is properly implemented

**Build dependencies fails**
- Make sure you're running the build script inside the Ledger Docker container
- Check that you have enough disk space for building multiple apps

## CI Integration

The swap tests can be run in GitHub Actions. See `.github/workflows/` for CI configuration.

## Implementation Overview

### How Ledger Swap Protocol Works

1. **Exchange app** receives swap request from Ledger Live
2. Exchange validates the swap proposal with the user (shows destination, amounts, fees)
3. Exchange calls the **Coin app** (Cardano) as a library via `os_lib_call()`
4. Coin app validates and signs the payment transaction
5. Coin app returns result to Exchange, which completes the swap

### Library Mode vs Standalone Mode

When started for swap, the app runs in **library mode** (not standalone mode):
- `main(arg0)` receives non-zero `arg0` containing `libargs_t*`
- The SDK's `lib_standard_app/main.c` dispatches to appropriate handlers
- The app does NOT show its usual UI - it processes APDUs directly
- `G_called_from_swap` flag is set by the SDK

### Security Considerations

**Critical Security Points:**

1. **BSS Clearing**: Call `os_explicit_zero_BSS_segment()` in `swap_copy_transaction_parameters()` to prevent data leakage from Exchange app

2. **Single Transaction**: Set `G_swap_response_ready` at transaction completion to prevent signing multiple transactions

3. **Instruction Whitelist**: Only allow necessary instructions (`GET_VERSION`, `GET_PUBLIC_KEY`, `SIGN_TX`) in swap mode

4. **Parameter Validation**: All swap parameters (destination, amount, fee) MUST be validated against what Exchange showed the user

5. **No Prompt Override**: `POLICY_HIDE` is safe ONLY because Exchange already obtained user confirmation

6. **Return to Exchange**: Always call `os_lib_end()` to return control to Exchange, never `app_exit()`

7. **Error Reporting**: Use proper swap error codes to help diagnose issues without leaking sensitive data

**Address Validation Security:**
- Only accept `DESTINATION_THIRD_PARTY` outputs for swap destination
- Device-owned outputs (change) should NOT be validated against swap parameters

**Multi-Output Transactions:**
- Exactly ONE output should match swap destination/amount
- Other outputs are likely change back to user
- Current implementation validates only the first matching third-party output

### SDK Dependencies

The swap feature requires headers from `lib_standard_app/`:

```c
#include "swap.h"                    // Main include
#include "swap_entrypoints.h"        // Handler function declarations
#include "swap_lib_calls.h"          // Parameter structures, command IDs
#include "swap_utils.h"              // Global flags, utility functions
#include "swap_error_code_helpers.h" // Error reporting functions
```

**SDK-Provided Globals:**
```c
extern volatile bool G_called_from_swap;
extern volatile bool G_swap_response_ready;
extern volatile uint8_t *G_swap_signing_return_value_address;
```

**Build Configuration** (`Makefile`):
```makefile
ENABLE_SWAP = 1
```

### Implementation Scope

Current implementation:
- ✅ **Shelley addresses only** - Modern Cardano standard
- ✅ **Native ADA only** - No token swaps
- ❌ **Byron addresses** - Legacy, not supported in new app
- ❌ **Token swaps** - Can be added later if needed

## References

- [Ledger Swap Documentation](https://ledgerhq.github.io/app-exchange/)
- [Exchange Test Runner](https://github.com/LedgerHQ/app-exchange)
- [Ragger Testing Framework](https://github.com/LedgerHQ/ragger)
