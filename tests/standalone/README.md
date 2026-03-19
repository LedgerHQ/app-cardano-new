# Standalone Functional Tests (Ragger)

This directory contains the standalone functional test suite for the app (launched from dashboard, not library mode).

## Purpose

- Validate APDU flows end-to-end with device UI interaction.
- Verify navigation and confirmation behavior.
- Check user-visible behavior for normal and deny paths.

## Quick Start

Install dependencies:

```bash
pip install --extra-index-url https://test.pypi.org/simple/ -r requirements.txt
sudo apt-get update && sudo apt-get install qemu-user-static
```

Run a simple test on Speculos:

```bash
pytest -v --tb=short --device nanox --display
```

## Important Notes

- `test_sign_tx.py` uses a DEBUG-only settings APDU to toggle expert mode between runs.
- In `test_sign_tx_deny`, some deny cases are witness-phase policy denials: tx review is approved first, then deny is expected on `SIGN_TX_WITNESS`.
- In this repository workflow, ragger tests are run only on explicit request.
- Build the app first; if automated app build is unavailable, use the unit tests build flow as a compile-health proxy.
- Parallel runs with `pytest-xdist` are supported for the Speculos backend. The standalone `conftest.py` assigns deterministic per-worker Speculos API/APDU ports automatically, so `-n <workers>` can be used without port collisions.

## Useful Options

```text
-v
-s
-k <pattern>
--tb=short
--device <nanox|nanosp|stax|flex|all>
--backend <speculos>
--display
--golden_run
--no-nav
-n <workers>
--lf
--ff
--last-failed-no-failures <all|none>
--collect-only -q
--timeout <seconds>
--log_apdu_file <path>
```

Examples:

```bash
# Run one test by name fragment
pytest tests/standalone/test_sign_tx.py --device nanosp -k "Byron" -v --tb=short

# Debug navigation manually in Speculos (no automatic navigation)
pytest tests/standalone/test_sign_tx.py --device nanosp --display --no-nav

# Run tests in parallel with pytest-xdist
pytest tests/standalone/test_sign_tx.py --device stax -n 2

# Rerun only tests that failed in the previous pytest run
pytest --lf --device stax -v --tb=short

# Run previously failed tests first, then continue with the rest
pytest --ff --device stax -v --tb=short

# Regenerate snapshots after intended UI changes
pytest tests/standalone/test_sign_tx.py --device stax --golden_run

# Increase timeout for slower scenarios (or faster timeout for tests with failing navigation)
pytest tests/standalone/test_sign_tx.py --device nanosp --timeout 20

# Only list selected tests without executing them
pytest --device nanosp -k "menu or opcert" --collect-only -q
```

## Directory Layout

```text
standalone/
├── conftest.py
├── input_files/
├── test_*.py
├── snapshots/
├── snapshots-tmp/
├── requirements.txt
└── utils.py
```
