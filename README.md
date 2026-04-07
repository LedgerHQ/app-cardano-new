# Cardano Ledger Application

This is the Ledger application for the Cardano blockchain, providing secure storage and transaction signing for ADA and Cardano native tokens.

## Overview

The Cardano Ledger app allows users to manage their Cardano assets on Ledger hardware devices (Stax, Flex, Nano X, Nano S+). It supports a wide range of transaction types across different Cardano eras, including Shelley, Allegra, Mary, Alonzo, Babbage, and Conway.

For detailed information about the application, please refer to:
- [doc/OVERVIEW.md](doc/OVERVIEW.md): High-level architecture, data flow, and testing infrastructure.
- [doc/tx.md](doc/tx.md): Detailed transaction body processing and hashing specifications.
- [doc/apdu.md](doc/apdu.md): Compact APDU command/flow reference and source-of-truth pointers.
- [AGENTS.md](AGENTS.md): Development guidelines and instructions for AI agents.

## Quick start guide

### With VSCode

You can setup a convenient environment to build and test your application using [Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).

1. Install and run [Docker](https://www.docker.com/products/docker-desktop/).
2. Install [VSCode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
3. Open this folder in VSCode.
4. Use the extension's sidebar to build, run with Speculos, or execute functional tests.

### With a terminal

See **[doc/testing.md](doc/testing.md)** for environment setup (system dependencies, Python venv) and the full testing workflow.

## Compilation

*Note: Nano S is no longer supported.*

The repo-root `Makefile` is used exclusively for building the device binary inside the
Ledger SDK / Docker environment. It is not used by unit tests, fuzzing, or Python tooling
(those are driven by `tests/Makefile` and cmake).

```shell
make DEBUG=1  # compile optionally with TRACE enabled
```

Extra preprocessor defines can be passed via `DEFINES+=`, e.g.:
```shell
make DEBUG=1 DEFINES+=TRACE_TX_PARSE
```

Supported `BOLOS_SDK` targets:
- `STAX_SDK`
- `FLEX_SDK`
- `NANOX_SDK`
- `NANOSP_SDK`

## Test

The application uses a multi-layered testing approach, including unit tests, end-to-end functional tests, and fuzzing.

For detailed instructions on setting up the test environment and running different test suites, please refer to **[doc/testing.md](doc/testing.md)**.

### Quick Commands

```shell
# Unit tests (regenerates fixtures, checks drift, builds, and runs)
make -C tests tests-unit

# Functional tests (requires Speculos/Ragger setup)
pytest tests/standalone/ --device nanox
```


## Documentation

- Architecture Overview: [doc/OVERVIEW.md](doc/OVERVIEW.md)
- Testing Overview: [doc/testing.md](doc/testing.md)
- Transaction Processing: [doc/tx.md](doc/tx.md)
- APDU Overview: [doc/apdu.md](doc/apdu.md)
- Known Non-Issues: [doc/non_bugs.md](doc/non_bugs.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Unit Tests: [tests/unit/README.md](tests/unit/README.md)
- Fuzzing: [tests/fuzzing/FUZZING.md](tests/fuzzing/FUZZING.md)

## Continuous Integration

The project uses GitHub Actions for CI, including guidelines enforcement, code formatting checks, compilation for all supported devices, unit tests, and functional tests.
