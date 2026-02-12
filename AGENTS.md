# Cardano Ledger App Development Guidelines

We are converting an old version of the Ledger Cardano app into a new modernized version with a refreshed UI.

## Context
- **Old app (Shelley):** `../app-cardano`. Refer to this for established logic and processing patterns.
- **New app:** `../ledger-app-cardano`. A fork of the Ledger boilerplate app.
- **Device Support:** Supporting Stax, Flex, Nano X, and Nano S+. *Nano S is no longer supported.*
- **UI Framework:** NBGL is used exclusively for UI. Prefer high-level functions for standard use cases.

## Architectural Overview
For detailed analysis, see:
- [doc/OVERVIEW.md](doc/OVERVIEW.md): High-level architecture, directory structure, and data flow.
- [doc/TX.md](doc/TX.md): Detailed transaction body processing and hashing.

**Note:** When exploring the codebase or answering questions about code organization, consult `doc/OVERVIEW.md` first for directory structure and conventions.

## Instructions for Coding Agent

### What to DO
- **Mimic Established Patterns:** Search the new app repository before copying logic from the old app.
- **Style:** Use long, descriptive variable names.
- **Security:** Use `STATIC_ASSERT` and `LEDGER_ASSERT` liberally for parameter validation and state machine invariants.
- **Debugging:** Use `TRACE` (avoid `PRINTF`).
- **Memory Management:** Be extremely mindful of scarce memory. Global context data should be strictly necessary.
- **Imports:** Organize imports logically and avoid forward declarations.
- **Legacy Code:** Identify and propose removal of any boilerplate leftovers.

### What NOT to DO
- **Do NOT modify `src/transaction/tx_hash_builder.c`, `src/addressUtils/addressUtilsShelley.c`, or `src/addressUtils/bip44.c`** without explicit confirmation. They are trusted components.
- **Do NOT add custom CBOR serialization**, address manipulation, or BIP44 path functions. Use existing utilities.
- **Do NOT remove original comments** explaining crucial details without confirmation.
- **Do NOT perform git operations** (modifications/writes).

### License Comment Policy
- **Preserve attribution:** Apache-2.0 requires preserving copyright/attribution notices from upstream code.
- **Do not imply false authorship:** If code is Ledger-derived, keep Ledger as original work.
- **Use file-by-file classification:**
  - **Vacuumlabs-only:** files created in this repo (Cardano-specific original work) use Vacuumlabs copyright.
  - **Copied from Ledger/boilerplate/eth (unmodified):** keep original upstream copyright/license header.
  - **Copied + modified:** keep original upstream attribution and add Vacuumlabs in a separate `Modifications` block.
  - **Copied from old app (`../app-cardano`):** treat as Vacuumlabs-only unless there is evidence the specific part is Ledger-origin; ambiguous cases require confirmation.
- **Third-party code:** never replace third-party license blocks (e.g., ISC/MIT). Keep them intact; only append minimal modification note if needed.
- **Header text stability:** keep established file title wording when present (e.g., `Ledger App Cardano.`), change only ownership/license lines unless explicitly requested.
- **Ambiguous provenance:** do not auto-rewrite; prepare a numbered decision list for human confirmation first.
- **Repository-level notices:** keep `LICENSE.md` Apache-2.0; maintain a `NOTICE` file with third-party components and attributions when distributing.

## Instructions for Reviewing Agent

- **Security focus:** Be thorough and paranoid about security and correctness. Unless a security policy allows HIDE, all data must be displayed or confirmed by human app users.
- **Verification:** Ensure that every received BIP44 path is validated against `securityPolicy.c` (typically applies to other incoming data too, e.g. tx body elements).
- **Consistency:** Verify that new handlers are consistent with existing ones.
- **Memory Safety:** Check for potential memory leaks, overflows, or excessive stack usage.
- **UI Logic:** Ensure that UI display items follow the order of items in the transaction body and display format/encoding is consistent with old app.
- **Instruction Interleaving:** Confirm that handlers correctly guard against instruction interleaving attacks.

## Additional Resources
- **BOLOS SDK:** `/opt/ledger-secure-sdk` (underlying library).
- **Reference Apps:** `../../ledger/app-ethereum` (eth app) and `../../ledger/app-bitcoin-new` (btc app) for modern coding patterns.
- **Client Libraries:** `../ledgerjs-cardano-shelley` and `../cardano-hw-interop-lib`.
- **Testing:**
    - [unit-tests/README.md](unit-tests/README.md): Unit tests setup, build, and fixture management.
    - [tests/standalone/README.md](tests/standalone/README.md): Ragger standalone tests.
    - [tests/swap/README.md](tests/swap/README.md): Swap/library-mode tests.
    - [fuzzing/FUZZING.md](fuzzing/FUZZING.md): Fuzzing harnesses and usage.

## Testing Workflow
- **When C code is modified:** run unit tests.
- **Do not run ragger tests or swap tests unless explicitly requested.**
- **Build process note:** the primary app build uses the VSCode Ledger plugin and is not automated here; use the unit-tests build process as a practical proxy for compile health.
- **After unit tests pass:** check fuzzing build as an additional compile-health gate.
- **Compilation warnings are not acceptable:** treat warnings as issues to fix.
