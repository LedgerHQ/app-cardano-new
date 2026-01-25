# Application Client for Tests

This package is a minimal Python client used by the test suite to talk to the Cardano app over APDUs. It is intentionally small and mirrors the on-device dispatcher and response formats.

## Files

- `command_builder.py` — Builds APDUs and transaction chunks; owns CLA/INS/P1/P2 constants.
- `command_sender.py` — Sends APDUs via `ragger` backends; provides sync and `*_async` helpers for UI flows.
- `app_def.py` — Shared enums/structures used by the test vectors and builders.
- `response_unpacker.py` — Validates and unpacks response payloads.
- `status_words.py` — Status word constants (SDK + Cardano-specific).

## Mapping to the Device Dispatcher

The APDU constants are defined here to mirror the C dispatcher:

- `command_builder.CLA` ↔ `src/apdu/dispatcher.h` (`CLA`).
- `command_builder.InsType` ↔ `src/apdu/dispatcher.h` (`command_e`).
- `command_builder.P1Type` ↔ `src/apdu/dispatcher.h` (`p1_e`).
- `command_builder.P2Type` ↔ `src/apdu/dispatcher.h` (`p2_e`).

When adding or changing APDU commands, update both `command_builder.py` and `src/apdu/dispatcher.h` (and keep any P1/P2 ranges consistent).

## Status Words

`status_words.py` mirrors the app status words defined in `src/cardano_swo.h` (plus ISO/IEC 7816-4 SDK words). Keep them aligned when introducing new error codes.

## Usage

See the tests under `tests/standalone` for examples.
