# Cardano APDU Overview

This document is a compact guide to APDU-level integration for the Cardano app.
It intentionally avoids duplicating payload-level parsing rules that are best kept in code.

## Source of Truth

- Command and P1/P2 constants: `src/apdu/dispatcher.h`
- Status words: `src/cardano_swo.h`
- Test-client mirror: `tests/application_client/command_builder.py`
- Test-client status words: `tests/application_client/status_words.py`

If this document conflicts with code, code wins.

## APDU Header

- `CLA`: `0xD7`
- Standard header: `CLA | INS | P1 | P2 | Lc | cdata`

## Supported Commands (`INS`)

- `0x01` `INS_GET_SERIAL`
- `0x00` `INS_GET_VERSION`
- `0x04` `INS_GET_APP_NAME`
- `0x10` `INS_GET_PUBLIC_KEY`
- `0x11` `INS_DERIVE_ADDRESS`
- `0x12` `INS_DERIVE_NATIVE_SCRIPT_HASH`
- `0x21` `INS_SIGN_TX`
- `0x22` `INS_SIGN_OPCERT`
- `0x23` `INS_SIGN_CVOTE`
- `0x24` `INS_SIGN_MSG`
- `0xF0` `INS_DEBUG_SET_SETTINGS` (debug builds only)

## Command Flow and Chunking

- `SIGN_TX` uses multi-APDU flow:
  - `P1_TX_INIT` (`0x10`)
  - `P1_TX_CHUNK` (`0x11`) zero or more times
  - `P1_TX_CONFIRM` (`0x12`) final step
  - `P1_TX_AUX_DATA` (`0x13`) for aux-data subflow when present
- `SIGN_CVOTE` uses:
  - `P1_CVOTE_INIT` (`0x50`)
  - `P1_CVOTE_CHUNK` (`0x51`)
  - `P1_CVOTE_CONFIRM` (`0x52`)
- `SIGN_MSG` uses:
  - `P1_SIGN_MSG_INIT` (`0x01`)
  - `P1_SIGN_MSG_CHUNK` (`0x02`)
  - `P1_SIGN_MSG_CONFIRM` (`0x03`)
- Native script hash flow uses:
  - `P1_NATIVE_SCRIPT_INIT` (`0x00`)
  - `P1_NATIVE_SCRIPT_START_COMPLEX` (`0x01`)
  - `P1_NATIVE_SCRIPT_ADD_SIMPLE` (`0x02`)
  - `P1_NATIVE_SCRIPT_FINISH` (`0x03`)

- `DERIVE_ADDRESS` uses:
  - `P1_ADDRESS_RETURN` (`0x01`)
  - `P1_ADDRESS_DISPLAY` (`0x02`)
- `SIGN_TX` witness signing uses:
  - `P1_TX_SIGN_WITNESS` (`0x0F`)

Notes:
- `P2_AUX_DATA_INIT` (`0x36`) and `P2_AUX_DATA_DELEGATION` (`0x37`) are used with tx aux-data flow.
- Interleaving commands between steps of a multi-APDU flow is rejected by dispatcher state checks.

## Status Words

The app uses SDK ISO-7816 words and Cardano-specific words.
For integration and troubleshooting, use `src/cardano_swo.h` as the primary table.
