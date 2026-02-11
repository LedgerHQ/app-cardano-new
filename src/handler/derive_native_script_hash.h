/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"

typedef enum {
    DISPLAY_NATIVE_SCRIPT_HASH_BECH32 = 1,
    DISPLAY_NATIVE_SCRIPT_HASH_POLICY_ID = 2,
} display_format;

typedef enum {
    UI_SCRIPT_PUBKEY_PATH,  // aka DEVICE_OWNED
    UI_SCRIPT_PUBKEY_HASH,  // aka THIRD_PARTY
    UI_SCRIPT_ALL,
    UI_SCRIPT_ANY,
    UI_SCRIPT_N_OF_K,
    UI_SCRIPT_INVALID_BEFORE,
    UI_SCRIPT_INVALID_HEREAFTER,
    UI_SCRIPT_DISPLAY_BECH32,
    UI_SCRIPT_DISPLAY_POLICY_ID,
} ui_native_script_type;

/**
 * Handler for INS_DERIVE_NATIVE_SCRIPT_HASH command.
 * Processes native script hash derivation APDUs.
 *
 * @param[in,out] cdata
 *   Buffer containing APDU payload for the current native script step.
 * @param script_type
 *   Current step selector (start complex, add simple, finish).
 */
void handler_derive_native_script_hash(buffer_t *cdata, uint8_t script_type);
