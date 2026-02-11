/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "bip44.h"

typedef enum {
    KEY_REFERENCE_PATH = 1,  // device-owned path reference
    KEY_REFERENCE_HASH = 2,  // third-party key hash
} key_reference_type_t;

typedef struct {
    key_reference_type_t keyReferenceType;
    union {
        bip44_path_t path;
        const uint8_t* hashBuffer;
    };
// TODO maybe we do not need this type and it could be replaced by credential
// TODO since network id is stored globally for tx, but it might affect public API in ledgerjs
} pool_reward_account_t;
