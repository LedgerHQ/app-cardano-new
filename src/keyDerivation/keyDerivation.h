/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "bip44.h"
#include "cx.h"
#include "utils.h"

#define PUBLIC_KEY_LENGTH    (32)
#define CHAIN_CODE_LENGTH    (32)
#define EXTENDED_PUBKEY_SIZE (CHAIN_CODE_LENGTH + PUBLIC_KEY_LENGTH)

typedef cx_ecfp_256_extended_private_key_t privateKey_t;

typedef struct {
    uint8_t code[CHAIN_CODE_LENGTH];
} chain_code_t;

typedef struct {
    uint8_t pubKey[PUBLIC_KEY_LENGTH];
    uint8_t chainCode[CHAIN_CODE_LENGTH];
} extendedPublicKey_t;

__noinline_due_to_stack__ void deriveExtendedPublicKey(const bip44_path_t *pathSpec,
                                                       extendedPublicKey_t *out);

__noinline_due_to_stack__ void keyPathToKeyHash(const bip44_path_t *pathSpec,
                                                uint8_t *hash,
                                                size_t hashSize);
