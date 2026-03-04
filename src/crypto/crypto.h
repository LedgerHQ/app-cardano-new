/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>  // uint*_t

#include "os.h"
#include "cx.h"
#include "cardano_constants.h"

void crypto_get_pubkey(const uint32_t* path,
                       size_t path_len,
                       uint8_t raw_pubkey[static ED25519_PUBKEY_UNCOMPRESSED_LENGTH],
                       uint8_t* chain_code);

void crypto_eddsa_sign(const uint32_t* path,
                       size_t path_len,
                       const uint8_t* hash,
                       size_t hash_len,
                       uint8_t* sig,
                       size_t expected_sig_len);
