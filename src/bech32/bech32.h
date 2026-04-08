/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bech32_cardano.h"

#define BECH32_SEPARATOR_LENGTH 1
#define BECH32_CHECKSUM_LENGTH  6

// Maximum input bytes accepted by format_bech32().
// WARNING: increasing this would take more stack space, see data5bit definition in bech32.c.
// We are not supposed to use more for Cardano Shelley.
#define MAX_BECH32_BUFFER_LENGTH 65

#define MAX_BECH32_ENCODED_DATA_LENGTH (((8 * MAX_BECH32_BUFFER_LENGTH) + 4) / 5)
#define MAX_BECH32_STRING_LENGTH                                                   \
    (MAX_BECH32_PREFIX_LENGTH + BECH32_SEPARATOR_LENGTH + BECH32_CHECKSUM_LENGTH + \
     MAX_BECH32_ENCODED_DATA_LENGTH + 1)

/*
 * Encode bytes, using human-readable prefix given in hrp.
 *
 * The resulting string length equals strlen(hrp) + BECH32_SEPARATOR_LENGTH +
 * BECH32_CHECKSUM_LENGTH +
 * ceiling(8/5 * bytesSize) [base32 encoding with padding], and the output buffer must
 * have space for the trailing null character.
 *
 * Returns true on success; formatting failures indicate bugs and should not happen in production.
 */
bool format_bech32(const char* hrp,
                   const uint8_t* bytes,
                   size_t bytesSize,
                   char* output,
                   size_t maxOutputSize);
