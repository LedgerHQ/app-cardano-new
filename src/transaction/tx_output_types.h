/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cardano_constants.h"
#include "addressUtilsShelley.h"

typedef enum {
    DESTINATION_THIRD_PARTY = 1,
    DESTINATION_DEVICE_OWNED = 2,
} tx_output_destination_type_t;

// Third-party address: pointer to raw address bytes and length
// Used by both TX outputs and CVote destinations
typedef struct {
    const uint8_t* buffer;
    size_t length;
} third_party_address_t;

// Unified output destination.  For DESTINATION_THIRD_PARTY the address pointer
// references the persistent raw buffer.  For DESTINATION_DEVICE_OWNED, params
// is embedded by value and its credential pointers reference the persistent raw buffer.
typedef struct {
    tx_output_destination_type_t type;
    union {
        third_party_address_t address;
        address_params_t params;
    };
} tx_output_destination_t;

typedef struct {
    const uint8_t* assetName;
    uint8_t assetNameLen;
    uint64_t amount;
} output_token_t;

typedef enum {
    DATUM_HASH = 0,
    DATUM_INLINE = 1,
} datum_type_t;

typedef struct {
    datum_type_t type;
    union {
        const uint8_t* hash;  // Points to 32-byte hash in raw_tx buffer
        struct {
            size_t length;
            const uint8_t* buffer;  // Points to inline datum bytes in raw_tx buffer
        } inline_datum;
    };
} output_datum_t;

typedef struct {
    uint16_t size;
    const uint8_t* data;  // Points to data in raw_tx buffer
} ref_script_t;

typedef enum { ARRAY_LEGACY = 0, MAP_BABBAGE = 1 } tx_output_serialization_format_t;
