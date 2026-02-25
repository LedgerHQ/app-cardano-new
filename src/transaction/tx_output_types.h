/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cardano_constants.h"
#include "lists.h"
#include "addressUtilsShelley.h"
#include "assert.h"

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
// points to an address_params_t whose credential pointers likewise reference the
// persistent raw buffer.  No separate "storage" variant is needed.
typedef struct {
    tx_output_destination_type_t type;
    union {
        third_party_address_t address;
        address_params_t* params;
    };
} tx_output_destination_t;

static inline tx_output_destination_t tx_output_destination_make_third_party(const uint8_t* addressBuffer,
                                                                             size_t addressLength)
{
    ASSERT(addressBuffer != NULL);
    ASSERT(addressLength > 0);
    ASSERT(addressLength <= MAX_ADDRESS_LENGTH);

    tx_output_destination_t destination = {
        .type = DESTINATION_THIRD_PARTY,
        .address = {
            .buffer = addressBuffer,
            .length = addressLength,
        },
    };
    return destination;
}

static inline tx_output_destination_t tx_output_destination_make_device_owned(address_params_t* params)
{
    ASSERT(params != NULL);

    tx_output_destination_t destination = {
        .type = DESTINATION_DEVICE_OWNED,
        .params = params,
    };
    return destination;
}

typedef struct {
    const uint8_t* assetName;
    uint8_t assetNameLen;
    uint64_t amount;
} output_token_t;

typedef struct {
    flist_node_t flist_node;
    output_token_t token_data;
} output_token_node_t;

typedef struct {
    const uint8_t* policyId;
    uint16_t numTokens;
    flist_node_t* tokens;
} output_asset_group_t;

typedef struct {
    flist_node_t flist_node;
    output_asset_group_t asset_group;
} output_asset_group_node_t;

typedef enum {
    DATUM_HASH = 0,
    DATUM_INLINE = 1,
} datum_type_t;

// Dynamically allocated when datum is present; NULL means no datum.
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

// Dynamically allocated when ref script is present; NULL means no ref script.
typedef struct {
    uint16_t size;
    const uint8_t* data;  // Points to data in raw_tx buffer
} ref_script_t;

typedef enum {
    ARRAY_LEGACY = 0,
    MAP_BABBAGE = 1
} tx_output_serialization_format_t;

typedef struct {
    tx_output_destination_t destination;
    // Note: For DESTINATION_DEVICE_OWNED, destination.params points to dynamically
    // allocated memory that must be freed when the output is freed.
    // For DESTINATION_THIRD_PARTY, destination.address points to the raw_tx buffer.
    uint64_t adaAmount;
    uint16_t numAssetGroups;
    flist_node_t* assetGroups;
    output_datum_t* datum;    // NULL if no datum; heap-allocated if present
    ref_script_t* refScript;  // NULL if no ref script; heap-allocated if present
    tx_output_serialization_format_t format;
} parsed_tx_output_t;

typedef struct {
    flist_node_t flist_node;
    parsed_tx_output_t output_data;
} tx_output_node_t;
