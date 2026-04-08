/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"
#include "tx_hash_builder.h"
#include "tx_output_types.h"
#include "assert.h"

static inline tx_output_destination_t tx_output_destination_make_third_party(
    const uint8_t* addressBuffer,
    size_t addressLength) {
    ASSERT(addressBuffer != NULL);
    ASSERT(addressLength > 0);
    ASSERT(addressLength <= MAX_ADDRESS_LENGTH);

    tx_output_destination_t destination = {
        .type = DESTINATION_THIRD_PARTY,
        .address =
            {
                .buffer = addressBuffer,
                .length = addressLength,
            },
    };
    return destination;
}

static inline tx_output_destination_t tx_output_destination_make_device_owned(
    const address_params_t* params) {
    ASSERT(params != NULL);

    tx_output_destination_t destination = {
        .type = DESTINATION_DEVICE_OWNED,
        .params = *params,
    };
    return destination;
}

/**
 * Parse transaction output destination from buffer.
 *
 * Parses either a third-party address (raw bytes) or device-owned address (params).
 * This is a common operation when parsing transaction outputs.
 *
 * Wire format:
 * - destination type: 1 byte (DESTINATION_THIRD_PARTY=1 or DESTINATION_DEVICE_OWNED=2)
 * - if DESTINATION_THIRD_PARTY:
 *     - address length: 2 bytes (BE)
 *     - address bytes: <length> bytes
 * - if DESTINATION_DEVICE_OWNED:
 *     - address params (see buffer_read_address_params in addressUtilsShelley.h)
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] destination Destination structure to populate
 *   - For DESTINATION_THIRD_PARTY: destination.address points to raw_tx buffer
 *   - For DESTINATION_DEVICE_OWNED: destination.params is embedded by value;
 *     credential pointers within params reference the persistent raw buffer
 * @return 0 on success, SWO_* on failure
 */
uint16_t parse_output_destination(buffer_t* buf, tx_output_destination_t* destination);

/**
 * Parse transaction output serialization format from buffer.
 *
 * Validates that the format is either ARRAY_LEGACY or MAP_BABBAGE.
 *
 * Wire format:
 * - format: 1 byte (ARRAY_LEGACY=0 or MAP_BABBAGE=1)
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] format Output format to populate
 * @param[in] parseFailureSwo SWO to return on parse failure
 * @return 0 on success, parseFailureSwo on failure
 */
uint16_t parse_output_format(buffer_t* buf,
                             tx_output_serialization_format_t* format,
                             uint16_t parseFailureSwo);

/**
 * Parse the top-level fields of a transaction output from buffer.
 *
 * Reads: destination, amount, serialization format, datum-present flag,
 * ref-script-present flag, and numAssetGroups into out_description.
 * The includeDatum and includeRefScript fields in out_description reflect
 * the presence flags; the caller is responsible for subsequently parsing
 * asset groups, datum body, and ref script body.
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] out_description Populated on success. For DESTINATION_DEVICE_OWNED,
 *   destination.params is embedded by value; no cleanup required.
 * @param[in] parseFailureSwo SWO to return on parse failure
 * @return 0 on success, or parseFailureSwo on failure
 */
uint16_t parse_output_top_level(buffer_t* buf,
                                tx_output_description_t* out_description,
                                uint16_t parseFailureSwo);

typedef struct {
    const uint8_t* policyId;  // points into raw tx buffer
    uint16_t numTokens;
} output_asset_group_t;

/**
 * Parse one asset group header (policy ID + token count) from a transaction output.
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] out_group Populated on success
 * @return true on success, false on parse failure
 */
bool parse_output_asset_group(buffer_t* buf, output_asset_group_t* out_group);

/**
 * Parse one token (asset name + amount) from a transaction output.
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] out_token Populated on success
 * @return true on success, false on parse failure
 */
bool parse_output_token(buffer_t* buf, output_token_t* out_token);

/**
 * Parse transaction output datum body from buffer (presence flag already consumed).
 *
 * Wire format (when datum is present):
 * - datum_type: 1 byte (DATUM_HASH/DATUM_INLINE)
 * - if HASH (0):
 *     - hash bytes: 32 bytes (no length prefix)
 * - if INLINE (1):
 *     - size: 2 bytes (BE)
 *     - data bytes: <size> bytes
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] datum_out Populated on success
 * @return true on success, false on parse failure
 */
bool parse_output_datum(buffer_t* buf, output_datum_t* datum);

/**
 * Parse transaction output reference script body from buffer (presence flag already consumed).
 *
 * Wire format (when ref script is present):
 * - size: 2 bytes (BE)
 * - data bytes: <size> bytes
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] ref_script_out Populated on success
 * @return true on success, false on parse failure
 */
bool parse_output_ref_script(buffer_t* buf, ref_script_t* ref_script);
