/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"
#include "tx_output_types.h"
#include "tx_parse.h"

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
 *   - For DESTINATION_DEVICE_OWNED: destination.params points to dynamically allocated
 *     address_params_t that must be freed by the caller
 * @return PARSING_OK on success, OUT_OF_MEMORY_ERROR or appropriate error code on failure
 */
parser_status_e parse_output_destination(buffer_t* buf,
                                         tx_output_destination_t* destination);

/**
 * Clean up dynamically allocated memory in output destination.
 *
 * @param[in,out] destination Destination structure to clean up
 */
void cleanup_output_destination(tx_output_destination_t* destination);

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
 * @param[in] parseFailureStatus Error status to return on parse failure
 * @return PARSING_OK on success, parseFailureStatus on failure
 */
parser_status_e parse_output_format(buffer_t* buf,
                                    tx_output_serialization_format_t* format,
                                    parser_status_e parseFailureStatus);

/**
 * Parse transaction output datum from buffer.
 *
 * Wire format:
 * - datum_present: 1 byte (FLAG_INCLUDED_NO/FLAG_INCLUDED_YES)
 * - datum_type: 1 byte (DATUM_HASH/DATUM_INLINE), only if present
 * - if HASH (0):
 *     - hash bytes: 32 bytes (no length prefix)
 * - if INLINE (1):
 *     - size: 2 bytes (BE)
 *     - data bytes: <size> bytes
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] datum_out Set to heap-allocated output_datum_t if present, NULL if absent.
 *   Caller must free via APP_MEM_FREE on success if non-NULL.
 * @param[in] parseFailureStatus Error status to return on parse failure
 * @return PARSING_OK on success, OUT_OF_MEMORY_ERROR or parseFailureStatus on failure
 */
parser_status_e parse_output_datum(buffer_t* buf,
                                   output_datum_t** datum_out,
                                   parser_status_e parseFailureStatus);

/**
 * Parse transaction output reference script from buffer.
 *
 * Wire format:
 * - ref_script_present: 1 byte (FLAG_INCLUDED_NO/FLAG_INCLUDED_YES)
 * - if HAS_SCRIPT (1):
 *     - size: 2 bytes (BE)
 *     - data bytes: <size> bytes
 *
 * @param[in,out] buf Buffer to read from
 * @param[out] ref_script_out Set to heap-allocated ref_script_t if present, NULL if absent.
 *   Caller must free via APP_MEM_FREE on success if non-NULL.
 * @param[in] parseFailureStatus Error status to return on parse failure
 * @return PARSING_OK on success, OUT_OF_MEMORY_ERROR or parseFailureStatus on failure
 */
parser_status_e parse_output_ref_script(buffer_t* buf,
                                        ref_script_t** ref_script_out,
                                        parser_status_e parseFailureStatus);
