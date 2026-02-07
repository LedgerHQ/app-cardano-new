/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Vacuumlabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "tx_parse_outputs.h"
#include "assert.h"
#include "buffer_write.h"
#include "addressUtilsShelley.h"
#include "cardano_swo.h"
#include "cardano_parsers.h"
#include "app_mem_utils.h"

parser_status_e parse_output_destination(buffer_t* buf,
                                         tx_output_destination_t* destination) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(destination != NULL, "NULL destination");

    // Read destination type
    uint8_t dest_type = 0;
    if (!buffer_read_u8(buf, &dest_type)) {
        return OUTPUTS_PARSING_ERROR;
    }
    TRACE("Deserialize: Output destination type=0x%02x (1=THIRD_PARTY, 2=DEVICE_OWNED)", dest_type);

    switch (dest_type) {
        case DESTINATION_THIRD_PARTY: {
            // Read address length
            uint16_t addr_size = 0;
            if (!buffer_read_u16(buf, &addr_size, BE)) {
                return OUTPUTS_PARSING_ERROR;
            }
            if (addr_size == 0 || addr_size > MAX_ADDRESS_LENGTH) {
                return OUTPUT_ADDRESS_SIZE_ERROR;
            }

            // Store pointer to address in raw buffer instead of copying
            const uint8_t* address_buffer = NULL;
            if (!buffer_read_bytes_ptr(buf, &address_buffer, addr_size)) {
                return OUTPUTS_PARSING_ERROR;
            }
            *destination = tx_output_destination_make_third_party(address_buffer, addr_size);
            break;
        }

        case DESTINATION_DEVICE_OWNED: {
            // Dynamically allocate storage for address params
            address_params_t* params = NULL;
            if (!APP_MEM_CALLOC((void**)&params, sizeof(address_params_t))) {
                TRACE("parse_output_destination: out of memory allocating address_params_t");
                return OUT_OF_MEMORY_ERROR;
            }

            // Parse address params into the dynamically allocated storage.
            // Credential pointers within params reference the persistent raw buffer.
            if (!buffer_read_address_params(buf, params)) {
                APP_MEM_FREE(params);
                return OUTPUTS_PARSING_ERROR;
            }
            *destination = tx_output_destination_make_device_owned(params);
            break;
        }

        default:
            return OUTPUT_DESTINATION_TYPE_ERROR;
    }

    return PARSING_OK;
}

parser_status_e parse_output_format(buffer_t* buf,
                                    tx_output_serialization_format_t* format,
                                    parser_status_e parseFailureStatus) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(format != NULL, "NULL format");
    LEDGER_ASSERT(parseFailureStatus != PARSING_OK, "Invalid parse failure status");

    uint8_t output_format = 0;
    if (!buffer_read_u8(buf, &output_format)) {
        return parseFailureStatus;
    }

    // Validate format is one of the supported values
    if (output_format != ARRAY_LEGACY && output_format != MAP_BABBAGE) {
        TRACE("Invalid output format: %u", output_format);
        return parseFailureStatus;
    }

    *format = (tx_output_serialization_format_t) output_format;
    TRACE("Output serialization format: %u", output_format);

    return PARSING_OK;
}

parser_status_e parse_output_datum(buffer_t* buf,
                                   output_datum_t* datum,
                                   parser_status_e parseFailureStatus) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(datum != NULL, "NULL datum");
    LEDGER_ASSERT(parseFailureStatus != PARSING_OK, "Invalid parse failure status");

    if (!buffer_read_flag_included(buf, &datum->hasDatum)) {
        return parseFailureStatus;
    }
    TRACE("Datum present: %u", datum->hasDatum);

    if (!datum->hasDatum) {
        return PARSING_OK;
    }

    uint8_t datum_wire_type = 0;
    if (!buffer_read_u8(buf, &datum_wire_type)) {
        return parseFailureStatus;
    }
    TRACE("Datum type: wire=%u", datum_wire_type);

    switch (datum_wire_type) {
        case DATUM_HASH: {  // Datum hash
            datum->type = DATUM_HASH;

            if (!buffer_read_bytes_ptr(buf, &datum->hash, OUTPUT_DATUM_HASH_LENGTH)) {
                return parseFailureStatus;
            }
            ASSERT(datum->hash != NULL);
            TRACE("Datum hash read");
            TRACE_BUFFER(datum->hash, OUTPUT_DATUM_HASH_LENGTH);
            break;
        }

        case DATUM_INLINE: {  // Inline datum
            datum->type = DATUM_INLINE;

            uint16_t datum_size;
            if (!buffer_read_u16(buf, &datum_size, BE)) {
                return parseFailureStatus;
            }
            datum->inline_datum.length = datum_size;

            if (!buffer_read_bytes_ptr(buf, &datum->inline_datum.buffer, datum_size)) {
                return parseFailureStatus;
            }
            ASSERT(datum->inline_datum.buffer != NULL);
            TRACE("Inline datum read: %u bytes", datum_size);
            TRACE_BUFFER(datum->inline_datum.buffer, datum->inline_datum.length);
            break;
        }

        default:
            return parseFailureStatus;
    }

    return PARSING_OK;
}

parser_status_e parse_output_ref_script(buffer_t* buf,
                                        ref_script_t* refScript,
                                        parser_status_e parseFailureStatus) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(refScript != NULL, "NULL refScript");
    LEDGER_ASSERT(parseFailureStatus != PARSING_OK, "Invalid parse failure status");

    if (!buffer_read_flag_included(buf, &refScript->hasRefScript)) {
        return parseFailureStatus;
    }
    TRACE("Reference script present: %u", refScript->hasRefScript);

    if (!refScript->hasRefScript) {
        refScript->size = 0;
        refScript->data = NULL;
        return PARSING_OK;
    }

    uint16_t script_size;
    if (!buffer_read_u16(buf, &script_size, BE)) {
        return parseFailureStatus;
    }
    refScript->size = script_size;

    if (!buffer_read_bytes_ptr(buf, &refScript->data, script_size)) {
        return parseFailureStatus;
    }
    ASSERT(refScript->data != NULL);
    TRACE("Reference script read: %u bytes", script_size);

    return PARSING_OK;
}
