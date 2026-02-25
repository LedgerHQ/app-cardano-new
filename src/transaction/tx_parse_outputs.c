/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_parse_outputs.h"
#include "assert.h"
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

void cleanup_output_destination(tx_output_destination_t* destination) {
    if (destination == NULL) {
        return;
    }

    if (destination->type == DESTINATION_DEVICE_OWNED) {
        if (destination->params != NULL) {
            APP_MEM_FREE(destination->params);
            destination->params = NULL;
        }
    }

    // Leave destination in a stable empty state so repeated cleanup is safe
    // even if caller does not reinitialize the whole struct.
    destination->type = DESTINATION_THIRD_PARTY;
    destination->address.buffer = NULL;
    destination->address.length = 0;
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
                                   output_datum_t** datum_out,
                                   parser_status_e parseFailureStatus) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(datum_out != NULL, "NULL datum_out");
    LEDGER_ASSERT(parseFailureStatus != PARSING_OK, "Invalid parse failure status");

    *datum_out = NULL;

    bool datum_present = false;
    if (!buffer_read_flag_included(buf, &datum_present)) {
        return parseFailureStatus;
    }
    TRACE("Datum present: %u", datum_present);

    if (!datum_present) {
        return PARSING_OK;
    }

    output_datum_t* datum = NULL;
    if (!APP_MEM_CALLOC((void **) &datum, (uint16_t) sizeof(*datum))) {
        TRACE("parse_output_datum: out of memory");
        return OUT_OF_MEMORY_ERROR;
    }

    uint8_t datum_wire_type = 0;
    if (!buffer_read_u8(buf, &datum_wire_type)) {
        APP_MEM_FREE(datum);
        return parseFailureStatus;
    }
    TRACE("Datum type: wire=%u", datum_wire_type);

    switch (datum_wire_type) {
        case DATUM_HASH: {  // Datum hash
            datum->type = DATUM_HASH;

            if (!buffer_read_bytes_ptr(buf, &datum->hash, OUTPUT_DATUM_HASH_LENGTH)) {
                APP_MEM_FREE(datum);
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
                APP_MEM_FREE(datum);
                return parseFailureStatus;
            }
            datum->inline_datum.length = datum_size;

            if (!buffer_read_bytes_ptr(buf, &datum->inline_datum.buffer, datum_size)) {
                APP_MEM_FREE(datum);
                return parseFailureStatus;
            }
            ASSERT(datum->inline_datum.buffer != NULL);
            TRACE("Inline datum read: %u bytes", datum_size);
            TRACE_BUFFER(datum->inline_datum.buffer, datum->inline_datum.length);
            break;
        }

        default:
            APP_MEM_FREE(datum);
            return parseFailureStatus;
    }

    *datum_out = datum;
    return PARSING_OK;
}

parser_status_e parse_output_ref_script(buffer_t* buf,
                                        ref_script_t** ref_script_out,
                                        parser_status_e parseFailureStatus) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(ref_script_out != NULL, "NULL ref_script_out");
    LEDGER_ASSERT(parseFailureStatus != PARSING_OK, "Invalid parse failure status");

    *ref_script_out = NULL;

    bool ref_script_present = false;
    if (!buffer_read_flag_included(buf, &ref_script_present)) {
        return parseFailureStatus;
    }
    TRACE("Reference script present: %u", ref_script_present);

    if (!ref_script_present) {
        return PARSING_OK;
    }

    ref_script_t* ref_script = NULL;
    if (!APP_MEM_CALLOC((void **) &ref_script, (uint16_t) sizeof(*ref_script))) {
        TRACE("parse_output_ref_script: out of memory");
        return OUT_OF_MEMORY_ERROR;
    }

    uint16_t script_size;
    if (!buffer_read_u16(buf, &script_size, BE)) {
        APP_MEM_FREE(ref_script);
        return parseFailureStatus;
    }
    ref_script->size = script_size;

    if (!buffer_read_bytes_ptr(buf, &ref_script->data, script_size)) {
        APP_MEM_FREE(ref_script);
        return parseFailureStatus;
    }
    ASSERT(ref_script->data != NULL);
    TRACE("Reference script read: %u bytes", script_size);

    *ref_script_out = ref_script;
    return PARSING_OK;
}
