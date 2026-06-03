/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "tx_parse_outputs.h"
#include "assert.h"
#include "addressUtilsShelley.h"
#include "cardano_swo.h"
#include "cardano_parsers.h"
#include "tx_constants.h"
#include "cardano_constants.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_TX_PARSE to trace this module's parsing details.
 */
#ifdef TRACE_TX_PARSE
#define TRACE_MODULE(...) TRACE("[tx_parse_outputs] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void) 0  // Compiled out
#endif

__noinline_due_to_stack__ uint16_t parse_output_destination(buffer_t* buf,
                                                            tx_output_destination_t* destination) {
    ASSERT(buf != NULL);
    ASSERT(destination != NULL);

    // Read destination type
    uint8_t dest_type = 0;
    if (!buffer_read_u8(buf, &dest_type)) {
        TRACE("Failed to read destination type");
        return SWO_TX_PARSING_FAIL_OUTPUTS;
    }
    TRACE_MODULE("Deserialize: Output destination type=0x%02x (1=THIRD_PARTY, 2=DEVICE_OWNED)",
                 dest_type);

    switch (dest_type) {
        case DESTINATION_THIRD_PARTY: {
            // Read address length
            uint16_t address_size = 0;
            if (!buffer_read_u16(buf, &address_size, BE)) {
                TRACE("Failed to read address size");
                return SWO_TX_PARSING_FAIL_OUTPUTS;
            }
            if (address_size == 0 || address_size > MAX_ADDRESS_LENGTH) {
                TRACE("Invalid address size: %u", (unsigned) address_size);
                return SWO_TX_PARSING_FAIL_OUTPUTS;
            }

            // Store pointer to address in raw buffer instead of copying
            const uint8_t* address_buffer = NULL;
            if (!buffer_read_bytes_ptr(buf, &address_buffer, address_size)) {
                TRACE("Failed to read address bytes");
                return SWO_TX_PARSING_FAIL_OUTPUTS;
            }
            *destination = tx_output_destination_make_third_party(address_buffer, address_size);
            break;
        }

        case DESTINATION_DEVICE_OWNED: {
            if (!buffer_read_address_params(buf, &destination->params)) {
                TRACE("Failed to read address params");
                return SWO_TX_PARSING_FAIL_OUTPUTS;
            }
            destination->type = DESTINATION_DEVICE_OWNED;
            break;
        }

        default:
            TRACE("Unknown destination type: 0x%02x", dest_type);
            return SWO_TX_PARSING_FAIL_OUTPUTS;
    }

    return SWO_OK;
}

uint16_t parse_output_format(buffer_t* buf,
                             tx_output_serialization_format_t* format,
                             uint16_t parseFailureSwo) {
    ASSERT(buf != NULL);
    ASSERT(format != NULL);
    LEDGER_ASSERT(parseFailureSwo != SWO_OK, "Invalid parse failure SWO");

    uint8_t output_format = 0;
    if (!buffer_read_u8(buf, &output_format)) {
        TRACE("Failed to read output format");
        return parseFailureSwo;
    }

    switch (output_format) {
        case ARRAY_LEGACY:
        case MAP_BABBAGE:
            *format = (tx_output_serialization_format_t) output_format;
            TRACE_MODULE("output_format=%u", output_format);
            return SWO_OK;
        default:
            TRACE("Unknown output format: 0x%02x", (unsigned) output_format);
            return parseFailureSwo;
    }
}

uint16_t parse_output_top_level(buffer_t* buf,
                                tx_output_description_t* out_description,
                                uint16_t parseFailureSwo) {
    ASSERT(buf != NULL);
    ASSERT(out_description != NULL);
    LEDGER_ASSERT(parseFailureSwo != SWO_OK, "Invalid parse failure SWO");

    explicit_bzero(out_description, sizeof(*out_description));

    uint16_t status = parse_output_destination(buf, &out_description->destination);
    if (status != SWO_OK) {
        return parseFailureSwo;
    }

    ASSERT_TYPE(out_description->amount, uint64_t);
    if (!buffer_read_u64(buf, &out_description->amount, BE)) {
        TRACE("Failed to read output amount");
        return parseFailureSwo;
    }
    if (out_description->amount >= LOVELACE_MAX_SUPPLY) {
        TRACE("Output amount too large: %llu", (unsigned long long) out_description->amount);
        return parseFailureSwo;
    }

    status = parse_output_format(buf, &out_description->format, parseFailureSwo);
    if (status != SWO_OK) {
        return status;
    }

    bool datum_present = false;
    if (!buffer_read_flag_included(buf, &datum_present)) {
        TRACE("Failed to read datum inclusion flag");
        return parseFailureSwo;
    }
    bool ref_script_present = false;
    if (!buffer_read_flag_included(buf, &ref_script_present)) {
        TRACE("Failed to read ref script inclusion flag");
        return parseFailureSwo;
    }

    ASSERT_TYPE(out_description->numAssetGroups, uint16_t);
    if (!buffer_read_u16(buf, &out_description->numAssetGroups, BE)) {
        TRACE("Failed to read num asset groups");
        return parseFailureSwo;
    }

    if (ref_script_present && out_description->format != MAP_BABBAGE) {
        TRACE("Ref script present in non-Babbage output");
        return parseFailureSwo;
    }
    out_description->includeDatum = datum_present;
    out_description->includeRefScript = ref_script_present;

    return SWO_OK;
}

bool parse_output_asset_group(buffer_t* buf, output_asset_group_t* out_group) {
    ASSERT(buf != NULL);
    ASSERT(out_group != NULL);

    if (!buffer_read_bytes_ptr(buf, &out_group->policyId, MINTING_POLICY_ID_LENGTH) ||
        out_group->policyId == NULL) {
        TRACE("Failed to read policy ID");
        return false;
    }

    if (!buffer_read_u16(buf, &out_group->numTokens, BE)) {
        TRACE("Failed to read number of tokens in group");
        return false;
    }
    if (out_group->numTokens == 0) {
        TRACE("Zero tokens in asset group");
        return false;
    }

    return true;
}

bool parse_output_token(buffer_t* buf, output_token_t* out_token) {
    ASSERT(buf != NULL);
    ASSERT(out_token != NULL);

    if (!buffer_read_u8(buf, &out_token->assetNameLen) ||
        out_token->assetNameLen > MAX_ASSET_NAME_LENGTH) {
        TRACE("Failed to read asset name length or too long: %u",
              (unsigned) out_token->assetNameLen);
        return false;
    }
    if (!buffer_read_bytes_ptr(buf, &out_token->assetName, out_token->assetNameLen)) {
        TRACE("Failed to read asset name");
        return false;
    }
    ASSERT(out_token->assetName != NULL);

    if (!buffer_read_u64(buf, &out_token->amount, BE)) {
        TRACE("Failed to read token amount");
        return false;
    }
    if (out_token->amount == 0) {
        TRACE("Output token amount must be positive");
        return false;
    }

    return true;
}

bool parse_output_datum(buffer_t* buf, output_datum_t* datum) {
    ASSERT(buf != NULL);
    ASSERT(datum != NULL);

    uint8_t datum_wire_type = 0;
    if (!buffer_read_u8(buf, &datum_wire_type)) {
        TRACE("Failed to read datum wire type");
        return false;
    }
    TRACE("Datum type: wire=%u", datum_wire_type);

    switch (datum_wire_type) {
        case DATUM_HASH: {
            datum->type = DATUM_HASH;

            if (!buffer_read_bytes_ptr(buf, &datum->hash, OUTPUT_DATUM_HASH_LENGTH)) {
                TRACE("Failed to read datum hash");
                return false;
            }
            ASSERT(datum->hash != NULL);
            TRACE("Datum hash read");
            TRACE_BUFFER(datum->hash, OUTPUT_DATUM_HASH_LENGTH);
            break;
        }

        case DATUM_INLINE: {
            datum->type = DATUM_INLINE;

            uint16_t datum_size;
            if (!buffer_read_u16(buf, &datum_size, BE)) {
                TRACE("Failed to read inline datum size");
                return false;
            }
            // Inline datum payload is encoded as data = #6.24(bytes .cbor plutus_data)
            // (see doc/conway.cddl). The bytestring must therefore contain a complete CBOR
            // item representing plutus_data. Zero-length bytes cannot encode any CBOR item,
            // so accepting datum_size == 0 would violate the CDDL and admit malformed data.
            if (datum_size == 0) {
                TRACE("Inline datum size must be non-zero");
                return false;
            }
            datum->inline_datum.length = datum_size;

            if (!buffer_read_bytes_ptr(buf, &datum->inline_datum.buffer, datum_size)) {
                TRACE("Failed to read inline datum buffer");
                return false;
            }
            ASSERT(datum->inline_datum.buffer != NULL);
            TRACE("Inline datum read: %u bytes", datum_size);
            TRACE_BUFFER(datum->inline_datum.buffer, datum->inline_datum.length);
            break;
        }

        default:
            TRACE("Unknown datum wire type: 0x%02x", datum_wire_type);
            return false;
    }

    return true;
}

bool parse_output_ref_script(buffer_t* buf, ref_script_t* ref_script) {
    ASSERT(buf != NULL);
    ASSERT(ref_script != NULL);

    uint16_t script_size;
    if (!buffer_read_u16(buf, &script_size, BE)) {
        TRACE("Failed to read ref script size");
        return false;
    }
    // Reference scripts are encoded as script_ref = #6.24(bytes .cbor script)
    // (see doc/conway.cddl). The bytestring must embed a full CBOR value of type script.
    // A zero-length bytestring cannot contain a CBOR item, so script_size == 0 is invalid.
    if (script_size == 0) {
        TRACE("Reference script size must be non-zero");
        return false;
    }
    ref_script->size = script_size;

    if (!buffer_read_bytes_ptr(buf, &ref_script->data, script_size)) {
        TRACE("Failed to read ref script data");
        return false;
    }
    ASSERT(ref_script->data != NULL);
    TRACE("Reference script read: %u bytes", script_size);

    return true;
}
