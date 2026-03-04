/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cvote_parser.h"

#include <stdint.h>
#include <string.h>

#include "addressUtilsShelley.h"
#include "globals.h"
#include "sign_tx_ctx.h"
#include "mem.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "tx_parse_outputs.h"
#include "utils.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_CVOTE to trace voting data processing.
 */
#ifdef TRACE_CVOTE
#define TRACE_MODULE(...) TRACE("[cvote_parser] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void)0  // Compiled out
#endif

/**
 * Parse CVote credential
 *
 * Per CIP-36 CBOR spec, CVote credentials are:
 * - Type 0: 32-byte public key (not 28-byte key hash like in regular TX)
 * - Type 2: BIP44 derivation path
 * Script hashes (type 1) are NOT allowed per CIP-36 spec.
 */
bool buffer_read_cvote_credential(buffer_t *buf, cvote_credential_t *credential) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(credential != NULL, "NULL credential");

    uint8_t cred_type = 0;
    if (!buffer_read_u8(buf, &cred_type)) {
        TRACE("Failed to read CVote credential type");
        return false;
    }

    switch (cred_type) {
        case CVOTE_CREDENTIAL_KEY_PATH:
            credential->type = CVOTE_CREDENTIAL_KEY_PATH;
            if (!buffer_read_bip44_path(buf, &credential->keyPath)) {
                TRACE("Failed to read CVote BIP44 path");
                return false;
            }
            break;
        case CVOTE_CREDENTIAL_KEY:
            credential->type = CVOTE_CREDENTIAL_KEY;
            // CVote: reads 32-byte public key per CIP-36
            if (!buffer_read_bytes_ptr(buf, &credential->publicKey, PUBLIC_KEY_LENGTH)) {
                TRACE("Failed to read CVote public key");
                return false;
            }
            LEDGER_ASSERT(credential->publicKey != NULL, "NULL public key");
            break;
        default:
            TRACE("Invalid CVote credential type: %u (only 0=KEY, 2=KEY_PATH allowed)", cred_type);
            return false;
    }
    return true;
}

static cvote_parser_status_t _map_output_parser_status(uint16_t swo) {
    switch (swo) {
        case 0:
            return CVOTE_PARSER_OK;
        case SWO_INSUFFICIENT_MEMORY:
            return CVOTE_PARSER_OUT_OF_MEMORY;
        default:
            return CVOTE_PARSER_INVALID_FORMAT;
    }
}

cvote_parser_status_t cvote_parse_destination(buffer_t *buf,
                                              tx_output_destination_t *destination) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(destination != NULL, "NULL destination");

    uint16_t output_status = parse_output_destination(buf, destination);
    cvote_parser_status_t cvote_status = _map_output_parser_status(output_status);
    if (cvote_status != CVOTE_PARSER_OK) {
        TRACE("CVote destination parsing failed with output status 0x%04x", output_status);
        return cvote_status;
    }

    if (destination->type == DESTINATION_DEVICE_OWNED) {
        TRACE_MODULE("CVote destination type 0x%x, staking %d",
              destination->params.type,
              addressParams_getStakingPartType(&destination->params));
    } else {
        TRACE_MODULE("CVote destination: third-party payload");
    }

    return CVOTE_PARSER_OK;
}

cvote_parser_status_t cvote_parse_aux_data_init(cvote_aux_data_t *out_data) {
    LEDGER_ASSERT(out_data != NULL, "NULL out_data");
    LEDGER_ASSERT(tx_aux_data_ctx()->raw_cvote_init_data != NULL, "NULL raw_cvote_init_data");

    if (tx_aux_data_ctx()->raw_cvote_init_data_len < 3) {
        TRACE("CVote init payload too short: %u bytes", (unsigned)tx_aux_data_ctx()->raw_cvote_init_data_len);
        return CVOTE_PARSER_INVALID_FORMAT;
    }

    buffer_t parse_buf = {
        .ptr = tx_aux_data_ctx()->raw_cvote_init_data,
        .size = tx_aux_data_ctx()->raw_cvote_init_data_len,
        .offset = 0
    };

    // Zero out output structure
    explicit_bzero(out_data, sizeof(*out_data));

    // Parse format and delegation count
    uint8_t format = 0;
    ASSERT_TYPE(out_data->remaining_delegations, uint16_t);
    if (!buffer_read_u8(&parse_buf, &format) ||
        !buffer_read_u16(&parse_buf, &out_data->remaining_delegations, BE)) {
        TRACE("CVote init: failed to read format/remaining_delegations");
        return CVOTE_PARSER_INVALID_FORMAT;
    }

    switch (format) {
        case CIP15:
        case CIP36:
            out_data->format = format;
            break;
        default:
            TRACE("CVote init: invalid format %u", format);
            return CVOTE_PARSER_INVALID_FORMAT;
    }

    // Parse staking credential using CVote-specific credential reader
    // (reads 32-byte public keys for KEY_HASH type, not 28-byte key hashes)
    // Pointers stored into raw_buffer (no manual allocation needed!)
    if (!buffer_read_cvote_credential(&parse_buf, &out_data->staking_credential)) {
        TRACE("CVote init: failed to parse staking credential");
        return CVOTE_PARSER_INVALID_FORMAT;
    }

    // Parse destination
    cvote_parser_status_t dest_status = cvote_parse_destination(&parse_buf, &out_data->destination);
    if (dest_status != CVOTE_PARSER_OK) {
        TRACE("CVote init: failed to parse destination");
        return dest_status;
    }

    // Parse nonce
    ASSERT_TYPE(out_data->nonce, uint64_t);
    if (!buffer_read_u64(&parse_buf, &out_data->nonce, BE)) {
        TRACE("CVote init: failed to read nonce");
        dest_status = CVOTE_PARSER_INVALID_FORMAT;
        return dest_status;
    }

    // Parse format-specific fields
    // Type checks for voting_purpose moved outside switch to avoid static assert in case label
    ASSERT_TYPE(out_data->voting_purpose, uint64_t);
    switch (out_data->format) {
        case CIP36:
            if (!buffer_read_u64(&parse_buf, &out_data->voting_purpose, BE)) {
                TRACE("CVote init: failed to read voting_purpose");
                dest_status = CVOTE_PARSER_INVALID_FORMAT;
                return dest_status;
            }

            // CIP36 with 0 delegations includes vote credential in init
            if (out_data->remaining_delegations == 0) {
                if (!buffer_read_cvote_credential(&parse_buf, &out_data->vote_credential)) {
                    TRACE("CVote init: failed to parse vote credential (CIP36, no delegations)");
                    dest_status = CVOTE_PARSER_INVALID_FORMAT;
                    return dest_status;
                }
            }
            break;

        case CIP15:
            // CIP15 always includes vote credential in init
            if (!buffer_read_cvote_credential(&parse_buf, &out_data->vote_credential)) {
                TRACE("CVote init: failed to parse vote credential (CIP15)");
                dest_status = CVOTE_PARSER_INVALID_FORMAT;
                return dest_status;
            }
            break;

        default:
            LEDGER_ASSERT(false, "Invalid CVote registration format: %u", out_data->format);
            dest_status = CVOTE_PARSER_INVALID_FORMAT;
            return dest_status;
    }

    // Verify buffer fully consumed
    if (parse_buf.offset != parse_buf.size) {
        TRACE("CVote init payload not fully consumed: %u/%u bytes",
              (unsigned)parse_buf.offset, (unsigned)parse_buf.size);
        dest_status = CVOTE_PARSER_INVALID_FORMAT;
        return dest_status;
    }

    TRACE("CVote init parsed: format=%u, delegations=%u, nonce=%llu",
          out_data->format, out_data->remaining_delegations, out_data->nonce);

    return CVOTE_PARSER_OK;
}
