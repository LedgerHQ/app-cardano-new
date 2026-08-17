#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "cvote_parser.h"
#include "fuzz_utils.h"
#include "globals.h"
#include "mem.h"
#include "securityPolicy.h"
#include "securityWarnings.h"

#define FUZZ_APP_CUSTOM_ENTRY
#include "fuzz_harness.h"

int fuzz_entry(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    // Parse INIT payload via global raw_cvote_init_data.
    // tx_aux_data_ctx() asserts TX_STATE_AUX_DATA so set it before calling.
    if (size > 0) {
        uint8_t *init_copy = malloc(size);
        if (init_copy != NULL) {
            memcpy(init_copy, data, size);
            G_context.state.tx_state = TX_STATE_AUX_DATA;
            G_context.tx_info.aux_data.raw_cvote_init_data = init_copy;
            G_context.tx_info.aux_data.raw_cvote_init_data_len = size;

            cvote_aux_data_t aux_data = {0};
            if (cvote_parse_aux_data_init(&aux_data) == CVOTE_PARSER_OK) {
                warning_bits_t warnings = 0;
                (void) policyForCVoteRegistrationVoteKey(&aux_data.vote_credential,
                                                         aux_data.format,
                                                         &warnings);
                if (aux_data.staking_credential.type == CVOTE_CREDENTIAL_KEY_PATH) {
                    (void) policyForCVoteRegistrationStakingKey(
                        &aux_data.staking_credential.keyPath,
                        &warnings);
                }
            }

            free(init_copy);
            G_context.tx_info.aux_data.raw_cvote_init_data = NULL;
            G_context.tx_info.aux_data.raw_cvote_init_data_len = 0;
        }
    }

    // Directly fuzz low-level CVote credential parsing.
    buffer_t credential_buffer = {
        .ptr = (uint8_t *) data,
        .size = size,
        .offset = 0,
    };
    cvote_credential_t credential = {0};
    (void) buffer_read_cvote_credential(&credential_buffer, &credential);

    // Directly fuzz destination parser, including dynamic destination params allocation.
    buffer_t destination_buffer = {
        .ptr = (uint8_t *) data,
        .size = size,
        .offset = 0,
    };
    tx_output_destination_t destination = {0};
    (void) cvote_parse_destination(&destination_buffer, &destination);

    return 0;
}
