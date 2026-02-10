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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    // Parse INIT payload via global raw_cvote_init_data.
    if (size > 0) {
        uint8_t *init_copy = malloc(size);
        if (init_copy != NULL) {
            memcpy(init_copy, data, size);
            G_context.tx_info.raw_cvote_init_data = init_copy;
            G_context.tx_info.raw_cvote_init_data_len = size;

            cvote_aux_data_t aux_data = {0};
            if (cvote_parse_aux_data_init(&aux_data) == CVOTE_PARSER_OK) {
                warning_bits_t warnings = 0;
                (void) policyForCVoteRegistrationVoteKey(&aux_data.vote_credential,
                                                         aux_data.format,
                                                         &warnings);
                if (aux_data.staking_credential.type == CVOTE_CREDENTIAL_KEY_PATH) {
                    (void) policyForCVoteRegistrationStakingKey(&aux_data.staking_credential.keyPath,
                                                                &warnings);
                }
            }

            if (aux_data.destination.type == DESTINATION_DEVICE_OWNED &&
                aux_data.destination.params != NULL) {
                APP_MEM_FREE(aux_data.destination.params);
                aux_data.destination.params = NULL;
            }

            free(init_copy);
            G_context.tx_info.raw_cvote_init_data = NULL;
            G_context.tx_info.raw_cvote_init_data_len = 0;
        }
    }

    // Directly fuzz low-level CVote credential parsing.
    buffer_t credential_buffer = {
        .ptr = data,
        .size = size,
        .offset = 0,
    };
    cvote_credential_t credential = {0};
    (void) buffer_read_cvote_credential(&credential_buffer, &credential);

    // Directly fuzz destination parser, including dynamic destination params allocation.
    buffer_t destination_buffer = {
        .ptr = data,
        .size = size,
        .offset = 0,
    };
    tx_output_destination_t destination = {0};
    (void) cvote_parse_destination(&destination_buffer, &destination);
    if (destination.type == DESTINATION_DEVICE_OWNED && destination.params != NULL) {
        APP_MEM_FREE(destination.params);
        destination.params = NULL;
    }

    return 0;
}
