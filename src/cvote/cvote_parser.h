#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "buffer.h"
#include "cardano_constants.h"
#include "aux_data_hash_builder.h"
#include "cvote_types.h"

typedef enum {
    CVOTE_PARSER_OK = 0,
    CVOTE_PARSER_INVALID_FORMAT,
    CVOTE_PARSER_OUT_OF_MEMORY,
} cvote_parser_status_t;

#define CVOTE_PUBLIC_KEY_LENGTH (PUBLIC_KEY_LENGTH)

typedef struct {
    // Parsed CVote registration data
    // Credentials point into raw_cvote_init_data buffer (like TX credentials)
    cvote_registration_format_t format;
    uint16_t remaining_delegations;
    cvote_credential_t staking_credential;  // CVote-specific credential (KEY_HASH = 32-byte pubkey)
    cvote_credential_t vote_credential;     // CVote-specific credential (KEY_HASH = 32-byte pubkey)
    tx_output_destination_t destination;     // Address params pointer or raw buffer pointer
    address_params_t destinationParamsStorage; // Storage for device-owned destination params
    uint64_t nonce;
    uint64_t voting_purpose;

    // Hash building state
    bool final_fields_processed;
    bool hash_finalized;
    aux_data_hash_builder_t hash_builder;
    uint8_t registration_signature[ED25519_SIGNATURE_LENGTH];

    // Validation results - what fields to display based on security policies
    struct {
        bool voting_purpose;
        bool nonce;
        bool vote_key;
        bool staking_key;
        bool payment_destination;
    } ui_show;

    // UI delegation tracking (all modes)
    uint16_t ui_delegations_total;           // Total delegation count
    uint16_t ui_delegations_shown;           // Delegations displayed so far

    // UI streaming state - only populated when ui_streaming.on == true
    // Streaming is forced when there are too many UI pairs for a single review
    // Invariants:
    // - ui_streaming.on == true IFF (too many UI pairs)
    // - NBGL streaming started IFF review_started == true
    struct {
        bool on;                             // Streaming mode forced (too many pairs)
        bool review_started;                 // NBGL streaming review session started
    } ui_streaming;

    // State machine for CVote aux data processing
    cvote_aux_data_state_e state;
} cvote_aux_data_t;

// Parse CVote credential from buffer
// Supported types: KEY (0, 32-byte pubkey) and KEY_PATH (2, BIP44 path)
bool buffer_read_cvote_credential(buffer_t *buf, cvote_credential_t *credential);

// Parse CVote destination (device-owned params or third-party address pointer).
// For DESTINATION_DEVICE_OWNED, params are dynamically allocated and must be freed
// or transferred to storage by the caller.
// For DESTINATION_THIRD_PARTY, destination.address points to raw buffer.
cvote_parser_status_t cvote_parse_destination(buffer_t *buf,
                                              tx_output_destination_t *destination);

// Parse CVote init from global context raw_cvote_init_data into cvote_aux_data structure
// Credentials and addresses point into the persistent raw_cvote_init_data buffer
cvote_parser_status_t cvote_parse_aux_data_init(cvote_aux_data_t *out_data);
