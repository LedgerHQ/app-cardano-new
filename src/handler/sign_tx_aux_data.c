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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_context.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "cvote_parser.h"
#include "globals.h"
#include "io.h"
#include "mem.h"
#include "securityPolicy.h"
#include "buffer_helpers.h"
#include "sign_tx_aux_data.h"
#include "tx.h"
#include "tx_credential_types.h"
#include "ui_display_cvote_aux_data.h"
#include "utils.h"

// CVote AUX-DATA state machine (handler + UI callback transitions):
// EXPECTING_INIT
//   -> RECEIVING_DELEGATIONS      (non-streaming init with delegations)
//   -> STREAMING_INITIAL_PAGE     (streaming init with delegations)
//   -> ALL_DATA_RECEIVED          (non-streaming init with zero delegations)
// STREAMING_INITIAL_PAGE
//   -> RECEIVING_DELEGATIONS      (after initial page callback)
// RECEIVING_DELEGATIONS
//   -> ALL_DATA_RECEIVED          (after last delegation APDU)
// ALL_DATA_RECEIVED
//   -> NONE                       (after user confirm/reject callback)

// Validate CVote aux data against security policies
// Returns false if any policy denies, true if all policies allow
static bool cvote_aux_data_validate(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");

    // Assert that CVote warnings are initially empty and TX warnings haven't leaked in
    LEDGER_ASSERT(warning_bits_is_empty(&G_context.tx_info.cvote_warning_bits), "Non-empty cvote_warning_bits");

    // 1. Vote key (only checked in CIP15 or CIP36 with no delegations)
    security_policy_t vote_key_policy;
    if (aux_data->remaining_delegations == 0) {
        warning_bits_t vote_key_warnings = 0;
        vote_key_policy = policyForCVoteRegistrationVoteKey(
            &aux_data->vote_credential,
            aux_data->format,
            &vote_key_warnings);
        LEDGER_ASSERT(warning_bits_except_mask(vote_key_warnings, warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0, "Unexpected vote-key warnings");
        // CVote vote-key unusual derivation warning is rendered inline as a dedicated UI pair.
    } else {
        vote_key_policy = POLICY_HIDE;  // Not used with delegations
    }

    switch (vote_key_policy) {
        case POLICY_DENY:
            TRACE("CVote vote key policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.vote_key = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.vote_key = false;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown vote key policy: %u", vote_key_policy);
            return false;
    }

    // 2. Staking key
    security_policy_t staking_key_policy = policyForCVoteRegistrationStakingKey(
        &aux_data->staking_credential.keyPath,
        &G_context.tx_info.cvote_warning_bits);

    switch (staking_key_policy) {
        case POLICY_DENY:
            TRACE("CVote staking key policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.staking_key = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.staking_key = false;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown staking key policy: %u", staking_key_policy);
            return false;
    }

    // 3. Payment destination
    security_policy_t destination_policy = policyForCVoteRegistrationPaymentDestination(
        &aux_data->destination,
        G_context.tx_info.transaction.networkId,
        &G_context.tx_info.cvote_warning_bits);

    switch (destination_policy) {
        case POLICY_DENY:
            TRACE("CVote payment destination policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.payment_destination = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.payment_destination = false;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown destination policy: %u", destination_policy);
            return false;
    }

    // 4. Nonce
    security_policy_t nonce_policy = policyForCVoteRegistrationNonce();

    switch (nonce_policy) {
        case POLICY_DENY:
            TRACE("CVote nonce policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.nonce = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.nonce = false;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown nonce policy: %u", nonce_policy);
            return false;
    }

    // 5. Voting purpose (CIP36 only)
    security_policy_t voting_purpose_policy = policyForCVoteRegistrationVotingPurpose();

    switch (voting_purpose_policy) {
        case POLICY_DENY:
            TRACE("CVote voting purpose policy denied");
            return false;
        case POLICY_SHOW:
            aux_data->ui_show.voting_purpose = true;
            break;
        case POLICY_HIDE:
            aux_data->ui_show.voting_purpose = false;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown voting purpose policy: %u", voting_purpose_policy);
            return false;
    }

    // Aux data hash is no longer displayed in UI (finalized after user confirms)
    // No policy check needed

    return true;
}

static void handler_tx_aux_data_init(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "Bad req_type");
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA, "Bad tx_state");
    cvote_aux_data_t *aux_data = &G_context.tx_info.cvote_aux_data;

    LEDGER_ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_EXPECTING_INIT, "Bad aux state");
    LEDGER_ASSERT(G_context.tx_info.raw_cvote_init_data == NULL, "Stale raw init ptr");
    LEDGER_ASSERT(G_context.tx_info.raw_cvote_init_data_len == 0, "Stale raw init len");

    // Allocate persistent buffer for CVote init data
    const size_t init_payload_len = buffer_remaining(cdata);
    if ((init_payload_len > UINT16_MAX) ||
        !APP_MEM_CALLOC((void **) &G_context.tx_info.raw_cvote_init_data, (uint16_t) init_payload_len)) {
        TRACE("CVote AUX_DATA init: failed to allocate %u byte buffer", (unsigned)init_payload_len);
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    const uint8_t *payload_start = buffer_current_ptr(cdata);
    LEDGER_ASSERT(payload_start != NULL, "NULL cdata ptr in AUX_DATA init");
    memcpy(G_context.tx_info.raw_cvote_init_data, payload_start, init_payload_len);
    G_context.tx_info.raw_cvote_init_data_len = init_payload_len;

    cvote_parser_status_t status = cvote_parse_aux_data_init(aux_data);
    if (status != CVOTE_PARSER_OK) {
        TRACE("CVote AUX_DATA init parse failed: %d", status);
        send_swo_and_reset(status == CVOTE_PARSER_OUT_OF_MEMORY
                           ? SWO_INSUFFICIENT_MEMORY
                           : SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }

    // Validate all security policies
    if (!cvote_aux_data_validate(aux_data)) {
        TRACE("CVote AUX_DATA validation failed");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    cvote_hash_builder_setup(aux_data);

    // Transition state based on delegation count
    if (aux_data->remaining_delegations > 0) {
        aux_data->state = CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS;
    } else {
        aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
    }

    TRACE("CVote AUX_DATA init: format=%u, delegations=%u",
          aux_data->format,
          aux_data->remaining_delegations);

    ui_cvote_aux_data_init_vars(aux_data);

    if (aux_data->ui_streaming.on) {
        LEDGER_ASSERT(aux_data->remaining_delegations > 0, "Streaming without delegations");
        aux_data->state = CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE;
        ui_cvote_aux_data_streaming_show_initial_page(aux_data);
        // waiting for NBGL callback cvote_aux_data_review_streaming_continue, so no APDU sent
        return;
    }

    if (!ui_cvote_aux_data_init_non_streaming(aux_data)) {
        TRACE("CVote AUX_DATA non-streaming UI init failed");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Non-streaming with zero delegations: show final review immediately
    if (aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED) {
        LEDGER_ASSERT(aux_data->remaining_delegations == 0, "Delegations remaining");
        G_context.state.tx_state = TX_STATE_CHUNKS;
        TRACE("CVote AUX_DATA ready for UI confirmation");
        ui_cvote_aux_data_show_non_streaming_final_review(aux_data);
        // waiting for NBGL callback cvote_aux_data_review_choice, so no APDU sent
        return;
    }

    io_send_sw(SWO_SUCCESS);
}

static void handler_tx_aux_data_delegation(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "Bad req_type");
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA, "Bad tx_state");
    cvote_aux_data_t *aux_data = &G_context.tx_info.cvote_aux_data;

    LEDGER_ASSERT(aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS, "Bad aux state");
    LEDGER_ASSERT(aux_data->remaining_delegations > 0, "No delegations remaining");

    TRACE("CVote AUX_DATA delegation received, payload_len=%u",
          cdata->size);
    cvote_credential_t delegation_credential = {0};
    if (!buffer_read_cvote_credential(cdata, &delegation_credential)) {
        TRACE("CVote AUX_DATA delegation: parsing failed");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }

    // Validate delegation credential against security policy BEFORE adding to hash
    // Per CIP-36, delegation vote keys can be device-owned (KEY_PATH) or third-party (KEY)
    // Device-owned paths must be valid CVote key paths (m/1694'/1815'/account'/0/address_index)
    warning_bits_t delegation_warnings = 0;
    security_policy_t delegation_policy =
        policyForCVoteRegistrationVoteKey(&delegation_credential,
                                          aux_data->format,
                                          &delegation_warnings);
    LEDGER_ASSERT(warning_bits_except_mask(delegation_warnings, warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0, "Unexpected delegation warnings");
    // CVote vote-key unusual derivation warning is rendered inline as a dedicated UI pair.
    if (delegation_policy == POLICY_DENY) {
        TRACE("CVote AUX_DATA delegation: vote key policy denied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    uint32_t weight = 0;
    if (!buffer_read_u32(cdata, &weight, BE)) {
        TRACE("CVote AUX_DATA delegation: missing weight");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("CVote AUX_DATA delegation APDU not fully consumed");
        send_swo_and_reset(SWO_CVOTE_AUX_DATA_PARSING_FAIL);
        return;
    }
    LEDGER_ASSERT(!buffer_can_read(cdata, 1), "APDU not fully consumed");

    cvote_hash_builder_add_delegation(aux_data, &delegation_credential, weight);

    LEDGER_ASSERT(aux_data->remaining_delegations > 0, "wrong remaining delegation count");
    aux_data->remaining_delegations--;

    if (aux_data->ui_streaming.on) {
        // Streaming mode
        bool chunk_complete = ui_cvote_aux_data_add_delegation_streaming(aux_data,
                                                                          &delegation_credential,
                                                                          weight);

        // Transition state when all delegations received
        if (aux_data->remaining_delegations == 0) {
            aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
            TRACE("CVote AUX_DATA: all delegations received");
            // Transition back to CHUNKS state - ready to receive transaction data
            G_context.state.tx_state = TX_STATE_CHUNKS;
        }

        if (chunk_complete) {
            // Waiting for NBGL callback cvote_aux_data_review_streaming_continue, so no APDU sent
            return;
        }

        // Chunk not complete, more delegations expected
        io_send_sw(SWO_SUCCESS);
    } else {
        // Non-streaming mode
        ui_cvote_aux_data_add_delegation_non_streaming(aux_data,
                                                        &delegation_credential,
                                                        weight);

        if (aux_data->remaining_delegations == 0) {
            // All delegations received, transition state and show final review
            aux_data->state = CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED;
            TRACE("CVote AUX_DATA ready for UI confirmation");
            // Transition back to CHUNKS state - ready to receive transaction data
            G_context.state.tx_state = TX_STATE_CHUNKS;

            ui_cvote_aux_data_show_non_streaming_final_review(aux_data);
            // waiting for NBGL callback cvote_aux_data_review_choice, so no APDU sent
            return;
        }

        // More delegations expected, send success
        io_send_sw(SWO_SUCCESS);
    }
}

void handler_sign_tx_aux_data(buffer_t *cdata, uint8_t p2) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    TRACE_BUFFER_T(cdata);

    cvote_aux_data_t *aux_data = &G_context.tx_info.cvote_aux_data;

    if (G_context.req_type != REQUEST_SIGN_TRANSACTION) {
        TRACE("AUX_DATA rejected: wrong request type %d", G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    if (G_context.state.tx_state != TX_STATE_AUX_DATA) {
        TRACE("Bad state for AUX_DATA: expected TX_STATE_AUX_DATA, got %d", G_context.state.tx_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    switch (p2) {
        case P2_AUX_DATA_INIT:
            if (aux_data->state != CVOTE_AUX_DATA_STATE_EXPECTING_INIT) {
                TRACE("P2_AUX_DATA_INIT in wrong state: %d", aux_data->state);
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }
            handler_tx_aux_data_init(cdata);
            return;
        case P2_AUX_DATA_DELEGATION:
            if (aux_data->state != CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS) {
                TRACE("P2_AUX_DATA_DELEGATION in wrong state: %d", aux_data->state);
                send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
                return;
            }
            handler_tx_aux_data_delegation(cdata);
            return;
        default:
            TRACE("Unexpected P2 for AUX_DATA APDU");
            send_swo_and_reset(SWO_INCORRECT_P1_P2);
            return;
    }
}

void finalize_sign_tx_aux_data(bool confirmed) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_TRANSACTION, "Bad req_type");
    LEDGER_ASSERT(G_context.tx_info.cvote_aux_data.state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED, "Bad aux state");
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA || G_context.state.tx_state == TX_STATE_CHUNKS, "Bad tx_state");

    if (!confirmed) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    cvote_hash_finalize();

    // CVote init buffer is no longer needed once aux-data hash is finalized.
    APP_MEM_FREE_AND_NULL((void **) &G_context.tx_info.raw_cvote_init_data);
    G_context.tx_info.raw_cvote_init_data_len = 0;

    G_context.tx_info.cvote_aux_data.state = CVOTE_AUX_DATA_STATE_NONE;
    G_context.state.tx_state = TX_STATE_CHUNKS;

    io_send_response_pointer(G_context.tx_info.transaction.auxDataHash,
                             AUX_DATA_HASH_LENGTH,
                             SWO_SUCCESS);
}
