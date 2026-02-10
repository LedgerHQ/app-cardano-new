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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "addressUtilsShelley.h"
#include "app_context.h"
#include "bech32.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "format.h"
#include "globals.h"
#include "io.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "securityPolicy.h"
#include "tx_output_types.h"
#include "tx_utils.h"
#include "ui_constants.h"
#include "ui_display_cvote_aux_data.h"
#include "ui_formatters.h"
#include "ui_icons.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "utils.h"

// Each delegation uses 3 UI pairs (index, key, weight), plus one optional warning pair.
#define CVOTE_DELEGATION_UI_PAIRS 3
#define CVOTE_DELEGATION_WARNING_UI_PAIRS 1
#define CVOTE_DELEGATION_UI_PAIRS_MAX (CVOTE_DELEGATION_UI_PAIRS + CVOTE_DELEGATION_WARNING_UI_PAIRS)
#define CVOTE_REGISTRATIONS_UI_PAIRS 1
#define CVOTE_VOTE_KEY_UI_PAIRS 1
#define CVOTE_STAKING_KEY_UI_PAIRS 1
#define CVOTE_PAYMENT_DESTINATION_UI_PAIRS 1
#define CVOTE_NONCE_UI_PAIRS 1
#define CVOTE_VOTING_PURPOSE_UI_PAIRS 1
#define CVOTE_AUX_DATA_HASH_UI_PAIRS 1

static const char cvote_review_title[] = "Review vote delegation";

static void cvote_aux_data_review_streaming_continue(bool confirm);

// Helper to check if this is the last streaming page
static inline bool cvote_is_last_chunk(const cvote_aux_data_t *aux_data) {
    uint16_t remaining = aux_data->ui_delegations_total - aux_data->ui_delegations_shown;
    return (remaining == 0);
}

static void cvote_add_vote_key_path_warning_pair(void) {
    UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                  UI_STATIC_LABEL("UNUSUAL key derivation path"));
}

static void cvote_aux_data_review_cleanup(void) {
    ui_free_pairs();
    ui_free_warnings();
}

static bool cvote_start_streaming_review(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");
    LEDGER_ASSERT(aux_data != NULL && !aux_data->ui_streaming.review_started,
                  "Streaming review already started");

    LEDGER_ASSERT(warning_bits_except_mask(G_context.tx_info.cvote_warning_bits,
                                           CVOTE_WARNING_BITS_MASK) == 0,
                  "Transaction warnings leaked into CVote warning bits - cvote_warning_bits should only contain CVote-specific warnings");

    // Build warnings known at start of streaming flow.
    // Warnings for specific delegations are added via cvote_add_vote_key_path_warning_pair.
    ui_status_t warning_status = ui_build_warnings(G_context.tx_info.cvote_warning_bits);
    if (warning_status != UI_STATUS_SUCCESS) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return false;
    }

    const nbgl_warning_t *warning_ptr = ui_get_warnings();
    nbgl_useCaseAdvancedReviewStreamingStart(TYPE_OPERATION,
                                             &ICON_APP_CARDANO,
                                             cvote_review_title,
                                             NULL,
                                             warning_ptr,
                                             cvote_aux_data_review_streaming_continue);
    aux_data->ui_streaming.review_started = true;

    return true;
}

static void cvote_aux_data_send_hash_response(void) {
    LEDGER_ASSERT(G_context.tx_info.cvote_aux_data.state == CVOTE_AUX_DATA_STATE_APPROVED,
                  "Sending hash in wrong state: %d",
                  G_context.tx_info.cvote_aux_data.state);

    // Deallocate raw CVote init buffer (credentials will become invalid after this)
    // Buffer is managed by mem.c allocator, deallocation happens on reset_app_context
    if (G_context.tx_info.raw_cvote_init_data != NULL) {
        G_context.tx_info.raw_cvote_init_data = NULL;
        G_context.tx_info.raw_cvote_init_data_len = 0;
    }

    G_context.tx_info.cvote_aux_data.state = CVOTE_AUX_DATA_STATE_NONE;
    G_context.state.tx_state = TX_STATE_CHUNKS;

    io_send_response_pointer(G_context.tx_info.transaction.auxDataHash,
                             AUX_DATA_HASH_LENGTH,
                             SWO_SUCCESS);
}

static void cvote_aux_data_review_choice(bool confirm) {
    // CLEANUP
    cvote_aux_data_review_cleanup();

    // FINALIZE
    if (!confirm) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    // Show spinner while finalizing hash
    nbgl_useCaseSpinner("Processing");

    // Finalize hash after user confirmation
    cvote_hash_finalize();
    G_context.tx_info.cvote_aux_data.state = CVOTE_AUX_DATA_STATE_APPROVED;
    cvote_aux_data_send_hash_response();
}

static void cvote_aux_data_review_streaming_continue(bool confirm) {
    cvote_aux_data_t *aux_data = &G_context.tx_info.cvote_aux_data;

    ui_free_pairs();

    if (!confirm) {
        ui_free_warnings();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    if (cvote_is_last_chunk(aux_data)) {
        nbgl_useCaseReviewStreamingFinish("Confirm vote delegation",
                                          cvote_aux_data_review_choice);
        return;
    }

    if (aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE) {
        aux_data->state = CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS;
    }

    io_send_sw(SWO_SUCCESS);
}

static bool format_cvote_delegation_index(uint16_t delegation_index,
                                          char *out,
                                          size_t out_size) {
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    int written = snprintf(out, out_size, "#%u", delegation_index);
    return (written > 0) && ((size_t) written < out_size);
}

static bool format_cvote_reward_address(const tx_output_destination_t *destination,
                                        uint8_t network_id,
                                        char *out,
                                        size_t out_size) {
    (void) network_id;

    return format_tx_output_destination_human_readable(destination, out, out_size);
}

static void cvote_add_vote_key_pair(const char *label,
                                    const cvote_credential_t *credential,
                                    warning_bits_t vote_key_warnings) {
    LEDGER_ASSERT(label != NULL, "NULL label");
    LEDGER_ASSERT(credential != NULL, "NULL vote credential");
    LEDGER_ASSERT(warning_bits_except_mask(vote_key_warnings,
                                           warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected vote-key warning bits");

    switch (credential->type) {
        case CVOTE_CREDENTIAL_KEY_PATH:
            if (warning_bits_has(vote_key_warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) {
                cvote_add_vote_key_path_warning_pair();
            }
            UI_ADD_FORMAT1(label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case CVOTE_CREDENTIAL_KEY:
            UI_ADD_FORMAT3(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "cvote_vk",
                           credential->publicKey,
                           PUBLIC_KEY_LENGTH);
            break;
        default:
            LEDGER_ASSERT(false, "Unexpected vote credential type");
            break;
    }
}

static uint16_t cvote_initial_pairs_count(const cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");

    uint16_t pair_count = CVOTE_REGISTRATIONS_UI_PAIRS;

    if (aux_data->ui_show.vote_key) {
        warning_bits_t vote_key_warnings = 0;
        security_policy_t vote_key_policy = policyForCVoteRegistrationVoteKey(
            &aux_data->vote_credential,
            aux_data->format,
            &vote_key_warnings);
        LEDGER_ASSERT(warning_bits_except_mask(vote_key_warnings,
                                               warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                      "Unexpected vote-key warning bits");
        LEDGER_ASSERT(vote_key_policy == POLICY_SHOW, "Vote key policy changed before UI");

        pair_count += warning_bits_has(vote_key_warnings, WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                        ? CVOTE_DELEGATION_WARNING_UI_PAIRS
                        : 0;
        pair_count += CVOTE_VOTE_KEY_UI_PAIRS;
    }
    if (aux_data->ui_show.staking_key) {
        pair_count += CVOTE_STAKING_KEY_UI_PAIRS;
    }
    if (aux_data->ui_show.payment_destination) {
        pair_count += CVOTE_PAYMENT_DESTINATION_UI_PAIRS;
    }
    if (aux_data->ui_show.nonce) {
        pair_count += CVOTE_NONCE_UI_PAIRS;
    }
    if (aux_data->ui_show.voting_purpose && aux_data->format == CIP36) {
        pair_count += CVOTE_VOTING_PURPOSE_UI_PAIRS;
    }

    return pair_count;
}

static bool cvote_add_initial_pairs(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");

    START_COUNT();
    if (aux_data->ui_show.vote_key) {
        warning_bits_t vote_key_warnings = 0;
        security_policy_t vote_key_policy = policyForCVoteRegistrationVoteKey(
            &aux_data->vote_credential,
            aux_data->format,
            &vote_key_warnings);
        LEDGER_ASSERT(warning_bits_except_mask(vote_key_warnings,
                                               warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                      "Unexpected vote-key warning bits");
        LEDGER_ASSERT(vote_key_policy == POLICY_SHOW, "Vote key policy changed before UI");
        cvote_add_vote_key_pair(UI_STATIC_LABEL("Vote key"), &aux_data->vote_credential, vote_key_warnings);
    }

    if (aux_data->ui_show.staking_key) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Staking key"),
                       MAX_BIP44_PATH_STRING_LENGTH,
                       format_bip44_path,
                       &aux_data->staking_credential.keyPath);
    }

    if (aux_data->ui_show.payment_destination) {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Rewards go to"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_cvote_reward_address,
                       &aux_data->destination,
                       G_context.tx_info.transaction.networkId);
    }

    if (aux_data->ui_show.nonce) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Nonce"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       aux_data->nonce);
    }

    if (aux_data->ui_show.voting_purpose && aux_data->format == CIP36) {
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Voting purpose"),
                       MAX_UINT64_STRING_LENGTH,
                       format_uint64,
                       aux_data->voting_purpose);
    }

    UI_ADD_FORMAT1(UI_STATIC_LABEL("Delegations"),
                   MAX_UINT16_STRING_LENGTH,
                   format_uint16,
                   aux_data->ui_delegations_total);

    CHECK_COUNT(cvote_initial_pairs_count(aux_data));
    return (ui_get_error_status() == UI_STATUS_SUCCESS);
}

static bool cvote_add_delegation_pairs(cvote_aux_data_t *aux_data,
                                       const cvote_credential_t *credential,
                                       uint32_t weight) {
    LEDGER_ASSERT(credential != NULL, "NULL delegation credential");

    START_COUNT();
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->ui_delegations_shown < aux_data->ui_delegations_total,
                  "Delegation count exceeded");
    aux_data->ui_delegations_shown++;
    uint16_t delegation_index = aux_data->ui_delegations_shown;

    // Validate delegation policy (per-delegation check for streaming UI)
    warning_bits_t vote_key_warnings = 0;
    security_policy_t delegation_policy = policyForCVoteRegistrationVoteKey(
        credential,
        aux_data->format,
        &vote_key_warnings);
    LEDGER_ASSERT(warning_bits_except_mask(vote_key_warnings,
                                           warning_bits_mask_for(WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)) == 0,
                  "Unexpected vote-key warning bits");

    switch (delegation_policy) {
        case POLICY_DENY:
            TRACE("CVote delegation policy denied");
            send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
            return false;
        case POLICY_SHOW:
            // Add UI pairs for this delegation
            uint16_t expected_pairs = CVOTE_DELEGATION_UI_PAIRS +
                                      (warning_bits_has(vote_key_warnings,
                                                        WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH)
                                           ? CVOTE_DELEGATION_WARNING_UI_PAIRS
                                           : 0);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Delegation"),
                           MAX_DELEGATION_INDEX_STRING_LENGTH,
                           format_cvote_delegation_index,
                           delegation_index);
            cvote_add_vote_key_pair(UI_STATIC_LABEL("Key"), credential, vote_key_warnings);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Weight"),
                           MAX_UINT64_STRING_LENGTH,
                           format_uint64,
                           weight);
            CHECK_COUNT(expected_pairs);
            break;
        case POLICY_HIDE:
            // No UI pairs added, but delegation is allowed
            break;
        default:
            LEDGER_ASSERT(false, "Unknown delegation policy");
    }

    return (ui_get_error_status() == UI_STATUS_SUCCESS);
}

static bool cvote_init_pairs_for_streaming_page(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS,
                  "Streaming delegation page in wrong state: %d",
                  aux_data->state);

    uint16_t pair_count = CVOTE_DELEGATION_UI_PAIRS_MAX;

    TRACE("CVote streaming page: shown=%u/%u, total_pairs=%u, max_pairs=%u, is_last=%d",
          aux_data->ui_delegations_shown,
          aux_data->ui_delegations_total,
          pair_count,
          MAX_UI_PAIRS,
          cvote_is_last_chunk(aux_data));

    ui_reset_error_status();
    if (!ui_pairs_init(pair_count)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return false;
    }

    return true;
}

bool ui_cvote_aux_data_init_non_streaming(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL && !aux_data->ui_streaming.on,
                  "Called with streaming enabled");

    uint16_t total_pair_count = cvote_initial_pairs_count(aux_data) +
                                (aux_data->remaining_delegations * CVOTE_DELEGATION_UI_PAIRS_MAX);

    ui_reset_error_status();
    if (!ui_pairs_init(total_pair_count)) {
        TRACE("CVote UI: failed to initialize pairs");
        return false;
    }

    if (!cvote_add_initial_pairs(aux_data)) {
        TRACE("CVote UI: failed to add initial pairs");
        return false;
    }

    return true;
}

void ui_cvote_aux_data_init_vars(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL &&
                      (aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED ||
                       aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS ||
                       aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE),
                  "ui_cvote_aux_data_init_vars called in wrong state: %d",
                  aux_data->state);

    // Initialize UI delegation tracking
    aux_data->ui_delegations_total = aux_data->remaining_delegations;
    aux_data->ui_delegations_shown = 0;

    // Initialize streaming state (all fields zeroed)
    explicit_bzero(&aux_data->ui_streaming, sizeof(aux_data->ui_streaming));

    // Determine if streaming is forced: too many UI pairs
    uint16_t total_pair_count = cvote_initial_pairs_count(aux_data) +
                                (aux_data->remaining_delegations * CVOTE_DELEGATION_UI_PAIRS_MAX);
    aux_data->ui_streaming.on = (total_pair_count > MAX_UI_PAIRS);
}

void ui_cvote_aux_data_streaming_show_initial_page(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL && aux_data->ui_streaming.on,
                  "Called with streaming disabled");
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->state == CVOTE_AUX_DATA_STATE_STREAMING_INITIAL_PAGE,
                  "Streaming initial page in wrong state: %d",
                  aux_data->state);

    uint16_t initial_pairs = cvote_initial_pairs_count(aux_data);
    LEDGER_ASSERT(initial_pairs > 0, "No initial pairs for streaming page");

    TRACE("CVote streaming initial page: initial_pairs=%u, max_pairs=%u",
          initial_pairs,
          MAX_UI_PAIRS);

    ui_reset_error_status();
    if (!ui_pairs_init(initial_pairs)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    if (!cvote_add_initial_pairs(aux_data)) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    LEDGER_ASSERT(!aux_data->ui_streaming.review_started,
                  "Streaming review should start exactly once from initial page");
    if (!cvote_start_streaming_review(aux_data)) {
        return;
    }
    nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                        cvote_aux_data_review_streaming_continue);
}

void ui_cvote_aux_data_add_delegation_non_streaming(cvote_aux_data_t *aux_data,
                                                     const cvote_credential_t *credential,
                                                     uint32_t weight) {
    LEDGER_ASSERT(aux_data != NULL, "NULL aux data");
    LEDGER_ASSERT(credential != NULL, "NULL credential");
    LEDGER_ASSERT(aux_data != NULL && !aux_data->ui_streaming.on,
                  "Called with streaming enabled");
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS,
                  "ui_cvote_aux_data_add_delegation_non_streaming called in wrong state: %d",
                  aux_data->state);

    if (!cvote_add_delegation_pairs(aux_data, credential, weight)) {
        // Policy DENY sends error inside cvote_add_delegation_pairs
        // If we get here and it failed, it's a memory issue
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
    }
}

bool ui_cvote_aux_data_add_delegation_streaming(cvote_aux_data_t *aux_data,
                                                  const cvote_credential_t *credential,
                                                  uint32_t weight) {
    LEDGER_ASSERT(credential != NULL, "NULL credential");
    LEDGER_ASSERT(aux_data != NULL && aux_data->ui_streaming.on,
                  "Called with streaming disabled");
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->state == CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS,
                  "ui_cvote_aux_data_add_delegation_streaming called in wrong state: %d",
                  aux_data->state);
    LEDGER_ASSERT(aux_data->ui_streaming.review_started,
                  "Streaming review must be started before delegation pages");

    // Initialize pairs for this delegation page
    if (!cvote_init_pairs_for_streaming_page(aux_data)) {
        return true; // Error already sent
    }

    if (!cvote_add_delegation_pairs(aux_data, credential, weight)) {
        // Policy DENY sends error inside cvote_add_delegation_pairs
        // If we get here and it failed, it's a memory issue
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return true;
    }

    // Display this delegation immediately.
    nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                        cvote_aux_data_review_streaming_continue);

    return true; // Chunk displayed, waiting for callback
}

void ui_cvote_aux_data_show_non_streaming_final_review(cvote_aux_data_t *aux_data) {
    LEDGER_ASSERT(aux_data != NULL &&
                      aux_data->state == CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED,
                  "ui_cvote_aux_data_show_non_streaming_final_review called in wrong state: %d",
                  aux_data->state);
    LEDGER_ASSERT(aux_data != NULL && !aux_data->ui_streaming.on,
                  "ui_cvote_aux_data_show_non_streaming_final_review called with streaming on");

    LEDGER_ASSERT(warning_bits_is_empty(&G_context.tx_info.warning_bits),
                  "Transaction warning_bits should be empty during CVote review - TX processing should not set warnings yet");

    LEDGER_ASSERT(warning_bits_except_mask(G_context.tx_info.cvote_warning_bits,
                                           CVOTE_WARNING_BITS_MASK) == 0,
                  "Transaction warnings leaked into CVote warning bits - cvote_warning_bits should only contain CVote-specific warnings");

    // Build CVote-specific warnings for display
    ui_status_t warning_status = ui_build_warnings(G_context.tx_info.cvote_warning_bits);
    if (warning_status != UI_STATUS_SUCCESS) {
        cvote_aux_data_review_cleanup();
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    const nbgl_warning_t *warningPtr = ui_get_warnings();
    nbgl_useCaseAdvancedReview(TYPE_OPERATION,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               cvote_review_title,
                               NULL,
                               "Confirm vote delegation",
                               NULL,
                               warningPtr,
                               cvote_aux_data_review_choice);
}
