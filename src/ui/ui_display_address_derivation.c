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

#include "nbgl_use_case.h"
#include "io.h"

#include "ui_icons.h"
#include "cardano_constants.h"
#include "globals.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "menu.h"
#include "securityPolicy.h"
#include "ui_utils.h"
#include "ui_display_address_derivation.h"
#include "tx_ui_helpers.h"
/**
 * Cleanup dynamically allocated buffers
 */
static void derive_address_buffer_cleanup(void) {
    ui_free_pairs();
}

// Called when long press button is touched or when reject footer is touched
static void derive_address_return_review_choice(bool confirm) {
    TRACE("confirmed = %d", confirm);
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "derive_address_return_review_choice called without REQUEST_DERIVE_ADDRESS");
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "derive_address_return_review_choice called in wrong state: %d",
                  G_context.state.derive_address_state);

    // CLEANUP
    derive_address_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_APPROVED;
        derive_address_ctx_t *ctx = &G_context.derive_address_info;
        LEDGER_ASSERT(ctx->address.length <= sizeof(ctx->address.buffer), "Address length too large");
        io_send_response_pointer(ctx->address.buffer, ctx->address.length, SWO_SUCCESS);
        reset_app_context();
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

// Called when long press button is touched or when reject footer is touched
static void derive_address_display_review_choice(bool confirm) {
    TRACE("confirmed = %d", confirm);
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "derive_address_display_review_choice called without REQUEST_DERIVE_ADDRESS");
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "derive_address_display_review_choice called in wrong state: %d",
                  G_context.state.derive_address_state);

    // CLEANUP
    derive_address_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_APPROVED;
        io_send_response_pointer(NULL, 0, SWO_SUCCESS);
        reset_app_context();
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

// Address derivation UI pair counts
#define DERIVE_ADDRESS_PAIRS_REWARD_ONLY        1  // Staking info only
#define DERIVE_ADDRESS_PAIRS_PAYMENT_AND_STAKE  2  // Payment + Staking info
#define DERIVE_ADDRESS_PAIRS_WARNING            1  // Warning banner

static ui_status_t format_address_fields(const address_params_t *params, warning_bits_t warnings) {
    ui_reset_error_status();
    const bool hasWarning = (warnings != 0);

    switch (params->type) {
        // Reward addresses: staking info only
        case REWARD_KEY:
        case REWARD_SCRIPT: {
            const int expectedPairs = DERIVE_ADDRESS_PAIRS_REWARD_ONLY +
                                     (hasWarning ? DERIVE_ADDRESS_PAIRS_WARNING : 0);

            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                return UI_STATUS_OUT_OF_MEMORY;
            }

            START_COUNT();

            if (hasWarning) {
                TRACE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request, proceed with care"));
            }

            addStakingInfoUIPairs(params);
            CHECK_COUNT(expectedPairs);
            break;
        }

        // Base addresses: payment + staking info
        case BASE_PAYMENT_KEY_STAKE_KEY:
        case BASE_PAYMENT_KEY_STAKE_SCRIPT:
        case BASE_PAYMENT_SCRIPT_STAKE_KEY:
        case BASE_PAYMENT_SCRIPT_STAKE_SCRIPT:
        // Enterprise addresses: payment info + no staking
        case ENTERPRISE_KEY:
        case ENTERPRISE_SCRIPT:
        // Pointer addresses: payment info + blockchain pointer
        case POINTER_KEY:
        case POINTER_SCRIPT:
        // Byron addresses: payment info + legacy (no staking)
        case BYRON: {
            const int expectedPairs = DERIVE_ADDRESS_PAIRS_PAYMENT_AND_STAKE +
                                     (hasWarning ? DERIVE_ADDRESS_PAIRS_WARNING : 0);

            if (!ui_pairs_init(expectedPairs)) {
                TRACE("Failed to initialize pairs");
                return UI_STATUS_OUT_OF_MEMORY;
            }

            START_COUNT();

            if (hasWarning) {
                TRACE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request, proceed with care"));
            }

            addPaymentInfoUIPairs(params);
            addStakingInfoUIPairs(params);
            CHECK_COUNT(expectedPairs);
            break;
        }

        default:
            LEDGER_ASSERT(false, "Unsupported address type: %d", params->type);
            return UI_STATUS_OUT_OF_MEMORY;
    }
    return ui_get_error_status();
}

static void ui_displayAddressReview(const char *title,
                                    const char *subtitle,
                                    nbgl_choiceCallback_t callback,
                                    warning_bits_t warnings) {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ui_status_t status = format_address_fields(&ctx->address_params, warnings);

    switch (status) {
        case UI_STATUS_SUCCESS:
            break;
        case UI_STATUS_OUT_OF_MEMORY:
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return;
        case UI_STATUS_UNINITIALIZED:
        default:
            LEDGER_ASSERT(false, "Unexpected UI status: %d", status);
            return;
    }

    LEDGER_ASSERT(ctx->address.length <= MAX_HUMAN_ADDRESS_LENGTH, "Address length too large");

    static char humanAddress[MAX_HUMAN_ADDRESS_LENGTH] = {0};
    format_address_human_readable(ctx->address.buffer,
                                  ctx->address.length,
                                  humanAddress,
                                  SIZEOF(humanAddress));
    // TODO: unusual-path warning presentation changed: old app showed a dedicated warning screen
    nbgl_useCaseAddressReview(humanAddress,
                              g_pairsList,
                              &ICON_APP_CARDANO,
                              title,
                              subtitle,
                              callback);
}

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
    // Validate state before proceeding (address must be prepared before UI display)
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "ui_deriveAddress_handleReturn called with wrong request type: %d", G_context.req_type);
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "ui_deriveAddress_handleReturn called in wrong state: %d", G_context.state.derive_address_state);

    switch (policy) {
        case POLICY_SHOW:
            ui_displayAddressReview("Export address",
                                    NULL,
                                    derive_address_return_review_choice,
                                    warnings);
            break;
        case POLICY_HIDE: {
            // Silently approve and return address without UI
            derive_address_ctx_t *ctx = &G_context.derive_address_info;
            LEDGER_ASSERT(ctx->address.length <= sizeof(ctx->address.buffer), "Address length too large");
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_APPROVED;
            io_send_response_pointer(ctx->address.buffer, ctx->address.length, SWO_SUCCESS);
            reset_app_context();
            break;
        }
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleReturn: %d", policy);
            break;
    }
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    // Validate state before proceeding (address must be prepared before UI display)
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "ui_deriveAddress_handleDisplay called with wrong request type: %d", G_context.req_type);
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED,
                  "ui_deriveAddress_handleDisplay called in wrong state: %d", G_context.state.derive_address_state);

    switch (policy) {
        case POLICY_SHOW:
            ui_displayAddressReview("Display address",
                                    "(not exported)",
                                    derive_address_display_review_choice,
                                    warnings);
            break;
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleDisplay: %d", policy);
            break;
    }
}
