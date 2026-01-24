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

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "addressUtils/bip44.h"
#include "format.h"

#include "ui/ui_icons.h"
#include "cardano_constants.h"
#include "globals.h"
#include "utils/utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "opcert_types.h"
#include "menu.h"
#include "securityPolicy.h"
#include "memory/mem_utils.h"
#include "ui_utils.h"
#include "handler/derive_address.h"
#include "ui_display_address_derivation.h"
#include "tx_ui_helpers.h"
/**
 * Cleanup dynamically allocated buffers
 */
static void derive_address_buffer_cleanup(void) {
    // Cleanup all tracked allocations (all string buffers and warning structure)
    ui_cleanup_tracked_allocations();
    // Cleanup the pairs array
    ui_pairs_cleanup();
}

// Review choice handler for display address derivation

void finalize_display_address_derivation(bool confirmed) {
    TRACE("confirmed = %d", confirmed);
    if (confirmed) {
        io_send_response_pointer(NULL, 0, SWO_SUCCESS);
        reset_app_context();
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }
}

static void derive_address_display_review_choice(bool confirm) {
    // CLEANUP
    derive_address_buffer_cleanup();

    // FINALIZE
    finalize_display_address_derivation(confirm);

    // SHOW STATUS
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

// Review choice handler for return address derivation
static void respond_with_address_success(derive_address_ctx_t *ctx) {
    ctx->responseReadyMagic = 0;
    LEDGER_ASSERT(ctx->address.size <= sizeof(ctx->address.buffer), "Address size too large");
    io_send_response_pointer(ctx->address.buffer, ctx->address.size, SWO_SUCCESS);
}

void finalize_return_address_derivation(bool confirmed) {
    TRACE("confirmed = %d", confirmed);
    if (confirmed) {
        derive_address_ctx_t *ctx = &G_context.derive_address_info;
        respond_with_address_success(ctx);
        reset_app_context();
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }
}

static void derive_address_return_review_choice(bool confirm) {
    // CLEANUP
    derive_address_buffer_cleanup();

    // FINALIZE
    finalize_return_address_derivation(confirm);

    // SHOW STATUS
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);

    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);");
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

static ui_status_t format_address_fields(const addressParams_t *params, warning_bits_t warnings) {
    ui_reset_error_status();
    const bool hasWarning = (warnings != 0);
    switch (params->type) {
        case REWARD_SCRIPT:
        case REWARD_KEY: {
            // Initialize UI pairs count
            int pairCount = 1;
            // Add extra pair for warning if needed
            if (hasWarning) {
                pairCount += 1;
            }
            // Initialize pairs
            if (!ui_pairs_init(pairCount)) {
                TRACE("Failed to initialize pairs");
                return UI_STATUS_OUT_OF_MEMORY;
            }
            // Add warning banner first, if needed
            if (hasWarning) {
                TRACE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request\nProceed with care"));
            }
            // Add staking info only
            addStakingInfoUIPairs(params);
            break;
        }
        default: {
            // Initialize UI pairs count
            int pairCount = 2;
            // Add extra pair for warning if needed
            if (hasWarning) {
                pairCount += 1;
            }
            // Initialize pairs
            if (!ui_pairs_init(pairCount)) {
                TRACE("Failed to initialize pairs");
                return UI_STATUS_OUT_OF_MEMORY;
            }
            // Add warning banner first, if needed
            if (hasWarning) {
                TRACE("Adding warning banner");
                UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"),
                              UI_STATIC_LABEL("Unusual request\nProceed with care"));
            }
            // Add payment and staking info
            addPaymentInfoUIPairs(params);
            addStakingInfoUIPairs(params);
            break;
        }
    }
    return ui_get_error_status();
}

static void ui_displayExportAddress(warning_bits_t warnings) {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ui_status_t status = format_address_fields(&ctx->addressParams, warnings);
    if (status == UI_STATUS_OUT_OF_MEMORY) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    LEDGER_ASSERT(status == UI_STATUS_SUCCESS, "Failed to prepare address UI pairs");
    LEDGER_ASSERT(ctx->address.size <= MAX_HUMAN_ADDRESS_LENGTH, "Address size too large");
    
    static char humanAddress[MAX_HUMAN_ADDRESS_LENGTH] = {0};
    format_address_human_readable(ctx->address.buffer,
                                  ctx->address.size,
                                  humanAddress,
                                  SIZEOF(humanAddress));
    // TODO: unusual-path warning presentation changed: old app showed a dedicated warning screen
    nbgl_useCaseAddressReview(humanAddress,
                              g_pairsList,
                              &ICON_APP_CARDANO,
                              "Verify Cardano address",
                              NULL,
                              derive_address_display_review_choice);
    return;
}

static void ui_returnExportAddress(warning_bits_t warnings) {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ui_status_t status = format_address_fields(&ctx->addressParams, warnings);
    if (status == UI_STATUS_OUT_OF_MEMORY) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    LEDGER_ASSERT(status == UI_STATUS_SUCCESS, "Failed to prepare address UI pairs");
    // TODO: unusual-path warning presentation changed: old app showed a dedicated warning screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            g_pairsList,
                            &ICON_APP_CARDANO,
                            "Export address",
                            NULL,
                            "Confirm\n address export",
                            derive_address_return_review_choice);
    return;
}

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    switch (policy) {
        case POLICY_SHOW:
            ui_returnExportAddress(warnings);
            break;
        case POLICY_HIDE:
            respond_with_address_success(ctx);
            break;
        default:
            // TODO: check if status is appropiate
            send_swo_and_reset(SWO_BAD_STATE);
            break;
    }
    return;
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    switch (policy) {
        case POLICY_SHOW:
            ui_displayExportAddress(warnings);
            break;
        default:
            // TODO: check if status is appropiate
            send_swo_and_reset(SWO_BAD_STATE);
            break;
    }
    return;
}