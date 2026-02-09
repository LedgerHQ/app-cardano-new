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
#include "cardano_swo.h"
#include "menu.h"
#include "securityPolicy.h"
#include "ui_utils.h"
#include "ui_cvote.h"
#include "ui_warnings.h"
#include "ui_formatters.h"
#include "app_context.h"
#include "sign_cvote.h"

/**
 * Cleanup dynamically allocated buffers and UI pairs
 */
static void cvote_buffer_cleanup(void) {
    ui_free_pairs();
    ui_free_warnings();
}

static void cvote_review_choice(bool confirm) {
    // CLEANUP
    cvote_buffer_cleanup();

    // FINALIZE
    finalize_sign_cvote(confirm);

    // SHOW STATUS
    // TODO: customize status screen?
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
}

void ui_display_cvote_confirm(security_policy_t securityPolicy) {
    cvote_ctx_t *ctx = &G_context.cvote_info;

    TRACE("=== ui_display_cvote_confirm START ===");

    // Check state
    LEDGER_ASSERT(G_context.req_type == REQUEST_CVOTE,
                  "ui_display_cvote_confirm called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STAGE_CONFIRM,
                  "ui_display_cvote_confirm called in wrong state: %d",
                  G_context.state.cvote_state);

    // Check policy
    TRACE("securityPolicy: %d", securityPolicy);
    LEDGER_ASSERT(securityPolicy == POLICY_SHOW,
                  "ui_display_cvote_confirm called with wrong security policy: %d",
                  securityPolicy);

    // Build warnings - only use SDK's blind signing warning
    // TODO it says "drain your wallet" --- but maybe this does not apply to votecast signing?...
    ui_status_t warning_status = ui_build_predefined_warning(1u << BLIND_SIGNING_WARN);
    if (warning_status != UI_STATUS_SUCCESS) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Format all fields and check for errors
    if (!ui_pairs_init(4)) {
        TRACE("Failed to initialize pairs");
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
    }

    UI_ADD_FORMAT1(UI_STATIC_LABEL("Witness"),
                   MAX_BIP44_PATH_STRING_LENGTH,
                   format_bip44_path,
                   &ctx->witness_path);
    UI_ADD_FORMAT2(UI_STATIC_LABEL("Vote plan id"),
                   2 * VOTE_PLAN_ID_SIZE + 1,
                   format_hex_bytes,
                   ctx->vote_plan_id,
                   SIZEOF(ctx->vote_plan_id));
    UI_ADD_FORMAT2(UI_STATIC_LABEL("Proposal index"),
                   MAX_UINT64_STRING_LENGTH,
                   format_decimal_amount,
                   ctx->proposal_index,
                   0);
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Payload type tag", "Payload tag"),
                   MAX_UINT64_STRING_LENGTH,
                   format_decimal_amount,
                   ctx->payload_type_tag,
                   0);

    TRACE("Calling nbgl_useCaseAdvancedReview(TYPE_OPERATION)");
    nbgl_useCaseAdvancedReview(TYPE_OPERATION,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               "Confirm CIP-36 vote?",
                               NULL,
                               "Sign vote",
                               NULL,
                               ui_get_warnings(),
                               cvote_review_choice);
}
