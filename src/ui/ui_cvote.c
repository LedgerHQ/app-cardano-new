/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

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

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace UI flow details.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_cvote] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void)0  // Compiled out
#endif

/**
 * Cleanup dynamically allocated buffers and UI pairs
 */
static void cvote_buffer_cleanup(void) {
    ui_all_cleanup();
}

static void cvote_review_choice(bool confirm) {
    // CLEANUP
    cvote_buffer_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE_MODULE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE_MODULE("User confirmed");
    nbgl_useCaseSpinner("Processing");
    finalize_sign_cvote();

    // SHOW STATUS
    nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
}

void ui_display_cvote_confirm(security_policy_t securityPolicy, warning_bits_t warnings) {
    cvote_ctx_t *ctx = &G_context.cvote_info;

    TRACE_MODULE("=== ui_display_cvote_confirm START ===");

    // Check state
    LEDGER_ASSERT(G_context.req_type == REQUEST_CVOTE, "ui_display_cvote_confirm called with wrong request type: %d", G_context.req_type);
    LEDGER_ASSERT(G_context.state.cvote_state == VOTECAST_STATE_CONFIRM, "ui_display_cvote_confirm called in wrong state: %d", G_context.state.cvote_state);

    // Check policy
    TRACE_MODULE("securityPolicy: %d", securityPolicy);
    LEDGER_ASSERT(securityPolicy == POLICY_SHOW, "ui_display_cvote_confirm called with wrong security policy: %d", securityPolicy);

    ui_status_t warning_status = ui_build_warnings(warnings);
    if (warning_status != UI_STATUS_SUCCESS) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Format all fields and check for errors
    ui_render_session_t session = {0};
    ui_render_scope_begin(&session);
    if (!ui_pairs_init(4)) {
        TRACE_MODULE("Failed to initialize pairs");
        ui_render_scope_end();
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
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
    ui_status_t render_status = ui_render_scope_end();
    LEDGER_ASSERT(render_status == UI_STATUS_SUCCESS,
                  "Unexpected UI status: %d",
                  render_status);

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
