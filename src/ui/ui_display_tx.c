/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "utils.h"

#include "ui_icons.h"
#include "globals.h"
#include "cardano_swo.h"
#include "menu.h"
#include "app_context.h"
#include "sign_tx_ctx.h"
#include "tx_processing.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "ui_display_tx.h"
#include "sign_tx.h"

void tx_review_cleanup(void) {
    ui_all_cleanup();
}

static void tx_review_choice(bool confirm) {

    // CLEANUP
    tx_review_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    TRACE("User confirmed");
    const bool has_witnesses = (G_context.tx_info.num_witnesses > 0);
    if (has_witnesses) {
        // we will wait for a witness APDU
        // the spinner is not needed for finalize_sign_tx on its own, it is fast
        nbgl_useCaseSpinner("Processing");
    }
    finalize_sign_tx();

    // SHOW STATUS
    if (!has_witnesses) {
        // we are totally finished
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    }
}

// Forward declaration for streaming callbacks
static void tx_streaming_continue_choice(bool confirm);

static void tx_streaming_start_choice(bool confirm) {
    if (!confirm) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }
    // Serve the already-rendered first chunk.
    nbgl_useCaseReviewStreamingContinue(g_pairsList, tx_streaming_continue_choice);
}

static void tx_streaming_continue_choice(bool confirm) {
    if (!confirm) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
        return;
    }

    // Free the pairs rendered for the previous chunk.
    ui_free_pairs();

    uint16_t next_from = tx_body_ctx()->rendered_ui_pairs;
    uint16_t total     = tx_body_ctx()->total_ui_pairs;

    if (next_from >= total) {
        // All chunks done — finish screen.
        nbgl_useCaseReviewStreamingFinish("Sign transaction", tx_review_choice);
        return;
    }

    // Render the next chunk.
    ui_reset_error_status();
    if (!ui_pairs_init(MAX_UI_PAIRS)) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    if (!tx_render_ui_chunk(next_from)) {
        tx_review_cleanup();
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    // Update cursor for the next chunk.
    uint16_t rendered_count = ui_pairs_get_count();
    if (rendered_count == 0) {
        // If nothing rendered, the single pair exceeds memory. This should
        // never happen in practice because individual UI strings are bounded and small, but without
        // this guard the cursor would not advance and the app would loop forever on this chunk.
        tx_review_cleanup();
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }
    tx_body_ctx()->rendered_ui_pairs = next_from + rendered_count;

    // If the chunk hit the pairs limit, reset CHUNK_FULL — it is the expected boundary signal.
    // If status is SUCCESS the remaining pairs fit in this chunk (it's the last one).
    LEDGER_ASSERT(g_ui_error_status == UI_STATUS_CHUNK_FULL || g_ui_error_status == UI_STATUS_SUCCESS,
                  "Unexpected UI status after streaming chunk render");
    g_ui_error_status = UI_STATUS_SUCCESS;

    // Finalize the pairs count for display.
    LEDGER_ASSERT(g_pairsList != NULL, "NULL g_pairsList after rendering");
    g_pairsList->nbPairs = (uint8_t) rendered_count;

    TRACE("Streaming chunk: from=%u rendered=%u cursor_after=%u total=%u",
          next_from, rendered_count, tx_body_ctx()->rendered_ui_pairs, total);

    nbgl_useCaseReviewStreamingContinue(g_pairsList, tx_streaming_continue_choice);
}

void ui_display_transaction(void) {
    if (G_context.req_type != REQUEST_SIGN_TRANSACTION || G_context.state.tx_state != TX_STATE_UI_PREPARED) {
        G_context.state.tx_state = TX_STATE_NONE;
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return;
    }

    const char *review_subtitle = NULL;
    switch (G_context.tx_info.tx_params.txSigningMode) {
        case SIGN_TX_SIGNINGMODE_PLUTUS_TX:
            review_subtitle = "Plutus execution";
            break;
        case SIGN_TX_SIGNINGMODE_MULTISIG_TX:
            review_subtitle = "Multisig transaction";
            break;
        default:
            break;
    }

    const nbgl_warning_t *warningPtr = ui_get_warnings();

    if (!tx_body_ctx()->streaming_mode) {
        // Non-streaming: identical to before.
        nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                                   g_pairsList,
                                   &ICON_APP_CARDANO,
                                   "Review transaction",
                                   review_subtitle,
                                   "Sign transaction",
                                   NULL,
                                   warningPtr,
                                   tx_review_choice);
    } else {
        // Streaming: first chunk already rendered.
        nbgl_useCaseAdvancedReviewStreamingStart(TYPE_TRANSACTION,
                                                 &ICON_APP_CARDANO,
                                                 "Review transaction",
                                                 review_subtitle,
                                                 warningPtr,
                                                 tx_streaming_start_choice);
    }
}
