/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip44.h"
#include "format.h"

#include "ui_constants.h"
#include "ui_icons.h"
#include "ui_formatters.h"
#include "ui_utils.h"
#include "ui_sign_msg.h"
#include "globals.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "menu.h"
#include "securityPolicy.h"
#include "app_context.h"
#include "sign_msg.h"
#include "addressUtilsShelley.h"
#include "ui_warnings.h"

static bool format_ascii_chunk(const uint8_t *bytes, size_t size, char *out, size_t outSize) {
    LEDGER_ASSERT(bytes != NULL, "NULL input buffer");
    LEDGER_ASSERT(out != NULL, "NULL output buffer");
    LEDGER_ASSERT(outSize > 0, "Zero output buffer size");
    if (size + 1 > outSize) {
        return false;
    }
    memcpy(out, bytes, size);
    out[size] = '\0';
    return true;
}

/**
 * Cleanup dynamically allocated buffers and UI pairs
 */
static void sign_msg_buffer_cleanup(void) {
    ui_all_cleanup();
}

static void sign_msg_review_choice(bool confirm) {
    // CLEANUP
    sign_msg_buffer_cleanup();

    // FINALIZE
    if (!confirm) {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
        return;
    }

    TRACE("User confirmed");
    nbgl_useCaseSpinner("Processing");
    finalize_sign_msg();

    // SHOW STATUS
    nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
}

void ui_display_sign_msg(security_policy_t securityPolicy, warning_bits_t warnings) {
    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    TRACE("=== ui_display_sign_msg START ===");

    // Check state
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_MSG, "ui_display_sign_msg called with wrong request type: %d", G_context.req_type);
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STATE_CONFIRM, "ui_display_sign_msg called in wrong state: %d", G_context.state.sign_msg_state);

    // Check policy
    TRACE("securityPolicy: %d", securityPolicy);
    LEDGER_ASSERT(securityPolicy == POLICY_SHOW, "ui_display_sign_msg called with wrong security policy: %d", securityPolicy);

    ui_render_session_t session = {0};
    ui_render_scope_begin(&session);

    // Initialize pairs for display (6 fields)
    if (!ui_pairs_init(6)) {
        TRACE("Failed to initialize pairs");
        ui_render_scope_end();
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    // Field 1: Payload type (hashed or non-hashed)
    if (ctx->hashPayload) {
        UI_ADD_STATIC(UI_STATIC_LABEL("Payload type"), UI_STATIC_LABEL("Hashed"));
    } else {
        UI_ADD_STATIC(UI_STATIC_LABEL("Payload type"), UI_STATIC_LABEL("Non-hashed"));
    }

    // Field 2: Signing path
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Signing path"),
                   MAX_BIP44_PATH_STRING_LENGTH,
                   format_bip44_path,
                   &ctx->signingPath);

    // Field 3: Address field (address or key hash)
    switch (ctx->addressFieldType) {
        case CIP8_ADDRESS_FIELD_ADDRESS: {
            // Display human-readable address
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Address field"),
                           MAX_HUMAN_ADDRESS_LENGTH,
                           format_address_human_readable,
                           ctx->addressField,
                           ctx->addressFieldSize);
            break;
        }
        case CIP8_ADDRESS_FIELD_KEYHASH: {
            // Display key hash as hex
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Address field (keyhash)", "Addr field"),
                           2 * ADDRESS_KEY_HASH_LENGTH + 1,
                           format_hex_bytes,
                           ctx->addressField,
                           ctx->addressFieldSize);
            break;
        }
        // LCOV_EXCL_START
        default:
            ui_render_scope_end();
            LEDGER_ASSERT(false, "Invalid address field type");
            return;
        // LCOV_EXCL_STOP
    }

    // Field 4: Message length in bytes
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Message length (bytes)", "Msg len (B)"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   ctx->msgLength);

    // Field 5: Full message content (ASCII or hex)
    if (ctx->msgLength == 0) {
        if (ctx->isAscii) {
            UI_ADD_STATIC(UI_LABEL_BY_SCREEN("Message (ASCII)", "Msg (ASCII)"), UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_STATIC(UI_LABEL_BY_SCREEN("Message (hex)", "Msg (hex)"), UI_STATIC_LABEL("(empty)"));
        }
    } else {
        if (ctx->msgBuffer == NULL) {
            ui_render_scope_end();
            LEDGER_ASSERT(false, "Message buffer not allocated");
            return;
        }
        if (ctx->isAscii) {
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Message (ASCII)", "Msg (ASCII)"),
                           ctx->msgLength,
                           format_ascii_chunk,
                           ctx->msgBuffer,
                           ctx->msgLength);
        } else {
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Message (hex)", "Msg (hex)"),
                           2 * ctx->msgLength + 1,
                           format_hex_bytes,
                           ctx->msgBuffer,
                           ctx->msgLength);
        }
    }

    // Field 6: Message hash (always computed)
    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Message hash", "Msg hash"),
                   2 * CIP8_MSG_HASH_LENGTH + 1,
                   format_hex_bytes,
                   ctx->msgHash,
                   SIZEOF(ctx->msgHash));

    ui_status_t format_status = ui_render_scope_end();
    switch (format_status) {
        case UI_STATUS_SUCCESS:
            break;
        case UI_STATUS_OUT_OF_MEMORY:
            send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
            return;
        case UI_STATUS_UNINITIALIZED:
        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unexpected UI status");
            return;
        // LCOV_EXCL_STOP
    }

    // Build warnings if any
    ui_status_t warning_status = ui_build_warnings(warnings);
    if (warning_status != UI_STATUS_SUCCESS) {
        send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
        return;
    }

    nbgl_operationType_t reviewOperationType = TYPE_OPERATION;
#ifdef SCREEN_SIZE_WALLET
    // Keep skip only on large wallet screens.
    reviewOperationType |= SKIPPABLE_OPERATION;
#endif

    // Display review screen
    nbgl_useCaseAdvancedReview(reviewOperationType,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               "Review message",
                               "CIP-8",
                               "Sign message",
                               NULL,
                               ui_get_warnings(),
                               sign_msg_review_choice);
}
