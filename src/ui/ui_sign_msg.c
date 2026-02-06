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
// no local mem allocations needed

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
    ui_free_pairs();
}

static void sign_msg_review_choice(bool confirm) {
    // CLEANUP
    sign_msg_buffer_cleanup();

    // FINALIZE
    finalize_sign_msg(confirm);

    // SHOW STATUS
    if (confirm) {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
    } else {
        TRACE("Calling nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main)");
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
}

void ui_display_sign_msg(security_policy_t securityPolicy) {
    sign_msg_ctx_t *ctx = &G_context.sign_msg_info;

    TRACE("=== ui_display_sign_msg START ===");

    // Check state
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_MSG,
                  "ui_display_sign_msg called with wrong request type: %d",
                  G_context.req_type);
    LEDGER_ASSERT(G_context.state.sign_msg_state == SIGN_MSG_STAGE_CONFIRM,
                  "ui_display_sign_msg called in wrong state: %d",
                  G_context.state.sign_msg_state);

    // Check policy
    TRACE("securityPolicy: %d", securityPolicy);
    LEDGER_ASSERT(securityPolicy == POLICY_SHOW,
                  "ui_display_sign_msg called with wrong security policy: %d",
                  securityPolicy);

    // Initialize pairs for display (6 fields)
    if (!ui_pairs_init(6)) {
        TRACE("Failed to initialize pairs");
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
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Address field (keyhash)"),
                           2 * ADDRESS_KEY_HASH_LENGTH + 1,
                           format_hex_bytes,
                           ctx->addressField,
                           ctx->addressFieldSize);
            break;
        }
        default:
            LEDGER_ASSERT(false, "Invalid address field type");
            return;
    }

    // Field 4: Message length
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Message length"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   ctx->msgLength);

    // Field 5: Full message content (ASCII or hex)
    if (ctx->msgLength == 0) {
        if (ctx->isAscii) {
            UI_ADD_STATIC(UI_STATIC_LABEL("Message (ASCII)"), UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_STATIC(UI_STATIC_LABEL("Message (hex)"), UI_STATIC_LABEL("(empty)"));
        }
    } else if (ctx->isAscii) {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Message (ASCII)"),
                       ctx->msgLength,
                       format_ascii_chunk,
                       ctx->msgBuffer,
                       ctx->msgLength);
    } else {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Message (hex)"),
                       2 * ctx->msgLength + 1,
                       format_hex_bytes,
                       ctx->msgBuffer,
                       ctx->msgLength);
    }

    // Field 6: Message hash (always computed)
    UI_ADD_FORMAT2(UI_STATIC_LABEL("Message hash"),
                   2 * CIP8_MSG_HASH_LENGTH + 1,
                   format_hex_bytes,
                   ctx->msgHash,
                   SIZEOF(ctx->msgHash));

    // Display review screen with skip button for long messages
    TRACE("Calling nbgl_useCaseAdvancedReview(TYPE_OPERATION | SKIPPABLE_OPERATION)");
    nbgl_useCaseAdvancedReview(TYPE_OPERATION | SKIPPABLE_OPERATION,
                               g_pairsList,
                               &ICON_APP_CARDANO,
                               "Sign message",
                               "CIP-8",
                               "Sign message",
                               NULL,
                               NULL,  // No warnings for message signing
                               sign_msg_review_choice);
}
