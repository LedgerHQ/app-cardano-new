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
#include "ui_formatters.h"
#include "ui/ui_icons.h"
#include "cardano_constants.h"
#include "globals.h"
#include "utils/utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "menu.h"
#include "securityPolicy.h"
#include "memory/mem_utils.h"
#include "ui_utils.h"
#include "handler/derive_native_script_hash.h"
#include "bech32.h"
#include "textUtils.h"
#include "ui_display_native_script_hash.h"

void buildPositionDescription(const derive_native_script_hash_ctx_t *ctx,
                              char *out,
                              size_t out_len) {
    explicit_bzero(out, out_len);

    char *ptr = out;
    char *end = out + out_len;

    // Prefix
    snprintf(ptr, end - ptr, "Position: ");
    ptr += strlen(ptr);

    // Levels
    for (size_t i = 1; i <= ctx->level; i++) {
        LEDGER_ASSERT(i < MAX_SCRIPT_DEPTH, "Excedeed max script depth");

        uint32_t position =
            ctx->complexScripts[i].totalScripts - ctx->complexScripts[i].remainingScripts + 1;

        // STATIC_ASSERT(sizeof(position) <= sizeof(unsigned), "oversized type for %u");
        // STATIC_ASSERT(!IS_SIGNED(position), "signed type for %u");

        snprintf(ptr, end - ptr, "%u.", position);

        LEDGER_ASSERT(strlen(out) + 1 < out_len, "Excedeed output size");
        ptr += strlen(ptr);
    }

    // Remove trailing '.'
    LEDGER_ASSERT(ptr > out, "Excedeed output size");
    *(ptr - 1) = '\0';

    LEDGER_ASSERT(strlen(out) + 1 < out_len, "Excedeed output size");

    return;
}

static void derive_native_script_hash_buffer_cleanup(void) {
    // Cleanup all tracked allocations (all string buffers and warning structure)
    ui_cleanup_tracked_allocations();
    // Cleanup the pairs array
    ui_pairs_cleanup();
}

static void derive_native_script_hash_review_continue(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        io_send_response_pointer(NULL, 0, SWO_SUCCESS);
    } else {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
    }
}

static void derive_native_script_hash_review_confirmation_output(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;
    if (confirm) {
        TRACE("User confirmed");
        io_send_response_pointer(ctx->scriptHashBuffer, SCRIPT_HASH_LENGTH, SWO_SUCCESS);
    } else {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
        nbgl_useCaseStatus("Confirm\n native script hash", true, ui_menu_main);
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
    }
}

static void derive_native_script_hash_review_ask_confirmation(bool confirm) {
    // CLEANUP
    derive_native_script_hash_buffer_cleanup();

    // FINALIZE
    if (confirm) {
        TRACE("User confirmed");

    } else {
        TRACE("User rejected");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
    }

    // SHOW STATUS
    if (confirm) {
        TRACE("User confirmed");
        nbgl_useCaseReviewStreamingFinish("Confirm hash",
                                          derive_native_script_hash_review_confirmation_output);
    } else {
        TRACE("User rejected");
        nbgl_useCaseStatus("Native script hash\nrejected", false, ui_menu_main);
    }
}

void ui_display_native_script_hash(security_policy_t securityPolicy) {
    derive_native_script_hash_ctx_t *ctx = &G_context.derive_native_script_hash_info;

    char positionDescription[100] = {0};
    buildPositionDescription(ctx, positionDescription, SIZEOF(positionDescription));
    TRACE("positionDescription: \"%s\"", positionDescription);
    TRACE("=== ui_display_native_script_hash ===");
    TRACE("securityPolicy: %d", securityPolicy);

    if (securityPolicy == POLICY_DENY) {
        TRACE("Security condition not satisfied");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    switch (ctx->ui_scriptType) {
        case UI_SCRIPT_INIT: {
            // TODO: mismatch with previous app: first screen is passed automatically without user
            // intervention just after a call to function nbgl_useCaseReviewStreamingContinue
            nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                             &ICON_APP_CARDANO,
                                             "Review Script",
                                             "Swipe to review",
                                             derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_ALL: {
            char text[87] = {0};
            explicit_bzero(text, SIZEOF(text));
            snprintf(text,
                     SIZEOF(text),
                     "%u nested scripts",
                     ctx->complexScripts[ctx->level].remainingScripts);
            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "ALL";
            g_pairs[1].item = "Content";
            g_pairs[1].value = text;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);

            break;
        }
        case UI_SCRIPT_N_OF_K: {
            char text[87] = {0};
            explicit_bzero(text, SIZEOF(text));
            snprintf(text,
                     SIZEOF(text),
                     "%u out of %u signatures",
                     ctx->scriptContent.requiredScripts,
                     ctx->complexScripts[ctx->level].remainingScripts);

            char text2[87] = {0};
            explicit_bzero(text2, SIZEOF(text2));
            snprintf(text2,
                     SIZEOF(text2),
                     "%u nested scripts",
                     ctx->complexScripts[ctx->level].remainingScripts);

            if (!ui_pairs_init(3)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "N out K";
            g_pairs[1].item = "Requirement";
            g_pairs[1].value = text;
            g_pairs[2].item = "Script contents";
            g_pairs[2].value = text2;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_ANY: {
            char text[87] = {0};
            explicit_bzero(text, SIZEOF(text));
            snprintf(text,
                     SIZEOF(text),
                     "%u nested scripts",
                     ctx->complexScripts[ctx->level].remainingScripts);
            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "ANY";
            g_pairs[1].item = "Content";
            g_pairs[1].value = text;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_PUBKEY_PATH: {
            static char *pathStr = NULL;
            const size_t pathStrSize = MAX_BIP44_PATH_STRING_LENGTH + 1;
            pathStr = (char *) ui_mem_alloc(pathStrSize);
            if (pathStr == NULL) {
                TRACE("Failed to allocate pathStr");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            explicit_bzero(pathStr, pathStrSize);
            bool poolPathFormatted =
                format_bip44_path(&ctx->scriptContent.pubkeyPath, pathStr, pathStrSize);
            ASSERT(poolPathFormatted);
            ASSERT(strlen(pathStr) + 1 < pathStrSize);

            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "Pubkey path";
            g_pairs[1].item = "Pubkey path";
            g_pairs[1].value = pathStr;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_PUBKEY_HASH: {
            static char encodedStr[MAX_BECH32_STRING_LENGTH] = {0};
            explicit_bzero(encodedStr, SIZEOF(encodedStr));
            format_bech32("addr_shared_vkh",
                          ctx->scriptContent.pubkeyHash,
                          ADDRESS_KEY_HASH_LENGTH,
                          encodedStr,
                          SIZEOF(encodedStr));

            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "Pubkey hash";
            g_pairs[1].item = "Pubkey hash";
            g_pairs[1].value = encodedStr;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_INVALID_BEFORE: {
            char tmp[100] = {0};
            format_decimal_amount(ctx->scriptContent.timelock, 0, tmp, sizeof(tmp));

            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "Invalid before";
            g_pairs[1].item = "Invalid before";
            g_pairs[1].value = tmp;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_INVALID_HEREAFTER: {
            char tmp[100] = {0};
            format_decimal_amount(ctx->scriptContent.timelock, 0, tmp, sizeof(tmp));

            if (!ui_pairs_init(2)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script type";
            g_pairs[0].value = "Invalid hereafter";
            g_pairs[1].item = "Invalid hereafter";
            g_pairs[1].value = tmp;
            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_continue);
            break;
        }
        case UI_SCRIPT_DISPLAY_BECH32: {
            static char encodedStr[MAX_BECH32_STRING_LENGTH] = {0};
            explicit_bzero(encodedStr, SIZEOF(encodedStr));
            format_bech32("script",
                          ctx->scriptHashBuffer,
                          SCRIPT_HASH_LENGTH,
                          encodedStr,
                          SIZEOF(encodedStr));

            if (!ui_pairs_init(1)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Script hash";
            g_pairs[0].value = encodedStr;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_ask_confirmation);
            break;
        }
        case UI_SCRIPT_DISPLAY_POLICY_ID: {
            char bufferHex[2 * SCRIPT_HASH_LENGTH + 1] = {0};
            bytes_to_lowercase_hex(bufferHex,
                                   SIZEOF(bufferHex),
                                   ctx->scriptHashBuffer,
                                   SCRIPT_HASH_LENGTH);
            if (!ui_pairs_init(1)) {
                TRACE("Failed to initialize pairs");
                send_swo_and_reset(SWO_INSUFFICIENT_MEMORY);
                return;
            }
            g_pairs[0].item = "Policy ID";
            g_pairs[0].value = bufferHex;

            nbgl_useCaseReviewStreamingContinue(g_pairsList,
                                                derive_native_script_hash_review_ask_confirmation);
            break;
        }
        default: {
            TRACE("Invalid UI step");
            send_swo_and_reset(SWO_BAD_STATE);
            return;
        }
    }
    return;
}