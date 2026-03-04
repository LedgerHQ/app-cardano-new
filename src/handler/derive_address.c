/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

#include "utils.h"
#include "buffer.h"
#include "derive_address.h"
#include "cardano_swo.h"
#include "globals.h"
#include "addressUtilsShelley.h"
#include "securityPolicy.h"
#include "assert.h"
#include "app_context.h"
#include "io.h"
#include "ui_display_address_derivation.h"
#include "cardano_buffer.h"

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_HANDLERS to trace handler-level flow.
 */
#ifdef TRACE_HANDLERS
#define TRACE_MODULE(...) TRACE("[derive_address] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void)0  // Compiled out
#endif

static bool ensure_derive_address_init_request_state(void) {
    if (G_context.req_type != REQUEST_NONE) {
        TRACE_MODULE("DERIVE_ADDRESS init rejected: request already active (req_type=%d)",
                     G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool ensure_derive_address_state(derive_address_state_e required_state) {
    if (G_context.state.derive_address_state != required_state) {
        TRACE_MODULE("DERIVE_ADDRESS rejected in state %d (expected %d)",
                     G_context.state.derive_address_state,
                     required_state);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

static bool prepareResponse(void) {
    if (G_context.req_type != REQUEST_DERIVE_ADDRESS) {
        TRACE_MODULE("DERIVE_ADDRESS response preparation rejected: bad request type %d",
                     G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }

    if (!ensure_derive_address_state(DERIVE_ADDRESS_STATE_VALIDATED)) {
        return false;
    }

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ctx->address.length =
        deriveAddress(&ctx->address_params, ctx->address.buffer, SIZEOF(ctx->address.buffer));
    if (ctx->address.length == 0 || ctx->address.length > SIZEOF(ctx->address.buffer)) {
        send_swo_and_reset(SWO_INCORRECT_DATA);
        return false;
    }

    // Address successfully derived and ready for display/response
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_PREPARED;
    return true;
}

void handler_derive_address(buffer_t *cdata, uint8_t p1) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata");
    TRACE_BUFFER_T(cdata);

    if (!ensure_derive_address_init_request_state()) {
        return;
    }

    G_context.req_type = REQUEST_DERIVE_ADDRESS;
    explicit_bzero(&G_context.derive_address_info, sizeof(G_context.derive_address_info));
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_NONE;

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ctx->should_export_address = false;
    bool is_parsed = buffer_read_address_params(cdata, &ctx->address_params);
    TRACE_MODULE("Parsed address params: %d", is_parsed);
    if (!is_parsed) {
        send_swo_and_reset(SWO_DERIVE_ADDRESS_PARSING_FAIL_ADDRESS_PARAMS);
        return;
    }
    if (deny_unconsumed_bytes(cdata, SWO_WRONG_DATA_LENGTH)) {
        return;
    }
    // Copy any hash pointers into context-owned storage so they survive beyond this APDU
    address_params_copyHashesToStorage(&ctx->address_params,
                                     &ctx->hashStorage);

    // Parameters successfully parsed
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_PARSED;

    TRACE_MODULE("Display type: %d", p1);
    switch (p1) {
        case P1_ADDRESS_RETURN: {
            TRACE_MODULE("ADDRESS_RETURN");
            ctx->should_export_address = true;
            if (!ensure_derive_address_state(DERIVE_ADDRESS_STATE_PARSED)) {
                return;
            }
            warning_bits_t warnings = 0;
            security_policy_t policy = policyForReturnDeriveAddress(&ctx->address_params, &warnings);
            TRACE_MODULE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_VALIDATED;
            if (!prepareResponse()) {
                return;
            }
            apdu_response_deferred();
            ui_deriveAddress_handleReturn(policy, warnings);
            break;
        }
        case P1_ADDRESS_DISPLAY: {
            TRACE_MODULE("ADDRESS_DISPLAY");
            ctx->should_export_address = false;
            if (!ensure_derive_address_state(DERIVE_ADDRESS_STATE_PARSED)) {
                return;
            }
            warning_bits_t warnings = 0;
            security_policy_t policy = policyForShowDeriveAddress(&ctx->address_params, &warnings);
            TRACE_MODULE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_VALIDATED;
            if (!prepareResponse()) {
                return;
            }
            apdu_response_deferred();
            ui_deriveAddress_handleDisplay(policy, warnings);
            break;
        }
        default:
            TRACE("Bad display type");
            LEDGER_ASSERT(false, "display type should be handled before");
            break;
    }
    return;
}

void finalize_derive_address(void) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS, "Bad req_type");
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PREPARED, "Bad derive_address state");

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    if (ctx->should_export_address) {
        LEDGER_ASSERT(ctx->address.length <= sizeof(ctx->address.buffer), "Address length too large");
        apdu_response_send_data(ctx->address.buffer, ctx->address.length, SWO_SUCCESS);
    } else {
        apdu_response_send_data(NULL, 0, SWO_SUCCESS);
    }
    reset_app_context();
}
