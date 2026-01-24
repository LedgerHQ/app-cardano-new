#include <stdint.h>

#include "utils/utils.h"
#include "buffer.h"
#include "derive_address.h"
#include "cardano_swo.h"
#include "globals.h"
#include "addressUtils/addressUtilsShelley.h"
#include "securityPolicy.h"
#include "utils/assert.h"
#include "app_context.h"
#include "io.h"
#include "ui/ui_display_address_derivation.h"

static void prepareResponse() {
    // Verify we're at the expected state: parameters validated by policy
    LEDGER_ASSERT(G_context.req_type == REQUEST_DERIVE_ADDRESS,
                  "prepareResponse called without REQUEST_DERIVE_ADDRESS");
    LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_VALIDATED,
                  "prepareResponse called in wrong state: %d", G_context.state.derive_address_state);

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ctx->address.size =
        deriveAddress(&ctx->addressParams, ctx->address.buffer, SIZEOF(ctx->address.buffer));
    if (ctx->address.size == 0 || ctx->address.size > SIZEOF(ctx->address.buffer)) {
        send_swo_and_reset(SWO_INCORRECT_DATA);
        return;
    }

    // Address successfully derived and ready for display/response
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_PREPARED;
}

void handler_derive_address(buffer_t *cdata, uint8_t p1) {
    G_context.req_type = REQUEST_DERIVE_ADDRESS;
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_NONE;
    if (!cdata->ptr) {
        io_send_sw(SWO_WRONG_DATA_LENGTH);
        return;
    }
    TRACE_BUFFER(cdata->ptr, cdata->size);

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    bool is_parsed = buffer_parseAddressParams(cdata, &ctx->addressParams);
    TRACE("Parsed address params: %d", is_parsed);
    if (!is_parsed) {
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Parameters successfully parsed
    G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_PARSED;

    TRACE("Display type: %d", p1);
    switch (p1) {
        case P1_ADDRESS_RETURN: {
            TRACE("ADDRESS_RETURN");
            LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PARSED,
                          "handleReturn called in wrong state: %d", G_context.state.derive_address_state);
            warning_bits_t warnings = 0;
            warning_bits_init(&warnings);
            security_policy_t policy = policyForReturnDeriveAddress(&ctx->addressParams, &warnings);
            TRACE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_VALIDATED;
            prepareResponse();
            ui_deriveAddress_handleReturn(policy, warnings);
            break;
        }
        case P1_ADDRESS_DISPLAY: {
            TRACE("ADDRESS_DISPLAY");
            LEDGER_ASSERT(G_context.state.derive_address_state == DERIVE_ADDRESS_STATE_PARSED,
                          "handleDisplay called in wrong state: %d", G_context.state.derive_address_state);
            warning_bits_t warnings = 0;
            warning_bits_init(&warnings);
            security_policy_t policy = policyForShowDeriveAddress(&ctx->addressParams, &warnings);
            TRACE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_VALIDATED;
            prepareResponse();
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