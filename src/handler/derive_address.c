#include <stdint.h>

#include "utils/utils.h"
#include "buffer.h"
#include "derive_address.h"
#include "deriveAddress/deriveAddress_types.h"
#include "cardano_swo.h"
#include "globals.h"
#include "apdu_constants.h"
#include "addressUtils/addressUtilsShelley.h"
#include "securityPolicy.h"
#include "utils/assert.h"
#include "nbgl_use_case.h"
#include "app_context.h"

#include "io.h"

#include "ux.h"
#include "utils.h"
#include "os_io_seproxyhal.h"
#include "ui/ui_display_address_derivation.h"

static uint16_t RESPONSE_READY_MAGIC = 11223;

static void prepareResponse() {
    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ctx->address.size =
        deriveAddress(&ctx->addressParams, ctx->address.buffer, SIZEOF(ctx->address.buffer));
    if (ctx->address.size == 0 || ctx->address.size > SIZEOF(ctx->address.buffer)) {
        send_swo_and_reset(SWO_INCORRECT_DATA);
        return;
    }
    ctx->responseReadyMagic = RESPONSE_READY_MAGIC;
}

void handler_derive_address(buffer_t *cdata, uint8_t display_type) {
    G_context.req_type = REQUEST_DERIVE_ADDRESS;
    if (!cdata->ptr) {
        io_send_sw(SWO_WRONG_DATA_LENGTH);
        return;
    }
    TRACE_BUFFER(cdata->ptr, cdata->size);

    derive_address_ctx_t *ctx = &G_context.derive_address_info;
    ctx->responseReadyMagic = 0;
    bool is_parsed = buffer_parseAddressParams(cdata, &ctx->addressParams);
    TRACE("Parsed address params: %d", is_parsed);
    if (!is_parsed) {
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    TRACE("Display type: %d", display_type);
    switch (display_type) {
        case P1_ADDRESS_RETURN: {
            TRACE("ADDRESS_RETURN");
            warning_bits_t warnings = 0;
            warning_bits_init(&warnings);
            security_policy_t policy = policyForReturnDeriveAddress(&ctx->addressParams, &warnings);
            TRACE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
            prepareResponse();
            ui_deriveAddress_handleReturn(policy, warnings);
            break;
        }
        case P1_ADDRESS_DISPLAY: {
            TRACE("ADDRESS_DISPLAY");
            warning_bits_t warnings = 0;
            warning_bits_init(&warnings);
            security_policy_t policy = policyForShowDeriveAddress(&ctx->addressParams, &warnings);
            TRACE("Policy: %d", (int) policy);
            if (policy == POLICY_DENY) {
                TRACE("Policy denied");
                send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
                return;
            }
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