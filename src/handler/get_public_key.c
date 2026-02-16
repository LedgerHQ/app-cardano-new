/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "io.h"
#include "buffer.h"
#include "crypto_helpers.h"
#include "nbgl_use_case.h"

#include "get_public_key.h"
#include "globals.h"
#include "keyDerivation.h"
#include "utils.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "ui_display_pubkey.h"
#include "dispatcher.h"
#include "securityPolicy.h"
#include "menu.h"

static bool ensure_get_public_key_init_request_state(void) {
    if (G_context.req_type != REQUEST_NONE) {
        TRACE("GET_PUBLIC_KEY rejected: request already active (req_type=%d)",
              G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

void handler_get_public_key(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to handler");
    TRACE_BUFFER_T(cdata);

    if (!ensure_get_public_key_init_request_state()) {
        return;
    }

    G_context.req_type = REQUEST_EXPORT_PUBKEY;

    if (!buffer_read_bip44_path(cdata, &G_context.pk_info.path)) {
        TRACE("Failed to parse BIP44 path for public key export");
        send_swo_and_reset(SWO_BIP44_PATH_PARSING_FAIL);
        return;
    }
    if (buffer_can_read(cdata, 1)) {
        TRACE("Get pubkey APDU not fully consumed");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Log the requested path for easier debugging.
    BIP44_PRINTF(&G_context.pk_info.path);

    // Check security policy
    warning_bits_t warnings = 0;
    security_policy_t policy = policyForGetExtendedPublicKey(&G_context.pk_info.path, &warnings);
    TRACE("Security policy: %d", (int) policy);
    if (policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting operation");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    deriveExtendedPublicKey(&G_context.pk_info.path, &G_context.pk_info.extPubKey);

    apdu_response_deferred();
    ui_display_pubkey(policy, warnings);
}

void finalize_pubkey_export(bool confirmed) {
    TRACE("confirmed = %d", confirmed);

    if (!confirmed) {
        TRACE("Public key export rejected by user");
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    LEDGER_ASSERT(G_context.req_type == REQUEST_EXPORT_PUBKEY, "Bad req_type");

    // Send the extended public key back to the client
    apdu_response_send_data((uint8_t*) &G_context.pk_info.extPubKey,
                                     SIZEOF(G_context.pk_info.extPubKey),
                                     SWO_SUCCESS);
    reset_app_context();
}
