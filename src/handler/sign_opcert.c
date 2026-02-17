/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero

#include "app_context.h"
#include "bip44.h"
#include "buffer.h"
#include "buffer_write.h"
#include "cardano_swo.h"
#include "globals.h"
#include "io.h"
#include "messageSigning.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "opcert_parse.h"
#include "opcert_types.h"
#include "securityPolicy.h"
#include "sign_opcert.h"
#include "ui_formatters.h"
#include "ui_display_opcert.h"
#include "utils.h"

#define OP_CERT_BODY_LENGTH (KES_PUBLIC_KEY_LENGTH + 8 + 8)

static bool ensure_sign_opcert_init_request_state(void) {
    if (G_context.req_type != REQUEST_NONE) {
        TRACE("SIGN_OPCERT init rejected: request already active (req_type=%d)",
              G_context.req_type);
        send_swo_and_reset(SWO_COMMAND_NOT_ALLOWED);
        return false;
    }
    return true;
}

void handler_sign_opcert(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to handler");
    TRACE_BUFFER_T(cdata);

    if (!ensure_sign_opcert_init_request_state()) {
        return;
    }

    G_context.req_type = REQUEST_SIGN_OPCERT;
    G_context.state.opcert_state = OPCERT_STATE_NONE;

    G_context.opcert_info.raw_opcert_len = cdata->size;
    if (!buffer_move(cdata, G_context.opcert_info.raw_opcert, sizeof(G_context.opcert_info.raw_opcert))) {
        send_swo_and_reset(SWO_INVALID_OPCERT_LENGTH);
        return;
    }

    buffer_t buf = {.ptr = G_context.opcert_info.raw_opcert,
                    .size = G_context.opcert_info.raw_opcert_len,
                    .offset = 0};
    TRACE_BUFFER(buf.ptr, buf.size);

    opcert_parser_status_e status = parse_opcert(&buf, &G_context.opcert_info.opcert);
    TRACE("Opcert parsing status: %d", status);
    if (status != PARSING_OK) {
        send_swo_and_reset(opcert_map_parser_status_to_swo(status));
        return;
    }
    G_context.state.opcert_state = OPCERT_STATE_PARSED;
    const parsed_opcert_t* opcert = &G_context.opcert_info.opcert;

    // Log parsed opcert details (path, KES period, issue counter)
    BIP44_PRINTF(&opcert->poolColdKeyPath);
    TRACE("KES period = %llu", (unsigned long long) opcert->kesPeriod);
    TRACE("issue counter = %llu", (unsigned long long) opcert->issueCounter);

    // Check security policy
    warning_bits_t warnings = 0;
    security_policy_t policy = policyForSignOpCert(&opcert->poolColdKeyPath, &warnings);
    TRACE("Security policy: %d", policy);
    if (policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting operation");
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    G_context.state.opcert_state = OPCERT_STATE_VALIDATED;
    apdu_response_deferred();
    ui_display_opcert(policy, warnings);
}

void finalize_sign_opcert(void) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_OPCERT, "Bad req_type");
    LEDGER_ASSERT(G_context.state.opcert_state == OPCERT_STATE_VALIDATED, "Bad opcert state");

    // user confirmed
    G_context.state.opcert_state = OPCERT_STATE_APPROVED;

    // assemble the opcert bytestring and sign it
    const parsed_opcert_t* opcert = &G_context.opcert_info.opcert;
    uint8_t opCertBodyBuffer[OP_CERT_BODY_LENGTH] = {0};
    {
        write_buffer_t buf = buffer_init_write(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));

        // Buffer is exactly sized - failure is programming error
        LEDGER_ASSERT(buffer_write_bytes(&buf, (const uint8_t*) opcert->kesPublicKey, KES_PUBLIC_KEY_LENGTH), "Write KES pubkey failed");
        LEDGER_ASSERT(buffer_write_u64(&buf, opcert->issueCounter, BE), "Write issueCounter failed");
        LEDGER_ASSERT(buffer_write_u64(&buf, opcert->kesPeriod, BE), "Write kesPeriod failed");

        LEDGER_ASSERT(buffer_written_size(&buf) == OP_CERT_BODY_LENGTH, "Bad body length");
        TRACE_BUFFER(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));
    }

    LEDGER_ASSERT(bip44_isPoolColdKeyPath(&opcert->poolColdKeyPath), "Bad pool cold path");
    signRawMessageWithPath(
        &opcert->poolColdKeyPath,
        opCertBodyBuffer, SIZEOF(opCertBodyBuffer),
        G_context.opcert_info.signature, SIZEOF(G_context.opcert_info.signature)
    );

    apdu_response_send_data(
        G_context.opcert_info.signature,
        SIZEOF(G_context.opcert_info.signature),
        SWO_SUCCESS
    );
    reset_app_context();
}
