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

void handler_sign_opcert(buffer_t *cdata) {
    LEDGER_ASSERT(cdata != NULL, "NULL cdata passed to sign_opcert handler");
    // Handler entry invariant: no other request should be active
    // (Dispatcher prevents this with SWO_COMMAND_NOT_ALLOWED, but we validate here too)
    LEDGER_ASSERT(G_context.req_type == REQUEST_NONE, "opcert init called while another request active");

    G_context.req_type = REQUEST_SIGN_OPCERT;
    G_context.state.opcert_state = OPCERT_STATE_NONE;

    TRACE_BUFFER_T(cdata);

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
    warning_bits_init(&warnings);
    security_policy_t policy = policyForSignOpCert(&opcert->poolColdKeyPath, &warnings);
    TRACE("Security policy: %d", policy);
    if (policy == POLICY_DENY) {
        TRACE("Security policy DENY - rejecting operation");
        TRACE("Calling nbgl_useCaseStatus(\"Operational certificate denied\", false, ui_menu_main)");
        nbgl_useCaseStatus("Operational certificate denied", false, ui_menu_main);
        send_swo_and_reset(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        return;
    }

    G_context.state.opcert_state = OPCERT_STATE_VALIDATED;
    ui_display_opcert(policy, warnings);
    // waiting for NBGL callback opcert_review_choice, so no APDU sent
}

void finalize_sign_opcert(bool confirmed) {
    LEDGER_ASSERT(G_context.req_type == REQUEST_SIGN_OPCERT,
                  "finalize_sign_opcert called without REQUEST_SIGN_OPCERT");
    LEDGER_ASSERT(G_context.state.opcert_state == OPCERT_STATE_VALIDATED,
                  "finalize_sign_opcert called in wrong state: %d", G_context.state.opcert_state);

    if (!confirmed) {
        send_swo_and_reset(SWO_CONDITIONS_NOT_SATISFIED);
        return;
    }

    // user confirmed
    G_context.state.opcert_state = OPCERT_STATE_APPROVED;

    // assemble the opcert bytestring and sign it
    const parsed_opcert_t* opcert = &G_context.opcert_info.opcert;
    uint8_t opCertBodyBuffer[OP_CERT_BODY_LENGTH] = {0};
    explicit_bzero(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));
    {
        write_buffer_t buf = buffer_init_write(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));

        // Buffer is exactly sized - failure is programming error
        ASSERT(buffer_write_bytes(&buf,
                                  (const uint8_t*) opcert->kesPublicKey,
                                  KES_PUBLIC_KEY_LENGTH));
        ASSERT(buffer_write_u64(&buf, opcert->issueCounter, BE));
        ASSERT(buffer_write_u64(&buf, opcert->kesPeriod, BE));

        ASSERT(buffer_written_size(&buf) == OP_CERT_BODY_LENGTH);
        TRACE_BUFFER(opCertBodyBuffer, SIZEOF(opCertBodyBuffer));
    }

    ASSERT(bip44_isPoolColdKeyPath(&opcert->poolColdKeyPath));
    signRawMessageWithPath(
        &opcert->poolColdKeyPath,
        opCertBodyBuffer, SIZEOF(opCertBodyBuffer),
        G_context.opcert_info.signature, SIZEOF(G_context.opcert_info.signature)
    );

    io_send_response_pointer(
        G_context.opcert_info.signature,
        SIZEOF(G_context.opcert_info.signature),
        SWO_SUCCESS
    );
    reset_app_context();
}
