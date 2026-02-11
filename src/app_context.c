/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>  // explicit_bzero
#include <stdbool.h>

#include "globals.h"
#include "app_context.h"
#include "utils.h"
#include "mem.h"
#include "ui_utils.h"
#include "ui_warnings.h"
#include "io.h"

typedef struct {
    bool response_sent;
    bool response_deferred_to_ux;
    command_e instruction;
} apdu_response_state_t;

static apdu_response_state_t G_apdu_response_state = {0};

void apdu_response_begin(command_e instruction) {
    // Deferred APDUs are completed in two steps:
    // 1) handler marks "deferred" (response will be sent from UX callback),
    // 2) UX callback later sends the response ("sent").
    // If that prior async APDU already reached this completed state, clear it now
    // before tracking a new APDU.
    if (G_apdu_response_state.response_sent &&
        G_apdu_response_state.response_deferred_to_ux) {
        explicit_bzero(&G_apdu_response_state, SIZEOF(G_apdu_response_state));
    }

    LEDGER_ASSERT(!G_apdu_response_state.response_sent &&
                      !G_apdu_response_state.response_deferred_to_ux,
                  "Previous APDU response state not finalized");

    G_apdu_response_state.response_sent = false;
    G_apdu_response_state.response_deferred_to_ux = false;
    G_apdu_response_state.instruction = instruction;
}

void apdu_response_deferred(void) {
    LEDGER_ASSERT(!G_apdu_response_state.response_sent,
                  "Response already sent for INS=0x%02x",
                  G_apdu_response_state.instruction);

    G_apdu_response_state.response_deferred_to_ux = true;
}

void apdu_response_assert_sent_or_deferred(void) {
    LEDGER_ASSERT(G_apdu_response_state.response_sent ||
                      G_apdu_response_state.response_deferred_to_ux,
                  "No APDU response or UX defer marker for INS=0x%02x",
                  G_apdu_response_state.instruction);

    if (G_apdu_response_state.response_sent) {
        explicit_bzero(&G_apdu_response_state, SIZEOF(G_apdu_response_state));
    }
}

int apdu_response_send_sw(uint16_t swo) {
    LEDGER_ASSERT(!G_apdu_response_state.response_sent,
                  "Second APDU response for INS=0x%02x",
                  G_apdu_response_state.instruction);
    G_apdu_response_state.response_sent = true;

    return io_send_sw(swo);
}

int apdu_response_send_data(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    LEDGER_ASSERT(!G_apdu_response_state.response_sent,
                  "Second APDU response for INS=0x%02x",
                  G_apdu_response_state.instruction);
    G_apdu_response_state.response_sent = true;

    return io_send_response_pointer(buffer, bufferLength, swo);
}

void reset_app_context(void) {
    TRACE("reset_app_context");

    ui_free_pairs();
    ui_free_warnings();

    // Reset the SDK allocator to wipe all transient memory
    LEDGER_ASSERT(mem_utils_reset_app_heap(), "Failed to reset memory allocator");

    // Securely zero out the entire global context
    explicit_bzero(&G_context, sizeof(G_context));

    // Ensure request type is explicitly idle
    G_context.req_type = REQUEST_NONE;
}

void send_swo_and_reset(uint16_t swo) {
    TRACE("send_swo_and_reset swo=0x%04x", swo);
    reset_app_context();
    apdu_response_send_sw(swo);
}
