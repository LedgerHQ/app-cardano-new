/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "ui_display_cvote_aux_data.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "cvote_hash.h"
#include "globals.h"
#include "utils.h"

void ui_cvote_aux_data_init_vars(cvote_aux_data_t *aux_data MARK_UNUSED) {
    // Stub: no-op
}

bool ui_cvote_aux_data_init_non_streaming(cvote_aux_data_t *aux_data MARK_UNUSED) {
    return true;
}

void ui_cvote_aux_data_streaming_show_initial_page(cvote_aux_data_t *aux_data MARK_UNUSED) {
    apdu_response_send_sw(SWO_SUCCESS);
}

void ui_cvote_aux_data_add_delegation_non_streaming(cvote_aux_data_t *aux_data MARK_UNUSED,
                                                    const cvote_credential_t *credential
                                                        MARK_UNUSED,
                                                    uint32_t weight MARK_UNUSED) {
    // Stub: no-op
}

void ui_cvote_aux_data_add_delegation_streaming(cvote_aux_data_t *aux_data MARK_UNUSED,
                                                const cvote_credential_t *credential MARK_UNUSED,
                                                uint32_t weight MARK_UNUSED) {
    // Stub: no-op
}

void ui_cvote_aux_data_show_non_streaming_final_review(cvote_aux_data_t *aux_data MARK_UNUSED) {
    // Finalize hash before cleanup (simulating what the real callback does)
    cvote_hash_finalize();
    G_context.state.tx_state = TX_STATE_CHUNKS;
    apdu_response_send_sw(SWO_SUCCESS);
}
