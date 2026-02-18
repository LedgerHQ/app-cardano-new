/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#ifdef DEBUG

#include <stdint.h>

#include "os.h"
#include "io.h"
#include "ledger_assert.h"
#include "buffer.h"
#include "cardano_buffer.h"

#include "debug_settings.h"
#include "globals.h"
#include "app_context.h"
#include "cardano_swo.h"
#include "cardano_settings.h"

void handler_debug_set_settings(const buffer_t *buf) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");

    // Expect exactly 2 bytes of data
    const size_t remaining = buffer_data_size(buf);
    if (remaining != 2) {
        TRACE("DEBUG: Invalid data length: %d (expected 2)", (int)remaining);
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Parse settings from buffer to respect offset
    uint8_t expert_mode = 0;
    uint8_t silent_export = 0;
    buffer_t read_buf = *buf;
    if (!buffer_read_u8(&read_buf, &expert_mode) ||
        !buffer_read_u8(&read_buf, &silent_export) ||
        read_buf.offset != read_buf.size) {
        TRACE("DEBUG: Invalid data length while reading settings");
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    // Validate values (only 0x00 or 0x01 allowed)
    if ((expert_mode != SETTINGS_NO && expert_mode != SETTINGS_YES) ||
        (silent_export != SETTINGS_NO && silent_export != SETTINGS_YES)) {
        TRACE("DEBUG: Invalid setting values: expert=%d, silent=%d", expert_mode, silent_export);
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    TRACE("DEBUG: Setting expert_mode=%d, silent_export=%d", expert_mode, silent_export);

    // Write to NVM to mirror the UI toggles
    nvm_write((void*)&N_storage.expert_mode_enabled, &expert_mode, sizeof(uint8_t));
    nvm_write((void*)&N_storage.silent_pubkey_export_enabled, &silent_export, sizeof(uint8_t));

    // Return current settings as confirmation (2 bytes)
    uint8_t response[2] = {
        N_storage.expert_mode_enabled,
        N_storage.silent_pubkey_export_enabled
    };

    apdu_response_send_data(response, sizeof(response), SWO_SUCCESS);
}

#endif  // DEBUG
