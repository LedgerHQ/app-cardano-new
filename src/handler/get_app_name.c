/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>  // uint*_t

#include "io.h"
#include "buffer.h"

#include "get_app_name.h"
#include "globals.h"
#include "cardano_swo.h"
#include "assert.h"
#include "app_context.h"

void handler_get_app_name(const buffer_t *data_buffer) {
    LEDGER_ASSERT(data_buffer != NULL, "NULL data_buffer");

    // Verify no data is present
    if (buffer_can_read(data_buffer, 1)) {
        send_swo_and_reset(SWO_WRONG_DATA_LENGTH);
        return;
    }

    _Static_assert(APPNAME_LEN < MAX_APP_NAME_LENGTH, "APPNAME must be at most 64 characters!");

    apdu_response_send_data(PIC(APPNAME), APPNAME_LEN, SWO_SUCCESS);
}
