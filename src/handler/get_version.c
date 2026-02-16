/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>  // uint*_t
#include <limits.h>  // UINT8_MAX
#include <assert.h>  // _Static_assert

#include "io.h"
#include "buffer.h"

#include "get_version.h"
#include "globals.h"
#include "cardano_swo.h"
#include "assert.h"
#include "app_context.h"
#include "buffer_helpers.h"
#include "utils.h"

void handler_get_version(const buffer_t *data_buffer) {
    LEDGER_ASSERT(data_buffer != NULL, "NULL data_buffer");

    // Verify no data is present
    if (deny_unconsumed_bytes(data_buffer, SWO_WRONG_DATA_LENGTH)) {
        TRACE("Get version APDU must be empty");
        return;
    }

    _Static_assert(APPVERSION_LEN == 3, "Length of (MAJOR || MINOR || PATCH) must be 3!");
    _Static_assert(MAJOR_VERSION >= 0 && MAJOR_VERSION <= UINT8_MAX,
                   "MAJOR version must be between 0 and 255!");
    _Static_assert(MINOR_VERSION >= 0 && MINOR_VERSION <= UINT8_MAX,
                   "MINOR version must be between 0 and 255!");
    _Static_assert(PATCH_VERSION >= 0 && PATCH_VERSION <= UINT8_MAX,
                   "PATCH version must be between 0 and 255!");

    apdu_response_send_data(
        (const uint8_t *) &(uint8_t[APPVERSION_LEN]){(uint8_t) MAJOR_VERSION,
                                                     (uint8_t) MINOR_VERSION,
                                                     (uint8_t) PATCH_VERSION},
        APPVERSION_LEN,
        SWO_SUCCESS);
}
