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
#include "cardano_buffer.h"
#include "utils.h"

void handler_get_version(const buffer_t *data_buffer) {
    ASSERT(data_buffer != NULL);

    // Verify no data is present
    if (deny_unconsumed_bytes(data_buffer, SWO_WRONG_DATA_LENGTH)) {
        TRACE("Get version APDU must be empty");
        return;
    }

    _Static_assert(APPVERSION_LEN == 4, "Length of (MAJOR || MINOR || PATCH || FLAGS) must be 4!");
    _Static_assert(MAJOR_VERSION >= 0 && MAJOR_VERSION <= UINT8_MAX,
                   "MAJOR version must be between 0 and 255!");
    _Static_assert(MINOR_VERSION >= 0 && MINOR_VERSION <= UINT8_MAX,
                   "MINOR version must be between 0 and 255!");
    _Static_assert(PATCH_VERSION >= 0 && PATCH_VERSION <= UINT8_MAX,
                   "PATCH version must be between 0 and 255!");

    uint8_t response_flags = 0;
#ifdef DEBUG
    response_flags |= GET_VERSION_FLAG_DEBUG;
#endif  // DEBUG

    apdu_response_send_data(
        (const uint8_t *) &(uint8_t[APPVERSION_LEN]){(uint8_t) MAJOR_VERSION,
                                                     (uint8_t) MINOR_VERSION,
                                                     (uint8_t) PATCH_VERSION,
                                                     response_flags},
        APPVERSION_LEN,
        SWO_SUCCESS);
}
