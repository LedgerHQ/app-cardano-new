/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>

#include "os.h"
#include "io.h"
#include "buffer.h"

#include "get_serial.h"
#include "cardano_swo.h"
#include "assert.h"
#include "app_context.h"
#include "buffer_helpers.h"
#include "utils.h"

/**
 * Device serial number length as returned by os_serial().
 * Standard Ledger device serial is 7 bytes.
 */
#define SERIAL_LENGTH 7

void handler_get_serial(const buffer_t *data_buffer) {
    LEDGER_ASSERT(data_buffer != NULL, "NULL data_buffer");

    // Verify no data is present
    if (deny_unconsumed_bytes(data_buffer, SWO_WRONG_DATA_LENGTH)) {
        TRACE("Get serial APDU must be empty");
        return;
    }

    uint8_t serial[SERIAL_LENGTH] = {0};

    // Get device serial from the system
    size_t len = os_serial(serial, SERIAL_LENGTH);

    // Verify we got the expected length
    LEDGER_ASSERT(len == SERIAL_LENGTH, "Bad serial len");

    apdu_response_send_data(serial, SERIAL_LENGTH, SWO_SUCCESS);
}
