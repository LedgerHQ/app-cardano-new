/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cardano_buffer.h"
#include "cbor.h"   // for cbor_writeToken
#include "assert.h"

bool buffer_read_bytes_ptr(buffer_t *buffer, const uint8_t **destBuffer, size_t n) {
    LEDGER_ASSERT(buffer != NULL, "NULL buffer");
    LEDGER_ASSERT(destBuffer != NULL, "NULL destination");

    if (!buffer_can_read(buffer, n)) {
        return false;
    }

    *destBuffer = buffer_get_cur(buffer);
    return buffer_seek_cur(buffer, n);
}

bool buffer_write_cbor_token(buffer_t *buffer, uint8_t type, uint64_t value) {
    ASSERT(buffer_data_size(buffer) <= BUFFER_SIZE_PARANOIA);

    if (!buffer_can_read(buffer, 1)) {
        return false;
    }

    size_t written = 0;
    if (!cbor_writeToken(type, value,
                         buffer_get_cur(buffer),
                         buffer_data_size(buffer),
                         &written)) {
        // cbor_writeToken returns false on failure
        return false;
    }

    return buffer_seek_cur(buffer, written);
}
