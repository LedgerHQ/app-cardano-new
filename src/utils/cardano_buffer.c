/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "cardano_buffer.h"
#include "cbor.h"  // for cbor_writeToken
#include "app_assert.h"

bool buffer_read_bytes_ptr(buffer_t *buffer, const uint8_t **destBuffer, size_t n) {
    ASSERT(buffer != NULL);
    ASSERT(destBuffer != NULL);

    if (!buffer_can_read(buffer, n)) {
        return false;
    }

    *destBuffer = buffer_get_cur(buffer);
    return buffer_seek_cur(buffer, n);
}

bool buffer_write_cbor_token(buffer_t *buffer, uint8_t type, uint64_t value) {
    ASSERT(buffer != NULL);
    ASSERT(buffer_data_size(buffer) < BUFFER_SIZE_PARANOIA);

    size_t written = 0;
    if (!cbor_writeToken(type, value, buffer_get_cur(buffer), buffer_data_size(buffer), &written)) {
        // cbor_writeToken returns false on failure
        return false;
    }

    return buffer_seek_cur(buffer, written);
}
