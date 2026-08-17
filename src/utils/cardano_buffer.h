/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "app_assert.h"
#include "app_context.h"

/**
 * Cardano-specific buffer extensions on top of the SDK buffer_t.
 *
 * The SDK buffer_t (buffer.h) now provides a unified read/write type with a
 * mutable ptr and full buffer_read/buffer_write family of functions. This file
 * provides only the Cardano-specific additions that are not part of the SDK.
 *
 * - For read/write operations use SDK's buffer_t and buffer_read/buffer_write family
 * - For buffer initialisation use SDK's buffer_create()
 * - For current position pointer use SDK's buffer_get_cur()
 */

/**
 * Return number of bytes remaining (unread/unwritten) in the buffer.
 *
 * @param[in] buffer Pointer to buffer struct.
 * @return Number of bytes from current offset to end of buffer.
 */
static inline size_t buffer_data_size(const buffer_t *buffer) {
    if (buffer == NULL) {
        return 0;
    }
    return buffer->size - buffer->offset;
}

/**
 * Reject a command if the buffer still has unconsumed bytes.
 * Sends a SW status word and resets the app state.
 *
 * @param[in] buffer Pointer to buffer struct.
 * @param[in] swo    Status word to send on error.
 * @return true if unconsumed bytes were found (error sent), false if buffer is fully consumed.
 */
static inline bool deny_unconsumed_bytes(const buffer_t *buffer, uint16_t swo) {
    ASSERT(buffer != NULL);
    if (!buffer_can_read(buffer, 1)) {
        return false;
    }
    send_swo_and_reset(swo);
    return true;
}

/**
 * Read n bytes from the buffer, storing a pointer into the buffer rather than copying.
 * The pointer is valid as long as the underlying buffer memory is valid.
 *
 * @param[in,out] buffer     Pointer to buffer struct.
 * @param[out]    destBuffer Set to point at the n bytes inside the buffer.
 * @param[in]     n          Number of bytes to read.
 * @return true if success, false if not enough bytes available.
 */
bool buffer_read_bytes_ptr(buffer_t *buffer, const uint8_t **destBuffer, size_t n);

/**
 * Write a CBOR-encoded token to the buffer.
 * Wraps cbor_writeToken with buffer safety checks.
 *
 * @param[in,out] buffer Pointer to buffer struct.
 * @param[in]     type   CBOR major type tag.
 * @param[in]     value  CBOR value.
 * @return true if success, false if not enough space.
 */
bool buffer_write_cbor_token(buffer_t *buffer, uint8_t type, uint64_t value);
