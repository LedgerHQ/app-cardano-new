#pragma once

#include <stddef.h>
#include <stdint.h>

#include "buffer.h"
#include "assert.h"

static inline size_t buffer_total_size(const buffer_t *buffer) {
    return buffer != NULL ? buffer->size : 0;
}

static inline size_t buffer_current_offset(const buffer_t *buffer) {
    return buffer != NULL ? buffer->offset : 0;
}

static inline size_t buffer_remaining(const buffer_t *buffer) {
    if (buffer == NULL) {
        return 0;
    }
    return buffer_total_size(buffer) - buffer_current_offset(buffer);
}

static inline const uint8_t *buffer_current_ptr(const buffer_t *buffer) {
    const uint8_t *current_ptr =
            (buffer != NULL && buffer->ptr != NULL)
                    ? (buffer->ptr + buffer_current_offset(buffer))
                    : NULL;
    LEDGER_ASSERT(current_ptr != NULL, "NULL buffer or buffer ptr");
    return current_ptr;
}

static inline bool buffer_consume(buffer_t *buffer, size_t length) {
    if (buffer == NULL) {
        return false;
    }
    return buffer_seek_cur(buffer, length);
}
