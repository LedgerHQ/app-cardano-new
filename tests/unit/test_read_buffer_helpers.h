/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "buffer.h"

typedef struct {
    buffer_t sdk_buffer;
    uint8_t* mutable_copy;
    size_t data_length;
} test_read_buffer_t;

static inline test_read_buffer_t make_test_read_buffer(const uint8_t* source_data, size_t source_length) {
    test_read_buffer_t test_buffer = {0};

    const size_t allocated_length = (source_length > 0) ? source_length : 1;
    test_buffer.mutable_copy = (uint8_t*) malloc(allocated_length);
    assert_non_null(test_buffer.mutable_copy);

    if (source_length > 0) {
        assert_non_null(source_data);
        memcpy(test_buffer.mutable_copy, source_data, source_length);
    }

    test_buffer.data_length = source_length;
    test_buffer.sdk_buffer = (buffer_t) {
        .ptr = test_buffer.mutable_copy,
        .size = source_length,
        .offset = 0,
    };
    return test_buffer;
}

static inline void assert_read_buffer_unchanged_and_cleanup(test_read_buffer_t* test_buffer, const uint8_t* source_data) {
    assert_non_null(test_buffer);
    assert_non_null(test_buffer->mutable_copy);

    if (test_buffer->data_length > 0) {
        assert_non_null(source_data);
        assert_memory_equal(test_buffer->mutable_copy, source_data, test_buffer->data_length);
    }

    free(test_buffer->mutable_copy);
    test_buffer->mutable_copy = NULL;
    test_buffer->data_length = 0;
    test_buffer->sdk_buffer.ptr = NULL;
    test_buffer->sdk_buffer.size = 0;
    test_buffer->sdk_buffer.offset = 0;
}
