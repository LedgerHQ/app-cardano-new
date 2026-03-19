/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include <cmocka.h>

#include "utils/cardano_buffer.h"
#include "utils/cbor.h"
#include "buffer.h"

static void test_buffer_data_size(void **state) {
    (void) state;

    assert_int_equal(buffer_data_size(NULL), 0);

    uint8_t raw[5] = {0};
    buffer_t buffer = {
        .ptr = raw,
        .size = sizeof(raw),
        .offset = 2,
    };

    assert_int_equal(buffer_data_size(&buffer), 3);
}

static void test_buffer_read_bytes_ptr(void **state) {
    (void) state;

    uint8_t raw[] = {0xAA, 0xBB, 0xCC, 0xDD};
    buffer_t buffer = {
        .ptr = raw,
        .size = sizeof(raw),
        .offset = 0,
    };

    const uint8_t *slice = NULL;
    assert_true(buffer_read_bytes_ptr(&buffer, &slice, 2));
    assert_ptr_equal(slice, raw);
    assert_int_equal(buffer.offset, 2);

    assert_true(buffer_read_bytes_ptr(&buffer, &slice, 2));
    assert_ptr_equal(slice, raw + 2);
    assert_int_equal(buffer.offset, 4);

    assert_false(buffer_read_bytes_ptr(&buffer, &slice, 1));
    assert_int_equal(buffer.offset, 4);
}

static void test_buffer_write_cbor_token(void **state) {
    (void) state;

    uint8_t raw[16] = {0};
    buffer_t buffer = buffer_create(raw, sizeof(raw));

    assert_true(buffer_write_cbor_token(&buffer, CBOR_TYPE_UNSIGNED, 0x15));
    assert_int_equal(raw[0], CBOR_TYPE_UNSIGNED | 0x15);
    assert_int_equal(buffer.offset, 1);

    assert_true(buffer_write_cbor_token(&buffer, CBOR_TYPE_UNSIGNED, 0x100));
    assert_int_equal(buffer.offset, 4);

    buffer_t tiny = buffer_create(raw, 1);
    assert_false(buffer_write_cbor_token(&tiny, CBOR_TYPE_UNSIGNED, 0xFFFF));
    assert_int_equal(tiny.offset, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_data_size),
        cmocka_unit_test(test_buffer_read_bytes_ptr),
        cmocka_unit_test(test_buffer_write_cbor_token),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
