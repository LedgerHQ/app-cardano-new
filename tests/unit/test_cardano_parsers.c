/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"

static void fill_bytes(uint8_t *buffer, size_t buffer_size, uint8_t value) {
    memset(buffer, value, buffer_size);
}

static void test_buffer_read_flag_included_rejects_truncated_input(void **state) {
    (void) state;

    buffer_t buf = buffer_create(NULL, 0);
    bool is_included = false;

    assert_false(buffer_read_flag_included(&buf, &is_included));
}

static void test_buffer_read_flag_included_rejects_invalid_wire_value(void **state) {
    (void) state;

    uint8_t raw[] = {0x00};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    bool is_included = false;

    assert_false(buffer_read_flag_included(&buf, &is_included));
}

static void test_buffer_read_bytes_rejects_short_buffer(void **state) {
    (void) state;

    uint8_t raw[] = {0x01, 0x02};
    uint8_t out[3] = {0};
    buffer_t buf = buffer_create(raw, sizeof(raw));

    assert_false(buffer_read_bytes(&buf, out, sizeof(out)));
}

static void test_buffer_read_int64_rejects_short_buffer(void **state) {
    (void) state;

    uint8_t raw[] = {0x01, 0x02, 0x03};
    int64_t value = 0;
    buffer_t buf = buffer_create(raw, sizeof(raw));

    assert_false(buffer_read_int64(&buf, &value, BE));
}

static void test_buffer_read_anchor_rejects_invalid_flag(void **state) {
    (void) state;

    uint8_t raw[] = {0x00};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_anchor_rejects_oversized_url(void **state) {
    (void) state;

    uint8_t raw[] = {FLAG_INCLUDED_YES, 0x01, 0x00};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_anchor_rejects_truncated_url_length(void **state) {
    (void) state;

    uint8_t raw[] = {FLAG_INCLUDED_YES};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_anchor_rejects_truncated_url_bytes(void **state) {
    (void) state;

    uint8_t raw[] = {FLAG_INCLUDED_YES, 0x00, 0x01};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_anchor_rejects_non_printable_url(void **state) {
    (void) state;

    uint8_t raw[4 + ANCHOR_HASH_LENGTH] = {0};
    raw[0] = FLAG_INCLUDED_YES;
    raw[1] = 0x00;
    raw[2] = 0x01;
    raw[3] = 0x20;  // spaces are forbidden
    fill_bytes(&raw[4], ANCHOR_HASH_LENGTH, 0xAA);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_anchor_rejects_truncated_hash(void **state) {
    (void) state;

    uint8_t raw[4 + ANCHOR_HASH_LENGTH - 1] = {0};
    raw[0] = FLAG_INCLUDED_YES;
    raw[1] = 0x00;
    raw[2] = 0x01;
    raw[3] = 'a';
    fill_bytes(&raw[4], ANCHOR_HASH_LENGTH - 1, 0xAA);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    anchor_t anchor = {0};

    assert_false(buffer_read_anchor(&buf, &anchor));
}

static void test_buffer_read_drep_rejects_invalid_type(void **state) {
    (void) state;

    uint8_t raw[] = {0xFF};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_drep_t drep = {0};

    assert_false(buffer_read_drep(&buf, &drep));
}

static void test_buffer_read_drep_rejects_truncated_type_byte(void **state) {
    (void) state;

    buffer_t buf = buffer_create(NULL, 0);
    ext_drep_t drep = {0};

    assert_false(buffer_read_drep(&buf, &drep));
}

static void test_buffer_read_drep_rejects_truncated_key_path(void **state) {
    (void) state;

    uint8_t raw[] = {
        EXT_DREP_KEY_PATH,
        0x02,  // claims 2 path elements
        0x80,
        0x00,
        0x07,
        0x3c,  // only one element present
    };
    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_drep_t drep = {0};

    assert_false(buffer_read_drep(&buf, &drep));
}

static void test_buffer_read_drep_rejects_truncated_key_hash(void **state) {
    (void) state;

    uint8_t raw[ADDRESS_KEY_HASH_LENGTH] = {0};
    raw[0] = EXT_DREP_KEY_HASH;
    fill_bytes(&raw[1], ADDRESS_KEY_HASH_LENGTH - 1, 0x11);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_drep_t drep = {0};

    assert_false(buffer_read_drep(&buf, &drep));
}

static void test_buffer_read_drep_rejects_truncated_script_hash(void **state) {
    (void) state;

    uint8_t raw[SCRIPT_HASH_LENGTH] = {0};
    raw[0] = EXT_DREP_SCRIPT_HASH;
    fill_bytes(&raw[1], SCRIPT_HASH_LENGTH - 1, 0x22);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_drep_t drep = {0};

    assert_false(buffer_read_drep(&buf, &drep));
}

static void test_buffer_read_credential_rejects_invalid_type(void **state) {
    (void) state;

    uint8_t raw[] = {0xFF};
    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_credential_t credential = {0};

    assert_false(buffer_read_credential(&buf, &credential));
}

static void test_buffer_read_credential_rejects_truncated_type_byte(void **state) {
    (void) state;

    buffer_t buf = buffer_create(NULL, 0);
    ext_credential_t credential = {0};

    assert_false(buffer_read_credential(&buf, &credential));
}

static void test_buffer_read_credential_rejects_truncated_key_hash(void **state) {
    (void) state;

    uint8_t raw[ADDRESS_KEY_HASH_LENGTH] = {0};
    raw[0] = EXT_CREDENTIAL_KEY_HASH;
    fill_bytes(&raw[1], ADDRESS_KEY_HASH_LENGTH - 1, 0x33);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_credential_t credential = {0};

    assert_false(buffer_read_credential(&buf, &credential));
}

static void test_buffer_read_credential_rejects_truncated_key_path(void **state) {
    (void) state;

    uint8_t raw[] = {
        EXT_CREDENTIAL_KEY_PATH,
        0x02,  // claims 2 path elements
        0x80,
        0x00,
        0x07,
        0x3c,  // only one element present
    };
    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_credential_t credential = {0};

    assert_false(buffer_read_credential(&buf, &credential));
}

static void test_buffer_read_credential_rejects_truncated_script_hash(void **state) {
    (void) state;

    uint8_t raw[SCRIPT_HASH_LENGTH] = {0};
    raw[0] = EXT_CREDENTIAL_SCRIPT_HASH;
    fill_bytes(&raw[1], SCRIPT_HASH_LENGTH - 1, 0x44);

    buffer_t buf = buffer_create(raw, sizeof(raw));
    ext_credential_t credential = {0};

    assert_false(buffer_read_credential(&buf, &credential));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_read_flag_included_rejects_truncated_input),
        cmocka_unit_test(test_buffer_read_flag_included_rejects_invalid_wire_value),
        cmocka_unit_test(test_buffer_read_bytes_rejects_short_buffer),
        cmocka_unit_test(test_buffer_read_int64_rejects_short_buffer),
        cmocka_unit_test(test_buffer_read_anchor_rejects_invalid_flag),
        cmocka_unit_test(test_buffer_read_anchor_rejects_oversized_url),
        cmocka_unit_test(test_buffer_read_anchor_rejects_truncated_url_length),
        cmocka_unit_test(test_buffer_read_anchor_rejects_truncated_url_bytes),
        cmocka_unit_test(test_buffer_read_anchor_rejects_non_printable_url),
        cmocka_unit_test(test_buffer_read_anchor_rejects_truncated_hash),
        cmocka_unit_test(test_buffer_read_drep_rejects_invalid_type),
        cmocka_unit_test(test_buffer_read_drep_rejects_truncated_type_byte),
        cmocka_unit_test(test_buffer_read_drep_rejects_truncated_key_path),
        cmocka_unit_test(test_buffer_read_drep_rejects_truncated_key_hash),
        cmocka_unit_test(test_buffer_read_drep_rejects_truncated_script_hash),
        cmocka_unit_test(test_buffer_read_credential_rejects_invalid_type),
        cmocka_unit_test(test_buffer_read_credential_rejects_truncated_type_byte),
        cmocka_unit_test(test_buffer_read_credential_rejects_truncated_key_hash),
        cmocka_unit_test(test_buffer_read_credential_rejects_truncated_key_path),
        cmocka_unit_test(test_buffer_read_credential_rejects_truncated_script_hash),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
