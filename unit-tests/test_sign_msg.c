// Unit tests for message signing (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_sign_msg_fixtures.h"
#include "test_sign_msg_common.h"

// ======================================================================
// CIP-8 Message Signing Tests (Auto-Generated)
// ======================================================================

static void test_sign_message_sign_msg_empty_message_with_keyhash_as_address_field_0(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[0]);
}

static void test_sign_message_sign_msg_short_nonhashed_ascii_message_with_keyhash_as_address_field_1(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[1]);
}

static void test_sign_message_sign_msg_short_hashed_ascii_message_with_keyhash_as_address_field_2(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[2]);
}

static void test_sign_message_sign_msg_short_nonhashed_ascii_message_displayed_as_hex_3(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[3]);
}

static void test_sign_message_sign_msg_short_nonhashed_hex_message_with_keyhash_as_address_field_4(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[4]);
}

static void test_sign_message_sign_msg_short_hashed_hex_message_with_keyhash_as_address_field_5(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[5]);
}

static void test_sign_message_sign_msg_198_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field_6(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[6]);
}

static void test_sign_message_sign_msg_99_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field_7(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[7]);
}

static void test_sign_message_sign_msg_1000_bytes_long_hashed_ascii_message_with_keyhash_as_address_field_8(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[8]);
}

static void test_sign_message_sign_msg_349_bytes_long_hashed_hex_message_with_keyhash_as_address_field_9(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[9]);
}

static void test_sign_message_sign_msg_short_nonhashed_hex_message_with_base_address_in_address_field_10(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[10]);
}

static void test_sign_message_sign_msg_short_nonhashed_hex_message_with_reward_address_in_address_field_11(void **state) {
    (void) state;
    run_fixture(&SIGN_MSG_FIXTURES[11]);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_message_sign_msg_empty_message_with_keyhash_as_address_field_0),
        cmocka_unit_test(test_sign_message_sign_msg_short_nonhashed_ascii_message_with_keyhash_as_address_field_1),
        cmocka_unit_test(test_sign_message_sign_msg_short_hashed_ascii_message_with_keyhash_as_address_field_2),
        cmocka_unit_test(test_sign_message_sign_msg_short_nonhashed_ascii_message_displayed_as_hex_3),
        cmocka_unit_test(test_sign_message_sign_msg_short_nonhashed_hex_message_with_keyhash_as_address_field_4),
        cmocka_unit_test(test_sign_message_sign_msg_short_hashed_hex_message_with_keyhash_as_address_field_5),
        cmocka_unit_test(test_sign_message_sign_msg_198_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field_6),
        cmocka_unit_test(test_sign_message_sign_msg_99_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field_7),
        cmocka_unit_test(test_sign_message_sign_msg_1000_bytes_long_hashed_ascii_message_with_keyhash_as_address_field_8),
        cmocka_unit_test(test_sign_message_sign_msg_349_bytes_long_hashed_hex_message_with_keyhash_as_address_field_9),
        cmocka_unit_test(test_sign_message_sign_msg_short_nonhashed_hex_message_with_base_address_in_address_field_10),
        cmocka_unit_test(test_sign_message_sign_msg_short_nonhashed_hex_message_with_reward_address_in_address_field_11),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
