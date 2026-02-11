#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "app_context.h"

#include "blake2b.h"

#include "test_address_derivation_fixtures_deny.h"
#include "test_fixture_types.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;

// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings);
void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings);

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
    (void) warnings;
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
    (void) warnings;
}

static void run_deny_fixture(const derive_address_fixture_t *fixture) {
    g_last_sw = 0;

    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };
    TRACE_BUFFER(buf.ptr, buf.size);
    TRACE("Running deny fixture: %s", fixture->name);
    apdu_response_begin(INS_DERIVE_ADDRESS);
    handler_derive_address(&buf, fixture->p1);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, fixture->check_expected);
}

static void test_derive_address_deny_0_derive_address_path_too_short(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[0]);
}

static void test_derive_address_deny_1_derive_address_invalid_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[1]);
}

static void test_derive_address_deny_2_derive_address_byron_with_shelley_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[2]);
}

static void test_derive_address_deny_3_derive_address_base_key_key_with_byron_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[3]);
}

static void test_derive_address_deny_4_derive_address_base_key_key_with_wrong_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[4]);
}

static void test_derive_address_deny_5_derive_address_base_key_key_with_wrong_staking_path_1(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[5]);
}

static void test_derive_address_deny_6_derive_address_base_key_script_with_byron_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[6]);
}

static void test_derive_address_deny_7_derive_address_base_address_scripthash_keyhash_not_allowed(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[7]);
}

static void test_derive_address_deny_8_derive_address_pointer_with_byron_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[8]);
}

static void test_derive_address_deny_9_derive_address_pointer_with_wrong_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[9]);
}

static void test_derive_address_deny_10_derive_address_enterprise_with_byron_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[10]);
}

static void test_derive_address_deny_11_derive_address_enterprise_with_wrong_spending_path(void **state) {
    (void) state;
    run_deny_fixture(&DERIVE_ADDRESS_DENY_FIXTURES[11]);
}

int main(void) {
    TRACE("Starting test_derive_address_deny_tests");
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_derive_address_deny_0_derive_address_path_too_short),
        cmocka_unit_test(test_derive_address_deny_1_derive_address_invalid_path),
        cmocka_unit_test(test_derive_address_deny_2_derive_address_byron_with_shelley_path),
        cmocka_unit_test(test_derive_address_deny_3_derive_address_base_key_key_with_byron_spending_path),
        cmocka_unit_test(test_derive_address_deny_4_derive_address_base_key_key_with_wrong_spending_path),
        cmocka_unit_test(test_derive_address_deny_5_derive_address_base_key_key_with_wrong_staking_path_1),
        cmocka_unit_test(test_derive_address_deny_6_derive_address_base_key_script_with_byron_spending_path),
        cmocka_unit_test(test_derive_address_deny_7_derive_address_base_address_scripthash_keyhash_not_allowed),
        cmocka_unit_test(test_derive_address_deny_8_derive_address_pointer_with_byron_spending_path),
        cmocka_unit_test(test_derive_address_deny_9_derive_address_pointer_with_wrong_spending_path),
        cmocka_unit_test(test_derive_address_deny_10_derive_address_enterprise_with_byron_spending_path),
        cmocka_unit_test(test_derive_address_deny_11_derive_address_enterprise_with_wrong_spending_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
