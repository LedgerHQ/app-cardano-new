// Unit tests for native script hash derivation (auto-generated)
// Following AGENTS.md: 'Mimic Established Patterns'

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

//#include "test_derive_native_script_fixtures.h"
#include "test_derive_native_script_common.h"

// ======================================================================
// Native Script Hash Derivation Tests (Auto-Generated)
// ======================================================================

static void test_derive_native_script_pubkey_device_owned(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[0]);
}

static void test_derive_native_script_pubkey_third_party(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[1]);
}

static void test_derive_native_script_pubkey_third_party_script_hash_displayed_as_policy_id(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[2]);
}

static void test_derive_native_script_all_script(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[3]);
}

static void test_derive_native_script_all_script_no_subscripts(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[4]);
}

static void test_derive_native_script_any_script(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[5]);
}

static void test_derive_native_script_any_script_no_subscripts(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[6]);
}

static void test_derive_native_script_n_of_k_script(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[7]);
}

static void test_derive_native_script_n_of_k_script_no_subscripts(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[8]);
}

static void test_derive_native_script_invalid_before_script(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[9]);
}

static void test_derive_native_script_invalid_before_script_slot_is_a_big_number(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[10]);
}

static void test_derive_native_script_invalid_hereafter_script(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[11]);
}

static void test_derive_native_script_invalid_hereafter_script_slot_is_a_big_number(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[12]);
}

static void test_derive_native_script_nested_native_scripts(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[13]);
}

static void test_derive_native_script_nested_native_scripts_num2(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[14]);
}

static void test_derive_native_script_nested_native_scripts_num3(void **state) {
    (void) state;
    run_fixture(&NATIVE_SCRIPT_FIXTURES[15]);
}
// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_derive_native_script_pubkey_device_owned),
        cmocka_unit_test(test_derive_native_script_pubkey_third_party),
        cmocka_unit_test(test_derive_native_script_pubkey_third_party_script_hash_displayed_as_policy_id),
        cmocka_unit_test(test_derive_native_script_all_script),
        cmocka_unit_test(test_derive_native_script_all_script_no_subscripts),
        cmocka_unit_test(test_derive_native_script_any_script),
        cmocka_unit_test(test_derive_native_script_any_script_no_subscripts),
        cmocka_unit_test(test_derive_native_script_n_of_k_script),
        cmocka_unit_test(test_derive_native_script_n_of_k_script_no_subscripts),
        cmocka_unit_test(test_derive_native_script_invalid_before_script),
        cmocka_unit_test(test_derive_native_script_invalid_before_script_slot_is_a_big_number),
        cmocka_unit_test(test_derive_native_script_invalid_hereafter_script),
        cmocka_unit_test(test_derive_native_script_invalid_hereafter_script_slot_is_a_big_number),
        cmocka_unit_test(test_derive_native_script_nested_native_scripts),
        cmocka_unit_test(test_derive_native_script_nested_native_scripts_num2),
        cmocka_unit_test(test_derive_native_script_nested_native_scripts_num3),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
