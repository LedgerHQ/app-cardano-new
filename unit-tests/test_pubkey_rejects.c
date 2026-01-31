// Unit tests for public key export rejects (auto-generated)

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "test_pubkey_fixtures_rejects.h"
#include "test_pubkey_common.h"

// ======================================================================
// Public Key Export Reject Tests (Auto-Generated)
// ======================================================================

static void test_pubkey_reject_0_export_pubkey_path_shorter_than_3_indexes(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[0]);
}

static void test_pubkey_reject_1_export_pubkey_path_not_matching_cold_key_structure(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[1]);
}

static void test_pubkey_reject_2_export_pubkey_invalid_vote_key_path_1(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[2]);
}

static void test_pubkey_reject_3_export_pubkey_invalid_vote_key_path_2(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[3]);
}

static void test_pubkey_reject_4_export_pubkey_invalid_vote_key_path_3(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[4]);
}

static void test_pubkey_reject_5_export_pubkey_invalid_multisig_account_not_hardened(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[5]);
}

static void test_pubkey_reject_6_export_pubkey_invalid_multisig_chain(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[6]);
}

static void test_pubkey_reject_7_export_pubkey_invalid_multisig_address_hardened(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[7]);
}

static void test_pubkey_reject_8_export_pubkey_invalid_mint_policy_not_hardened(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[8]);
}

static void test_pubkey_reject_9_export_pubkey_invalid_drep_chain(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[9]);
}

static void test_pubkey_reject_10_export_pubkey_invalid_committee_cold_address_hardened(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[10]);
}

static void test_pubkey_reject_11_export_pubkey_invalid_committee_hot_account_not_hardened(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[11]);
}

static void test_pubkey_reject_12_export_pubkey_invalid_pool_cold_usecase(void **state) {
    (void) state;
    run_fixture(&PUBKEY_REJECT_FIXTURES[12]);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pubkey_reject_0_export_pubkey_path_shorter_than_3_indexes),
        cmocka_unit_test(test_pubkey_reject_1_export_pubkey_path_not_matching_cold_key_structure),
        cmocka_unit_test(test_pubkey_reject_2_export_pubkey_invalid_vote_key_path_1),
        cmocka_unit_test(test_pubkey_reject_3_export_pubkey_invalid_vote_key_path_2),
        cmocka_unit_test(test_pubkey_reject_4_export_pubkey_invalid_vote_key_path_3),
        cmocka_unit_test(test_pubkey_reject_5_export_pubkey_invalid_multisig_account_not_hardened),
        cmocka_unit_test(test_pubkey_reject_6_export_pubkey_invalid_multisig_chain),
        cmocka_unit_test(test_pubkey_reject_7_export_pubkey_invalid_multisig_address_hardened),
        cmocka_unit_test(test_pubkey_reject_8_export_pubkey_invalid_mint_policy_not_hardened),
        cmocka_unit_test(test_pubkey_reject_9_export_pubkey_invalid_drep_chain),
        cmocka_unit_test(test_pubkey_reject_10_export_pubkey_invalid_committee_cold_address_hardened),
        cmocka_unit_test(test_pubkey_reject_11_export_pubkey_invalid_committee_hot_account_not_hardened),
        cmocka_unit_test(test_pubkey_reject_12_export_pubkey_invalid_pool_cold_usecase),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
