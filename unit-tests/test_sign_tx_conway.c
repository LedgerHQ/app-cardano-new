// Unit tests for transaction signing (auto-generated)
// DO NOT EDIT - regenerate using generators/generate_unit_tests_from_ragger.py

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "handler/sign_tx.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "cardano_constants.h"
#include "globals.h"
#include "tx.h"
#include "tx_parse.h"
#include "securityPolicy/securityPolicy.h"
#include "hexUtils.h"
#include "utils/utils.h"
#include "blake2b.h"
#include "init_apdu.h"
#include "io_capture.h"

#include "test_sign_tx_fixtures_conway.h"

#include "test_sign_tx_common.h"
#include "app_mem_utils.h"

// ======================================================================
// UI code: using REAL ui_display_*.c with mocked NBGL
// ======================================================================
// The real UI code from ../src/ui/ui_display_tx.c and ui_display_witness.c
// is included in cardano_sign_tx_core library. It calls NBGL functions which
// are mocked in mock_sources/nbgl_mock.c to auto-approve for testing.
// This way we test the actual UI formatting, tag-value pair generation,
// and state management logic.

// ======================================================================
// CONWAY Era Tests
// ======================================================================

static void test_sign_tx_with_a_stake_registration_path_certificate_conway_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_REGISTRATION_PATH_CERTIFICATE_CONWAY, false);
}

static void test_sign_tx_with_a_stake_registration_path_certificate_conway_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_REGISTRATION_PATH_CERTIFICATE_CONWAY, false);
}

static void test_sign_tx_with_a_stake_registration_path_certificate_conway_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_REGISTRATION_PATH_CERTIFICATE_CONWAY, true);
}

static void test_sign_tx_with_a_stake_registration_path_certificate_conway_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_REGISTRATION_PATH_CERTIFICATE_CONWAY, true);
}

static void test_sign_tx_with_a_stake_deregistration_path_certificate_conway_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_DEREGISTRATION_PATH_CERTIFICATE_CONWAY, false);
}

static void test_sign_tx_with_a_stake_deregistration_path_certificate_conway_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_DEREGISTRATION_PATH_CERTIFICATE_CONWAY, false);
}

static void test_sign_tx_with_a_stake_deregistration_path_certificate_conway_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_DEREGISTRATION_PATH_CERTIFICATE_CONWAY, true);
}

static void test_sign_tx_with_a_stake_deregistration_path_certificate_conway_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_A_STAKE_DEREGISTRATION_PATH_CERTIFICATE_CONWAY, true);
}

static void test_sign_tx_with_vote_delegation_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_VOTE_DELEGATION_CERTIFICATES, false);
}

static void test_sign_tx_with_vote_delegation_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_VOTE_DELEGATION_CERTIFICATES, false);
}

static void test_sign_tx_with_vote_delegation_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_VOTE_DELEGATION_CERTIFICATES, true);
}

static void test_sign_tx_with_vote_delegation_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_VOTE_DELEGATION_CERTIFICATES, true);
}

static void test_sign_tx_with_stake_pool_and_drep_delegation_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_STAKE_POOL_AND_DREP_DELEGATION_CERTIFICATES, false);
}

static void test_sign_tx_with_stake_pool_and_drep_delegation_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_STAKE_POOL_AND_DREP_DELEGATION_CERTIFICATES, false);
}

static void test_sign_tx_with_stake_pool_and_drep_delegation_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_STAKE_POOL_AND_DREP_DELEGATION_CERTIFICATES, true);
}

static void test_sign_tx_with_stake_pool_and_drep_delegation_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_STAKE_POOL_AND_DREP_DELEGATION_CERTIFICATES, true);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_CERTIFICATE, true);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_CERTIFICATE, true);
}

static void test_sign_tx_with_account_registration_delegation_to_drep_certificate_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_drep_certificate_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_drep_certificate_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP_CERTIFICATE, true);
}

static void test_sign_tx_with_account_registration_delegation_to_drep_certificate_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP_CERTIFICATE, true);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP_CERTIFICATE, false);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP_CERTIFICATE, true);
}

static void test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP_CERTIFICATE, true);
}

static void test_sign_tx_with_all_certificates_except_pool_registration_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ALL_CERTIFICATES_EXCEPT_POOL_REGISTRATION, false);
}

static void test_sign_tx_with_all_certificates_except_pool_registration_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ALL_CERTIFICATES_EXCEPT_POOL_REGISTRATION, false);
}

static void test_sign_tx_with_all_certificates_except_pool_registration_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ALL_CERTIFICATES_EXCEPT_POOL_REGISTRATION, true);
}

static void test_sign_tx_with_all_certificates_except_pool_registration_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_ALL_CERTIFICATES_EXCEPT_POOL_REGISTRATION, true);
}

static void test_sign_tx_with_authorize_committee_hot_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_AUTHORIZE_COMMITTEE_HOT_CERTIFICATES, false);
}

static void test_sign_tx_with_authorize_committee_hot_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_AUTHORIZE_COMMITTEE_HOT_CERTIFICATES, false);
}

static void test_sign_tx_with_authorize_committee_hot_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_AUTHORIZE_COMMITTEE_HOT_CERTIFICATES, true);
}

static void test_sign_tx_with_authorize_committee_hot_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_AUTHORIZE_COMMITTEE_HOT_CERTIFICATES, true);
}

static void test_sign_tx_with_resign_committee_cold_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_RESIGN_COMMITTEE_COLD_CERTIFICATES, false);
}

static void test_sign_tx_with_resign_committee_cold_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_RESIGN_COMMITTEE_COLD_CERTIFICATES, false);
}

static void test_sign_tx_with_resign_committee_cold_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_RESIGN_COMMITTEE_COLD_CERTIFICATES, true);
}

static void test_sign_tx_with_resign_committee_cold_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_RESIGN_COMMITTEE_COLD_CERTIFICATES, true);
}

static void test_sign_tx_with_drep_registration_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_REGISTRATION_CERTIFICATES, false);
}

static void test_sign_tx_with_drep_registration_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_REGISTRATION_CERTIFICATES, false);
}

static void test_sign_tx_with_drep_registration_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_REGISTRATION_CERTIFICATES, true);
}

static void test_sign_tx_with_drep_registration_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_REGISTRATION_CERTIFICATES, true);
}

static void test_sign_tx_with_drep_deregistration_certificate_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_DEREGISTRATION_CERTIFICATE, false);
}

static void test_sign_tx_with_drep_deregistration_certificate_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_DEREGISTRATION_CERTIFICATE, false);
}

static void test_sign_tx_with_drep_deregistration_certificate_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_DEREGISTRATION_CERTIFICATE, true);
}

static void test_sign_tx_with_drep_deregistration_certificate_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_DEREGISTRATION_CERTIFICATE, true);
}

static void test_sign_tx_with_drep_update_certificates_expert_off(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_UPDATE_CERTIFICATES, false);
}

static void test_sign_tx_with_drep_update_certificates_reject_tx_expert_off(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_UPDATE_CERTIFICATES, false);
}

static void test_sign_tx_with_drep_update_certificates_expert_on(void **state) {
    (void) state;
    run_fixture_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_UPDATE_CERTIFICATES, true);
}

static void test_sign_tx_with_drep_update_certificates_reject_tx_expert_on(void **state) {
    (void) state;
    run_fixture_reject_tx_with_expert_mode(&FIXTURE_CONWAY_SIGN_TX_WITH_DREP_UPDATE_CERTIFICATES, true);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_tx_with_a_stake_registration_path_certificate_conway_expert_off),
        cmocka_unit_test(test_sign_tx_with_a_stake_registration_path_certificate_conway_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_a_stake_registration_path_certificate_conway_expert_on),
        cmocka_unit_test(test_sign_tx_with_a_stake_registration_path_certificate_conway_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_a_stake_deregistration_path_certificate_conway_expert_off),
        cmocka_unit_test(test_sign_tx_with_a_stake_deregistration_path_certificate_conway_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_a_stake_deregistration_path_certificate_conway_expert_on),
        cmocka_unit_test(test_sign_tx_with_a_stake_deregistration_path_certificate_conway_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_vote_delegation_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_vote_delegation_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_vote_delegation_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_vote_delegation_certificates_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_stake_pool_and_drep_delegation_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_stake_pool_and_drep_delegation_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_stake_pool_and_drep_delegation_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_stake_pool_and_drep_delegation_certificates_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_certificate_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_drep_certificate_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_drep_certificate_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_drep_certificate_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_drep_certificate_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_expert_on),
        cmocka_unit_test(test_sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_all_certificates_except_pool_registration_expert_off),
        cmocka_unit_test(test_sign_tx_with_all_certificates_except_pool_registration_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_all_certificates_except_pool_registration_expert_on),
        cmocka_unit_test(test_sign_tx_with_all_certificates_except_pool_registration_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_authorize_committee_hot_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_authorize_committee_hot_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_authorize_committee_hot_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_authorize_committee_hot_certificates_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_resign_committee_cold_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_resign_committee_cold_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_resign_committee_cold_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_resign_committee_cold_certificates_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_registration_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_registration_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_registration_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_registration_certificates_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_deregistration_certificate_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_deregistration_certificate_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_deregistration_certificate_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_deregistration_certificate_reject_tx_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_update_certificates_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_update_certificates_reject_tx_expert_off),
        cmocka_unit_test(test_sign_tx_with_drep_update_certificates_expert_on),
        cmocka_unit_test(test_sign_tx_with_drep_update_certificates_reject_tx_expert_on),
    };
    return _cmocka_run_group_tests("test_sign_tx_conway", tests, ARRAY_LEN(tests), NULL, NULL);
}
