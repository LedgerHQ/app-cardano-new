#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "transaction/tx_credential_types.h"
#include "addressUtils/bip44.h"
#include "cardano_constants.h"
#include "globals.h"

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

static bip44_path_t make_ordinary_staking_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = 2; // CARDANO_CHAIN_STAKING_KEY (not exported in headers)
    path.path[4] = 0;
    return path;
}

static bip44_path_t make_pool_cold_key_path(void) {
    bip44_path_t path;
    memset(&path, 0, sizeof(path));
    path.length = 4;
    path.path[0] = bip44_harden(PURPOSE_POOL_COLD_KEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = bip44_harden(0);
    return path;
}

static ext_credential_t make_stake_credential(void) {
    ext_credential_t credential;
    memset(&credential, 0, sizeof(credential));
    credential.type = EXT_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_ordinary_staking_path();
    return credential;
}

static ext_credential_t make_pool_cold_credential(void) {
    ext_credential_t credential;
    memset(&credential, 0, sizeof(credential));
    credential.type = EXT_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_pool_cold_key_path();
    return credential;
}

static void test_stake_registration_denied_in_pool_registration_owner(void **state) {
    (void) state;
    reset_context();

    ext_credential_t stake_credential = make_stake_credential();
    security_policy_t policy = policyForSignTxCertificateStaking(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
        CERTIFICATE_STAKE_REGISTRATION,
        &stake_credential
    );
    assert_int_equal(policy, POLICY_DENY);
}

static void test_stake_registration_denied_in_pool_registration_operator(void **state) {
    (void) state;
    reset_context();

    ext_credential_t stake_credential = make_stake_credential();
    security_policy_t policy = policyForSignTxCertificateStaking(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
        CERTIFICATE_STAKE_REGISTRATION,
        &stake_credential
    );
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_multisig(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_MULTISIG_TX,
        &pool_credential,
        0
    );
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_pool_registration_owner(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER,
        &pool_credential,
        0
    );
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_denied_in_pool_registration_operator(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR,
        &pool_credential,
        0
    );
    assert_int_equal(policy, POLICY_DENY);
}

static void test_pool_retirement_allowed_in_ordinary(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_ORDINARY_TX,
        &pool_credential,
        0
    );
    assert_int_equal(policy, POLICY_SHOW);
}

static void test_pool_retirement_allowed_in_plutus(void **state) {
    (void) state;
    reset_context();

    ext_credential_t pool_credential = make_pool_cold_credential();
    security_policy_t policy = policyForSignTxCertificateStakePoolRetirement(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX,
        &pool_credential,
        0
    );
    assert_int_equal(policy, POLICY_SHOW);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_stake_registration_denied_in_pool_registration_owner),
        cmocka_unit_test(test_stake_registration_denied_in_pool_registration_operator),
        cmocka_unit_test(test_pool_retirement_denied_in_multisig),
        cmocka_unit_test(test_pool_retirement_denied_in_pool_registration_owner),
        cmocka_unit_test(test_pool_retirement_denied_in_pool_registration_operator),
        cmocka_unit_test(test_pool_retirement_allowed_in_ordinary),
        cmocka_unit_test(test_pool_retirement_allowed_in_plutus),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
