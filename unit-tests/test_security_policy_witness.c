/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Focused policy tests for witness and CVote vote-key functions.
 *
 * Philosophy: we test non-trivial invariants that would be hard to catch
 * through handler-level fixtures alone, not exhaustive mirrors of the
 * switch/case logic.  Three invariants are covered:
 *
 *  1. Plutus witness policy never DENYs any ordinarily-valid signing path.
 *     (Plutus is the most permissive mode; a regression here would silently
 *      block legitimate Plutus tx witnesses.)
 *
 *  2. policyForSignCVoteWitness: only PATH_CVOTE_KEY is allowed; every
 *     other path class is DENY.  This is a tight allowlist with security
 *     implications.
 *
 *  3. policyForCVoteRegistrationVoteKey: KEY_PATH credential is rejected
 *     when the format is CIP15 (only CIP36 permits a path-based vote key).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "addressUtils/bip44.h"
#include "globals.h"

static void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

// ======================================================================
// Path builders
// Chain index values mirror the CARDANO_CHAIN_* local enum in bip44.c:
//   external=0, internal=1, staking=2, drep=3, committee_cold=4, committee_hot=5
// ======================================================================

static bip44_path_t make_shelley_payment_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;  // external chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_shelley_staking_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 2;  // staking key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_multisig_payment_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_MULTISIG);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;  // external chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_multisig_staking_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_MULTISIG);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 2;  // staking key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_drep_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 3;  // drep key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_committee_cold_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 4;  // committee cold key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_committee_hot_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_SHELLEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 5;  // committee hot key chain
    p.path[4] = 0;
    return p;
}

static bip44_path_t make_mint_path(void) {
    bip44_path_t p = {0};
    p.length = 3;
    p.path[0] = bip44_harden(PURPOSE_MINT);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    return p;
}

static bip44_path_t make_pool_cold_key_path(void) {
    bip44_path_t p = {0};
    p.length = 4;
    p.path[0] = bip44_harden(PURPOSE_POOL_COLD_KEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = bip44_harden(0);
    return p;
}

static bip44_path_t make_cvote_key_path(void) {
    bip44_path_t p = {0};
    p.length = 5;
    p.path[0] = bip44_harden(PURPOSE_CVOTE_KEY);
    p.path[1] = bip44_harden(ADA_COIN_TYPE);
    p.path[2] = bip44_harden(0);
    p.path[3] = 0;
    p.path[4] = 0;
    return p;
}

// ======================================================================
// 1. Plutus witness policy never DENYs ordinarily-valid signing paths
// ======================================================================

static void test_plutus_witness_payment_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_staking_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_multisig_payment_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_multisig_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_multisig_staking_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_multisig_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_drep_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_drep_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_committee_cold_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_committee_cold_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_committee_hot_path_not_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_committee_hot_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_plutus_witness_mint_path_not_denied_when_mint_present(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_mint_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, true /* mintPresent */, NULL, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// Pool cold key is the one path class explicitly denied in Plutus mode —
// verify the DENY is still in place (regression guard for the opposite direction).
static void test_plutus_witness_pool_cold_key_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignTxWitness(
        SIGN_TX_SIGNINGMODE_PLUTUS_TX, false, &path, false, NULL, &w);
    assert_int_equal(policy, POLICY_DENY);
}

// ======================================================================
// 2. policyForSignCVoteWitness: tight allowlist — only cvote key allowed
// ======================================================================

static void test_cvote_witness_cvote_key_allowed(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_payment_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_payment_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_staking_path_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_shelley_staking_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_witness_pool_cold_key_denied(void **state) {
    (void) state;
    reset_context();
    bip44_path_t path = make_pool_cold_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForSignCVoteWitness(&path, &w);
    assert_int_equal(policy, POLICY_DENY);
}

// ======================================================================
// 3. policyForCVoteRegistrationVoteKey: KEY_PATH requires CIP36 format
// ======================================================================

static void test_cvote_vote_key_path_denied_for_cip15(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP15, &w);
    assert_int_equal(policy, POLICY_DENY);
}

static void test_cvote_vote_key_path_allowed_for_cip36(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY_PATH;
    credential.keyPath = make_cvote_key_path();
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP36, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// Raw public key credential is always allowed regardless of format
static void test_cvote_vote_key_raw_pubkey_allowed_for_cip15(void **state) {
    (void) state;
    reset_context();
    cvote_credential_t credential = {0};
    credential.type = CVOTE_CREDENTIAL_KEY;
    warning_bits_t w = 0;
    security_policy_t policy = policyForCVoteRegistrationVoteKey(&credential, CIP15, &w);
    assert_int_not_equal(policy, POLICY_DENY);
}

// ======================================================================
// Main
// ======================================================================

int main(void) {
    const struct CMUnitTest tests[] = {
        // Plutus witness: ordinarily-valid paths not denied
        cmocka_unit_test(test_plutus_witness_payment_path_not_denied),
        cmocka_unit_test(test_plutus_witness_staking_path_not_denied),
        cmocka_unit_test(test_plutus_witness_multisig_payment_path_not_denied),
        cmocka_unit_test(test_plutus_witness_multisig_staking_path_not_denied),
        cmocka_unit_test(test_plutus_witness_drep_path_not_denied),
        cmocka_unit_test(test_plutus_witness_committee_cold_path_not_denied),
        cmocka_unit_test(test_plutus_witness_committee_hot_path_not_denied),
        cmocka_unit_test(test_plutus_witness_mint_path_not_denied_when_mint_present),
        cmocka_unit_test(test_plutus_witness_pool_cold_key_denied),
        // CVote witness allowlist
        cmocka_unit_test(test_cvote_witness_cvote_key_allowed),
        cmocka_unit_test(test_cvote_witness_payment_path_denied),
        cmocka_unit_test(test_cvote_witness_staking_path_denied),
        cmocka_unit_test(test_cvote_witness_pool_cold_key_denied),
        // CVote vote key: KEY_PATH format gating
        cmocka_unit_test(test_cvote_vote_key_path_denied_for_cip15),
        cmocka_unit_test(test_cvote_vote_key_path_allowed_for_cip36),
        cmocka_unit_test(test_cvote_vote_key_raw_pubkey_allowed_for_cip15),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
