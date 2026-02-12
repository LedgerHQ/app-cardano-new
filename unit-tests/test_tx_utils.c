/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "tx_utils.h"
#include "tx.h"

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

static bip44_path_t make_wallet_path(uint32_t purpose, uint32_t account, uint32_t chain, uint32_t address) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(purpose);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = chain;
    path.path[4] = address;
    return path;
}

static void test_single_account_store_and_reuse_same_account(void **state) {
    (void) state;
    reset_test_context();

    bip44_path_t path0 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 0);
    bip44_path_t path1 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 1);

    assert_false(violatesSingleAccountOrStoreIt(&path0));
    assert_true(G_context.tx_info.single_account_data.isStored);
    assert_false(violatesSingleAccountOrStoreIt(&path1));
}

static void test_single_account_rejects_different_account(void **state) {
    (void) state;
    reset_test_context();

    bip44_path_t path_account0 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 0);
    bip44_path_t path_account1 = make_wallet_path(PURPOSE_SHELLEY, 1, 0, 0);

    assert_false(violatesSingleAccountOrStoreIt(&path_account0));
    assert_true(violatesSingleAccountOrStoreIt(&path_account1));
}

static void test_single_account_byron_shelley_mix_allowed_only_for_account_zero(void **state) {
    (void) state;
    reset_test_context();

    bip44_path_t byron_account0 = make_wallet_path(PURPOSE_BYRON, 0, 0, 0);
    bip44_path_t shelley_account0 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 0);
    bip44_path_t byron_account1 = make_wallet_path(PURPOSE_BYRON, 1, 0, 0);
    bip44_path_t shelley_account1 = make_wallet_path(PURPOSE_SHELLEY, 1, 0, 0);

    assert_false(violatesSingleAccountOrStoreIt(&byron_account0));
    assert_false(violatesSingleAccountOrStoreIt(&shelley_account0));

    reset_test_context();
    assert_false(violatesSingleAccountOrStoreIt(&byron_account1));
    assert_true(violatesSingleAccountOrStoreIt(&shelley_account1));
}

static void test_count_pool_owner_nodes_counts_paths_and_first_path_owner(void **state) {
    (void) state;
    reset_test_context();

    tx_certificate_node_t owner1 = {0};
    tx_certificate_node_t owner2 = {0};
    tx_certificate_node_t owner3 = {0};

    owner1.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_HASH;
    owner2.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_PATH;
    owner3.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_PATH;

    owner1.flist_node.next = &owner2.flist_node;
    owner2.flist_node.next = &owner3.flist_node;
    owner3.flist_node.next = NULL;

    pool_owner_counts_t counts = count_pool_owner_nodes(&owner1.flist_node);
    assert_int_equal(counts.total_owners, 3);
    assert_int_equal(counts.path_owners, 2);
    assert_ptr_equal(counts.first_path_owner, &owner2.certificate.stakeCredential);
}

static void test_count_pool_owner_nodes_single_owner(void **state) {
    (void) state;
    reset_test_context();

    tx_certificate_node_t owner = {0};
    owner.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_PATH;
    owner.flist_node.next = NULL;

    pool_owner_counts_t counts = count_pool_owner_nodes(&owner.flist_node);
    assert_int_equal(counts.total_owners, 1);
    assert_int_equal(counts.path_owners, 1);
    assert_ptr_equal(counts.first_path_owner, &owner.certificate.stakeCredential);
}

static void test_count_pool_owner_nodes_all_hashes(void **state) {
    (void) state;
    reset_test_context();

    tx_certificate_node_t owner1 = {0};
    tx_certificate_node_t owner2 = {0};

    owner1.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_HASH;
    owner2.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_HASH;

    owner1.flist_node.next = &owner2.flist_node;
    owner2.flist_node.next = NULL;

    pool_owner_counts_t counts = count_pool_owner_nodes(&owner1.flist_node);
    assert_int_equal(counts.total_owners, 2);
    assert_int_equal(counts.path_owners, 0);
    assert_null(counts.first_path_owner);
}

static void test_count_pool_owner_nodes_mixed_with_path_first(void **state) {
    (void) state;
    reset_test_context();

    tx_certificate_node_t owner1 = {0};
    tx_certificate_node_t owner2 = {0};
    tx_certificate_node_t owner3 = {0};

    owner1.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_PATH;
    owner2.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_HASH;
    owner3.certificate.stakeCredential.type = EXT_CREDENTIAL_KEY_PATH;

    owner1.flist_node.next = &owner2.flist_node;
    owner2.flist_node.next = &owner3.flist_node;
    owner3.flist_node.next = NULL;

    pool_owner_counts_t counts = count_pool_owner_nodes(&owner1.flist_node);
    assert_int_equal(counts.total_owners, 3);
    assert_int_equal(counts.path_owners, 2);
    assert_ptr_equal(counts.first_path_owner, &owner1.certificate.stakeCredential);
}

static void test_single_account_account_number_zero_allowed_with_both_types(void **state) {
    (void) state;
    reset_test_context();

    // Account 0 should allow Byron/Shelley mixing
    bip44_path_t byron_0 = make_wallet_path(PURPOSE_BYRON, 0, 0, 0);
    bip44_path_t shelley_0 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 1);

    assert_false(violatesSingleAccountOrStoreIt(&byron_0));
    assert_false(violatesSingleAccountOrStoreIt(&shelley_0));
    assert_true(G_context.tx_info.single_account_data.isStored);
    assert_true(G_context.tx_info.single_account_data.isByron);
}

static void test_single_account_multiple_addresses_same_account(void **state) {
    (void) state;
    reset_test_context();

    bip44_path_t path0 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 0);
    bip44_path_t path1 = make_wallet_path(PURPOSE_SHELLEY, 0, 0, 1);
    bip44_path_t path2 = make_wallet_path(PURPOSE_SHELLEY, 0, 1, 0);

    assert_false(violatesSingleAccountOrStoreIt(&path0));
    assert_false(violatesSingleAccountOrStoreIt(&path1));
    assert_false(violatesSingleAccountOrStoreIt(&path2));
    assert_int_equal(G_context.tx_info.single_account_data.accountNumber, bip44_harden(0));
}

static void test_single_account_account_number_boundaries(void **state) {
    (void) state;
    reset_test_context();

    // Test account 1
    bip44_path_t account_1 = make_wallet_path(PURPOSE_SHELLEY, 1, 0, 0);
    assert_false(violatesSingleAccountOrStoreIt(&account_1));

    reset_test_context();

    // Test account 2
    bip44_path_t account_2 = make_wallet_path(PURPOSE_SHELLEY, 2, 0, 0);
    assert_false(violatesSingleAccountOrStoreIt(&account_2));

    // Now try account 3 - should fail
    bip44_path_t account_3 = make_wallet_path(PURPOSE_SHELLEY, 3, 0, 0);
    assert_true(violatesSingleAccountOrStoreIt(&account_3));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_single_account_store_and_reuse_same_account),
        cmocka_unit_test(test_single_account_rejects_different_account),
        cmocka_unit_test(test_single_account_byron_shelley_mix_allowed_only_for_account_zero),
        cmocka_unit_test(test_count_pool_owner_nodes_counts_paths_and_first_path_owner),
        cmocka_unit_test(test_count_pool_owner_nodes_single_owner),
        cmocka_unit_test(test_count_pool_owner_nodes_all_hashes),
        cmocka_unit_test(test_count_pool_owner_nodes_mixed_with_path_first),
        cmocka_unit_test(test_single_account_account_number_zero_allowed_with_both_types),
        cmocka_unit_test(test_single_account_multiple_addresses_same_account),
        cmocka_unit_test(test_single_account_account_number_boundaries),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

