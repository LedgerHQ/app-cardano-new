/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "addressUtils/bip44.h"

static bip44_path_t make_ordinary_account_path(uint32_t account) {
    bip44_path_t path = {0};
    path.length = 3;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    return path;
}

static bip44_path_t make_ordinary_payment_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 0;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_ordinary_staking_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 2;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_drep_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 3;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_committee_cold_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 4;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_committee_hot_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_SHELLEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 5;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_multisig_account_path(uint32_t account) {
    bip44_path_t path = {0};
    path.length = 3;
    path.path[0] = bip44_harden(PURPOSE_MULTISIG);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    return path;
}

static bip44_path_t make_multisig_payment_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_MULTISIG);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 0;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_multisig_staking_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_MULTISIG);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 2;
    path.path[4] = index;
    return path;
}

static bip44_path_t make_mint_path(uint32_t policy_index) {
    bip44_path_t path = {0};
    path.length = 3;
    path.path[0] = bip44_harden(PURPOSE_MINT);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(policy_index);
    return path;
}

static bip44_path_t make_pool_cold_path(uint32_t key_index) {
    bip44_path_t path = {0};
    path.length = 4;
    path.path[0] = bip44_harden(PURPOSE_POOL_COLD_KEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(0);
    path.path[3] = bip44_harden(key_index);
    return path;
}

static bip44_path_t make_cvote_account_path(uint32_t account) {
    bip44_path_t path = {0};
    path.length = 3;
    path.path[0] = bip44_harden(PURPOSE_CVOTE_KEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    return path;
}

static bip44_path_t make_cvote_key_path(uint32_t account, uint32_t index) {
    bip44_path_t path = {0};
    path.length = 5;
    path.path[0] = bip44_harden(PURPOSE_CVOTE_KEY);
    path.path[1] = bip44_harden(ADA_COIN_TYPE);
    path.path[2] = bip44_harden(account);
    path.path[3] = 0;
    path.path[4] = index;
    return path;
}

static void assert_policy_hides_path(const bip44_path_t *path) {
    assert_non_null(path);
    assert_int_equal(policyForDerivePrivateKey(path), POLICY_HIDE);
}

static void assert_path_is_invalid_for_private_key_policy(const bip44_path_t *path) {
    assert_non_null(path);
    assert_int_equal(bip44_classifyPath(path), PATH_INVALID);
}

static void test_policy_for_derive_private_key_hides_supported_key_families(void **state) {
    (void) state;

    const bip44_path_t paths[] = {
        make_ordinary_account_path(0),
        make_ordinary_payment_path(0, 0),
        make_ordinary_staking_path(0, 0),
        make_multisig_account_path(0),
        make_multisig_payment_path(0, 0),
        make_multisig_staking_path(0, 0),
        make_drep_path(0, 0),
        make_committee_cold_path(0, 0),
        make_committee_hot_path(0, 0),
        make_mint_path(0),
        make_pool_cold_path(0),
        make_cvote_account_path(0),
        make_cvote_key_path(0, 0),
    };

    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        assert_policy_hides_path(&paths[i]);
    }
}

static void test_policy_for_derive_private_key_rejects_invalid_ordinary_paths(void **state) {
    (void) state;

    const bip44_path_t paths[] = {
        {.path = {bip44_harden(PURPOSE_SHELLEY), bip44_harden(ADA_COIN_TYPE), bip44_harden(0), 0}, .length = 4},
        {.path = {bip44_harden(PURPOSE_SHELLEY), bip44_harden(ADA_COIN_TYPE), 0, 0, 0}, .length = 5},
    };

    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        assert_path_is_invalid_for_private_key_policy(&paths[i]);
    }
}

static void test_policy_for_derive_private_key_rejects_invalid_multisig_paths(void **state) {
    (void) state;

    const bip44_path_t paths[] = {
        {.path = {bip44_harden(PURPOSE_MULTISIG), bip44_harden(ADA_COIN_TYPE)}, .length = 2},
        {.path = {bip44_harden(PURPOSE_MULTISIG), bip44_harden(ADA_COIN_TYPE), 0, 0, 0}, .length = 5},
        {.path = {bip44_harden(PURPOSE_MULTISIG), bip44_harden(ADA_COIN_TYPE), bip44_harden(0), 0}, .length = 4},
    };

    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        assert_path_is_invalid_for_private_key_policy(&paths[i]);
    }
}

static void test_policy_for_derive_private_key_rejects_invalid_cvote_paths(void **state) {
    (void) state;

    const bip44_path_t paths[] = {
        {.path = {bip44_harden(PURPOSE_CVOTE_KEY), bip44_harden(ADA_COIN_TYPE)}, .length = 2},
        {.path = {bip44_harden(PURPOSE_CVOTE_KEY), bip44_harden(ADA_COIN_TYPE), 0, 3, 0}, .length = 5},
        {.path = {bip44_harden(PURPOSE_CVOTE_KEY), bip44_harden(ADA_COIN_TYPE), bip44_harden(0), 3}, .length = 4},
    };

    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        assert_path_is_invalid_for_private_key_policy(&paths[i]);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_policy_for_derive_private_key_hides_supported_key_families),
        cmocka_unit_test(test_policy_for_derive_private_key_rejects_invalid_ordinary_paths),
        cmocka_unit_test(test_policy_for_derive_private_key_rejects_invalid_multisig_paths),
        cmocka_unit_test(test_policy_for_derive_private_key_rejects_invalid_cvote_paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
