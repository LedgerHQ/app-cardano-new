/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "addressUtils/bip44.h"

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

static void test_policy_for_derive_private_key_hides_standard_payment_key(void **state) {
    (void) state;

    bip44_path_t path = make_ordinary_payment_path(0, 0);

    assert_int_equal(policyForDerivePrivateKey(&path), POLICY_HIDE);
}

static void test_policy_for_derive_private_key_denies_invalid_path(void **state) {
    (void) state;

    bip44_path_t path = {0};

    assert_int_equal(policyForDerivePrivateKey(&path), POLICY_DENY);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_policy_for_derive_private_key_hides_standard_payment_key),
        cmocka_unit_test(test_policy_for_derive_private_key_denies_invalid_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
