/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "securityPolicy/securityPolicy.h"
#include "transaction/tx.h"

static void test_reference_input_denied_in_ordinary_tx(void **state) {
    (void) state;

    tx_input_t reference_input = {0};
    warning_bits_t warnings = 0;

    assert_int_equal(
        policyForSignTxReferenceInput(SIGN_TX_SIGNINGMODE_ORDINARY, &reference_input, &warnings),
        POLICY_DENY);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reference_input_denied_in_ordinary_tx),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
