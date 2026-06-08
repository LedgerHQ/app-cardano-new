/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "app_mem_utils.h"
#include "cardano_constants.h"
#include "mem.h"
#include "tx_processing.h"
#include "tx_ui_pair_counts.h"
#include "tx_ui_render_certificates.h"
#include "ui_utils.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static void init_render_context(uint16_t pair_count) {
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
    assert_true(ui_pairs_init(pair_count));
    ui_reset_error_status();
}

static void test_render_pool_retirement_with_key_hash_credential(void **state) {
    (void) state;
    init_render_context(UI_PAIRS_CERTIFICATE_POOL_RETIREMENT);

    static const uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    certificate_data_t certificate_data = {
        .type = CERTIFICATE_STAKE_POOL_RETIREMENT,
        .poolCredential =
            {
                .type = EXT_CREDENTIAL_KEY_HASH,
                .keyHash = pool_key_hash,
            },
        .retirementEpoch = 42,
    };
    const tx_processing_mode_t mode = {
        .ui_render = true,
    };

    ui_render_session_t session = {0};
    ui_render_session_begin(&session, 0);
    tx_ui_plan_or_render_certificate(&mode, &certificate_data);
    ui_render_session_end();

    assert_int_equal(ui_get_error_status(), UI_STATUS_SUCCESS);
    assert_int_equal(ui_pairs_get_count(), UI_PAIRS_CERTIFICATE_POOL_RETIREMENT);
    assert_string_equal(g_pairs[0].item, "Certificate");
    assert_string_equal(g_pairs[1].item, "Pool ID");
    assert_string_equal(g_pairs[2].item, UI_LABEL_BY_SCREEN("Retirement epoch", "Retire epoch"));
    assert_string_equal(g_pairs[2].value, "42");

    ui_free_pairs();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_render_pool_retirement_with_key_hash_credential),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
