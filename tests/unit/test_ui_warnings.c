/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "mem.h"
#include "ui_warnings.h"
#include "securityPolicy.h"

#define TEST_HEAP_SIZE (32 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static void init_heap(void) {
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
}

/* ---- helpers ---- */

/* Build a minimal warning_definition_t array on the stack for testing. */
static warning_definition_t make_def(const char *title, const char *description) {
    warning_definition_t def = {
        .bit = WARNING_BIT_NETWORK_UNUSUAL,  // value doesn't matter for these tests
        .title = title,
        .description = description,
    };
    return def;
}

/* ---- tests for build_warning_summary_text ---- */

static void test_build_warning_summary_text_no_descriptions_single(void **state) {
    (void) state;
    init_heap();

    warning_definition_t def = make_def("Unusual network", "Network id deviates");
    const warning_definition_t *defs[] = {&def};
    char *out = NULL;

    assert_true(build_warning_summary_text(defs, 0, 1, false, &out));
    assert_non_null(out);
    /* expect "Unusual network. " */
    assert_string_equal(out, "Unusual network. ");
    APP_MEM_FREE(out);
}

static void test_build_warning_summary_text_no_descriptions_multiple(void **state) {
    (void) state;
    init_heap();

    warning_definition_t def0 = make_def("Warning A", "Description A");
    warning_definition_t def1 = make_def("Warning B", "Description B");
    const warning_definition_t *defs[] = {&def0, &def1};
    char *out = NULL;

    assert_true(build_warning_summary_text(defs, 0, 2, false, &out));
    assert_non_null(out);
    assert_string_equal(out, "Warning A. Warning B. ");
    APP_MEM_FREE(out);
}

static void test_build_warning_summary_text_with_descriptions_single(void **state) {
    (void) state;
    init_heap();

    warning_definition_t def = make_def("Unusual network", "Network id deviates");
    const warning_definition_t *defs[] = {&def};
    char *out = NULL;

    assert_true(build_warning_summary_text(defs, 0, 1, true, &out));
    assert_non_null(out);
    /* expect "Unusual network: Network id deviates" (trailing \n replaced by \0) */
    assert_string_equal(out, "Unusual network: Network id deviates");
    APP_MEM_FREE(out);
}

static void test_build_warning_summary_text_with_descriptions_multiple(void **state) {
    (void) state;
    init_heap();

    warning_definition_t def0 = make_def("Warning A", "Desc A");
    warning_definition_t def1 = make_def("Warning B", "Desc B");
    const warning_definition_t *defs[] = {&def0, &def1};
    char *out = NULL;

    assert_true(build_warning_summary_text(defs, 0, 2, true, &out));
    assert_non_null(out);
    assert_string_equal(out, "Warning A: Desc A\nWarning B: Desc B");
    APP_MEM_FREE(out);
}

static void test_build_warning_summary_text_start_index(void **state) {
    (void) state;
    init_heap();

    warning_definition_t def0 = make_def("Warning A", "Desc A");
    warning_definition_t def1 = make_def("Warning B", "Desc B");
    warning_definition_t def2 = make_def("Warning C", "Desc C");
    const warning_definition_t *defs[] = {&def0, &def1, &def2};
    char *out = NULL;

    /* start_index=1 skips def0 */
    assert_true(build_warning_summary_text(defs, 1, 3, false, &out));
    assert_non_null(out);
    assert_string_equal(out, "Warning B. Warning C. ");
    APP_MEM_FREE(out);
}

/* ---- tests for ui_build_warnings / ui_free_warnings round-trip ---- */

static void test_ui_build_warnings_no_warnings(void **state) {
    (void) state;
    init_heap();

    assert_int_equal(ui_build_warnings(0), UI_STATUS_SUCCESS);
    assert_null(ui_get_warnings());
    ui_free_warnings();
}

static void test_ui_build_warnings_single_warning(void **state) {
    (void) state;
    init_heap();

    warning_bits_t bits = warning_bits_mask_for(WARNING_BIT_NETWORK_UNUSUAL);
    assert_int_equal(ui_build_warnings(bits), UI_STATUS_SUCCESS);
    assert_non_null(ui_get_warnings());
    ui_free_warnings();
    assert_null(ui_get_warnings());
}

static void test_ui_build_warnings_multiple_warnings(void **state) {
    (void) state;
    init_heap();

    warning_bits_t bits = warning_bits_mask_for(WARNING_BIT_NETWORK_UNUSUAL) |
                          warning_bits_mask_for(WARNING_BIT_NETWORK_NOT_VERIFIABLE);
    assert_int_equal(ui_build_warnings(bits), UI_STATUS_SUCCESS);
    assert_non_null(ui_get_warnings());
    ui_free_warnings();
}

static void test_ui_free_warnings_idempotent(void **state) {
    (void) state;
    init_heap();

    ui_free_warnings();  /* safe when nothing was built */
    ui_free_warnings();

    warning_bits_t bits = warning_bits_mask_for(WARNING_BIT_NETWORK_UNUSUAL);
    assert_int_equal(ui_build_warnings(bits), UI_STATUS_SUCCESS);
    ui_free_warnings();
    ui_free_warnings();  /* second call must not crash */
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_build_warning_summary_text_no_descriptions_single),
        cmocka_unit_test(test_build_warning_summary_text_no_descriptions_multiple),
        cmocka_unit_test(test_build_warning_summary_text_with_descriptions_single),
        cmocka_unit_test(test_build_warning_summary_text_with_descriptions_multiple),
        cmocka_unit_test(test_build_warning_summary_text_start_index),
        cmocka_unit_test(test_ui_build_warnings_no_warnings),
        cmocka_unit_test(test_ui_build_warnings_single_warning),
        cmocka_unit_test(test_ui_build_warnings_multiple_warnings),
        cmocka_unit_test(test_ui_free_warnings_idempotent),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
