#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "mem.h"
#include "ui_utils.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static void test_ui_pairs_add_static_label_stores_value(void **state) {
    (void) state;
    assert_true(mem_utils_init(test_heap, sizeof(test_heap)));
    assert_true(ui_pairs_init(1));

    char *tmp = NULL;
    assert_true(APP_MEM_CALLOC((void **) &tmp, 16));
    memcpy(tmp, "hello", sizeof("hello"));

    assert_true(ui_pairs_add_static_label("Label", tmp));
    assert_string_equal(g_pairs[0].item, "Label");
    assert_string_equal(g_pairs[0].value, "hello");

    ui_free_pairs();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ui_pairs_add_static_label_stores_value),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
