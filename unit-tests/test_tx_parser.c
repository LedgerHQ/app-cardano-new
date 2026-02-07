#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "globals.h"
#include "tx_parse.h"
#include "tx_constants.h"
#include "cardano_swo.h"
#include "memory/mem.h"

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];
static uint16_t g_last_sw = 0;

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    assert_true(test_mem_init());
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

static void test_parse_tx_fails_on_missing_fee(void **state) {
    (void) state;
    reset_test_context();

    uint8_t empty_tx = 0;
    buffer_t buf = {
        .ptr = &empty_tx,
        .size = 0,
        .offset = 0,
    };
    transaction_t tx = {0};
    tx.num_inputs = 0;
    tx.num_outputs = 0;

    parser_status_e status = parse_tx(&buf, &tx);
    assert_int_equal(status, FEE_PARSING_ERROR);
}

static void test_parse_tx_rejects_oversized_buffer(void **state) {
    (void) state;
    reset_test_context();

    uint8_t one_byte = 0;
    buffer_t buf = {
        .ptr = &one_byte,
        .size = TX_BUFFER_SIZE + 1,
        .offset = 0,
    };
    transaction_t tx = {0};

    parser_status_e status = parse_tx(&buf, &tx);
    assert_int_equal(status, TX_SIZE_TOO_LARGE_ERROR);
}

static void test_parse_error_mapping_fee(void **state) {
    (void) state;
    reset_test_context();

    tx_handle_parse_error(FEE_PARSING_ERROR);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_FEE);
}

static void test_parse_error_mapping_buffer_not_fully_consumed(void **state) {
    (void) state;
    reset_test_context();

    tx_handle_parse_error(TX_BUFFER_NOT_FULLY_CONSUMED_ERROR);
    assert_int_equal(g_last_sw, SWO_TX_PARSING_FAIL_BUFFER_NOT_FULLY_CONSUMED);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_tx_fails_on_missing_fee),
        cmocka_unit_test(test_parse_tx_rejects_oversized_buffer),
        cmocka_unit_test(test_parse_error_mapping_fee),
        cmocka_unit_test(test_parse_error_mapping_buffer_not_fully_consumed),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
