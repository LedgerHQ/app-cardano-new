#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "globals.h"
#include "securityPolicy/securityPolicy.h"
#include "apdu/dispatcher.h"
#include "globals.h"

#include <cmocka.h>
#include "handler/derive_address.h"
#include "hexUtils.h"
#include "mock_crypto/crypto_mock_data.h"
#include "blake2b.h"
#include "memory/mem.h"

#include "test_derive_native_script_fixtures.h"
#include "handler/derive_address.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;

// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------

#define TEST_HEAP_SIZE (23 * 1024)
static uint8_t test_heap[TEST_HEAP_SIZE];

static inline bool test_mem_init(void) {
    return mem_utils_init(test_heap, sizeof(test_heap));
}

extern bool app_mem_init(void);
static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}


/*
run_simple_fixture(const native_script_test_case_t *fixture){
    
}

run_complex_fixture(const native_script_test_case_t *fixture){
    
}*/

static inline void run_fixture(const native_script_test_case_t *fixture) {
    reset_context();
    assert_true(test_mem_init());

    TRACE("Running derive address fixture: %s\n", fixture->name);
    /*
    // Mock the handler call with fixture data
    // The handler should reject and return the expected status word
    g_last_sw = 0;

    
    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };
    TRACE_BUFFER(buf.ptr, buf.size);
    handler_derive_native_script(&buf, fixture->p1);
    assert_int_equal(g_last_sw, fixture->check_expected);
    */
}