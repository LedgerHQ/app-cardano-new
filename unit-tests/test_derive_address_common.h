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
#include "app_context.h"

#include "test_fixture_types.h"
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

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings);
void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings);

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

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

void ui_deriveAddress_handleReturn(security_policy_t policy, warning_bits_t warnings) {
     derive_address_ctx_t *ctx = &G_context.derive_address_info;
// Validate state before proceeding (address must be prepared before UI display)
    switch (policy) {
        case POLICY_SHOW:
            io_send_response_pointer(ctx->address.buffer, ctx->address.length, SWO_SUCCESS);
            break;
        case POLICY_HIDE: {
            // Silently approve and return address without UI
            derive_address_ctx_t *ctx = &G_context.derive_address_info;
            LEDGER_ASSERT(ctx->address.length <= sizeof(ctx->address.buffer), "Address length too large");
            G_context.state.derive_address_state = DERIVE_ADDRESS_STATE_APPROVED;
            io_send_response_pointer(ctx->address.buffer, ctx->address.length, SWO_SUCCESS);
            reset_app_context();
            break;
        }
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleReturn: %d", policy);
            break;
    }
    
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    switch (policy) {
        case POLICY_SHOW:
            io_send_response_pointer(NULL, 0, SWO_SUCCESS);
            break;
        default:
            LEDGER_ASSERT(false, "Invalid policy in ui_deriveAddress_handleDisplay: %d", policy);
            break;
    }
}

static inline void run_fixture(const derive_address_fixture_t *fixture) {
    reset_context();
    assert_true(test_mem_init());

    TRACE("Running derive address fixture: %s\n", fixture->name);

    // Mock the handler call with fixture data
    // The handler should reject and return the expected status word
    g_last_sw = 0;

    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };
    TRACE_BUFFER(buf.ptr, buf.size);
    handler_derive_address(&buf, fixture->p1);
    assert_int_equal(g_last_sw, fixture->check_expected);

    if (fixture->expected_address != NULL && fixture->expected_address_len > 0) {
        derive_address_ctx_t *ctx = &G_context.derive_address_info;
        assert_int_equal(ctx->address.length, fixture->expected_address_len);
        assert_memory_equal(
            ctx->address.buffer,
            fixture->expected_address,
            fixture->expected_address_len);
    }
}
