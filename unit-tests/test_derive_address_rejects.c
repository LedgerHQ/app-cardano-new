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

#include "blake2b.h"

#include "test_address_derivation_fixtures_rejects.h"
#include "test_fixture_types.h"

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

// P1 constants now defined in dispatcher.h (already included above)

static uint16_t g_last_sw = 0;

// ----------------------------------------------------------------------
// Simple mocks for IO and UI plumbing so we can drive the handler
// ----------------------------------------------------------------------

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
    (void) policy;
}

void ui_deriveAddress_handleDisplay(security_policy_t policy, warning_bits_t warnings) {
    (void) policy;
}

// Test function that iterates through all rejection fixtures
static void test_derive_address_rejects(void **state) {
    (void) state;

    // Iterate through all generated rejection fixtures
    for (size_t i = 0; i < DERIVE_ADDRESS_REJECT_FIXTURE_COUNT; i++) {
        TRACE("+++++++++++++++++++++++Registering test: %d +++++++++++++++++++++++", i);
        const derive_address_reject_fixture_t *fixture = &DERIVE_ADDRESS_REJECT_FIXTURES[i];

        // Mock the handler call with fixture data
        // The handler should reject and return the expected status word
        g_last_sw = 0;

        buffer_t buf = {
            .ptr = fixture->data,
            .size = fixture->data_len,
            .offset = 0,
        };
        TRACE_BUFFER(buf.ptr, buf.size);
        handler_derive_address(&buf, P1_ADDRESS_RETURN);
        assert_int_equal(g_last_sw, fixture->check_expected);
    }
}

// Register the test
int main(void) {
    TRACE("Starting test_derive_address_rejects");
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_derive_address_rejects),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}