#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"
#include "app_context.h"
#include "handler/get_public_key.h"
#include "keyDerivation.h"
#include "securityPolicy/securityPolicyType.h"
#include "securityPolicy/securityWarnings.h"
#include "test_fixture_types.h"
#include "cardano_settings.h"

// ----------------------------------------------------------------------
// Test state
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;
static uint8_t g_last_response[EXTENDED_PUBKEY_SIZE];
static size_t g_last_response_len = 0;
static uint8_t g_last_policy = 0;
static const pubkey_fixture_t *g_active_fixture = NULL;

static inline void reset_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_NONE;
    g_last_sw = 0;
    g_last_response_len = 0;
    g_last_policy = 0;
    g_active_fixture = NULL;
}

// ----------------------------------------------------------------------
// Minimal stubs for IO and NBGL
// ----------------------------------------------------------------------

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    g_last_sw = swo;
    g_last_response_len = bufferLength;
    if (buffer != NULL && bufferLength > 0) {
        assert_true(bufferLength <= sizeof(g_last_response));
        memcpy(g_last_response, buffer, bufferLength);
    }
    return 0;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

void nbgl_useCaseStatus(const char *text, bool success, void (*callback)(void)) {
    (void) text;
    (void) success;
    if (callback != NULL) {
        callback();
    }
}

void ui_menu_main(void) {
    // no-op
}

// ----------------------------------------------------------------------
// UI stub
// ----------------------------------------------------------------------

void ui_display_pubkey(security_policy_t policy, warning_bits_t warnings) {
    (void) warnings;
    g_last_policy = (uint8_t) policy;

    if (g_active_fixture != NULL && g_active_fixture->expected_policy != 0) {
        assert_int_equal(g_active_fixture->expected_policy, g_last_policy);
    }

    finalize_pubkey_export(true);
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_fixture(const pubkey_fixture_t *fixture) {
    reset_context();

    unit_test_silent_pubkey_export_enabled = fixture->silent_export_enabled;
    g_active_fixture = fixture;

    buffer_t buf = {
        .ptr = fixture->data,
        .size = fixture->data_len,
        .offset = 0,
    };

    apdu_response_begin(INS_GET_PUBLIC_KEY);
    handler_get_public_key(&buf);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, fixture->check_expected);

    if (fixture->check_expected == SWO_SUCCESS) {
        assert_int_equal(g_last_response_len, fixture->expected_response_len);
        assert_memory_equal(g_last_response, fixture->expected_response, fixture->expected_response_len);
    }
}
