#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_swo.h"
#include "globals.h"
#include "handler/sign_msg.h"
#include "securityPolicy/securityPolicyType.h"
#include "test_fixture_types.h"
#include "mock_crypto/crypto_mock_data.h"

// ----------------------------------------------------------------------
// Test state
// ----------------------------------------------------------------------

static uint16_t g_last_sw = 0;
static uint8_t g_last_response[ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + MAX_ADDRESS_LENGTH];
static size_t g_last_response_len = 0;

static inline void reset_sign_msg_test_state(void) {
    reset_app_context();
    g_last_sw = 0;
    g_last_response_len = 0;
    G_context.state.sign_msg_state = SIGN_MSG_STATE_NONE;
    G_context.req_type = REQUEST_NONE;
}

// ----------------------------------------------------------------------
// IO / NBGL stubs
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

void nbgl_useCaseSpinner(const char *text) {
    (void) text;
}

void nbgl_useCaseStatus(const char *text, bool success, void (*callback)(void)) {
    (void) text;
    (void) success;
    if (callback != NULL) {
        callback();
    }
}

typedef enum {
    STATUS_TYPE_OPERATION_SIGNED = 0,
    STATUS_TYPE_OPERATION_REJECTED = 1,
} nbgl_reviewStatusType_t;

void nbgl_useCaseReviewStatus(nbgl_reviewStatusType_t reviewStatusType, void (*callback)(void)) {
    (void) reviewStatusType;
    if (callback != NULL) {
        callback();
    }
}

void ui_menu_main(void) {
    // stub
}

// ----------------------------------------------------------------------
// UI stub
// ----------------------------------------------------------------------

void ui_display_sign_msg(security_policy_t policy) {
    (void) policy;
    finalize_sign_msg(true);
}

// ----------------------------------------------------------------------
// Fixture runner
// ----------------------------------------------------------------------

static inline void run_fixture(const sign_msg_fixture_t *fixture) {
    assert_non_null(fixture);
    reset_sign_msg_test_state();
    reset_mock_signature_state();

    buffer_t init_buffer = {
        .ptr = fixture->init_data,
        .size = fixture->init_data_len,
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_MSG);
    handler_sign_msg(&init_buffer, P1_SIGN_MSG_INIT);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, fixture->check_expected);

    for (size_t chunk_idx = 0; chunk_idx < fixture->chunk_count; chunk_idx++) {
        const sign_msg_chunk_t *chunk = &fixture->chunks[chunk_idx];
        buffer_t chunk_buffer = {
            .ptr = chunk->data,
            .size = chunk->data_len,
            .offset = 0,
        };
        apdu_response_begin(INS_SIGN_MSG);
        handler_sign_msg(&chunk_buffer, P1_SIGN_MSG_CHUNK);
        apdu_response_assert_sent_or_deferred();
        assert_int_equal(g_last_sw, fixture->check_expected);
    }

    buffer_t confirm_buffer = {
        .ptr = fixture->confirm_data,
        .size = fixture->confirm_data_len,
        .offset = 0,
    };
    apdu_response_begin(INS_SIGN_MSG);
    handler_sign_msg(&confirm_buffer, P1_SIGN_MSG_CONFIRM);
    apdu_response_assert_sent_or_deferred();
    assert_int_equal(g_last_sw, fixture->check_expected);

    assert_true(g_last_response_len > 0);

    assert_non_null(g_mock_last_signature_entry);
    assert_true(g_mock_last_signed_message_len > 0);
    assert_int_equal(g_mock_last_signed_message_len, g_mock_last_signature_entry->message_len);
    assert_memory_equal(g_mock_last_signed_message,
                        g_mock_last_signature_entry->message,
                        g_mock_last_signature_entry->message_len);

    const uint8_t *response_ptr = g_last_response;
    assert_true(g_last_response_len >= ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4);

    const uint8_t *signed_message_signature = response_ptr;
    const uint8_t *signed_message_public_key = signed_message_signature + ED25519_SIGNATURE_LENGTH;
    const uint8_t *address_length_ptr = signed_message_public_key + PUBLIC_KEY_LENGTH;

    const size_t address_field_len = ((size_t)address_length_ptr[0] << 24)
        | ((size_t)address_length_ptr[1] << 16)
        | ((size_t)address_length_ptr[2] << 8)
        | (size_t)address_length_ptr[3];

    const uint8_t *address_field = address_length_ptr + 4;
    assert_true(
        g_last_response_len
        >= ED25519_SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + 4 + address_field_len
    );

    if (fixture->expected != NULL) {
        assert_int_equal(fixture->expected->signature_len, ED25519_SIGNATURE_LENGTH);
        assert_memory_equal(
            signed_message_signature,
            fixture->expected->signature,
            fixture->expected->signature_len
        );
        assert_int_equal(fixture->expected->public_key_len, PUBLIC_KEY_LENGTH);
        assert_memory_equal(
            signed_message_public_key,
            fixture->expected->public_key,
            fixture->expected->public_key_len
        );
        assert_int_equal(fixture->expected->address_field_len, address_field_len);
        assert_memory_equal(
            address_field,
            fixture->expected->address_field,
            fixture->expected->address_field_len
        );
    }
}
